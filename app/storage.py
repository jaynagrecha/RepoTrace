import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

DATA_DIR = Path("data/investigations")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _safe_slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value)[:90].strip("_") or "investigation"


def save_investigation(payload: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    snapshot = payload.get("snapshot") or {}
    title = payload.get("title") or snapshot.get("full_name") or "RepoTrace investigation"
    inv_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid4().hex[:8]}"
    record = {"id": inv_id, "title": title, "created_at": now, "updated_at": now, "payload": payload}
    path = DATA_DIR / f"{inv_id}_{_safe_slug(title)}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"id": inv_id, "title": title, "path": str(path), "created_at": now}


def list_investigations() -> list[dict[str, Any]]:
    rows = []
    for p in sorted(DATA_DIR.glob("*.json"), reverse=True):
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            rows.append({"id": obj.get("id"), "title": obj.get("title"), "created_at": obj.get("created_at"), "path": str(p)})
        except Exception:
            continue
    return rows[:200]


def read_investigation(inv_id: str) -> dict[str, Any]:
    for p in DATA_DIR.glob(f"{inv_id}*.json"):
        return json.loads(p.read_text(encoding="utf-8"))
    raise FileNotFoundError("Investigation not found")
