"""Confidence-aware risk scoring for RepoTrace (v2 engine).

The original model let a single secret-pattern regex hit add 40 points and any
VT-malicious file add 60, so one false-positive secret match (common on test
fixtures / example configs) could push a benign repository straight to
MEDIUM/HIGH. This version:

* Weights secret findings by the confidence tier from the IOC engine. A lone
  low-confidence assignment cannot move the needle much; corroborated
  high-confidence credentials still score strongly.
* Keeps VirusTotal as the dominant signal (it is ground truth about file
  reputation) but separates "score" from "confidence" so the UI can show how
  much of the score rests on soft signals.
* Returns named factors with per-factor confidence, so every point in the
  score is explainable in the dashboard.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskFactor:
    category: str
    points: int
    reason: str
    confidence: str  # high | medium | low


@dataclass
class RiskResult:
    score: int
    level: str
    confidence: str
    reasons: list[str] = field(default_factory=list)
    factors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "factors": self.factors,
        }


def _count_secret_tiers(files: list[dict], aggregate_iocs: dict) -> dict[str, int]:
    tiers = {"high": 0, "medium": 0, "low": 0}
    for f in files:
        for hit in (f.get("iocs", {}) or {}).get("secret_hits", []) or []:
            c = hit.get("confidence", "low")
            if c in tiers:
                tiers[c] += 1
    # Aggregate-level hits (from combined text) also count if files carried none.
    if not any(tiers.values()):
        for hit in aggregate_iocs.get("secret_hits", []) or []:
            c = hit.get("confidence", "low")
            if c in tiers:
                tiers[c] += 1
    return tiers


def score_risk(
    repo: dict,
    files: list[dict],
    commits: list[dict],
    iocs: dict,
    findings: list[dict],
    infra: dict,
) -> dict:
    factors: list[RiskFactor] = []

    def add(points: int, reason: str, category: str, confidence: str) -> None:
        factors.append(RiskFactor(category, points, reason, confidence))

    # --- Governance / state (low weight, high certainty) ---
    if not repo.get("license"):
        add(4, "No detected license", "governance", "high")
    if repo.get("archived"):
        add(3, "Repository is archived", "repo_state", "high")

    # --- Secrets, weighted by confidence tier ---
    tiers = _count_secret_tiers(files, iocs)
    if tiers["high"]:
        add(min(45, 25 + 10 * tiers["high"]),
            f"{tiers['high']} high-confidence secret(s) detected (e.g. cloud/API keys)",
            "secrets", "high")
    if tiers["medium"]:
        add(min(20, 8 * tiers["medium"]),
            f"{tiers['medium']} medium-confidence secret-like token(s) detected",
            "secrets", "medium")
    if tiers["low"]:
        # Soft: capped low so a lone test-fixture assignment cannot dominate.
        add(min(8, 3 * tiers["low"]),
            f"{tiers['low']} low-confidence secret-like assignment(s); likely needs manual triage",
            "secrets", "low")

    # --- External infrastructure breadth (soft) ---
    if len(iocs.get("urls", [])) > 25:
        add(6, "Large number of external URLs referenced", "external_infra", "low")
    if len(infra.get("external_services", [])) > 4:
        add(6, "Multiple external services referenced", "external_infra", "medium")

    # --- Commit trust ---
    unsigned = sum(1 for c in commits if c.get("verified") is False)
    if unsigned >= 5:
        add(7, "Multiple recent commits are unsigned/unverified", "commit_trust", "medium")

    # --- Recent change risk ---
    if any(f.get("type") == "sensitive_path_changed" for f in findings):
        add(14, "Sensitive paths changed recently", "change_risk", "medium")
    if any(f.get("type") == "suspicious_added_content" for f in findings):
        add(22, "Suspicious code/content introduced in recent changes", "change_risk", "medium")
    if any(f.get("type") == "interesting_file" for f in findings):
        add(5, "Interesting executable/config files present", "file_profile", "low")

    # --- VirusTotal: dominant, high-confidence signal ---
    vt_mal = sum(1 for f in files if (f.get("vt") or {}).get("verdict") == "malicious")
    vt_susp = sum(1 for f in files if (f.get("vt") or {}).get("verdict") == "suspicious")
    if vt_mal:
        add(60, f"VirusTotal reports {vt_mal} file(s) as malicious", "virustotal", "high")
    elif vt_susp:
        add(25, f"VirusTotal reports {vt_susp} file(s) as suspicious", "virustotal", "high")

    score = min(sum(f.points for f in factors), 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

    # Overall confidence = the strongest tier that materially contributes.
    high_pts = sum(f.points for f in factors if f.confidence == "high")
    med_pts = sum(f.points for f in factors if f.confidence == "medium")
    if high_pts >= max(20, score * 0.4):
        confidence = "high"
    elif (high_pts + med_pts) >= max(15, score * 0.4):
        confidence = "medium"
    else:
        confidence = "low"

    reasons = [f.reason for f in factors]
    if not factors:
        reasons = ["No major suspicious indicators in analyzed subset"]
        factors = [RiskFactor("baseline", 0, reasons[0], "high")]
        confidence = "high"

    return RiskResult(
        score=score,
        level=level,
        confidence=confidence,
        reasons=reasons,
        factors=[f.__dict__ for f in factors],
    ).to_dict()


def attack_narrative(result: dict) -> str:
    """Human-readable narrative that is honest about confidence."""
    risk = result.get("risk", {})
    findings = result.get("suspicious_findings", [])
    iocs = result.get("iocs", {})
    infra = result.get("infra_links", {})
    conf = risk.get("confidence", "low")

    parts = [
        f"This repository profiles as {risk.get('level', 'UNKNOWN')} risk "
        f"(score {risk.get('score', '-')}/100, {conf} confidence)."
    ]

    high_secret = any(
        h.get("confidence") == "high"
        for f in result.get("files_analyzed", []) or []
        for h in (f.get("iocs", {}) or {}).get("secret_hits", []) or []
    )
    low_only = (not high_secret) and bool(iocs.get("secret_pattern_hits"))
    if high_secret:
        parts.append("High-confidence credential material was detected and should be rotated and validated immediately.")
    elif low_only:
        parts.append("Only low-confidence secret-like strings were seen; these are frequently test fixtures and should be manually confirmed before treating as real exposure.")

    if any(f.get("type") in {"sensitive_path_changed", "suspicious_added_content"} for f in findings):
        parts.append("Recent changes touched sensitive paths or introduced suspicious constructs, so commit-level review is recommended.")
    if any((f.get("vt") or {}).get("verdict") == "malicious" for f in result.get("files_analyzed", []) or []):
        parts.append("One or more files have malicious VirusTotal reputation and should be treated as high-priority evidence.")
    if infra.get("external_services"):
        parts.append("The repository references external services that may matter for supply-chain or callback analysis.")
    if not findings:
        parts.append("No strong suspicious findings were detected in the scanned subset, though large repositories may require targeted follow-up.")
    return " ".join(parts)
