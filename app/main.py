from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from pathlib import Path
from io import BytesIO
from urllib.parse import urlencode
import os

from .github_client import GitHubClient
from .gitlab_client import GitLabClient
from .parsers import parse_github_url
from .analyzer import RepoTraceAnalyzer
from .storage import list_investigations, read_investigation, save_investigation
from .usage import usage_manager, enforce_or_429, require_admin_basic
from .payments import payment_manager

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

app = FastAPI(title="RepoTrace", version="0.22.1")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


class AnalyzeRequest(BaseModel):
    url: str = Field(..., examples=["https://github.com/owner/repo"])
    max_files: int = Field(120, ge=1, le=300)
    max_commits: int = Field(60, ge=1, le=120)


class BulkScanRequest(BaseModel):
    urls: list[str]
    max_files: int = Field(80, ge=1, le=220)
    max_commits: int = Field(35, ge=1, le=100)
    concurrency: int = Field(3, ge=1, le=6)


class CompareRequest(BaseModel):
    owner: str
    repo: str
    base: str
    head: str


class FileHistoryRequest(BaseModel):
    owner: str
    repo: str
    path: str
    branch: str | None = None
    max_commits: int = Field(50, ge=1, le=100)


class TimelineRequest(BaseModel):
    owner: str
    repo: str
    branch: str | None = None
    max_commits: int = Field(80, ge=1, le=120)


class ReportRequest(BaseModel):
    owner: str
    repo: str
    branch: str | None = None
    max_files: int = Field(100, ge=1, le=300)
    max_commits: int = Field(60, ge=1, le=120)


class SaveInvestigationRequest(BaseModel):
    title: str | None = None
    result: dict




class PaymentCreateRequest(BaseModel):
    units: int = Field(1, ge=1, le=20)


class PaymentVerifyRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class RepoCompareRequest(BaseModel):
    repo_a_url: str
    repo_b_url: str
    max_files: int = Field(80, ge=1, le=220)
    max_commits: int = Field(35, ge=1, le=100)

class AccountScanRequest(BaseModel):
    account: str
    account_type: str = Field("auto", pattern="^(auto|user|org)$")
    max_repos: int = Field(50, ge=1, le=200)
    max_files: int = Field(60, ge=1, le=220)
    max_commits: int = Field(25, ge=1, le=100)
    concurrency: int = Field(3, ge=1, le=6)


class WatchRequest(BaseModel):
    target: str
    target_type: str = Field("auto", pattern="^(auto|user|org|repo)$")
    notify_email: str | None = None
    max_repos: int = Field(50, ge=1, le=200)
    max_files: int = Field(70, ge=1, le=220)
    max_commits: int = Field(30, ge=1, le=100)
    concurrency: int = Field(3, ge=1, le=6)




def build_upi_uri(amount: str | None = None) -> str:
    upi_id = os.getenv("UPI_ID", "").strip()
    upi_name = os.getenv("UPI_NAME", "RepoTrace").strip() or "RepoTrace"
    price = str(amount or os.getenv("PRICE_PER_SEARCH") or os.getenv("PRICE_PER_SEARCH_INR") or "2").strip()
    params = {
        "pa": upi_id,
        "pn": upi_name,
        "am": price,
        "cu": "INR",
        "tn": os.getenv("UPI_PAYMENT_NOTE", f"RepoTrace search ₹{price}"),
    }
    return "upi://pay?" + urlencode(params)




@app.get("/api/payment-config")
async def payment_config(request: Request):
    cfg = payment_manager.public_config()
    status = usage_manager.status_for_request(request)
    return {
        "provider": cfg.provider,
        "configured": cfg.configured,
        "key_id": cfg.key_id,
        "currency": cfg.currency,
        "amount_inr": cfg.amount_inr,
        "mode": cfg.mode,
        "live_mode": cfg.live_mode,
        "webhook_configured": cfg.webhook_configured,
        "payments_enabled": cfg.payments_enabled,
        "upi_first": cfg.upi_first,
        "paid_credits": status.get("paid_credits", 0),
        "public_mode": status.get("public_mode"),
        "remaining_today": status.get("remaining_today"),
    }


@app.post("/api/payments/create")
async def create_payment(req: PaymentCreateRequest, request: Request):
    return await payment_manager.create_order(request, units=req.units)


@app.post("/api/payments/verify")
async def verify_payment(req: PaymentVerifyRequest):
    return await payment_manager.verify_checkout(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature)


@app.post("/api/payments/webhook")
async def razorpay_webhook(request: Request):
    return await payment_manager.handle_webhook(request)


@app.get("/api/payments/status/{order_id}")
async def payment_status(order_id: str):
    return await payment_manager.order_status(order_id)

@app.get("/api/payment-intent")
async def payment_intent(amount: str | None = None):
    upi_id = os.getenv("UPI_ID", "").strip()
    if not upi_id:
        raise HTTPException(status_code=400, detail="UPI_ID is not configured in .env")
    price = str(amount or os.getenv("PRICE_PER_SEARCH") or os.getenv("PRICE_PER_SEARCH_INR") or "2").strip()
    return {
        "upi_id": upi_id,
        "upi_name": os.getenv("UPI_NAME", "RepoTrace"),
        "amount_inr": price,
        "upi_uri": build_upi_uri(price),
        "qr_url": f"/api/payment-qr?amount={price}",
        "note": "This QR prefills the amount. Automatic payment verification requires a payment gateway/callback integration.",
    }


@app.get("/api/payment-qr")
async def payment_qr(amount: str | None = None):
    upi_id = os.getenv("UPI_ID", "").strip()
    if not upi_id:
        raise HTTPException(status_code=400, detail="UPI_ID is not configured in .env")
    try:
        import qrcode
    except Exception:
        raise HTTPException(status_code=500, detail="qrcode package missing. Run: pip install qrcode[pil]")
    uri = build_upi_uri(amount)
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png", headers={"Cache-Control": "no-store"})

@app.get("/")
async def home():
    return FileResponse("app/static/index.html")


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    try:
        enforce_or_429(request, units=1, endpoint="analyze")
        target = parse_github_url(req.url)
        result = await RepoTraceAnalyzer().analyze(target, max_files=req.max_files, max_commits=req.max_commits)
        result["usage"] = usage_manager.record(request, units=1, endpoint="analyze")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/bulk-scan")
async def bulk_scan(req: BulkScanRequest, request: Request):
    try:
        units = max(1, len(req.urls or []))
        enforce_or_429(request, units=units, endpoint="bulk-scan")
        result = await RepoTraceAnalyzer().bulk_scan(req.urls, max_files=req.max_files, max_commits=req.max_commits, concurrency=req.concurrency)
        result["usage"] = usage_manager.record(request, units=units, endpoint="bulk-scan")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/api/token-status")
async def token_status():
    gh = GitHubClient()
    gl = GitLabClient()
    status = {"github_token_configured": bool(gh.token), "gitlab_token_configured": bool(gl.token)}
    try:
        rl = await gh.rate_limit()
        core = (rl.get("resources") or {}).get("core") or {}
        status["rate_limit"] = {"limit": core.get("limit"), "remaining": core.get("remaining"), "reset": core.get("reset"), "used": core.get("used")}
    except Exception as e:
        status["rate_limit_error"] = str(e)
    return status


@app.get("/api/usage-status")
async def usage_status(request: Request):
    return usage_manager.status_for_request(request)


@app.get("/api/public-config")
async def public_config(request: Request):
    return usage_manager.status_for_request(request)


@app.get("/api/admin/usage")
async def admin_usage(request: Request):
    require_admin_basic(request)
    return usage_manager.admin_summary()


@app.post("/api/compare")
async def compare(req: CompareRequest):
    try:
        return await RepoTraceAnalyzer().compare_commits(req.owner, req.repo, req.base, req.head)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/file-history")
async def file_history(req: FileHistoryRequest):
    try:
        return await RepoTraceAnalyzer().file_history(req.owner, req.repo, req.path, branch=req.branch, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/timeline")
async def timeline(req: TimelineRequest):
    try:
        return await RepoTraceAnalyzer().timeline(req.owner, req.repo, branch=req.branch, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))





@app.post("/api/account-scan")
async def account_scan(req: AccountScanRequest, request: Request):
    try:
        units = max(1, min(req.max_repos, 10))
        enforce_or_429(request, units=units, endpoint="account-scan")
        result = await RepoTraceAnalyzer().scan_account(
            req.account,
            account_type=req.account_type,
            max_repos=req.max_repos,
            max_files=req.max_files,
            max_commits=req.max_commits,
            concurrency=req.concurrency,
        )
        result["usage"] = usage_manager.record(request, units=units, endpoint="account-scan")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/watch")
async def watch(req: WatchRequest, request: Request):
    try:
        enforce_or_429(request, units=1, endpoint="watch")
        result = await RepoTraceAnalyzer().watch_target(
            req.target,
            target_type=req.target_type,
            notify_email=req.notify_email,
            max_repos=req.max_repos,
            max_files=req.max_files,
            max_commits=req.max_commits,
            concurrency=req.concurrency,
        )
        result["usage"] = usage_manager.record(request, units=1, endpoint="watch")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.post("/api/repo-compare")
async def repo_compare(req: RepoCompareRequest):
    try:
        return await RepoTraceAnalyzer().compare_repos(req.repo_a_url, req.repo_b_url, max_files=req.max_files, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/report-html", response_class=PlainTextResponse)
async def report_html(req: ReportRequest):
    try:
        return await RepoTraceAnalyzer().analyst_report_html(req.owner, req.repo, branch=req.branch, max_files=req.max_files, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.post("/api/report", response_class=PlainTextResponse)
async def report(req: ReportRequest):
    try:
        return await RepoTraceAnalyzer().analyst_report(req.owner, req.repo, branch=req.branch, max_files=req.max_files, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/investigations")
async def save_inv(req: SaveInvestigationRequest):
    try:
        payload = req.result
        if req.title:
            payload["title"] = req.title
        return save_investigation(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/investigations")
async def list_inv():
    return {"investigations": list_investigations()}


@app.get("/api/investigations/{inv_id}")
async def get_inv(inv_id: str):
    try:
        return read_investigation(inv_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found")
