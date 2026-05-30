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
from .auth import auth_manager
from .reporting import build_report_template, save_report, maybe_email_report, malicious_file_evidence

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

app = FastAPI(title="RepoTrace", version="0.28.0")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


class AnalyzeRequest(BaseModel):
    url: str = Field(..., examples=["https://github.com/owner/repo"])
    max_files: int = Field(1000, ge=1, le=5000)
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
    max_files: int = Field(1000, ge=1, le=5000)
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

class AuthRegisterRequest(BaseModel):
    email: str
    password: str
    org_name: str | None = None

class AuthLoginRequest(BaseModel):
    email: str
    password: str

class ReportAbuseRequest(BaseModel):
    kind: str = Field("repo", pattern="^(repo|user|org)$")
    target_url: str
    analyst_email: str | None = None
    analyst_name: str | None = None
    analyst_designation: str | None = None
    analyst_org: str | None = None
    reason: str | None = None
    result: dict | None = None
    send_email: bool = True


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


def _session_token(request: Request) -> str | None:
    return request.headers.get("X-RepoTrace-Session") or request.cookies.get("repotrace_session")

def _analyzer_for_request(request: Request) -> RepoTraceAnalyzer:
    token = auth_manager.user_github_token(_session_token(request))
    return RepoTraceAnalyzer(github_token=token)


def _is_org_unlimited_request(request: Request) -> bool:
    return auth_manager.has_server_org_token(_session_token(request))


def _usage_status_for_request(request: Request) -> dict:
    if _is_org_unlimited_request(request):
        st = usage_manager.status_for_request(request)
        st.update({
            "access_mode": "org_unlimited",
            "org_unlimited": True,
            "remaining_today": None,
            "message": "Org unlimited mode: using server-side organization GitHub token; public quota is not consumed.",
        })
        return st
    return usage_manager.status_for_request(request)


def _enforce_search_quota(request: Request, units: int = 1, endpoint: str = "scan") -> None:
    if _is_org_unlimited_request(request):
        return
    enforce_or_429(request, units=units, endpoint=endpoint)


def _record_search_usage(request: Request, units: int = 1, endpoint: str = "scan") -> dict:
    if _is_org_unlimited_request(request):
        auth_manager.record_user_search(_session_token(request), units=units)
        return _usage_status_for_request(request)
    result = usage_manager.record(request, units=units, endpoint=endpoint)
    auth_manager.record_user_search(_session_token(request), units=units)
    return result

@app.post("/api/auth/register")
async def auth_register(req: AuthRegisterRequest):
    try:
        return auth_manager.register(req.email, req.password, org_name=req.org_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login")
async def auth_login(req: AuthLoginRequest):
    try:
        return auth_manager.login(req.email, req.password)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    return auth_manager.logout(_session_token(request) or "")

@app.get("/api/auth/status")
async def auth_status(request: Request):
    return auth_manager.status(_session_token(request))

@app.post("/api/report-abuse")
async def report_abuse(req: ReportAbuseRequest):
    malicious = malicious_file_evidence(req.result)
    if not malicious:
        raise HTTPException(status_code=400, detail="Report generation is allowed only when the current scan has at least one file marked malicious by VirusTotal.")
    template = build_report_template(req.kind, req.target_url, req.analyst_email, req.reason, req.result, analyst_name=req.analyst_name, analyst_designation=req.analyst_designation, analyst_org=req.analyst_org)
    saved = save_report(req.kind, req.target_url, template, req.analyst_email, req.result)
    email_status = maybe_email_report(f"RepoTrace malicious {req.kind} report", template) if req.send_email else {"attempted": False, "sent": False}
    return {"ok": True, "template": template, "saved": saved, "email": email_status, "malicious_files": malicious}



@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    try:
        _enforce_search_quota(request, units=1, endpoint="analyze")
        target = parse_github_url(req.url)
        result = await _analyzer_for_request(request).analyze(target, max_files=req.max_files, max_commits=req.max_commits)
        result["usage"] = _record_search_usage(request, units=1, endpoint="analyze")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/bulk-scan")
async def bulk_scan(req: BulkScanRequest, request: Request):
    try:
        units = max(1, len(req.urls or []))
        _enforce_search_quota(request, units=units, endpoint="bulk-scan")
        result = await _analyzer_for_request(request).bulk_scan(req.urls, max_files=req.max_files, max_commits=req.max_commits, concurrency=req.concurrency)
        result["usage"] = _record_search_usage(request, units=units, endpoint="bulk-scan")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/api/token-status")
async def token_status(request: Request):
    gh = GitHubClient(token=auth_manager.user_github_token(_session_token(request)))
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
    return _usage_status_for_request(request)


@app.get("/api/public-config")
async def public_config(request: Request):
    return _usage_status_for_request(request)


@app.get("/api/admin/usage")
async def admin_usage(request: Request):
    require_admin_basic(request)
    return usage_manager.admin_summary()


@app.post("/api/compare")
async def compare(req: CompareRequest, request: Request):
    try:
        return await _analyzer_for_request(request).compare_commits(req.owner, req.repo, req.base, req.head)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/file-history")
async def file_history(req: FileHistoryRequest, request: Request):
    try:
        return await _analyzer_for_request(request).file_history(req.owner, req.repo, req.path, branch=req.branch, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/timeline")
async def timeline(req: TimelineRequest, request: Request):
    try:
        return await _analyzer_for_request(request).timeline(req.owner, req.repo, branch=req.branch, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))





@app.post("/api/account-scan")
async def account_scan(req: AccountScanRequest, request: Request):
    try:
        units = max(1, min(req.max_repos, 10))
        _enforce_search_quota(request, units=units, endpoint="account-scan")
        result = await _analyzer_for_request(request).scan_account(
            req.account,
            account_type=req.account_type,
            max_repos=req.max_repos,
            max_files=req.max_files,
            max_commits=req.max_commits,
            concurrency=req.concurrency,
        )
        result["usage"] = _record_search_usage(request, units=units, endpoint="account-scan")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/watch")
async def watch(req: WatchRequest, request: Request):
    try:
        _enforce_search_quota(request, units=1, endpoint="watch")
        result = await _analyzer_for_request(request).watch_target(
            req.target,
            target_type=req.target_type,
            notify_email=req.notify_email,
            max_repos=req.max_repos,
            max_files=req.max_files,
            max_commits=req.max_commits,
            concurrency=req.concurrency,
        )
        result["usage"] = _record_search_usage(request, units=1, endpoint="watch")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.post("/api/repo-compare")
async def repo_compare(req: RepoCompareRequest, request: Request):
    try:
        return await _analyzer_for_request(request).compare_repos(req.repo_a_url, req.repo_b_url, max_files=req.max_files, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/report-html", response_class=PlainTextResponse)
async def report_html(req: ReportRequest, request: Request):
    try:
        return await _analyzer_for_request(request).analyst_report_html(req.owner, req.repo, branch=req.branch, max_files=req.max_files, max_commits=req.max_commits)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.post("/api/report", response_class=PlainTextResponse)
async def report(req: ReportRequest, request: Request):
    try:
        return await _analyzer_for_request(request).analyst_report(req.owner, req.repo, branch=req.branch, max_files=req.max_files, max_commits=req.max_commits)
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
