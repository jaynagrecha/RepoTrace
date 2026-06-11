"""RepoTrace v2 API.

Wires together the v2 engine, DB persistence, security hardening, and the
watch scheduler. Notable changes from v1:
* DB connect/close on the FastAPI lifespan; watch scheduler started here too.
* CORS + security-header middleware.
* auth/usage/payments calls are awaited (now async, DB-backed).
* Session token read from the X-Session-Token header (or rt_session cookie).
* All broad error handlers scrub internal details before returning.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from io import BytesIO
from pathlib import Path
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .github_client import GitHubClient
from .parsers import parse_github_url
from .resolver import resolve_to_repo_url
from . import watchlist as watchlist_mgr
from .analyzer import RepoTraceAnalyzer
from .storage import list_investigations, read_investigation, save_investigation
from .usage import usage_manager, enforce_or_429
from .payments import payment_manager
from .auth import auth_manager
from .reporting import build_report_template, save_report, maybe_email_report, malicious_file_evidence
from .security import require_admin_basic, SECURITY_HEADERS, scrub_error, client_ip
from .db import db
from .scheduler import start_scheduler, stop_scheduler

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    start_scheduler()
    try:
        yield
    finally:
        await stop_scheduler()
        await db.close()


app = FastAPI(title="RepoTrace", version="2.0.0", lifespan=lifespan)

_ALLOWED = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED or [],  # same-origin SPA needs none; set in prod
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


app.mount("/static", StaticFiles(directory="app/static"), name="static")


def _session(request: Request) -> str | None:
    return request.headers.get("x-repotrace-session") or request.headers.get("x-session-token") or request.cookies.get("rt_session")


# --------------------------------------------------------------------------- models

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


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class OtpVerifyRequest(BaseModel):
    email: str
    code: str


class OtpResendRequest(BaseModel):
    email: str


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
    max_commits: int = Field(30, ge=1, le=120)
    concurrency: int = Field(3, ge=1, le=6)
    interval_min: int = Field(360, ge=30, le=10080)
    test_email: bool = False


class WatchActionRequest(BaseModel):
    watch_id: str


class WatchIntervalRequest(BaseModel):
    watch_id: str
    interval_min: int = Field(360, ge=30, le=10080)


# --------------------------------------------------------------------------- pages / health

@app.get("/")
async def home():
    return FileResponse(str(BASE_DIR / "app" / "static" / "index.html"))


@app.get("/api/health")
async def health():
    return {"ok": True, "app": "RepoTrace", "version": "2.0.0",
            "github_token_configured": bool(os.getenv("GITHUB_TOKEN")),
            "public_mode": usage_manager.public_mode}


@app.get("/api/public-config")
async def public_config():
    cfg = payment_manager.public_config()
    return {"public_mode": usage_manager.public_mode,
            "free_searches_per_day": usage_manager.free_limit,
            "payment": cfg.__dict__}


# --------------------------------------------------------------------------- auth

@app.post("/api/auth/register")
async def auth_register(payload: AuthRegisterRequest):
    try:
        return await auth_manager.register(payload.email, payload.password, org_name=payload.org_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/auth/login")
async def auth_login(payload: AuthLoginRequest):
    try:
        return await auth_manager.login(payload.email, payload.password)
    except ValueError as e:
        if str(e) == "EMAIL_NOT_VERIFIED":
            raise HTTPException(
                status_code=403,
                detail={"code": "email_not_verified",
                        "message": "Please verify your account first. Check your email for the code, or resend it.",
                        "email": payload.email.strip().lower()},
            )
        raise HTTPException(status_code=401, detail=str(e))


@app.post("/api/auth/verify-otp")
async def auth_verify_otp(payload: OtpVerifyRequest):
    try:
        return await auth_manager.verify_otp(payload.email, payload.code)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/auth/resend-otp")
async def auth_resend_otp(payload: OtpResendRequest):
    return await auth_manager.resend_otp(payload.email)


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    return await auth_manager.logout(_session(request) or "")


@app.get("/api/auth/status")
async def auth_status(request: Request):
    return await auth_manager.status(_session(request))


@app.post("/api/auth/forgot-password")
async def auth_forgot_password(payload: PasswordResetRequest, request: Request):
    return await auth_manager.request_password_reset(payload.email, request_ip=client_ip(request))


@app.post("/api/auth/reset-password")
async def auth_reset_password(payload: PasswordResetConfirm):
    try:
        return await auth_manager.confirm_password_reset(payload.token, payload.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --------------------------------------------------------------------------- usage / admin

@app.get("/api/usage-status")
async def usage_status(request: Request):
    return await usage_manager.status_for_request(request)


@app.get("/api/admin/usage")
async def admin_usage(request: Request):
    require_admin_basic(request)
    return await usage_manager.admin_summary()


@app.get("/api/token-status")
async def token_status(request: Request):
    token = await auth_manager.user_github_token(_session(request))
    gh = GitHubClient(token=token)
    try:
        rl = await gh.rate_limit()
        core = (rl or {}).get("resources", {}).get("core", {})
        return {"configured": bool(token or os.getenv("GITHUB_TOKEN")),
                "remaining": core.get("remaining"), "limit": core.get("limit")}
    except Exception as e:
        return {"configured": bool(token or os.getenv("GITHUB_TOKEN")), "error": scrub_error(e)}


# --------------------------------------------------------------------------- payments

@app.get("/api/payment-config")
async def payment_config():
    return payment_manager.public_config().__dict__


@app.post("/api/payments/create")
async def payments_create(payload: PaymentCreateRequest, request: Request):
    return await payment_manager.create_order(request, units=payload.units)


@app.post("/api/payments/verify")
async def payments_verify(payload: PaymentVerifyRequest):
    return await payment_manager.verify_checkout(
        payload.razorpay_order_id, payload.razorpay_payment_id, payload.razorpay_signature)


@app.post("/api/payments/webhook")
async def payments_webhook(request: Request):
    return await payment_manager.handle_webhook(request)


@app.get("/api/payments/status/{order_id}")
async def payments_status(order_id: str):
    return await payment_manager.order_status(order_id)


@app.get("/api/payment-intent")
async def payment_intent(amount: float | None = None):
    upi_id = os.getenv("UPI_ID", "").strip()
    if not upi_id:
        raise HTTPException(status_code=400, detail="UPI_ID is not configured.")
    amt = amount or float(os.getenv("PRICE_PER_SEARCH", "2"))
    params = {"pa": upi_id, "pn": os.getenv("UPI_NAME", "RepoTrace"),
              "am": f"{amt:.2f}", "cu": "INR", "tn": os.getenv("UPI_PAYMENT_NOTE", "RepoTrace search")}
    return {"upi_deeplink": f"upi://pay?{urlencode(params)}"}


@app.get("/api/payment-qr")
async def payment_qr(amount: float | None = None):
    upi_id = os.getenv("UPI_ID", "").strip()
    if not upi_id:
        raise HTTPException(status_code=400, detail="UPI_ID is not configured.")
    try:
        import qrcode
    except ImportError:
        raise HTTPException(status_code=500, detail="qrcode package missing.")
    amt = amount or float(os.getenv("PRICE_PER_SEARCH", "2"))
    params = {"pa": upi_id, "pn": os.getenv("UPI_NAME", "RepoTrace"),
              "am": f"{amt:.2f}", "cu": "INR", "tn": os.getenv("UPI_PAYMENT_NOTE", "RepoTrace search")}
    img = qrcode.make(f"upi://pay?{urlencode(params)}")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# --------------------------------------------------------------------------- analysis

async def _analyzer_for(request: Request) -> RepoTraceAnalyzer:
    token = await auth_manager.user_github_token(_session(request))
    return RepoTraceAnalyzer(github_token=token)


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="scan")
    try:
        analyzer = await _analyzer_for(request)
        # Release-asset / asset-CDN / mirror URLs are traced back to their source
        # repository so they analyze like any normal repo.
        provenance = None
        resolved = await resolve_to_repo_url(payload.url, analyzer.gh)
        url_to_parse = payload.url
        if resolved:
            url_to_parse = resolved.repo_url
            provenance = resolved.provenance
        target = parse_github_url(url_to_parse)
        result = await analyzer.analyze(target, max_files=payload.max_files, max_commits=payload.max_commits)
        if provenance:
            result["source_provenance"] = provenance
        await usage_manager.record(request, units=1, endpoint="scan")
        await auth_manager.record_user_search(_session(request), units=1)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=scrub_error(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/bulk-scan")
async def bulk_scan(payload: BulkScanRequest, request: Request):
    units = max(1, len(payload.urls))
    await enforce_or_429(request, units=units, endpoint="bulk")
    try:
        analyzer = await _analyzer_for(request)
        result = await analyzer.bulk_scan(payload.urls, max_files=payload.max_files,
                                          max_commits=payload.max_commits, concurrency=payload.concurrency)
        await usage_manager.record(request, units=units, endpoint="bulk")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/compare")
async def compare(payload: CompareRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="compare")
    try:
        analyzer = await _analyzer_for(request)
        result = await analyzer.compare_commits(payload.owner, payload.repo, payload.base, payload.head)
        await usage_manager.record(request, units=1, endpoint="compare")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/file-history")
async def file_history(payload: FileHistoryRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="file-history")
    try:
        analyzer = await _analyzer_for(request)
        result = await analyzer.file_history(payload.owner, payload.repo, payload.path,
                                             branch=payload.branch, max_commits=payload.max_commits)
        await usage_manager.record(request, units=1, endpoint="file-history")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/timeline")
async def timeline(payload: TimelineRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="timeline")
    try:
        analyzer = await _analyzer_for(request)
        result = await analyzer.timeline(payload.owner, payload.repo,
                                         branch=payload.branch, max_commits=payload.max_commits)
        await usage_manager.record(request, units=1, endpoint="timeline")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/repo-compare")
async def repo_compare(payload: RepoCompareRequest, request: Request):
    await enforce_or_429(request, units=2, endpoint="repo-compare")
    try:
        analyzer = await _analyzer_for(request)
        result = await analyzer.compare_repos(payload.repo_a_url, payload.repo_b_url,
                                              max_files=payload.max_files, max_commits=payload.max_commits)
        await usage_manager.record(request, units=2, endpoint="repo-compare")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/account-scan")
async def account_scan(payload: AccountScanRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="account-scan")
    try:
        analyzer = await _analyzer_for(request)
        result = await analyzer.scan_account(payload.account, account_type=payload.account_type,
                                             max_repos=payload.max_repos, max_files=payload.max_files,
                                             max_commits=payload.max_commits, concurrency=payload.concurrency)
        await usage_manager.record(request, units=1, endpoint="account-scan")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/watch")
async def watch(payload: WatchRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="watch")
    try:
        analyzer = await _analyzer_for(request)
        user = await auth_manager.user_from_session(_session(request))
        result = await analyzer.watch_target(
            payload.target, target_type=payload.target_type, notify_email=payload.notify_email,
            max_repos=payload.max_repos, max_files=payload.max_files, max_commits=payload.max_commits,
            concurrency=payload.concurrency, owner_email=(user or {}).get("email"),
            interval_min=payload.interval_min, test_email=payload.test_email)
        await usage_manager.record(request, units=1, endpoint="watch")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


async def _require_user(request: Request) -> dict:
    user = await auth_manager.user_from_session(_session(request))
    if not user:
        raise HTTPException(status_code=401, detail="Login required to manage your watchlist.")
    return user


@app.get("/api/watchlist")
async def watchlist_list(request: Request):
    user = await _require_user(request)
    return {"watches": await watchlist_mgr.list_watches(user["email"])}


@app.post("/api/watchlist/pause")
async def watchlist_pause(payload: WatchActionRequest, request: Request):
    user = await _require_user(request)
    try:
        return await watchlist_mgr.set_enabled(user["email"], payload.watch_id, False)
    except PermissionError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/watchlist/resume")
async def watchlist_resume(payload: WatchActionRequest, request: Request):
    user = await _require_user(request)
    try:
        return await watchlist_mgr.set_enabled(user["email"], payload.watch_id, True)
    except PermissionError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/watchlist/interval")
async def watchlist_interval(payload: WatchIntervalRequest, request: Request):
    user = await _require_user(request)
    try:
        return await watchlist_mgr.set_interval(user["email"], payload.watch_id, payload.interval_min)
    except PermissionError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/watchlist/delete")
async def watchlist_delete(payload: WatchActionRequest, request: Request):
    user = await _require_user(request)
    try:
        return await watchlist_mgr.delete_watch(user["email"], payload.watch_id)
    except PermissionError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --------------------------------------------------------------------------- reports

@app.post("/api/report", response_class=PlainTextResponse)
async def report_markdown(payload: ReportRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="report")
    try:
        analyzer = await _analyzer_for(request)
        md = await analyzer.analyst_report(payload.owner, payload.repo, branch=payload.branch,
                                           max_files=payload.max_files, max_commits=payload.max_commits)
        await usage_manager.record(request, units=1, endpoint="report")
        return PlainTextResponse(md)
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/report-html", response_class=HTMLResponse)
async def report_html(payload: ReportRequest, request: Request):
    await enforce_or_429(request, units=1, endpoint="report-html")
    try:
        analyzer = await _analyzer_for(request)
        html = await analyzer.analyst_report_html(payload.owner, payload.repo, branch=payload.branch,
                                                  max_files=payload.max_files, max_commits=payload.max_commits)
        await usage_manager.record(request, units=1, endpoint="report-html")
        return HTMLResponse(html)
    except Exception as e:
        raise HTTPException(status_code=502, detail=scrub_error(e))


@app.post("/api/report-abuse")
async def report_abuse(payload: ReportAbuseRequest):
    evidence = malicious_file_evidence(payload.result)
    if not evidence:
        raise HTTPException(status_code=400,
                            detail="Report generation is allowed only when the current scan has at least one VirusTotal-malicious file.")
    template = build_report_template(payload.kind, payload.target_url, payload.analyst_email, payload.reason,
                                     result=payload.result, analyst_name=payload.analyst_name,
                                     analyst_designation=payload.analyst_designation, analyst_org=payload.analyst_org)
    saved = save_report(payload.kind, payload.target_url, template, payload.analyst_email, result=payload.result)
    email_status = {"attempted": False}
    if payload.send_email:
        email_status = maybe_email_report("RepoTrace Abuse Report", template)
    return {"template": template, "saved": saved, "email": email_status, "evidence_count": len(evidence)}


# --------------------------------------------------------------------------- investigations

@app.post("/api/investigations")
async def investigations_save(payload: SaveInvestigationRequest, request: Request):
    try:
        user = await auth_manager.user_from_session(_session(request))
        record = {"title": payload.title, **payload.result}
        return await save_investigation(record, owner_email=(user or {}).get("email"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=scrub_error(e))


@app.get("/api/investigations")
async def investigations_list(request: Request):
    user = await auth_manager.user_from_session(_session(request))
    return await list_investigations(owner_email=(user or {}).get("email"))


@app.get("/api/investigations/{inv_id}")
async def investigations_read(inv_id: str):
    try:
        return await read_investigation(inv_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found")
