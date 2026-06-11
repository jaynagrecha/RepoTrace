"""DB-backed Razorpay payments for RepoTrace v2.

The verification logic (HMAC checkout signature, server-side amount/currency/
status re-check against Razorpay's API, idempotent grant, webhook signature
verification) is preserved unchanged from the original because it was correct.
What changed:
* Orders/payments persist in SQLite instead of payments.json.
* Credits are granted to the IDENTITY that created the order (user email when
  logged in, else ip:<addr>), so a paying user keeps credits across networks.
* mark_paid_and_grant stays idempotent via the orders.status guard.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass

import httpx
from fastapi import HTTPException, Request, status

from .db import db
from .security import client_ip
from .usage import usage_manager


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _price_rupees() -> int:
    try:
        return max(1, int(float(os.getenv("PRICE_PER_SEARCH") or os.getenv("PRICE_PER_SEARCH_INR", "2"))))
    except Exception:
        return 2


def _paise_for_units(units: int = 1) -> int:
    return _price_rupees() * 100 * max(1, int(units or 1))


@dataclass
class PaymentProviderConfig:
    provider: str
    configured: bool
    key_id: str | None = None
    currency: str = "INR"
    amount_inr: int = 2
    mode: str = "test"
    live_mode: bool = False
    webhook_configured: bool = False
    payments_enabled: bool = True
    upi_first: bool = True


class PaymentManager:
    @property
    def provider(self) -> str:
        return (os.getenv("PAYMENT_PROVIDER") or "razorpay").strip().lower()

    @property
    def key_id(self) -> str:
        return os.getenv("RAZORPAY_KEY_ID", "").strip()

    @property
    def key_secret(self) -> str:
        return os.getenv("RAZORPAY_KEY_SECRET", "").strip()

    @property
    def webhook_secret(self) -> str:
        return os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()

    @property
    def mode(self) -> str:
        configured = (os.getenv("RAZORPAY_MODE") or "").strip().lower()
        if configured in {"live", "test"}:
            return configured
        return "live" if self.key_id.startswith("rzp_live_") else "test"

    @property
    def live_mode(self) -> bool:
        return self.mode == "live"

    @property
    def upi_first(self) -> bool:
        return _env_bool("RAZORPAY_UPI_FIRST", True)

    @property
    def enabled(self) -> bool:
        return _env_bool("PAYMENTS_ENABLED", True)

    @property
    def razorpay_configured(self) -> bool:
        return bool(self.key_id and self.key_secret)

    def public_config(self) -> PaymentProviderConfig:
        return PaymentProviderConfig(
            provider=self.provider,
            configured=self.razorpay_configured if self.provider == "razorpay" else False,
            key_id=self.key_id or None,
            amount_inr=_price_rupees(),
            mode=self.mode,
            live_mode=self.live_mode,
            webhook_configured=bool(self.webhook_secret),
            payments_enabled=self.enabled,
            upi_first=self.upi_first,
        )

    async def _identity_for_request(self, request: Request) -> tuple[str, str]:
        from .auth import auth_manager
        ip = client_ip(request)
        session = request.headers.get("x-repotrace-session") or request.headers.get("x-session-token") or request.cookies.get("rt_session")
        user = await auth_manager.user_from_session(session) if session else None
        identity = user["email"] if user else f"ip:{ip}"
        return identity, ip

    async def create_order(self, request: Request, units: int = 1) -> dict:
        if not self.enabled:
            raise HTTPException(status_code=400, detail="Payments are disabled on this deployment.")
        if self.provider != "razorpay":
            raise HTTPException(status_code=400, detail="Only Razorpay is implemented for verified payments.")
        if not self.razorpay_configured:
            raise HTTPException(status_code=400, detail="Razorpay is not configured.")

        identity, ip = await self._identity_for_request(request)
        units = max(1, int(units or 1))
        receipt = f"rt_{uuid.uuid4().hex[:20]}"
        payload = {
            "amount": _paise_for_units(units),
            "currency": "INR",
            "receipt": receipt,
            "notes": {"product": "RepoTrace", "identity": identity, "ip": ip, "units": str(units)},
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post("https://api.razorpay.com/v1/orders",
                                     auth=(self.key_id, self.key_secret), json=payload)
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail={"message": "Razorpay order creation failed"})
        order = resp.json()
        await db.execute(
            """INSERT INTO orders(order_id, receipt, identity, ip, units, amount, currency,
                                  status, mode, created_at, provider_response)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (order["id"], receipt, identity, ip, units, payload["amount"], "INR",
             "created", self.mode, int(time.time()), json.dumps(order)),
        )
        return {
            "provider": "razorpay", "key_id": self.key_id, "order_id": order["id"],
            "amount": payload["amount"], "amount_inr": payload["amount"] / 100, "currency": "INR",
            "name": os.getenv("UPI_NAME", "RepoTrace"), "description": f"RepoTrace search credit x {units}",
            "units": units, "mode": self.mode, "live_mode": self.live_mode, "upi_first": self.upi_first,
            "prefill": {"email": os.getenv("PAYMENT_PREFILL_EMAIL", ""), "contact": os.getenv("PAYMENT_PREFILL_CONTACT", "")},
        }

    def _verify_checkout_signature(self, order_id: str, payment_id: str, signature: str) -> bool:
        body = f"{order_id}|{payment_id}".encode()
        expected = hmac.new(self.key_secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature or "")

    async def mark_paid_and_grant(self, order_id: str, payment_id: str | None = None,
                                  source: str = "checkout") -> dict:
        order = await db.fetchone("SELECT * FROM orders WHERE order_id = ?", (order_id,))
        if not order:
            raise HTTPException(status_code=404, detail="Payment order not found.")
        if order["status"] != "paid":
            async with db.transaction() as conn:
                await conn.execute(
                    "UPDATE orders SET status='paid', paid_at=?, payment_id=?, paid_source=? WHERE order_id=?",
                    (int(time.time()), payment_id, source, order_id),
                )
            await usage_manager.add_paid_credits(
                order["identity"], order["ip"], units=int(order["units"]),
                source=source, order_id=order_id, payment_id=payment_id,
            )
        return {"ok": True, "order_id": order_id, "payment_id": payment_id,
                "units_granted": int(order["units"]), "identity": order["identity"]}

    async def _fetch_razorpay_payment(self, payment_id: str) -> dict:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(f"https://api.razorpay.com/v1/payments/{payment_id}",
                                    auth=(self.key_id, self.key_secret))
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail={"message": "Could not verify Razorpay payment"})
        return resp.json()

    async def verify_checkout(self, order_id: str, payment_id: str, signature: str) -> dict:
        if not self.razorpay_configured:
            raise HTTPException(status_code=400, detail="Razorpay is not configured.")
        if not self._verify_checkout_signature(order_id, payment_id, signature):
            raise HTTPException(status_code=400, detail="Invalid Razorpay payment signature.")
        local = await db.fetchone("SELECT * FROM orders WHERE order_id = ?", (order_id,))
        if not local:
            raise HTTPException(status_code=404, detail="Payment order not found.")

        payment = await self._fetch_razorpay_payment(payment_id)
        if payment.get("order_id") != order_id:
            raise HTTPException(status_code=400, detail="Payment/order mismatch.")
        if int(payment.get("amount") or 0) != int(local["amount"] or 0):
            raise HTTPException(status_code=400, detail="Payment amount mismatch.")
        if payment.get("currency") != (local["currency"] or "INR"):
            raise HTTPException(status_code=400, detail="Payment currency mismatch.")
        if payment.get("status") != "captured":
            raise HTTPException(status_code=400, detail=f"Payment not captured. Status: {payment.get('status')}")

        out = await self.mark_paid_and_grant(order_id, payment_id, source="checkout:signature+api")
        await db.execute(
            """INSERT OR REPLACE INTO payments(payment_id, order_id, status, amount, currency,
                                               method, email, contact, mode, verified_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (payment_id, order_id, payment.get("status"), payment.get("amount"), payment.get("currency"),
             payment.get("method"), payment.get("email"), payment.get("contact"), self.mode, int(time.time())),
        )
        return out

    async def order_status(self, order_id: str) -> dict:
        order = await db.fetchone("SELECT * FROM orders WHERE order_id = ?", (order_id,))
        if not order:
            raise HTTPException(status_code=404, detail="Payment order not found.")
        if order["status"] == "paid":
            return {"ok": True, "order_id": order_id, "status": "paid", "paid": True,
                    "units_granted": int(order["units"]), "payment_id": order["payment_id"],
                    "source": order["paid_source"] or "local"}
        if not self.razorpay_configured:
            return {"ok": True, "order_id": order_id, "status": order["status"], "paid": False,
                    "configured": False, "message": "Razorpay not configured."}
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                resp = await client.get(f"https://api.razorpay.com/v1/orders/{order_id}/payments",
                                        auth=(self.key_id, self.key_secret))
            if resp.status_code >= 400:
                return {"ok": False, "order_id": order_id, "status": order["status"], "paid": False}
            for payment in resp.json().get("items", []):
                if payment.get("status") == "captured":
                    return await self.mark_paid_and_grant(order_id, payment.get("id"),
                                                          source="polling:razorpay_captured")
            return {"ok": True, "order_id": order_id, "status": order["status"], "paid": False}
        except Exception:
            return {"ok": False, "order_id": order_id, "status": order["status"], "paid": False}

    async def handle_webhook(self, request: Request) -> dict:
        raw = await request.body()
        if self.live_mode and not self.webhook_secret:
            raise HTTPException(status_code=400, detail="RAZORPAY_WEBHOOK_SECRET required for live webhooks.")
        if self.webhook_secret:
            supplied = request.headers.get("x-razorpay-signature", "")
            expected = hmac.new(self.webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, supplied):
                raise HTTPException(status_code=400, detail="Invalid Razorpay webhook signature.")
        try:
            event = json.loads(raw.decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid webhook JSON.")
        event_type = event.get("event", "")
        pe = (((event.get("payload") or {}).get("payment") or {}).get("entity") or {})
        oe = (((event.get("payload") or {}).get("order") or {}).get("entity") or {})
        order_id = pe.get("order_id") or oe.get("id")
        payment_id = pe.get("id")
        captured = event_type in {"payment.captured", "order.paid"} or pe.get("status") == "captured" or oe.get("status") == "paid"
        if captured and order_id:
            return await self.mark_paid_and_grant(order_id, payment_id, source=f"webhook:{event_type}")
        return {"ok": True, "ignored": True, "event": event_type}


payment_manager = PaymentManager()
