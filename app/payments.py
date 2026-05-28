from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import HTTPException, Request, status

from .usage import client_ip, usage_manager

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PAYMENTS_FILE = DATA_DIR / "payments.json"


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


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
    def __init__(self, path: Path = PAYMENTS_FILE):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

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
        v = os.getenv("RAZORPAY_UPI_FIRST", "true").strip().lower()
        return v in {"1", "true", "yes", "y", "on"}

    @property
    def enabled(self) -> bool:
        return _env_bool("PAYMENTS_ENABLED", True)

    @property
    def razorpay_configured(self) -> bool:
        return bool(self.key_id and self.key_secret)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"orders": {}, "payments": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"orders": {}, "payments": {}}

    def save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

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

    async def create_order(self, request: Request, units: int = 1) -> dict[str, Any]:
        if not self.enabled:
            raise HTTPException(status_code=400, detail="Payments are disabled on this deployment.")
        if self.provider != "razorpay":
            raise HTTPException(status_code=400, detail="Only Razorpay payment provider is implemented for verified payments.")
        if not self.razorpay_configured:
            raise HTTPException(status_code=400, detail="Razorpay is not configured. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in .env.")

        ip = client_ip(request)
        units = max(1, int(units or 1))
        receipt = f"rt_{uuid.uuid4().hex[:20]}"
        payload = {
            "amount": _paise_for_units(units),
            "currency": "INR",
            "receipt": receipt,
            "notes": {
                "product": "RepoTrace",
                "ip": ip,
                "units": str(units),
                "price_per_search_inr": str(_price_rupees()),
            },
        }
        auth = (self.key_id, self.key_secret)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post("https://api.razorpay.com/v1/orders", auth=auth, json=payload)
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail={"message": "Razorpay order creation failed", "razorpay": resp.text})
        order = resp.json()
        data = self.load()
        data.setdefault("orders", {})[order["id"]] = {
            "order_id": order["id"],
            "receipt": receipt,
            "ip": ip,
            "units": units,
            "amount": payload["amount"],
            "currency": "INR",
            "status": "created",
            "created_at": int(time.time()),
            "mode": self.mode,
            "provider_response": order,
        }
        self.save(data)
        return {
            "provider": "razorpay",
            "key_id": self.key_id,
            "order_id": order["id"],
            "amount": payload["amount"],
            "amount_inr": payload["amount"] / 100,
            "currency": "INR",
            "name": os.getenv("UPI_NAME", "RepoTrace"),
            "description": f"RepoTrace search credit x {units}",
            "units": units,
            "mode": self.mode,
            "live_mode": self.live_mode,
            "upi_first": self.upi_first,
            "prefill": {
                "email": os.getenv("PAYMENT_PREFILL_EMAIL", ""),
                "contact": os.getenv("PAYMENT_PREFILL_CONTACT", ""),
            },
        }

    def _verify_checkout_signature(self, order_id: str, payment_id: str, signature: str) -> bool:
        body = f"{order_id}|{payment_id}".encode("utf-8")
        expected = hmac.new(self.key_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature or "")

    def mark_paid_and_grant(self, order_id: str, payment_id: str | None = None, source: str = "checkout") -> dict[str, Any]:
        data = self.load()
        order = data.setdefault("orders", {}).get(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Payment order not found in RepoTrace storage.")
        if order.get("status") != "paid":
            order["status"] = "paid"
            order["paid_at"] = int(time.time())
            order["payment_id"] = payment_id
            order["paid_source"] = source
            units = int(order.get("units", 1))
            ip = order.get("ip", "unknown")
            usage_manager.add_paid_credits(ip, units=units, source=source, order_id=order_id, payment_id=payment_id)
        self.save(data)
        return {"ok": True, "order_id": order_id, "payment_id": payment_id, "units_granted": int(order.get("units", 1)), "ip": order.get("ip")}

    async def _fetch_razorpay_payment(self, payment_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                f"https://api.razorpay.com/v1/payments/{payment_id}",
                auth=(self.key_id, self.key_secret),
            )
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail={"message": "Could not verify Razorpay payment", "razorpay": resp.text})
        return resp.json()

    async def verify_checkout(self, order_id: str, payment_id: str, signature: str) -> dict[str, Any]:
        if not self.razorpay_configured:
            raise HTTPException(status_code=400, detail="Razorpay is not configured.")
        if not self._verify_checkout_signature(order_id, payment_id, signature):
            raise HTTPException(status_code=400, detail="Invalid Razorpay payment signature.")

        data = self.load()
        local_order = data.setdefault("orders", {}).get(order_id)
        if not local_order:
            raise HTTPException(status_code=404, detail="Payment order not found in RepoTrace storage.")

        payment = await self._fetch_razorpay_payment(payment_id)
        if payment.get("order_id") != order_id:
            raise HTTPException(status_code=400, detail="Payment/order mismatch during Razorpay verification.")
        if int(payment.get("amount") or 0) != int(local_order.get("amount") or 0):
            raise HTTPException(status_code=400, detail="Payment amount mismatch during Razorpay verification.")
        if payment.get("currency") != local_order.get("currency", "INR"):
            raise HTTPException(status_code=400, detail="Payment currency mismatch during Razorpay verification.")
        if payment.get("status") != "captured":
            raise HTTPException(status_code=400, detail=f"Payment not captured yet. Current status: {payment.get('status')}")

        out = self.mark_paid_and_grant(order_id, payment_id, source="checkout:signature+api")
        data = self.load()
        data.setdefault("payments", {})[payment_id] = {
            "order_id": order_id,
            "status": payment.get("status"),
            "amount": payment.get("amount"),
            "currency": payment.get("currency"),
            "method": payment.get("method"),
            "email": payment.get("email"),
            "contact": payment.get("contact"),
            "verified_at": int(time.time()),
            "mode": self.mode,
        }
        self.save(data)
        return out


    async def order_status(self, order_id: str) -> dict[str, Any]:
        """Return local + Razorpay-confirmed order status, granting credits if paid.

        Used by the frontend polling loop after Checkout/UPI QR opens.
        It never trusts the browser; it checks local state first, then Razorpay.
        """
        data = self.load()
        order = data.setdefault("orders", {}).get(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Payment order not found in RepoTrace storage.")

        if order.get("status") == "paid":
            return {
                "ok": True,
                "order_id": order_id,
                "status": "paid",
                "paid": True,
                "units_granted": int(order.get("units", 1)),
                "payment_id": order.get("payment_id"),
                "source": order.get("paid_source", "local"),
            }

        if not self.razorpay_configured:
            return {
                "ok": True,
                "order_id": order_id,
                "status": order.get("status", "created"),
                "paid": False,
                "configured": False,
                "message": "Razorpay not configured; automatic verification is unavailable.",
            }

        try:
            async with httpx.AsyncClient(timeout=12) as client:
                resp = await client.get(
                    f"https://api.razorpay.com/v1/orders/{order_id}/payments",
                    auth=(self.key_id, self.key_secret),
                )
            if resp.status_code >= 400:
                return {
                    "ok": False,
                    "order_id": order_id,
                    "status": order.get("status", "created"),
                    "paid": False,
                    "razorpay_error": resp.text,
                }
            payload = resp.json()
            for payment in payload.get("items", []):
                if payment.get("status") == "captured":
                    return self.mark_paid_and_grant(order_id, payment.get("id"), source="polling:razorpay_captured")
            return {
                "ok": True,
                "order_id": order_id,
                "status": order.get("status", "created"),
                "paid": False,
                "payments_seen": len(payload.get("items", [])),
            }
        except Exception as e:
            return {
                "ok": False,
                "order_id": order_id,
                "status": order.get("status", "created"),
                "paid": False,
                "error": str(e),
            }

    async def handle_webhook(self, request: Request) -> dict[str, Any]:
        raw = await request.body()
        if self.live_mode and not self.webhook_secret:
            # Live deployments should configure RAZORPAY_WEBHOOK_SECRET. Checkout verification still works,
            # but unsigned live webhooks are not accepted.
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="RAZORPAY_WEBHOOK_SECRET is required for live webhooks.")
        if self.webhook_secret:
            supplied = request.headers.get("x-razorpay-signature", "")
            expected = hmac.new(self.webhook_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, supplied):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Razorpay webhook signature.")
        try:
            event = json.loads(raw.decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid webhook JSON.")

        event_type = event.get("event", "")
        payment_entity = (((event.get("payload") or {}).get("payment") or {}).get("entity") or {})
        order_entity = (((event.get("payload") or {}).get("order") or {}).get("entity") or {})
        order_id = payment_entity.get("order_id") or order_entity.get("id")
        payment_id = payment_entity.get("id")
        captured = event_type in {"payment.captured", "order.paid"} or payment_entity.get("status") == "captured" or order_entity.get("status") == "paid"
        if captured and order_id:
            return self.mark_paid_and_grant(order_id, payment_id, source=f"webhook:{event_type}")
        return {"ok": True, "ignored": True, "event": event_type}


payment_manager = PaymentManager()
