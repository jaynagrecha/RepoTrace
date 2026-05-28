# RepoTrace v22

GitHub-first repository intelligence and public-ready OSINT radar.

## Run

```powershell
cd D:\repotrace_v22
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Tokens

Create a `.env` file in the project root:

```env
GITHUB_TOKEN=your_github_token
GITLAB_TOKEN=optional_gitlab_token
```

## v22 public launch controls

v22 adds optional public-deployment controls without disturbing the RepoTrace v20 analysis/watch workflow.

```env
PUBLIC_MODE=false
FREE_SEARCHES_PER_DAY=20
MAX_SEARCHES_PER_MINUTE=12
PRICE_PER_SEARCH_INR=2
UPI_ID=your-upi-id@bank
UPI_QR_IMAGE=/static/upi_qr.png
PAYMENT_NOTE=Free searches are limited. Pay ₹2 per extra search and include your email/reference in the note.
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-before-public-deploy
```

### What PUBLIC_MODE does

- `PUBLIC_MODE=false`: no daily free-search cap. Good for private/local usage.
- `PUBLIC_MODE=true`: enforces per-IP daily search limits and burst protection.

### Counted actions

- Analyze repo: 1 unit
- Bulk scan: 1 unit per repo URL
- Account scan: capped estimate based on max repos
- Watch scan: 1 unit

### Admin panel

The UI contains an admin usage panel. It calls `/api/admin/usage` using HTTP Basic auth from `ADMIN_USERNAME` and `ADMIN_PASSWORD`.

## Notes

This version intentionally remains RepoTrace-focused: repository intelligence, account scanning, watch mode, delta intelligence, graphing, and public launch readiness. RepoTriage-style payload/VT/archive workflows are not included here.


## v22.3 Dynamic UPI QR

Set these in `.env`:

```env
PUBLIC_MODE=true
FREE_DAILY_LIMIT=20
PRICE_PER_SEARCH=2
UPI_NAME=RepoTrace
UPI_ID=yourupi@bank
UPI_PAYMENT_NOTE=RepoTrace search
```

When a user reaches the free daily limit, RepoTrace shows a `Search ₹2` button. Clicking it generates a UPI QR dynamically from your configured UPI ID and prefills the ₹2 amount.

Note: this QR does not automatically verify payment. Automatic unlock requires a payment gateway/callback integration.


## v22 verified payments

When `PUBLIC_MODE=true` and the daily free limit is exhausted, RepoTrace creates a Razorpay order for one extra search. The frontend opens Razorpay Checkout with UPI enabled and polls `/api/payments/status/{order_id}` for up to 60 seconds. After Razorpay confirms a captured payment, RepoTrace grants exactly one paid search credit and automatically retries the pending search.

Required `.env` keys for verified payments:

```env
PAYMENT_PROVIDER=razorpay
PAYMENTS_ENABLED=true
RAZORPAY_KEY_ID=rzp_test_or_live_key
RAZORPAY_KEY_SECRET=your_secret
RAZORPAY_WEBHOOK_SECRET=optional_but_recommended
PRICE_PER_SEARCH=2
```

The older dynamic UPI QR remains as a fallback only; it cannot auto-verify payments without a gateway.


## RepoTrace v22.1 Production Hardening Notes

This build keeps JSON/file-based local storage to avoid SQL setup hassle, but adds production-readiness improvements around payments and public launch controls.

### Payment hardening
- Razorpay mode badge: test/live is detected from `RAZORPAY_MODE` or key prefix.
- Razorpay Checkout verification is server-side: signature is checked and the payment is fetched from Razorpay before one paid credit is granted.
- Webhooks verify `RAZORPAY_WEBHOOK_SECRET`; live webhooks are rejected if this secret is missing.
- UI is UPI-first, with cards/netbanking/wallet as fallback methods where Razorpay permits them.
- Public mode still uses JSON usage/payment files in `data/`; use persistent disk if deployed.

### Recommended public settings
```env
PUBLIC_MODE=true
FREE_DAILY_LIMIT=20
BURST_LIMIT_PER_MINUTE=12
PRICE_PER_SEARCH=2
RAZORPAY_MODE=live
RAZORPAY_KEY_ID=rzp_live_xxx
RAZORPAY_KEY_SECRET=xxx
RAZORPAY_WEBHOOK_SECRET=xxx
ADMIN_PASSWORD=use-a-long-random-password
```

### Local testing
Use Razorpay test keys, keep `RAZORPAY_MODE=test`, set `FREE_DAILY_LIMIT=1`, and use Razorpay test payment success flow.
