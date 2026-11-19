# Scam Check — backend

The checking engine for **Scam Check** (part of [Vulpfest Lab](https://lab.vulpfest.com)): a tool that
helps anyone avoid scams by checking a suspicious link before they click it.

The **server** opens the link, not the user''s phone. It never runs the page''s JavaScript and never
downloads files (it only reads headers), and every request goes through an SSRF guard that refuses
private and internal addresses.

This repository is the **JSON API** (Python / Flask). The user-facing site (Next.js) lives separately
and calls `POST /api/check`.

## What it looks for

- App downloads (`.apk`, `.exe`) hidden behind "invitation" or "receipt" links
- Look-alike domains impersonating banks, wallets or well-known brands
- Hidden redirects and link shorteners (the final destination is revealed)
- Pages that ask for passwords, PINs or OTPs and send them elsewhere
- Newly registered domains (via RDAP), risky TLDs, IP-address hosts, and other technical red flags

The result is one of three honest levels — **danger / caution / no danger found** — never "safe",
because no tool can guarantee a link is safe.

## Run locally

```bash
pip install -r requirements.txt
python app.py          # http://localhost:5000
pytest                 # run the tests
```

## API

`POST /api/check` with JSON `{"url": "example.com"}` returns the signals and a `verdict`.
CORS is restricted to the Scam Check frontend.

## License

MIT © 2026 Febri Osht (Vulpfest)