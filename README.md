<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.jsdelivr.net/npm/@vulpfest/icons@0.3/svg/vulpfest-logo-night.svg">
    <img src="https://cdn.jsdelivr.net/npm/@vulpfest/icons@0.3/svg/vulpfest-logo-day.svg" alt="Vulpfest" width="150">
  </picture>
</p>

# Scam Check — backend

The checking engine for **Scam Check** (part of [Vulpfest Lab](https://lab.vulpfest.com)): a free tool that
helps anyone avoid scams by checking a suspicious link before they click it.

The **server** opens the link, not the user''s phone. It never runs the page''s JavaScript and never
downloads files (it only reads headers), and every request goes through an SSRF guard that refuses
private and internal addresses. This repository is the **JSON API** (Python / Flask); the user-facing
site (Next.js) lives at [FebriOsht/scamcheck](https://github.com/FebriOsht/scamcheck) and calls `POST /api/check`.

## What it looks for

- App downloads (`.apk`, `.exe`) hidden behind "invitation" or "receipt" links
- Look-alike domains impersonating banks, wallets or well-known brands (global and Indonesian)
- Hidden redirects and link shorteners (the final destination is revealed)
- Pages that ask for passwords, PINs or OTPs and send them elsewhere
- Newly registered domains (via RDAP), risky TLDs, IP-address hosts, and other technical red flags

The result is one of three honest levels — **danger / caution / no danger found** — never "safe",
because no tool can guarantee a link is safe.

## Command line

Works on Windows, macOS and Linux. Only needs `requests` and `beautifulsoup4`.

```bash
pip install requests beautifulsoup4
python cli.py bca-co-id.xyz
python cli.py example.com/undangan.apk --json
```

Exit codes: `0` no danger found, `1` caution, `2` danger, `3` could not check.

## Run the API locally

```bash
pip install -r requirements.txt
python app.py          # http://localhost:5000
pytest                 # run the tests
```

`POST /api/check` with JSON `{"url": "example.com"}` returns the signals and a `verdict`.
CORS is restricted to the Scam Check frontend.

## Responsible use

Use this only to check links you have received or your own sites. Although the checks are passive,
scanning other people''s systems without permission may break their terms of service or local law.

## Security

Found a security issue? Please report it privately — see [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.

## Support this project

If these free tools help you, you can support their development: see the options at
[github.com/FebriOsht#support](https://github.com/FebriOsht#support) (Saweria, PayPal, or crypto).
Only send on the network stated there.

## License

MIT © 2026 Febri Osht (Vulpfest). See [LICENSE](LICENSE).