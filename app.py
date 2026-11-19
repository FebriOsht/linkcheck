"""Scam Check backend (Vulpfest Lab) - JSON API.

Mesin pemeriksa tautan. Frontend (Next.js di Vercel) memanggil /api/check dan menampilkan hasilnya.
Keamanan: tautan dibuka lewat ssrf_guard (menolak alamat internal), JavaScript tidak dijalankan,
file tidak diunduh (hanya header). Rate limit per-IP agar tidak dipakai membombardir situs lain.
"""
import os
import time
from collections import deque

from flask import Flask, jsonify, request

import checker

app = Flask(__name__)

# Hanya frontend tepercaya yang boleh memanggil API ini dari browser.
ALLOWED_ORIGINS = {
    "https://lab.vulpfest.com",
    "https://scamcheck-web.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}


@app.after_request
def cors_and_security(resp):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Max-Age"] = "86400"
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


_HITS = {}
RATE_MAX = 20
RATE_WINDOW = 60


def _rate_ok(ip):
    now = time.monotonic()
    q = _HITS.setdefault(ip, deque())
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_MAX:
        return False
    q.append(now)
    if len(_HITS) > 5000:
        for k in [k for k, v in _HITS.items() if not v or now - v[-1] > RATE_WINDOW]:
            _HITS.pop(k, None)
    return True


def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    return (xff.split(",")[0].strip() if xff else request.remote_addr) or "?"


@app.route("/ping")
def ping():
    return "OK", 200


@app.route("/api/check", methods=["POST", "OPTIONS"])
def api_check():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or request.form.get("url") or "").strip()
    if not url:
        return jsonify({"error": "empty", "message": "Masukkan tautan yang ingin diperiksa."}), 400
    if len(url) > 2000:
        return jsonify({"error": "too-long", "message": "Tautan terlalu panjang."}), 400
    if not _rate_ok(_client_ip()):
        return jsonify({"error": "rate", "message": "Terlalu banyak pemeriksaan. Coba lagi sebentar."}), 429
    try:
        result = checker.analyze(url)
    except Exception as e:
        print(f"[CHECK ERROR] {type(e).__name__}: {e}")
        return jsonify({"error": "internal", "message": "Tautan tidak dapat diperiksa. Pastikan formatnya benar."}), 200
    result["verdict"] = checker.verdict(result)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)