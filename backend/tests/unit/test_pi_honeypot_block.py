"""pi-deploy/aegis_honeypot.py _block_ip: auth header, force flag, reason."""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HONEYPOT = Path(__file__).resolve().parents[3] / "pi-deploy" / "aegis_honeypot.py"


class _Fake(BaseHTTPRequestHandler):
    seen = []
    status = 200

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        _Fake.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, json.loads(self.rfile.read(n))))
        self.send_response(_Fake.status)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def fw():
    _Fake.seen, _Fake.status = [], 200
    srv = HTTPServer(("127.0.0.1", 0), _Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_port
    srv.shutdown()


def _load(monkeypatch, tmp_path, url, secret):
    monkeypatch.setenv("AEGIS_LOCAL_FW", url)
    monkeypatch.setenv("HONEYPOT_LOG", str(tmp_path / "hp.log"))
    if secret:
        monkeypatch.setenv("AEGIS_FIREWALL_SECRET", secret)
    else:
        monkeypatch.delenv("AEGIS_FIREWALL_SECRET", raising=False)
    spec = importlib.util.spec_from_file_location("aegis_honeypot_t", HONEYPOT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_block_sends_auth_force_and_reason(fw, monkeypatch, tmp_path):
    mod = _load(monkeypatch, tmp_path, fw, "s3cret")
    mod._block_ip("203.0.113.9", "GET /.env")
    path, headers, body = _Fake.seen[0]
    assert path == "/block"
    assert headers.get("x-aegis-fw-auth") == "s3cret"
    assert body["force"] is True
    assert body["reason"] == "honeypot:GET /.env"
    assert body["threat_type"] == "honeypot" and body["severity"] == "high"


def test_no_secret_no_header(fw, monkeypatch, tmp_path):
    mod = _load(monkeypatch, tmp_path, fw, "")
    mod._block_ip("203.0.113.9", "x")
    assert "x-aegis-fw-auth" not in _Fake.seen[0][1]


def test_401_logged_distinctly(fw, monkeypatch, tmp_path, caplog):
    _Fake.status = 401
    mod = _load(monkeypatch, tmp_path, fw, "bad")
    with caplog.at_level("ERROR"):
        mod._block_ip("203.0.113.9", "x")
    assert "REJECTED http=401" in caplog.text
