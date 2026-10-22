import pytest

from app.core.auth_endpoints import is_credential_attempt


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/auth/login"),
    ("POST", "/api/v1/auth/login?next=/x"),
    ("POST", "/login"),
    ("POST", "/users/sign_in"),
    ("POST", "/wp-login.php"),
    ("POST", "/xmlrpc.php"),
    ("POST", "/oauth/token"),
    ("POST", "/token"),
    ("POST", "/api/admin/auth"),
    ("POST", "/api/auth/change-password"),
    ("PUT", "/api/sessions"),
    ("post", "/user/login/"),
    (None, "/api/auth/login"),
])
def test_credential_attempts(method, path):
    assert is_credential_attempt(method, path)


@pytest.mark.parametrize("method,path", [
    # expired-session traffic: the polling that blocked an office NAT
    ("GET", "/api/notifications/app"),
    ("GET", "/api/notifications/unread-count"),
    ("GET", "/api/printserver/status"),
    ("POST", "/api/control-procesos/generate-dst"),
    ("POST", "/api/control-procesos/processes"),
    ("POST", "/api/messaging/delivery-routes/0b1d2c3e/imprimir-etiqueta"),
    ("POST", "/api/notifications/token"),
    # auth namespace but not a credential submission
    ("GET", "/api/auth/me"),
    ("GET", "/api/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/auth/logout"),
    (None, "/api/auth/me"),
    (None, "/api/notifications/app"),
    ("POST", None),
    ("POST", ""),
    ("POST", "/"),
])
def test_not_credential_attempts(method, path):
    assert not is_credential_attempt(method, path)
