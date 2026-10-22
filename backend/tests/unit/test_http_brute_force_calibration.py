"""HTTP brute force counts credential attempts only, never expired sessions.

Regression: an office NAT with several browsers polling on an expired token
returned >20 x 401/min on non-auth endpoints and AEGIS auto-blocked it.
"""
import json
from pathlib import Path

import pytest
import yaml

from app.services import event_normalizer
from app.services.correlation_engine import _matches_filter
from app.services.log_watcher import LogWatcher

IP = "203.0.113.50"
RULES = Path(__file__).resolve().parents[2] / "app/rules/sigma"


def _line(method, path, status=401, ip=IP, app="example-backend"):
    return "[AEGIS] " + json.dumps({
        "ts": "2026-01-01T00:00:00.000Z", "app": app, "src_ip": ip,
        "method": method, "path": path, "status": status, "ua": "Mozilla/5.0",
        "host": "example.com",
    })


async def _feed(lines):
    lw = LogWatcher()
    incidents = []

    async def fake_create(line, pattern_name, threat_type, severity, source_ip, description):
        incidents.append((pattern_name, severity, source_ip))

    lw._create_incident_from_log = fake_create
    for line in lines:
        event = event_normalizer.normalize(line, source="example-backend")
        await lw._run_behavioural_detectors(line, event, IP)
    return incidents


async def test_expired_session_polling_does_not_trigger():
    lines = [_line("GET", "/api/notifications/app")] * 60
    lines += [_line("POST", "/api/control-procesos/generate-dst")] * 60
    lines += [_line("GET", "/api/auth/me")] * 30
    assert await _feed(lines) == []


async def test_failed_logins_trigger():
    incidents = await _feed([_line("POST", "/api/auth/login")] * 25)
    assert incidents and incidents[0][0] == "http_auth_brute"
    assert incidents[0][2] == IP


async def test_failed_logins_below_threshold_do_not_trigger():
    assert await _feed([_line("POST", "/api/auth/login")] * 19) == []


async def test_polling_does_not_mask_or_add_to_login_count():
    lines = [_line("GET", "/api/notifications/app")] * 100
    lines += [_line("POST", "/api/auth/login")] * 10
    assert await _feed(lines) == []


@pytest.mark.parametrize("method,path,expected", [
    ("GET", "/api/notifications/app", "http_request"),
    ("POST", "/api/control-procesos/generate-dst", "http_request"),
    ("POST", "/api/auth/login", "http_auth_failure"),
    ("POST", "/wp-login.php", "http_auth_failure"),
])
def test_normalizer_classification(method, path, expected):
    event = event_normalizer.normalize(_line(method, path), source="example-backend")
    assert event["event_type"] == expected


def _rule(name):
    return yaml.safe_load((RULES / name).read_text())


@pytest.mark.parametrize("rule_file,hit,miss", [
    ("web_attacks/sigma_cve_dell_recoverpoint_for_vms_2026_22769.yaml",
     "/manager/text/deploy?path=/x", "/api/admin/payments"),
    ("ai_infra/sigma_cve_kestra_2026_49869.yaml",
     "/api/v1/main/flows/demo/configs", "/api/v1/configs"),
    ("web_attacks/sigma_cve_connectwise_screenconnect_2024_1708.yaml",
     "/SetupWizard.aspx/abc", "/api/services/status"),
    ("web_attacks/sigma_cve_kentico_xperience_2025_2749.yaml",
     "/CMSPages/Staging/SyncServer.asmx", "/api/sync/state"),
    ("command_and_control/sigma_c2_cobalt_strike.yaml",
     "/__utm.gif", "/api/updates/list"),
    ("container_cloud/sigma_cloud_k8s_api_abuse.yaml",
     "/api/v1/namespaces/prod/secrets", "/api/v1/namespaces"),
])
def test_recalibrated_rules_match_product_urls_only(rule_file, hit, miss):
    flt = _rule(rule_file)["condition"]["filter"]
    assert _matches_filter({"request_path": hit}, flt)
    assert not _matches_filter({"request_path": miss}, flt)


@pytest.mark.parametrize("rule_file", [
    "web_attacks/sigma_cve_n_able_n_central_2026_86218.yaml",
    "web_attacks/sigma_cve_cisco_secure_firewall_mgmt_c_2026_20131.yaml",
    "web_attacks/sigma_cve_laravel_livewire_2025_54068.yaml",
    "supply_chain/sigma_cve_jetbrains_teamcity_2024_27199.yaml",
    "web_attacks/sigma_web_api_abuse.yaml",
    "web_attacks/sigma_web_parametric_brute.yaml",
])
def test_generic_path_rules_are_alert_only(rule_file):
    assert _rule(rule_file)["severity"] == "low"
