"""Fallback chain must never forward one provider's model id to another."""

import logging

import pytest

from app.core import ai_manager as am


class FakeProvider:
    def __init__(self, fail=False):
        self.fail = fail
        self.models = []

    async def chat(self, messages, model=None, temperature=0.3, max_tokens=4096):
        self.models.append(model)
        if self.fail:
            raise Exception("All connection attempts failed")
        return {"content": "ok", "tokens_used": 1, "cost_usd": 0.0, "latency_ms": 1}

    async def close(self):
        pass


def make(primary_fails=True, all_fail=False):
    mgr = am.AIManager()
    mgr.providers = {
        "omniroute": FakeProvider(fail=primary_fails or all_fail),
        "openrouter": FakeProvider(fail=all_fail),
    }
    mgr.fallback_chain = ["omniroute", "openrouter"]
    mgr.active_provider = "omniroute"
    mgr.task_routing = {}
    mgr.task_model_defaults = {"triage": {"openrouter": "or/own-default"}}
    return mgr


MSG = [{"role": "user", "content": "hi"}]


async def test_fallback_gets_its_own_model():
    mgr = make()
    res = await mgr.chat(
        MSG, model="antigravity/gemini-2.5-flash-lite", task_type="triage",
        model_provider="omniroute",
    )
    assert res["provider"] == "openrouter"
    assert mgr.providers["omniroute"].models == ["antigravity/gemini-2.5-flash-lite"]
    assert mgr.providers["openrouter"].models == ["or/own-default"]


async def test_fallback_uses_provider_default_without_task_default():
    mgr = make()
    await mgr.chat(MSG, model="antigravity/x", task_type="other", model_provider="omniroute")
    assert mgr.providers["openrouter"].models == [None]


async def test_model_without_provider_applies_to_primary_only():
    mgr = make()
    await mgr.chat(MSG, model="antigravity/x", task_type="triage")
    assert mgr.providers["omniroute"].models == ["antigravity/x"]
    assert "antigravity/x" not in mgr.providers["openrouter"].models


async def test_explicit_provider_and_model_honoured():
    mgr = make(primary_fails=False)
    res = await mgr.chat(MSG, model="m1", task_type="triage", model_provider="omniroute")
    assert res["provider"] == "omniroute"
    assert mgr.providers["omniroute"].models == ["m1"]
    assert mgr.last_success_at is not None


async def test_all_fail_error_is_rate_limited(caplog):
    mgr = make(all_fail=True)
    with caplog.at_level(logging.ERROR, logger="aegis.ai_manager"):
        for _ in range(3):
            res = await mgr.chat(MSG, task_type="triage")
    assert res["error"] is True
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "triage" in errors[0].getMessage() and "omniroute" in errors[0].getMessage()
    assert mgr.status()["ai_last_error"]

    # After the window, it logs again.
    mgr._last_all_failed_log -= am._ALL_FAILED_LOG_INTERVAL_SECONDS + 1
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="aegis.ai_manager"):
        await mgr.chat(MSG, task_type="triage")
    assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 1


async def test_connect_failure_does_not_quarantine():
    mgr = make()
    await mgr.chat(MSG, task_type="triage")
    assert not mgr._is_quarantined("omniroute")
    await mgr.chat(MSG, task_type="triage")
    assert len(mgr.providers["omniroute"].models) == 2  # retried on next call
