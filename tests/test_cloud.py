"""Tests for optional dashboard ingest (no network when no key)."""

import cognexus.cloud as cloud
from cognexus.cloud import configure, post_sdk_event


def test_post_sdk_event_no_key_no_crash():
    configure(api_key=None, base_url=None)
    post_sdk_event("unit_test", payload={"ok": True})


def test_configure_override(monkeypatch):
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)
    monkeypatch.delenv("COGNEXUS_API_BASE_URL", raising=False)
    configure(api_key="k", base_url="https://example.com")
    assert cloud._effective_key() == "k"
    assert cloud._effective_base() == "https://example.com"
    configure(api_key=None, base_url=None)
    assert cloud._effective_key() is None
    assert cloud._effective_base() == "https://cognexuslabs.ai"
