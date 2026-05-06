"""Optional HTTPS ingest of SDK telemetry into the CogNEXUS dashboard.

Requires an API key created under **Account → API Keys** in the dashboard.
If no key or base URL is configured, :func:`post_sdk_event` returns immediately
without raising — user application code keeps running.

Environment variables
---------------------
``COGNEXUS_API_KEY``
    Primary secret sent as ``X-Api-Key``.
``MYAPP_API_KEY``
    Fallback secret name (same semantics as ``COGNEXUS_API_KEY``).
``COGNEXUS_API_BASE_URL``
    API origin, e.g. ``https://cognexuslabs.ai`` — **no trailing slash required**.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
from typing import Any, Optional

_log = logging.getLogger("cognexus.cloud")

_override_key: Optional[str] = None
_override_base: Optional[str] = None

_MISSING = object()


def configure(*, api_key: Any = _MISSING, base_url: Any = _MISSING) -> None:
    """Set package-wide defaults (overrides env until cleared).

    Pass ``api_key=None`` or ``base_url=None`` to clear an override and fall
    back to environment variables / built-in default base URL.
    """
    global _override_key, _override_base
    if api_key is not _MISSING:
        if api_key is None:
            _override_key = None
        else:
            _override_key = str(api_key).strip() or None
    if base_url is not _MISSING:
        if base_url is None:
            _override_base = None
        else:
            _override_base = str(base_url).strip().rstrip("/") or None


def _effective_key() -> Optional[str]:
    if _override_key:
        return _override_key
    return (
        (os.environ.get("COGNEXUS_API_KEY") or "").strip()
        or (os.environ.get("MYAPP_API_KEY") or "").strip()
        or None
    )


def _effective_base() -> str:
    if _override_base:
        return _override_base.rstrip("/")
    raw = (os.environ.get("COGNEXUS_API_BASE_URL") or "").strip().rstrip("/")
    if raw:
        return raw
    return "https://cognexuslabs.ai"


def post_sdk_event(
    event_type: str,
    *,
    source: str = "pypi_sdk",
    payload: Optional[dict[str, Any]] = None,
    level: str = "info",
    title: Optional[str] = None,
    timeout_sec: float = 5.0,
) -> None:
    """POST one row to ``/api/events`` (fire-and-forget thread).

    Never raises to callers. Logs at DEBUG when skipped (no key); WARNING when
    the HTTP round-trip fails after a key was present.
    """
    key = _effective_key()
    if not key:
        _log.debug("cloud: skip event %r — no COGNEXUS_API_KEY / MYAPP_API_KEY", event_type)
        return

    body_obj = {
        "event_type": event_type,
        "source": source,
        "payload": payload or {},
        "level": level,
        "title": title,
    }

    def _run() -> None:
        url = _effective_base() + "/api/events"
        data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Api-Key": key,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status >= 400:
                    _log.warning(
                        "cloud: event POST %s returned HTTP %s", event_type, resp.status
                    )
        except urllib.error.HTTPError as exc:
            _log.warning(
                "cloud: event POST %s failed HTTP %s", event_type, exc.code
            )
        except Exception as exc:
            _log.warning("cloud: event POST %s failed: %s", event_type, exc)

    threading.Thread(target=_run, daemon=True).start()


__all__ = ["configure", "post_sdk_event"]
