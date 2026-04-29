"""Structured audit trail for prompt-injection / prompt-defense signals.

Writes **JSONL** (one JSON object per line) to disk for compliance and forensic
review.  Optionally mirrors rows into an external store (e.g. a database) via
a pluggable ``on_event`` callback so the record can appear in dashboards or
monitoring pipelines.

No raw user text is stored — only a short redacted preview and a SHA-256 hash
(privacy-by-design: logging without leakage).

Quick-start::

    from cognexus.events import record_prompt_defense_event

    # Minimal — just writes to JSONL
    record_prompt_defense_event(
        kind="prompt_injection",
        surface="chat",
        source="user",
        result=detection_result,
        action="logged",
    )

    # With a custom sink (e.g. database insert)
    def my_sink(record: dict) -> None:
        db.execute("INSERT INTO events ...", record)

    record_prompt_defense_event(..., on_event=my_sink)

Environment variables
---------------------
``COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR``
    Directory for the JSONL file. Falls back to ``REPORTS_DIR``, then ``/tmp``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cognexus.prompt_injection import DetectionResult

_log = logging.getLogger("cognexus.events")
_write_lock = threading.Lock()


def _events_path() -> Path:
    base = (
        os.environ.get("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR")
        or os.environ.get("REPORTS_DIR")
        or "/tmp"
    )
    root = Path(base)
    root.mkdir(parents=True, exist_ok=True)
    return root / "prompt_defense_events.jsonl"


def _redact_preview(text: str, max_len: int = 96) -> str:
    one_line = " ".join((text or "").split())[:max_len]
    return one_line + ("\u2026" if len((text or "")) > max_len else "")


def record_prompt_defense_event(
    *,
    kind: str,
    surface: str,
    source: str,
    result: DetectionResult,
    action: str,
    user_id: Optional[Any] = None,
    text: str = "",
    on_event: Optional[Callable[[dict[str, Any]], None]] = None,
) -> None:
    """Append one audit record to JSONL and optionally call *on_event*.

    Only records events where ``result.is_injection`` is True — clean scans
    are not written to disk.

    Args:
        kind: Logical category, e.g. ``"prompt_injection"``.
        surface: Input surface, e.g. ``"user_input"``, ``"rag_content"``.
        source: Component identifier that submitted the input.
        result: The :class:`~cognexus.prompt_injection.DetectionResult`.
        action: What happened — ``"blocked"`` or ``"logged"``.
        user_id: Optional identifier for the end user (any JSON-serialisable
            value). Stored in the JSONL record; useful for filtering.
        text: The original input text. Only a redacted preview and SHA-256
            hash are stored — the raw text is **never** written to disk.
        on_event: Optional callback receiving the full record dict. Use this
            to mirror the row into a database, message queue, or monitoring
            service without adding a hard dependency to the package.
    """
    if not result.is_injection:
        return

    payload_hash = hashlib.sha256((text or "").encode("utf-8")).hexdigest()
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "surface": surface,
        "source": source,
        "action": action,
        "user_id": user_id,
        "threat": result.threat_level.value,
        "injection_type": result.injection_type.value if result.injection_type else None,
        "confidence": result.confidence,
        "patterns": (result.matched_patterns or [])[:12],
        "input_sha256": payload_hash,
        "preview": _redact_preview(text),
    }
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))

    with _write_lock:
        try:
            path = _events_path()
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception as exc:
            _log.error("events: jsonl write failed: %s", exc)

    _log.warning(
        "PROMPT_DEFENSE_EVENT kind=%s surface=%s source=%s action=%s threat=%s "
        "type=%s user=%s hash=%s\u2026",
        kind,
        surface,
        source,
        action,
        result.threat_level.value,
        record["injection_type"],
        user_id if user_id is not None else "\u2014",
        payload_hash[:16],
    )

    if on_event is not None:
        try:
            on_event(record)
        except Exception as exc:
            _log.debug("events: on_event callback raised: %s", exc)


def read_recent_events(
    *,
    user_id: Any = None,
    limit: int = 50,
    events_dir: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return recent JSONL rows (newest first).

    Args:
        user_id: When provided, only rows whose ``user_id`` field matches are
            returned. Pass ``None`` to return rows regardless of user.
        limit: Maximum number of rows to return (capped at 200).
        events_dir: Override the directory to read from. Defaults to the value
            resolved by the ``COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR`` / ``REPORTS_DIR``
            environment variables.

    Returns:
        A list of dicts, newest first.
    """
    cap = max(1, min(int(limit), 200))

    if events_dir is not None:
        path = Path(events_dir) / "prompt_defense_events.jsonl"
    else:
        path = _events_path()

    if not path.is_file():
        return []

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return []

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    out: list[dict[str, Any]] = []
    for ln in reversed(lines):
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if user_id is not None and obj.get("user_id") != user_id:
            continue
        out.append(obj)
        if len(out) >= cap:
            break
    return out


__all__ = [
    "record_prompt_defense_event",
    "read_recent_events",
]
