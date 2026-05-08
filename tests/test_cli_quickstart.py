"""Unit tests for CLI quickstart helpers (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cognexus import __version__
from cognexus.cli import (
    _CLI_USER_AGENT,
    _dashboard_request_headers,
    extract_cognexus_api_key_from_text,
    find_cognexus_api_key_in_env_files,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("COGNEXUS_API_KEY=abc123\n", "abc123"),
        ('COGNEXUS_API_KEY="quoted"', "quoted"),
        ("export COGNEXUS_API_KEY=ex\n", "ex"),
        ("# comment\nFOO=1\nCOGNEXUS_API_KEY=k\n", "k"),
        ("MYAPP_API_KEY=fall\n", "fall"),
        ("MYAPP_API_KEY=a\nCOGNEXUS_API_KEY=b\n", "b"),
        ("COGNEXUS_API_KEY=b\nMYAPP_API_KEY=a\n", "b"),
        ("NOT_IT=x\n", None),
    ],
)
def test_extract_cognexus_api_key_from_text(text: str, expected: str | None) -> None:
    assert extract_cognexus_api_key_from_text(text) == expected


def test_find_cognexus_api_key_in_env_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("COGNEXUS_API_KEY=file-key\n", encoding="utf-8")
    key, path = find_cognexus_api_key_in_env_files()
    assert key == "file-key"
    assert path == (tmp_path / ".env").resolve()


def test_dashboard_request_headers_avoids_python_urllib_fingerprint() -> None:
    assert _CLI_USER_AGENT.startswith(f"cognexus-cli/{__version__}")
    assert "Python-urllib" not in _CLI_USER_AGENT
    h = _dashboard_request_headers()
    assert h["Accept"] == "application/json"
    assert "Python-urllib" not in h["User-Agent"]
    assert h["User-Agent"].startswith(f"cognexus-cli/{__version__}")
