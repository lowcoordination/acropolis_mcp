"""Issue #165: scan_result(), the pure response scanner. No HTTP here; the forwarding paths
are covered in tests/integration/test_response_dlp.py."""
from __future__ import annotations

import copy

import pytest

from argus.response_dlp import (
    HARD_LIMIT_MARKER,
    TRUNCATION_MARKER,
    UNPARSEABLE_MARKER,
    ResponseScan,
    format_limit,
    marker_message,
    response_dlp_enabled,
    scan_result,
)
from db.models import DlpCustomPattern, ServerPolicy

from tests.unit.test_dlp import _FAKE_GHP, _FAKE_JWT

PG_DSN = "postgres://app:s3cr3tpw@db:5432/x"


def _policy(**detectors) -> ServerPolicy:
    return ServerPolicy(response_dlp_detectors=detectors or {
        "jwt": "redact", "github_token": "redact", "url_credentials": "redact", "email": "redact",
    })


def _call_result(*texts, structured=None) -> dict:
    result = {"content": [{"type": "text", "text": t} for t in texts], "isError": False}
    if structured is not None:
        result["structuredContent"] = structured
    return {"jsonrpc": "2.0", "id": 7, "result": result}


def _non_result_repr(scan: ResponseScan) -> str:
    return repr((scan.detectors_fired, scan.match_count, scan.truncated))


async def test_every_string_leaf_is_scanned_keys_and_scalars_untouched():
    msg = _call_result(
        f"token {_FAKE_JWT}",
        structured={"nested": [{"dsn": PG_DSN}, 42, True, None], _FAKE_GHP: "key, not scanned"},
    )
    original = copy.deepcopy(msg)
    scan = await scan_result(msg, _policy())

    assert msg == original, "the input message must not be mutated"
    out = scan.result
    assert out["result"]["content"][0]["text"] == "token [REDACTED:jwt]"
    nested = out["result"]["structuredContent"]["nested"]
    assert nested[0]["dsn"] == "postgres://app:[REDACTED:url_credentials]@db:5432/x"
    assert nested[1:] == [42, True, None]
    assert _FAKE_GHP in out["result"]["structuredContent"], "keys are not scanned"
    assert out["jsonrpc"] == "2.0" and out["id"] == 7
    assert out["result"]["isError"] is False


async def test_detectors_fired_and_count_and_no_values_outside_result():
    msg = _call_result(f"a {_FAKE_JWT} b {_FAKE_JWT}", f"gh {_FAKE_GHP}")
    scan = await scan_result(msg, _policy())
    assert scan.detectors_fired == ["github_token", "jwt"]
    assert scan.match_count == 3
    assert scan.truncated is False
    rest = _non_result_repr(scan)
    for value in (_FAKE_JWT, _FAKE_GHP):
        assert value not in rest
        assert value not in repr(scan.result)


async def test_budget_cuts_both_strings_marks_them_and_still_redacts_the_head():
    head_secret = f"{_FAKE_GHP} "
    a = head_secret + "x" * (1000 - len(head_secret))
    b = "y" * 1000
    scan = await scan_result(_call_result(a, b), ServerPolicy(
        response_dlp_detectors={"github_token": "redact"}, response_dlp_max_bytes=1024,
    ))
    marker = TRUNCATION_MARKER.format(limit="1024 bytes")
    texts = [c["text"] for c in scan.result["result"]["content"]]
    assert all(t.endswith(marker) for t in texts)
    kept = [t[: -len(marker)] for t in texts]
    # The redaction placeholder is longer than the token it replaced, so measure kept
    # ORIGINAL text: the y-string carries no findings.
    assert len(kept[1].encode()) <= 512
    assert kept[0].startswith("[REDACTED:github_token] ")
    assert _FAKE_GHP not in texts[0]
    assert scan.truncated is True
    assert scan.detectors_fired == ["github_token"]


async def test_kept_text_total_is_within_budget():
    texts = ["a" * 3000, "b" * 200, "c" * 900]
    scan = await scan_result(_call_result(*texts), ServerPolicy(
        response_dlp_detectors={"jwt": "redact"}, response_dlp_max_bytes=1024,
    ))
    marker = TRUNCATION_MARKER.format(limit="1024 bytes")
    out = [c["text"] for c in scan.result["result"]["content"]]
    kept = [t[: -len(marker)] if t.endswith(marker) else t for t in out]
    assert sum(len(k.encode()) for k in kept) <= 1024
    assert out[1] == "b" * 200, "a string under the equal share is not cut"


async def test_secret_straddling_the_cut_is_still_redacted():
    """A token that starts in the kept head but ends past the cut must not leave a prefix."""
    a = "x" * 999 + " " + _FAKE_GHP + " " + "x" * 200  # cut at 1024 lands 24 chars into the token
    scan = await scan_result(_call_result(a), ServerPolicy(
        response_dlp_detectors={"github_token": "redact"}, response_dlp_max_bytes=1024,
    ))
    text = scan.result["result"]["content"][0]["text"]
    assert _FAKE_GHP[:20] not in text
    assert "[REDACTED:github_token]" in text


async def test_cut_respects_code_point_boundaries():
    s = "é" * 1000  # 2 bytes each
    scan = await scan_result(_call_result(s), ServerPolicy(
        response_dlp_detectors={"jwt": "redact"}, response_dlp_max_bytes=1025,
    ))
    text = scan.result["result"]["content"][0]["text"]
    kept = text.split("[TRUNCATED")[0]
    assert set(kept) == {"é"} and len(kept.encode()) <= 1025


async def test_just_under_budget_is_not_cut():
    s = "z" * 1000
    scan = await scan_result(_call_result(s), ServerPolicy(
        response_dlp_detectors={"jwt": "redact"}, response_dlp_max_bytes=1024,
    ))
    assert scan.result["result"]["content"][0]["text"] == s
    assert scan.truncated is False


async def test_timed_out_custom_pattern_redacts_the_whole_value():
    policy = ServerPolicy(
        dlp_custom_patterns=[DlpCustomPattern(name="evil", pattern=r"^(a*)*\1$", action="block")],
        response_dlp_detectors={"evil": "redact"},
    )
    evil = "a" * 30 + "b"
    scan = await scan_result(_call_result(evil, "unrelated"), policy)
    texts = [c["text"] for c in scan.result["result"]["content"]]
    assert texts[0] == "[REDACTED:evil]"
    assert scan.detectors_fired == ["evil"]


async def test_custom_pattern_uses_the_response_action_not_its_argument_action():
    policy = ServerPolicy(
        dlp_custom_patterns=[DlpCustomPattern(name="emp", pattern=r"EMP-\d{6}", action="block")],
        response_dlp_detectors={"emp": "redact"},
    )
    scan = await scan_result(_call_result("id EMP-123456 ok"), policy)
    assert scan.result["result"]["content"][0]["text"] == "id [REDACTED:emp] ok"


async def test_custom_pattern_not_named_in_the_response_map_does_not_run():
    policy = ServerPolicy(
        dlp_custom_patterns=[DlpCustomPattern(name="emp", pattern=r"EMP-\d{6}", action="redact")],
        response_dlp_detectors={"jwt": "redact"},
    )
    scan = await scan_result(_call_result("id EMP-123456 ok"), policy)
    assert scan.result["result"]["content"][0]["text"] == "id EMP-123456 ok"


async def test_error_response_is_scanned():
    msg = {"jsonrpc": "2.0", "id": 3, "error": {
        "code": -32000, "message": f"connect failed: {PG_DSN}", "data": {"trace": [f"jwt={_FAKE_JWT}"]},
    }}
    scan = await scan_result(msg, _policy())
    assert scan.result["error"]["message"] == "connect failed: postgres://app:[REDACTED:url_credentials]@db:5432/x"
    assert scan.result["error"]["data"]["trace"] == ["jwt=[REDACTED:jwt]"]
    assert scan.result["error"]["code"] == -32000


async def test_notification_params_in_the_stream_are_scanned():
    """An SSE tools/call stream can carry notifications (logging, progress) before the result.
    They are part of the response and get the same scan."""
    msg = {"jsonrpc": "2.0", "method": "notifications/message",
           "params": {"level": "info", "data": f"connecting {PG_DSN}"}}
    scan = await scan_result(msg, _policy())
    assert PG_DSN not in repr(scan.result)
    assert scan.result["method"] == "notifications/message"


async def test_allow_entry_never_applies_while_redact_entries_do():
    msg = _call_result(f"{_FAKE_JWT} me@example.com")
    scan = await scan_result(msg, ServerPolicy(response_dlp_detectors={"jwt": "allow", "email": "redact"}))
    assert scan.result["result"]["content"][0]["text"] == f"{_FAKE_JWT} [REDACTED:email]"
    assert scan.detectors_fired == ["email"]


async def test_nothing_fired_returns_equal_message():
    msg = _call_result("plain log line")
    scan = await scan_result(msg, _policy())
    assert scan.result == msg
    assert scan.detectors_fired == [] and scan.match_count == 0 and scan.truncated is False


def test_format_limit():
    assert format_limit(1_048_576) == "1 MB"
    assert format_limit(65536) == "65536 bytes"


def test_marker_message_is_a_valid_tools_call_result():
    assert marker_message(9, UNPARSEABLE_MARKER) == {
        "jsonrpc": "2.0", "id": 9,
        "result": {"content": [{"type": "text", "text": UNPARSEABLE_MARKER}], "isError": False},
    }
    assert "hard read limit" in HARD_LIMIT_MARKER


@pytest.mark.parametrize("detectors,method,expected", [
    ({}, "tools/call", False),
    ({"jwt": "redact"}, "tools/call", True),
    ({"jwt": "redact"}, "tools/list", False),
    ({"jwt": "redact"}, "initialize", False),
    ({"jwt": "redact"}, "resources/read", False),
])
def test_response_dlp_enabled(detectors, method, expected):
    assert response_dlp_enabled(ServerPolicy(response_dlp_detectors=detectors), method) is expected
