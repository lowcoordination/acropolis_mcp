from __future__ import annotations

import json

from argus.jsonrpc import rpc_error, sanitize_rpc_id


def test_sanitize_rpc_id_passthrough_types():
    assert sanitize_rpc_id(None) is None
    assert sanitize_rpc_id(42) == 42
    assert sanitize_rpc_id(3.14) == 3.14
    assert sanitize_rpc_id("abc") == "abc"


def test_sanitize_rpc_id_bool_rejected():
    # bool is a subclass of int in Python but is not a valid JSON-RPC id.
    assert sanitize_rpc_id(True) is None
    assert sanitize_rpc_id(False) is None


def test_sanitize_rpc_id_string_clamped():
    long_id = "x" * 1000
    result = sanitize_rpc_id(long_id)
    assert len(result) == 256


def test_sanitize_rpc_id_unknown_type_becomes_none():
    assert sanitize_rpc_id([1, 2, 3]) is None
    assert sanitize_rpc_id({"a": 1}) is None


def test_rpc_error_shape():
    body = json.loads(rpc_error(1, "boom"))
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert body["error"]["message"] == "boom"
    assert body["error"]["code"] == -32600


def test_rpc_error_with_data_and_code():
    body = json.loads(rpc_error("req-1", "mismatch", code=-32020, data={"tool": "read_file"}))
    assert body["error"]["code"] == -32020
    assert body["error"]["data"] == {"tool": "read_file"}
