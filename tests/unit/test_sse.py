"""Issue #165: argus/sse.py round-trips untouched events byte-for-byte and refuses half events."""
from __future__ import annotations

import pytest

from argus.sse import IncompleteStreamError, parse_events, serialize


@pytest.mark.parametrize("body", [
    b"event: message\nid: 1\ndata: {\"a\":1}\n\n",
    b": keep-alive\n\nevent: message\r\ndata: {\"a\":1}\r\n\r\n",
    b"data: line1\ndata: line2\n\n\n",
    b"retry: 1000\n\n",
    b"",
])
def test_round_trip_is_exact(body):
    assert serialize(parse_events(body)) == body


def test_multiline_data_is_joined():
    (ev,) = parse_events(b"data: a\ndata: b\n\n")
    assert ev.data == "a\nb"


def test_comment_has_no_data():
    (ev,) = parse_events(b": hi\n\n")
    assert ev.data is None


def test_replace_data_keeps_other_fields_and_line_endings():
    events = parse_events(b"event: message\r\nid: 7\r\ndata: x\r\ndata: y\r\n\r\n")
    events[0].replace_data('{"b":2}')
    assert serialize(events) == b'event: message\r\nid: 7\r\ndata: {"b":2}\r\n\r\n'


@pytest.mark.parametrize("body", [
    b"event: message\ndata: {\"a\":",
    b"data: x\n",
    b"data: x\n\ndata: y",
])
def test_incomplete_stream_raises(body):
    with pytest.raises(IncompleteStreamError):
        parse_events(body)


def test_non_utf8_raises():
    with pytest.raises(UnicodeDecodeError):
        parse_events(b"data: \xff\n\n")
