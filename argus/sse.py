"""Parse and rebuild a buffered `text/event-stream` body (issue #165, response DLP).

Only what response DLP needs: split a complete body into events, let the caller replace an
event's `data`, and serialize. An event whose data is not replaced comes back byte-for-byte,
including comments, `event:`/`id:`/`retry:` fields and its original line endings.

A body that ends part-way through an event (no blank line after its last field) raises
IncompleteStreamError. Response DLP treats that as unparseable and fails closed: a half event
cannot be scanned as a JSON-RPC message, and forwarding it raw would pass unscanned bytes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_LINE = re.compile(rb"[^\r\n]*(?:\r\n|\r|\n)")


class IncompleteStreamError(ValueError):
    pass


@dataclass
class SseEvent:
    raw_lines: list[bytes]          # every line of the event, line endings included
    terminator: bytes               # the blank line that ends it
    _new_data: Optional[str] = field(default=None, repr=False)

    @property
    def data(self) -> Optional[str]:
        """The event's data (multiple `data:` lines joined by newlines, per the SSE spec), or
        None when the event has no data field (a comment or keep-alive)."""
        values = []
        for line in self.raw_lines:
            name, value = _split_field(line)
            if name == "data":
                values.append(value)
        return "\n".join(values) if values else None

    def replace_data(self, data: str) -> None:
        if "\n" in data or "\r" in data:
            raise ValueError("replacement data must be a single line")
        self._new_data = data

    def serialize(self) -> bytes:
        if self._new_data is None:
            return b"".join(self.raw_lines) + self.terminator
        out: list[bytes] = []
        placed = False
        for line in self.raw_lines:
            name, _ = _split_field(line)
            if name != "data":
                out.append(line)
            elif not placed:
                ending = line[len(line.rstrip(b"\r\n")):]
                out.append(b"data: " + self._new_data.encode("utf-8") + ending)
                placed = True
        return b"".join(out) + self.terminator


def _split_field(line: bytes) -> tuple[str, str]:
    text = line.rstrip(b"\r\n").decode("utf-8")
    if text.startswith(":"):
        return "", text  # comment
    name, sep, value = text.partition(":")
    if sep and value.startswith(" "):
        value = value[1:]
    return name, value


def parse_events(body: bytes) -> list[SseEvent]:
    events: list[SseEvent] = []
    pending: list[bytes] = []
    pos = 0
    for m in _LINE.finditer(body):
        if m.start() != pos:
            break
        line = m.group(0)
        pos = m.end()
        if line in (b"\r\n", b"\n", b"\r"):
            if pending:
                events.append(SseEvent(raw_lines=pending, terminator=line))
                pending = []
            elif events:
                # Extra blank line between events: keep it with the previous one.
                events[-1].terminator += line
            else:
                events.append(SseEvent(raw_lines=[], terminator=line))
        else:
            pending.append(line)
    if pending or pos != len(body):
        raise IncompleteStreamError("event stream ended part-way through an event")
    # Validate every field decodes; a non-UTF-8 stream is unparseable.
    for ev in events:
        for line in ev.raw_lines:
            _split_field(line)
    return events


def serialize(events: list[SseEvent]) -> bytes:
    return b"".join(ev.serialize() for ev in events)
