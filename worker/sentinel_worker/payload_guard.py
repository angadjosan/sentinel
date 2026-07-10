"""Shared guard against source code leaking into outbound cloud payloads.

Sentinel's privacy invariant is that source code and diffs never leave the
machine running the scan — only graph pointers (file/line, not text) and
finding metadata are sent to the cloud. This module holds the marker list used
to catch accidental leaks, so every outbound-to-cloud call site (the LLM
system-prompt guard in `agent.py`, the `/graph/upsert` and `/findings/ingest`
endpoints, and eventually the local engine's cloud HTTP client) checks against
the same list instead of drifting copies.
"""

from __future__ import annotations

SOURCE_CONTENT_MARKERS = [
    "+++ b/",
    "--- a/",
    "diff --git",
    "AKIA",
    "req.query",
    "request.GET",
    "db.query(",
    "subprocess.",
    "child_process",
]

# Graph node/edge metadata fields (label, intent, name) are short LLM-written
# summaries, not source dumps — a field this long is a sign that source text
# was passed through instead of a summary.
MAX_METADATA_FIELD_LENGTH = 2000


class SourcePayloadError(ValueError):
    """Raised when an outbound payload appears to carry source code instead of metadata."""


def assert_no_source_markers(text: str, *, field: str = "payload") -> None:
    """Raise if `text` contains a diff/source marker or is implausibly long for metadata."""
    if not text:
        return
    for marker in SOURCE_CONTENT_MARKERS:
        if marker in text:
            raise SourcePayloadError(f"source content marker {marker!r} found in {field}")
    if len(text) > MAX_METADATA_FIELD_LENGTH:
        raise SourcePayloadError(
            f"{field} is {len(text)} chars, over the {MAX_METADATA_FIELD_LENGTH}-char metadata limit "
            "(graph fields carry pointers and short labels, not source text)"
        )
