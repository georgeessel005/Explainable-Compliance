"""
helpers.py  -  Shared non-fixture utilities for the test suite.

extract_pdf_text: ReportLab invariant-mode content streams are encoded with
``/Filter [/ASCII85Decode /FlateDecode]`` -- the filter list is applied in order at
READ time, so decoding must ASCII85-decode FIRST and inflate second. (Inflating the
raw stream bytes directly fails with a zlib error; that is an assertion bug in the
test, not a defect in the PDF.)
"""
from __future__ import annotations

import base64
import re
import zlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.models import AnalystDecision, DecisionType

#: Fixed anchor for decision timestamps so gate-ordering tests are explicit about
#: which decision is "later" instead of racing the wall clock.
T0 = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_decision(
    finding_id: str,
    decision: DecisionType = DecisionType.APPROVE,
    *,
    minute: int = 0,
    ts: Optional[datetime] = None,
    **kwargs,
) -> AnalystDecision:
    """An AnalystDecision with a deterministic timestamp (T0 + `minute`)."""
    if ts is None:
        ts = T0 + timedelta(minutes=minute)
    return AnalystDecision(
        finding_id=finding_id, decision=decision, timestamp=ts, **kwargs
    )


_STREAM_RE = re.compile(rb"stream\r?\n(.*?)endstream", re.S)


def extract_pdf_text(pdf_bytes: bytes) -> bytes:
    """Concatenated plaintext of every decodable content stream in the PDF.

    Tries ASCII85 -> Flate (the invariant-mode encoding) first, then plain Flate,
    then the raw bytes for unfiltered streams. Undecodable streams (e.g. font
    programs) are skipped -- the footer text lives in page content streams, which
    always decode.
    """
    out = b""
    for match in _STREAM_RE.finditer(pdf_bytes):
        raw = match.group(1).strip()
        try:
            out += zlib.decompress(base64.a85decode(raw, adobe=True))
            continue
        except Exception:
            pass
        try:
            out += zlib.decompress(raw)
        except Exception:
            out += raw
    return out
