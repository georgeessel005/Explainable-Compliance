"""
loader.py  -  Stage 1: ingestion and validation.

Reads a JSON dataset and validates every record against the frozen `AssetRecord`
contract (src/models.py, Pydantic v2). Valid records land in `IngestionResult.valid_records`;
anything that fails validation lands in `IngestionResult.rejected` as a `RejectionError`
carrying the original dict and the reason.

The central guarantee: **a malformed record never crashes the loader**. Stage 1 rejects it,
records why, and carries on with the rest of the file. Only a missing/unreadable file or a
structurally unusable payload raises.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NamedTuple

from pydantic import ValidationError

from src.models import AssetRecord, IngestionResult, RejectionError

#: Keys accepted when the payload is an object wrapping the record list rather than a
#: bare JSON array.
_LIST_KEYS = ("assets", "records", "data")


def _coerce_to_list(payload: Any, path: str) -> list[Any]:
    """Normalise the parsed payload into a list of records."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in _LIST_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return value
    raise ValueError(
        f"{path}: expected a JSON array of asset records "
        f"(or an object with an '{_LIST_KEYS[0]}' array), got {type(payload).__name__}."
    )


def load_and_validate(path: str) -> IngestionResult:
    """Load `path` and validate each record against AssetRecord.

    Args:
        path: path to the JSON dataset (e.g. data/synthetic/assets.json).

    Returns:
        IngestionResult with `valid_records` and `rejected` populated.

    Raises:
        FileNotFoundError: if `path` does not exist. Callers (the Streamlit app) handle
            this explicitly to prompt dataset generation, so it is deliberately not
            swallowed here.
        ValueError: if the file is not valid JSON, or the payload is not a record list.
    """
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"Dataset not found: {path}") from None

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: file is not valid JSON ({exc}).") from exc

    entries = _coerce_to_list(payload, path)

    result = IngestionResult()
    for index, entry in enumerate(entries):
        # Guard the non-dict case up front: RejectionError.raw is typed `dict`, so a
        # stray scalar would otherwise fail while constructing the rejection itself.
        if not isinstance(entry, dict):
            result.rejected.append(
                RejectionError(
                    raw={"_raw_value": repr(entry)},
                    reason=(
                        f"Record #{index} is not a JSON object "
                        f"(got {type(entry).__name__})."
                    ),
                )
            )
            continue

        try:
            result.valid_records.append(AssetRecord.model_validate(entry))
        except ValidationError as exc:
            result.rejected.append(RejectionError(raw=entry, reason=str(exc)))
        except Exception as exc:  # noqa: BLE001 - Stage 1 must never crash on one bad record.
            result.rejected.append(
                RejectionError(raw=entry, reason=f"{type(exc).__name__}: {exc}")
            )

    return result


# ---------------------------------------------------------------------------
# Presentation helper
#
# RejectionError.reason holds str(ValidationError) verbatim, which is the right
# thing to store: it is complete, and the audit story depends on not paraphrasing
# away detail. It is the wrong thing to *show* a reader unedited -- pydantic's
# format ("[type=string_pattern_mismatch, input_type=str]" plus a link to
# errors.pydantic.dev) reads as a leaked stack trace rather than a designed
# rejection, and readers assume the tool has crashed.
#
# describe_rejection() renders the same fact in plain English. It parses the
# stored reason rather than capturing structured errors at validation time,
# because RejectionError.reason is a str in the frozen models.py. Anything it
# cannot parse degrades to the raw string, never an exception.
# ---------------------------------------------------------------------------

_PROBLEM_BY_TYPE = {
    "string_pattern_mismatch": "Value does not match the required format",
    "less_than_equal": "Value is above the allowed maximum",
    "greater_than_equal": "Value is below the allowed minimum",
    "enum": "Not one of the recognised values",
    "missing": "Required field is missing",
    "extra_forbidden": "Unexpected field that the schema does not allow",
    "date_from_datetime_parsing": "Not a valid date",
    "date_parsing": "Not a valid date",
    "int_parsing": "Not a valid whole number",
    "float_parsing": "Not a valid number",
    "bool_parsing": "Not a valid true/false value",
    "string_type": "Expected text",
}

# Field-specific wording, which beats the generic message where we know the rule.
_PROBLEM_BY_FIELD = {
    ("cve_id", "string_pattern_mismatch"): "Invalid CVE identifier (expected CVE-YYYY-NNNN)",
    ("cvss_score", "less_than_equal"): "CVSS score above 10 (valid range is 0.0-10.0)",
    ("cvss_score", "greater_than_equal"): "CVSS score below 0 (valid range is 0.0-10.0)",
}


class RejectionSummary(NamedTuple):
    """A rejected record rendered for a human reader. `raw_reason` is unmodified."""

    asset_id: str
    field: str
    problem: str
    value: str
    raw_reason: str

    @property
    def headline(self) -> str:
        """One line: what was wrong, and with which value."""
        if self.value:
            return f"{self.problem} — {self.value}"
        return self.problem


def describe_rejection(rejection: RejectionError) -> RejectionSummary:
    """Turn a stored ValidationError string into a plain-English summary.

    Never raises: an unparseable reason yields the raw text as the problem, so a
    surprising error shape degrades to today's behaviour rather than hiding a record.
    """
    reason = rejection.reason or ""
    asset_id = str(rejection.raw.get("asset_id") or "unknown asset")

    # pydantic v2 lays each error out as:
    #     N validation error(s) for AssetRecord
    #     <field.path>
    #       <message> [type=<code>, input_value=<value>, input_type=<type>]
    field = ""
    lines = [ln for ln in reason.splitlines() if ln.strip()]
    if len(lines) >= 2 and "validation error" in lines[0]:
        field = lines[1].strip()

    err_type = ""
    match = re.search(r"\[type=([a-z_]+)", reason)
    if match:
        err_type = match.group(1)

    value = ""
    match = re.search(r"input_value=(.*?)(?:, input_type=|\])", reason, re.S)
    if match:
        value = match.group(1).strip()
        if len(value) > 60:
            value = value[:57] + "..."

    leaf = field.rsplit(".", 1)[-1] if field else ""
    problem = (
        _PROBLEM_BY_FIELD.get((leaf, err_type))
        or _PROBLEM_BY_TYPE.get(err_type)
        or (lines[2].strip().split("[type=")[0].strip() if len(lines) >= 3 else "")
        or reason.strip()
    )
    if err_type == "extra_forbidden" and leaf:
        problem = f"Unexpected field '{leaf}' that the schema does not allow"
        value = ""
    if err_type == "missing" and leaf:
        problem = f"Required field '{leaf}' is missing"
        value = ""

    return RejectionSummary(
        asset_id=asset_id,
        field=field,
        problem=problem,
        value=value,
        raw_reason=reason,
    )
