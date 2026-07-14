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
from pathlib import Path
from typing import Any

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
