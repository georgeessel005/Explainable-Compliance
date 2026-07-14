"""
audit/log.py  -  The accountability trail (Data Protection Act 2018).

Every analyst action and every stage transition appends a timestamped AuditLogEntry.
The log is append-only by design: entries are never mutated or removed, because the
point of the artefact is to show *who decided what, when*, including decisions that
were later superseded.

The AuditLog instance lives in st.session_state so it survives Streamlit reruns.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from src.models import AuditLogEntry, FindingStatus

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps pandas off the import path
    import pandas


class AuditLog:
    """Append-only, in-memory audit trail of the whole session."""

    #: Stage transitions are logged against this sentinel rather than a real finding id.
    SYSTEM_SCOPE = "SYSTEM"

    def __init__(self, entries: Optional[list[AuditLogEntry]] = None) -> None:
        self._entries: list[AuditLogEntry] = list(entries) if entries else []

    # ---------- writing ----------

    def record(
        self,
        finding_id: str,
        action: str,
        actor: str,
        previous_status: Optional[FindingStatus] = None,
        new_status: Optional[FindingStatus] = None,
        details: Optional[str] = None,
    ) -> None:
        """Append one entry. Timestamp is applied automatically (aware UTC)."""
        self._entries.append(
            AuditLogEntry(
                finding_id=finding_id,
                action=action,
                actor=actor,
                previous_status=previous_status,
                new_status=new_status,
                details=details,
            )
        )

    def record_stage(self, action: str, actor: str, details: Optional[str] = None) -> None:
        """Append a pipeline stage transition (Stage 1/2/3/5), not tied to a finding."""
        self.record(
            finding_id=self.SYSTEM_SCOPE,
            action=action,
            actor=actor,
            details=details,
        )

    # ---------- reading ----------

    @property
    def entries(self) -> list[AuditLogEntry]:
        """All entries in insertion order. A copy: the trail is not editable from outside."""
        return list(self._entries)

    def entries_for(self, finding_id: str) -> list[AuditLogEntry]:
        """All entries recorded against one finding, in insertion order."""
        return [e for e in self._entries if e.finding_id == finding_id]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self.entries)

    # ---------- export ----------

    def to_dataframe(self) -> "pandas.DataFrame":
        """Render the trail as a DataFrame for display/export.

        Columns are fixed even when the log is empty, so the UI can render a stable
        (if empty) table on first load rather than KeyError-ing on a missing column.
        """
        import pandas as pd

        columns = [
            "timestamp",
            "finding_id",
            "action",
            "actor",
            "previous_status",
            "new_status",
            "details",
        ]
        if not self._entries:
            return pd.DataFrame(columns=columns)

        rows = []
        for entry in self._entries:
            rows.append(
                {
                    "timestamp": entry.timestamp,
                    "finding_id": entry.finding_id,
                    "action": entry.action,
                    "actor": entry.actor,
                    "previous_status": (
                        entry.previous_status.value if entry.previous_status else None
                    ),
                    "new_status": entry.new_status.value if entry.new_status else None,
                    "details": entry.details,
                }
            )
        return pd.DataFrame(rows, columns=columns)

    def to_csv(self) -> str:
        """CSV export of the trail (offered as a download alongside the report)."""
        return self.to_dataframe().to_csv(index=False)
