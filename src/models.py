"""
models.py  -  Frozen shared data contracts.
Every module imports from here. Pydantic v2.
Dates use datetime.date and comparisons are done against AssetRecord.assessment_date
so the whole pipeline is deterministic (required for reproducible evaluation).
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------- Enumerations ----------

class Framework(str, Enum):
    CE = "Cyber Essentials"
    CE_PLUS = "Cyber Essentials Plus"
    ISO27001 = "ISO/IEC 27001:2022"


class MappingType(str, Enum):
    PRIMARY = "Primary"
    SECONDARY = "Secondary"


class Severity(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IssueCode(str, Enum):
    PATCH_MISSING = "PATCH_MISSING"
    PATCH_RECORD_ABSENT = "PATCH_RECORD_ABSENT"
    DEFAULT_CREDENTIALS = "DEFAULT_CREDENTIALS"
    INSECURE_PROTOCOL = "INSECURE_PROTOCOL"
    EXCESSIVE_PRIVILEGES = "EXCESSIVE_PRIVILEGES"
    STALE_ACCOUNT = "STALE_ACCOUNT"
    PASSWORD_POLICY_NONCOMPLIANCE = "PASSWORD_POLICY_NONCOMPLIANCE"
    MFA_ABSENT = "MFA_ABSENT"
    UNRESTRICTED_INBOUND = "UNRESTRICTED_INBOUND"
    UNMANAGED_SERVICE_EXPOSED = "UNMANAGED_SERVICE_EXPOSED"
    FLAT_NETWORK = "FLAT_NETWORK"
    AV_SIGNATURE_OUTDATED = "AV_SIGNATURE_OUTDATED"
    NO_EDR_INGESTION = "NO_EDR_INGESTION"
    AUTH_SCAN_FAILURE = "AUTH_SCAN_FAILURE"
    INSUFFICIENT_SCAN_CREDENTIALS = "INSUFFICIENT_SCAN_CREDENTIALS"


class DecisionType(str, Enum):
    APPROVE = "Approve"
    MODIFY = "Modify"
    ESCALATE = "Escalate"


class FindingStatus(str, Enum):
    AWAITING_REVIEW = "Awaiting Analyst Decision"
    APPROVED = "Approved"
    MODIFIED = "Modified"
    ESCALATED = "Escalated"
    COMMITTED = "Committed to Report"


# ---------- Stage 1: raw validated input ----------

class RawVulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$")
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    description: str
    published_date: date
    patch_released_date: Optional[date] = None
    patch_applied: bool = False

    def severity(self) -> Severity:
        s = self.cvss_score
        if s == 0:
            return Severity.NONE
        if s < 4:
            return Severity.LOW
        if s < 7:
            return Severity.MEDIUM
        if s < 9:
            return Severity.HIGH
        return Severity.CRITICAL

    def days_since_patch(self, assessment_date: date) -> Optional[int]:
        if self.patch_released_date is None:
            return None
        return (assessment_date - self.patch_released_date).days


class AssetRecord(BaseModel):
    """One asset plus everything detected on it (Stage 1 input unit)."""
    model_config = ConfigDict(extra="forbid")
    asset_id: str
    hostname: str
    operating_system: str
    ip_address: str
    internet_facing: bool = False
    environment: str = "production"
    criticality: Severity = Severity.MEDIUM
    assessment_date: date
    issue_codes: list[IssueCode] = Field(default_factory=list)
    vulnerabilities: list[RawVulnerability] = Field(default_factory=list)


class RejectionError(BaseModel):
    """A record that failed Stage 1 validation."""
    raw: dict
    reason: str


class IngestionResult(BaseModel):
    valid_records: list[AssetRecord] = Field(default_factory=list)
    rejected: list[RejectionError] = Field(default_factory=list)


# ---------- Rule base ----------

class ControlMapping(BaseModel):
    framework: Framework
    control_id: str            # e.g. "A.8.8" or a CE pillar name
    control_name: str          # e.g. "Management of technical vulnerabilities"
    mapping_type: MappingType


class IssueRule(BaseModel):
    """One rule keyed on an issue code, mapping across frameworks (Stage 2 rule base)."""
    rule_id: str               # e.g. "CE-PATCH-001"
    issue_code: IssueCode
    title: str                 # short human label
    control_mappings: list[ControlMapping]
    explanation_template: str  # may reference {hostname}, {cve_id}, {cvss_score}, {days}
    remediation_steps: list[str]


class RuleBase(BaseModel):
    rules: list[IssueRule]

    def by_issue(self, code: IssueCode) -> Optional[IssueRule]:
        for r in self.rules:
            if r.issue_code == code:
                return r
        return None


# ---------- Stage 2 output ----------

class ComplianceFinding(BaseModel):
    finding_id: str
    asset: AssetRecord
    issue_code: IssueCode
    rule_id: str
    triggering_cve: Optional[str] = None
    triggering_cvss: Optional[float] = None
    control_mappings: list[ControlMapping]
    frameworks_breached: list[Framework]


# ---------- Stage 3 output ----------

class Explanation(BaseModel):
    finding_id: str
    plain_english: str
    linked_controls: list[ControlMapping]
    remediation_steps: list[str]
    status: FindingStatus = FindingStatus.AWAITING_REVIEW


# ---------- Stage 4 (HITL) ----------

class AnalystDecision(BaseModel):
    finding_id: str
    decision: DecisionType
    modified_explanation: Optional[str] = None
    analyst_note: Optional[str] = None
    analyst_id: str = "analyst"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finding_id: str
    action: str
    actor: str
    previous_status: Optional[FindingStatus] = None
    new_status: Optional[FindingStatus] = None
    details: Optional[str] = None


# ---------- Stage 5 ----------

class ComplianceReport(BaseModel):
    report_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[ComplianceFinding]
    explanations: list[Explanation]
    decisions: list[AnalystDecision]
    sha256_hash: Optional[str] = None
    pdf_path: Optional[str] = None
