"""
explainer.py  -  Stage 3 explainability layer.

Turns a Stage 2 :class:`ComplianceFinding` into a plain-English
:class:`Explanation` in the spirit of the reference card FINDING #017:

    "This vulnerability allows ... Because the asset is internet-facing and the
     vendor patch was released 14 days ago without being applied, the finding
     fails Cyber Essentials patch-management requirements ... and ISO/IEC
     27001:2022 Annex A.8.8 ..."

Design notes
------------
*Never raises.* Rule templates are author-supplied strings, so
``str.format`` on them is a liability: a stray ``{foo}`` is a ``KeyError`` and a
``{cvss_score:.1f}`` against ``None`` is a ``TypeError``. Rendering therefore
goes through :class:`_SafeFormatter`, which resolves unknown or absent
placeholders to readable prose instead of blowing up.

*Absent CVEs are the common case, not an edge case.* Most issue codes are
configuration or process failures with no triggering CVE at all
(``FLAT_NETWORK``, ``STALE_ACCOUNT``, ``MFA_ABSENT`` ...), so
``triggering_cve`` / ``triggering_cvss`` are ``None`` and ``{days}`` is
unresolvable. That path is handled explicitly and reads naturally.

*The output always names the asset and the breached controls.* Whatever the
template says or omits, the assembled paragraph is guaranteed to reference the
asset hostname and to enumerate every breached control.
"""
from __future__ import annotations

import string
from datetime import date
from typing import Any, Optional

from src.models import (
    AssetRecord,
    ComplianceFinding,
    ControlMapping,
    Explanation,
    Framework,
    IssueCode,
    IssueRule,
    RawVulnerability,
    RuleBase,
    Severity,
)

__all__ = ["explain", "set_rulebase", "clear_rulebase_cache"]


# ---------- graceful degradation of template placeholders ----------

class _Missing:
    """Stand-in for a placeholder whose value is absent.

    Carries the prose used in its place, so a template hole degrades into
    readable English rather than a ``KeyError`` or a literal ``None``.
    """

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.text


#: Prose substituted when a named placeholder has no value. Keyed on the
#: placeholder name so each hole degrades into something that still scans.
_PLACEHOLDER_FALLBACKS: dict[str, str] = {
    "cve_id": "no associated CVE",
    "cvss_score": "not scored",
    "cvss_vector": "no CVSS vector recorded",
    "severity": "unrated",
    "days": "an unrecorded number of",
    "patch_released_date": "an unrecorded date",
    "published_date": "an unrecorded date",
    "description": "no vulnerability description recorded",
    "hostname": "an unnamed asset",
}

_GENERIC_FALLBACK = "not recorded"


def _fallback_for(key: Any) -> _Missing:
    return _Missing(_PLACEHOLDER_FALLBACKS.get(str(key), _GENERIC_FALLBACK))


class _SafeFormatter(string.Formatter):
    """A :class:`string.Formatter` that cannot raise on a bad template.

    Unknown names, out-of-range indices, failed attribute/item lookups and
    inapplicable format specs all degrade to prose instead of propagating.
    """

    def get_field(self, field_name, args, kwargs):
        try:
            return super().get_field(field_name, args, kwargs)
        except (KeyError, IndexError, AttributeError, TypeError, ValueError):
            # e.g. {nonexistent}, {0} with no positional args, {asset.bogus}
            root = str(field_name).split(".")[0].split("[")[0]
            return _fallback_for(root), field_name

    def get_value(self, key, args, kwargs):
        try:
            return super().get_value(key, args, kwargs)
        except (KeyError, IndexError):
            return _fallback_for(key)

    def convert_field(self, value, conversion):
        if isinstance(value, _Missing):
            return value
        try:
            return super().convert_field(value, conversion)
        except (TypeError, ValueError):
            return value

    def format_field(self, value, format_spec):
        # A spec like '.1f' is meaningless for absent prose - drop it.
        if isinstance(value, _Missing):
            return value.text
        if value is None:
            return _GENERIC_FALLBACK
        try:
            return super().format_field(value, format_spec)
        except (TypeError, ValueError):
            return str(value)


_FORMATTER = _SafeFormatter()


def _render(template: str, context: dict[str, Any]) -> str:
    """Render ``template`` against ``context``, degrading rather than raising."""
    if not template:
        return ""
    try:
        return _FORMATTER.vformat(template, (), context).strip()
    except Exception:
        # Unbalanced braces etc. leave the template unparseable; the raw text is
        # still more useful to an analyst than an exception.
        return template.strip()


# ---------- rule resolution ----------

_RULEBASE_CACHE: dict[str, Optional[RuleBase]] = {}
_INJECTED_RULEBASE: dict[str, Optional[RuleBase]] = {}


def set_rulebase(rulebase: Optional[RuleBase]) -> None:
    """Inject the rule base :func:`explain` should use.

    Lets callers that already hold a loaded rule base (the Streamlit UI, the
    tester) avoid a redundant disk load. Pass ``None`` to clear.
    """
    _INJECTED_RULEBASE["rb"] = rulebase


def clear_rulebase_cache() -> None:
    """Drop the lazily-loaded rule base cache (mainly for tests)."""
    _RULEBASE_CACHE.clear()


def _lazy_rulebase() -> Optional[RuleBase]:
    """Best-effort load of the rule base from disk, cached.

    ``explain(finding)`` is a frozen single-argument signature but the rule text
    lives in the rule base, so when no rule is supplied we fall back to loading
    it. Every failure mode (mapping engine not importable, rules/ absent,
    malformed YAML) degrades to ``None`` and the built-in templates below.
    """
    if "rb" in _INJECTED_RULEBASE and _INJECTED_RULEBASE["rb"] is not None:
        return _INJECTED_RULEBASE["rb"]
    if "rb" in _RULEBASE_CACHE:
        return _RULEBASE_CACHE["rb"]

    rulebase: Optional[RuleBase] = None
    try:
        from src.mapping.engine import load_rules  # imported late and optionally

        rulebase = load_rules()
    except Exception:
        rulebase = None

    _RULEBASE_CACHE["rb"] = rulebase
    return rulebase


def _resolve_rule(
    finding: ComplianceFinding,
    rule: Optional[IssueRule],
    rulebase: Optional[RuleBase],
) -> Optional[IssueRule]:
    if rule is not None:
        return rule
    if rulebase is not None:
        found = rulebase.by_issue(finding.issue_code)
        if found is not None:
            return found
    loaded = _lazy_rulebase()
    if loaded is not None:
        return loaded.by_issue(finding.issue_code)
    return None


# ---------- built-in fallback content ----------
#
# Used only when no rule template is reachable. The authoritative templates live
# in the Stage 2 rule base (rules/, owned by the mapping engine); these keep
# explain(finding) useful standalone rather than duplicating that content.

_FALLBACK_CLAUSES: dict[IssueCode, str] = {
    IssueCode.PATCH_MISSING: (
        "A known vulnerability on {hostname} has a vendor patch available that has not "
        "been applied, leaving the host exploitable by an attacker using published "
        "exploit code."
    ),
    IssueCode.PATCH_RECORD_ABSENT: (
        "No patch record exists for {hostname}, so there is no evidence that security "
        "updates are being applied or tracked through change management."
    ),
    IssueCode.DEFAULT_CREDENTIALS: (
        "{hostname} is still using vendor default credentials, which are publicly "
        "documented and allow trivial unauthorised access."
    ),
    IssueCode.INSECURE_PROTOCOL: (
        "{hostname} exposes an insecure protocol that transmits data without adequate "
        "encryption, allowing interception or tampering in transit."
    ),
    IssueCode.EXCESSIVE_PRIVILEGES: (
        "Accounts on {hostname} hold privileges beyond what their role requires, "
        "widening the blast radius of any single account compromise."
    ),
    IssueCode.STALE_ACCOUNT: (
        "{hostname} retains a dormant account that is no longer in legitimate use and "
        "provides an unmonitored route into the estate."
    ),
    IssueCode.PASSWORD_POLICY_NONCOMPLIANCE: (
        "The password policy in force on {hostname} does not meet the required strength "
        "and management rules, making credential guessing viable."
    ),
    IssueCode.MFA_ABSENT: (
        "{hostname} permits access without multi-factor authentication, so a single "
        "stolen password is sufficient to authenticate."
    ),
    IssueCode.UNRESTRICTED_INBOUND: (
        "{hostname} accepts unrestricted inbound connections, exposing services to any "
        "source address rather than only those with a business need."
    ),
    IssueCode.UNMANAGED_SERVICE_EXPOSED: (
        "An unmanaged network service is exposed on {hostname}, running outside the "
        "organisation's inventory and hardening process."
    ),
    IssueCode.FLAT_NETWORK: (
        "{hostname} sits on a flat network with no segregation, so an attacker gaining "
        "a foothold can move laterally to unrelated systems unimpeded."
    ),
    IssueCode.AV_SIGNATURE_OUTDATED: (
        "Malware signatures on {hostname} are out of date, so recently-observed malware "
        "will not be detected."
    ),
    IssueCode.NO_EDR_INGESTION: (
        "{hostname} is not forwarding endpoint telemetry, so malicious activity on the "
        "host would go unmonitored and uninvestigated."
    ),
    IssueCode.AUTH_SCAN_FAILURE: (
        "The authenticated vulnerability scan of {hostname} failed, so the host's true "
        "patch and configuration state is unverified."
    ),
    IssueCode.INSUFFICIENT_SCAN_CREDENTIALS: (
        "Scan credentials for {hostname} were insufficient, so the audit could not see "
        "the host's full configuration and the results understate its exposure."
    ),
}

_FALLBACK_REMEDIATION: dict[IssueCode, list[str]] = {
    IssueCode.PATCH_MISSING: [
        "Apply the outstanding vendor patch to the affected host.",
        "Record the change through the change-management process.",
        "Re-scan the host to confirm the vulnerability is resolved.",
    ],
    IssueCode.PATCH_RECORD_ABSENT: [
        "Establish and record a patch baseline for the affected host.",
        "Bring the host into the routine patch-management cycle.",
    ],
    IssueCode.DEFAULT_CREDENTIALS: [
        "Replace all vendor default credentials with unique strong secrets.",
        "Confirm no other host in the estate retains vendor defaults.",
    ],
    IssueCode.INSECURE_PROTOCOL: [
        "Disable the insecure protocol and enable its encrypted equivalent.",
        "Verify no dependent system still requires the insecure protocol.",
    ],
    IssueCode.EXCESSIVE_PRIVILEGES: [
        "Review the account's privileges against its documented role.",
        "Remove privileges beyond least-privilege requirements.",
    ],
    IssueCode.STALE_ACCOUNT: [
        "Disable the dormant account and confirm it is no longer required.",
        "Introduce a periodic review to catch dormant accounts.",
    ],
    IssueCode.PASSWORD_POLICY_NONCOMPLIANCE: [
        "Enforce a compliant password policy on the affected host.",
        "Force a reset of any credential that does not meet the policy.",
    ],
    IssueCode.MFA_ABSENT: [
        "Enable multi-factor authentication for access to the affected host.",
        "Verify MFA cannot be bypassed by legacy authentication paths.",
    ],
    IssueCode.UNRESTRICTED_INBOUND: [
        "Restrict inbound firewall rules to the minimum necessary sources.",
        "Document the business justification for each remaining rule.",
    ],
    IssueCode.UNMANAGED_SERVICE_EXPOSED: [
        "Identify the owner of the exposed service and bring it under management.",
        "Disable the service if it has no documented business need.",
    ],
    IssueCode.FLAT_NETWORK: [
        "Segregate the network so unrelated systems cannot reach each other.",
        "Apply access-control rules between the resulting segments.",
    ],
    IssueCode.AV_SIGNATURE_OUTDATED: [
        "Update malware signatures on the affected host.",
        "Confirm automatic signature updates are enabled and reporting.",
    ],
    IssueCode.NO_EDR_INGESTION: [
        "Restore endpoint telemetry ingestion for the affected host.",
        "Confirm alerting is active once telemetry resumes.",
    ],
    IssueCode.AUTH_SCAN_FAILURE: [
        "Investigate why the authenticated scan failed and correct the cause.",
        "Re-run the authenticated scan and confirm full coverage.",
    ],
    IssueCode.INSUFFICIENT_SCAN_CREDENTIALS: [
        "Provision scan credentials with sufficient rights for a full audit.",
        "Re-run the authenticated audit with the corrected credentials.",
    ],
}

_GENERIC_REMEDIATION = [
    "Review the finding against the linked controls and remediate the underlying issue.",
    "Re-assess the asset once the issue is resolved.",
]


# ---------- context assembly ----------

def _find_vulnerability(
    asset: AssetRecord, cve_id: Optional[str]
) -> Optional[RawVulnerability]:
    """Locate the RawVulnerability that triggered a finding, if any."""
    if not cve_id:
        return None
    for vuln in asset.vulnerabilities:
        if vuln.cve_id == cve_id:
            return vuln
    return None


def _severity_of(
    finding: ComplianceFinding, vuln: Optional[RawVulnerability]
) -> Optional[Severity]:
    if vuln is not None:
        return vuln.severity()
    if finding.triggering_cvss is not None:
        # Mirror RawVulnerability.severity() thresholds off the finding's score.
        probe = RawVulnerability(
            cve_id="CVE-0000-0000",
            cvss_score=finding.triggering_cvss,
            description="",
            published_date=date(1970, 1, 1),
        )
        return probe.severity()
    return None


def _build_context(
    finding: ComplianceFinding,
    rule: Optional[IssueRule],
    vuln: Optional[RawVulnerability],
) -> dict[str, Any]:
    """Assemble every placeholder a template might reference.

    Values genuinely absent are supplied as :class:`_Missing` so the formatter
    renders prose for them instead of ``None``.
    """
    asset = finding.asset
    severity = _severity_of(finding, vuln)

    days: Any = _fallback_for("days")
    if vuln is not None:
        computed = vuln.days_since_patch(asset.assessment_date)
        if computed is not None:
            days = computed

    cve_id: Any = finding.triggering_cve or _fallback_for("cve_id")
    cvss: Any = (
        finding.triggering_cvss
        if finding.triggering_cvss is not None
        else _fallback_for("cvss_score")
    )

    context: dict[str, Any] = {
        # asset
        "hostname": asset.hostname,
        "asset_id": asset.asset_id,
        "ip_address": asset.ip_address,
        "operating_system": asset.operating_system,
        "environment": asset.environment,
        "criticality": asset.criticality.value,
        "internet_facing": asset.internet_facing,
        "exposure": "internet-facing" if asset.internet_facing else "internal-only",
        "assessment_date": asset.assessment_date.isoformat(),
        # vulnerability
        "cve_id": cve_id,
        "cvss_score": cvss,
        "severity": severity.value if severity is not None else _fallback_for("severity"),
        "days": days,
        "cvss_vector": (
            vuln.cvss_vector
            if vuln is not None and vuln.cvss_vector
            else _fallback_for("cvss_vector")
        ),
        "description": (
            vuln.description
            if vuln is not None and vuln.description
            else _fallback_for("description")
        ),
        "published_date": (
            vuln.published_date.isoformat()
            if vuln is not None
            else _fallback_for("published_date")
        ),
        "patch_released_date": (
            vuln.patch_released_date.isoformat()
            if vuln is not None and vuln.patch_released_date is not None
            else _fallback_for("patch_released_date")
        ),
        "patch_applied": vuln.patch_applied if vuln is not None else False,
        # rule / finding
        "finding_id": finding.finding_id,
        "issue_code": finding.issue_code.value,
        "rule_id": finding.rule_id,
        "title": rule.title if rule is not None else finding.issue_code.value,
    }
    return context


# ---------- sentence assembly ----------

def _format_control(mapping: ControlMapping) -> str:
    """Render one control mapping as a citation an assessor would recognise."""
    if mapping.framework is Framework.ISO27001:
        label = f"{mapping.framework.value} Annex {mapping.control_id}"
        if mapping.control_name:
            label = f"{label} - {mapping.control_name}"
    else:
        label = f"{mapping.framework.value} {mapping.control_id}"
        name = (mapping.control_name or "").strip()
        if name and name.lower() != mapping.control_id.strip().lower():
            label = f"{label} ({name})"
    return f"{label} [{mapping.mapping_type.value}]"


def _join(items: list[str]) -> str:
    """Oxford-comma-free English list join."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _breach_sentence(finding: ComplianceFinding) -> str:
    """The sentence that ties the finding to the controls it fails.

    Always emitted: the report is only defensible if every finding states which
    controls it breaches. Preserves the mapping order the engine produced.
    """
    if not finding.control_mappings:
        return (
            "No control mappings are recorded against this finding, so it cannot be "
            "tied to a framework requirement and requires analyst review."
        )
    controls = [_format_control(cm) for cm in finding.control_mappings]
    return f"This finding fails {_join(controls)}."


def _cve_clause(
    finding: ComplianceFinding,
    vuln: Optional[RawVulnerability],
    severity: Optional[Severity],
) -> str:
    """Name the triggering CVE and its patch age, or state there is not one."""
    if not finding.triggering_cve:
        return (
            "No specific CVE triggered this finding; it arises from the asset's "
            "configuration or management state rather than a named vulnerability."
        )

    detail: list[str] = []
    if finding.triggering_cvss is not None:
        detail.append(f"CVSS {finding.triggering_cvss}")
    if severity is not None:
        detail.append(f"{severity.value.lower()} severity")
    suffix = f" ({', '.join(detail)})" if detail else ""
    sentence = f"The triggering vulnerability is {finding.triggering_cve}{suffix}."

    if vuln is not None:
        days = vuln.days_since_patch(finding.asset.assessment_date)
        if days is not None and not vuln.patch_applied:
            exposure = (
                "the asset is internet-facing"
                if finding.asset.internet_facing
                else "the asset remains in service"
            )
            sentence += (
                f" Because {exposure} and the vendor patch was released {days} days "
                "before the assessment date without being applied, the exposure is "
                "unmitigated."
            )
    return sentence


def _asset_clause(asset: AssetRecord) -> str:
    return (
        f"Asset {asset.hostname} ({asset.ip_address}, {asset.operating_system}) is "
        f"{'internet-facing' if asset.internet_facing else 'internal-only'} in the "
        f"{asset.environment} environment and was assessed on "
        f"{asset.assessment_date.isoformat()}."
    )


# ---------- public API ----------

def explain(
    finding: ComplianceFinding,
    rule: Optional[IssueRule] = None,
    rulebase: Optional[RuleBase] = None,
) -> Explanation:
    """Produce the plain-English :class:`Explanation` for a mapped finding.

    Frozen interface is ``explain(finding) -> Explanation``; ``rule`` and
    ``rulebase`` are optional injection points for callers that already hold the
    rule base. With neither supplied the rule is resolved from the Stage 2 rule
    base on disk, and if that is unavailable a built-in template is used.

    The returned paragraph always names the asset and enumerates the breached
    controls. ``status`` defaults to ``AWAITING_REVIEW``: Stage 3 explains, it
    never decides - only the Stage 4 human gate moves a finding beyond this.

    Never raises on template content: absent placeholders (no triggering CVE, so
    no ``{cve_id}``/``{cvss_score}``/``{days}``) degrade into readable prose.
    """
    resolved_rule = _resolve_rule(finding, rule, rulebase)
    vuln = _find_vulnerability(finding.asset, finding.triggering_cve)
    severity = _severity_of(finding, vuln)
    context = _build_context(finding, resolved_rule, vuln)

    # Rule template wins; the built-in clause is the standalone fallback.
    template = ""
    if resolved_rule is not None and resolved_rule.explanation_template:
        template = resolved_rule.explanation_template
    if not template:
        template = _FALLBACK_CLAUSES.get(
            finding.issue_code,
            "{hostname} breaches a Cyber Essentials requirement recorded as {issue_code}.",
        )

    body = _render(template, context)

    parts: list[str] = []
    if body:
        parts.append(body)

    # Guarantee the asset is named even if the template never mentioned it.
    if finding.asset.hostname not in " ".join(parts):
        parts.insert(0, _asset_clause(finding.asset))

    # Guarantee the CVE (or its absence) is addressed.
    cve_clause = _cve_clause(finding, vuln, severity)
    cve_marker = finding.triggering_cve or "No specific CVE"
    if cve_marker not in " ".join(parts):
        parts.append(cve_clause)

    # Guarantee the breached controls are enumerated.
    parts.append(_breach_sentence(finding))

    plain_english = " ".join(p.strip() for p in parts if p and p.strip())

    if resolved_rule is not None and resolved_rule.remediation_steps:
        remediation = list(resolved_rule.remediation_steps)
    else:
        remediation = list(
            _FALLBACK_REMEDIATION.get(finding.issue_code, _GENERIC_REMEDIATION)
        )

    return Explanation(
        finding_id=finding.finding_id,
        plain_english=plain_english,
        linked_controls=list(finding.control_mappings),
        remediation_steps=remediation,
    )
