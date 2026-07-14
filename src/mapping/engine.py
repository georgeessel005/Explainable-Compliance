"""
mapping/engine.py  -  Stage 2: the rule-based cross-framework mapping engine.

Loads the YAML rule base into the frozen models from src/models.py and turns validated
AssetRecords into ComplianceFindings carrying Cyber Essentials, CE Plus and ISO/IEC
27001:2022 control mappings.

Deliberately rule-based, not ML: every finding traces back to a rule_id in
rules/ce_iso_mappings.yaml, which is what makes Stage 3's explanation defensible.

DETERMINISM CONTRACT (the tester asserts this):
  * finding_id is F-<asset_id>-<ISSUE_CODE> - stable across runs and processes.
  * frameworks_breached is deduped preserving first appearance in control_mappings
    order. It is never built from a set, because set iteration order for str-enums is
    not a stable published guarantee across runs.
  * triggering vulnerability selection sorts by (-cvss_score, cve_id) so ties resolve
    the same way every time.

ACADEMIC INTEGRITY: mappings marked `verified: false` in the YAML are best-effort and
not sourced from George's Appendix Aii. They are loaded so Stage 2 has full IssueCode
coverage, and enumerated for confirmation in rules/UNVERIFIED_MAPPINGS.md. Verification
metadata is exposed via verification_report() / unverified_intersections(); it is
stripped before ControlMapping construction because models.py is frozen.

No Streamlit imports here - this module must stay importable headless.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from ..models import (
    AssetRecord,
    ComplianceFinding,
    ControlMapping,
    Framework,
    IssueCode,
    IssueRule,
    RawVulnerability,
    RuleBase,
)

RULES_FILENAME = "ce_iso_mappings.yaml"
TAXONOMY_FILENAME = "issue_taxonomy.json"

# The closed ISO Annex A control universe (blueprint Section 7). Loading a control
# outside this set is a rule-base error, not something to silently accept.
ISO_CONTROL_UNIVERSE: tuple[str, ...] = (
    "A.5.15", "A.5.16", "A.5.17", "A.8.5", "A.8.7", "A.8.8", "A.8.9",
    "A.8.16", "A.8.20", "A.8.21", "A.8.22", "A.8.23", "A.8.27", "A.8.32",
)

# Issue codes whose finding carries a triggering CVE. Mirrors `vulnerability_linked`
# in issue_taxonomy.json; kept here as a constant because map_findings() takes only a
# RuleBase and must not depend on the taxonomy file being present.
VULN_LINKED_ISSUES: frozenset[IssueCode] = frozenset({
    IssueCode.PATCH_MISSING,
    IssueCode.PATCH_RECORD_ABSENT,
    IssueCode.AUTH_SCAN_FAILURE,
})

# Rule-base metadata keys that are NOT part of the frozen ControlMapping contract.
_MAPPING_METADATA_KEYS = ("verified", "source", "matrix_rows", "note")

# Populated by load_rules(); read by matrix.py and the integrity report. Keyed by
# rule_id so a rule base loaded twice does not double-count.
_VERIFICATION_INDEX: dict[str, list[dict[str, Any]]] = {}


class RuleBaseError(ValueError):
    """The rule base on disk is malformed or violates a stated invariant."""


# --------------------------------------------------------------------------------
# Path resolution
# --------------------------------------------------------------------------------

def _resolve_rules_dir(rules_dir: str = "rules") -> Path:
    """Find the rules directory regardless of the caller's CWD.

    Streamlit Cloud, pytest and `python -m` all start from different working
    directories, so a bare relative "rules" cannot be trusted. Tries, in order: the
    path as given, then the same name anchored at the repo root (two levels up from
    this file), then a plain "rules" at the repo root.
    """
    candidates: list[Path] = []
    given = Path(rules_dir)
    candidates.append(given)

    repo_root = Path(__file__).resolve().parents[2]
    if not given.is_absolute():
        candidates.append(repo_root / given)
    candidates.append(repo_root / "rules")

    for candidate in candidates:
        if (candidate / RULES_FILENAME).is_file():
            return candidate.resolve()

    searched = ", ".join(str(c) for c in candidates)
    raise RuleBaseError(
        f"Could not locate {RULES_FILENAME}. Searched: {searched}"
    )


# --------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------

def _build_control_mapping(raw: dict, rule_id: str) -> tuple[ControlMapping, dict[str, Any]]:
    """Split one YAML mapping entry into a frozen ControlMapping plus its metadata."""
    if not isinstance(raw, dict):
        raise RuleBaseError(f"{rule_id}: control_mappings entries must be mappings")

    payload = {k: v for k, v in raw.items() if k not in _MAPPING_METADATA_KEYS}
    try:
        mapping = ControlMapping(**payload)
    except Exception as exc:  # pydantic ValidationError, surfaced with context
        raise RuleBaseError(f"{rule_id}: invalid control mapping {payload!r}: {exc}") from exc

    if mapping.framework is Framework.ISO27001 and mapping.control_id not in ISO_CONTROL_UNIVERSE:
        raise RuleBaseError(
            f"{rule_id}: ISO control {mapping.control_id!r} is outside the stated "
            f"Annex A control universe {ISO_CONTROL_UNIVERSE}"
        )

    meta = {
        "verified": bool(raw.get("verified", False)),
        "source": raw.get("source"),
        "matrix_rows": raw.get("matrix_rows"),
        "framework": mapping.framework,
        "control_id": mapping.control_id,
        "control_name": mapping.control_name,
        "mapping_type": mapping.mapping_type,
    }
    return mapping, meta


def load_rules(rules_dir: str = "rules") -> RuleBase:
    """Parse rules/ce_iso_mappings.yaml into a RuleBase.

    Raises RuleBaseError if the file is missing, malformed, contains an ISO control
    outside the stated universe, or duplicates an issue code.
    """
    resolved = _resolve_rules_dir(rules_dir)
    path = resolved / RULES_FILENAME

    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    if not isinstance(doc, dict) or "rules" not in doc:
        raise RuleBaseError(f"{path}: expected a mapping with a top-level 'rules' key")

    raw_rules = doc.get("rules") or []
    if not raw_rules:
        raise RuleBaseError(f"{path}: rule base is empty")

    rules: list[IssueRule] = []
    seen: set[IssueCode] = set()
    verification: dict[str, list[dict[str, Any]]] = {}

    for raw_rule in raw_rules:
        rule_id = raw_rule.get("rule_id", "<missing rule_id>")
        raw_mappings = raw_rule.get("control_mappings") or []
        if not raw_mappings:
            raise RuleBaseError(f"{rule_id}: has no control_mappings")

        mappings: list[ControlMapping] = []
        metas: list[dict[str, Any]] = []
        ce_pillar = raw_rule.get("ce_pillar")

        for raw_mapping in raw_mappings:
            mapping, meta = _build_control_mapping(raw_mapping, rule_id)
            # Default the matrix row(s) to the rule's CE pillar so matrix.py never has
            # to guess which row an ISO control belongs to.
            if not meta["matrix_rows"]:
                meta["matrix_rows"] = [ce_pillar] if ce_pillar else []
            meta["rule_id"] = rule_id
            meta["issue_code"] = raw_rule.get("issue_code")
            meta["ce_pillar"] = ce_pillar
            mappings.append(mapping)
            metas.append(meta)

        payload = {
            "rule_id": raw_rule.get("rule_id"),
            "issue_code": raw_rule.get("issue_code"),
            "title": raw_rule.get("title"),
            "control_mappings": mappings,
            "explanation_template": raw_rule.get("explanation_template", ""),
            "remediation_steps": raw_rule.get("remediation_steps") or [],
        }
        try:
            rule = IssueRule(**payload)
        except Exception as exc:
            raise RuleBaseError(f"{rule_id}: invalid rule: {exc}") from exc

        if rule.issue_code in seen:
            raise RuleBaseError(
                f"{rule_id}: duplicate rule for issue code {rule.issue_code.value}; "
                "RuleBase.by_issue() would silently return only the first"
            )
        seen.add(rule.issue_code)
        rules.append(rule)
        verification[rule.rule_id] = metas

    _VERIFICATION_INDEX.clear()
    _VERIFICATION_INDEX.update(verification)

    return RuleBase(rules=rules)


def load_taxonomy(rules_dir: str = "rules") -> dict:
    """Load rules/issue_taxonomy.json (labels, pillars, severity weights) for the UI."""
    path = _resolve_rules_dir(rules_dir) / TAXONOMY_FILENAME
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------------
# Coverage and verification reporting
# --------------------------------------------------------------------------------

def unmapped_issue_codes(rulebase: RuleBase) -> list[IssueCode]:
    """IssueCode enum members with no rule. Must be empty - Stage 2 covers all 15."""
    return [code for code in IssueCode if rulebase.by_issue(code) is None]


def mapping_metadata(rule_id: str) -> list[dict[str, Any]]:
    """Provenance metadata for one rule's control mappings (post-load_rules)."""
    return list(_VERIFICATION_INDEX.get(rule_id, []))


def all_mapping_metadata() -> list[dict[str, Any]]:
    """Provenance metadata for every control mapping in the loaded rule base."""
    out: list[dict[str, Any]] = []
    for metas in _VERIFICATION_INDEX.values():
        out.extend(metas)
    return out


def is_verified_mapping(
    rule_id: str,
    framework: "Framework | str",
    control_id: str,
) -> Optional[bool]:
    """Provenance of ONE control mapping, for the PDF and the review card.

    Answers "is this specific (rule_id, framework, control_id) intersection sourced
    from George's Appendix Aii, or is it a best-effort mapping?" so a renderer can mark
    the 9 unverified mappings visibly distinct from the 15 verified ones. This exists
    because ControlMapping (frozen in models.py) has no `verified` field, so the flag is
    stripped when a finding is built and cannot be read back off the mapping itself.

    Returns:
        True  - the intersection is present and VERIFIED (transcribed from Appendix Aii).
        False - present but UNVERIFIED (best-effort, flagged in UNVERIFIED_MAPPINGS.md).
        None  - this (rule_id, framework, control_id) triple is not in the rule base at
                all (unknown rule_id, unknown framework string, or that control is not
                mapped by that rule). Callers should treat None as "cannot assert" and
                render neither badge, not as "unverified".

    Pure and deterministic: a lookup over the index that load_rules() populated. It reads
    no rule data beyond that index, mutates nothing, and takes the caller's ControlMapping
    fields as-is - pass `mapping.framework, mapping.control_id` straight in. `framework`
    accepts either a Framework enum or its string value (e.g. "Cyber Essentials").

    If two mappings on one rule ever share a (framework, control_id) - they do not today -
    a verified assertion wins, so this can never mislabel a sourced mapping as unverified.
    Requires load_rules() to have run (as does mapping_metadata); before then, or for an
    unrecognised framework value, it returns None rather than raising.
    """
    if isinstance(framework, Framework):
        fw: Optional[Framework] = framework
    else:
        try:
            fw = Framework(str(framework))
        except ValueError:
            return None

    matches = [
        m
        for m in _VERIFICATION_INDEX.get(rule_id, [])
        if m["framework"] is fw and m["control_id"] == control_id
    ]
    if not matches:
        return None
    return any(bool(m["verified"]) for m in matches)


def iso_intersections(verified: Optional[bool] = None) -> list[dict[str, Any]]:
    """Distinct (CE pillar x ISO control) intersections from the loaded rule base.

    verified=True  -> only the intersections sourced from Appendix Aii.
    verified=False -> only the best-effort, unsourced intersections.
    None           -> all of them.

    An intersection asserted as verified by any rule counts as verified, so a
    best-effort mapping that happens to restate a sourced cell cannot downgrade it.
    """
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    for meta in all_mapping_metadata():
        if meta["framework"] is not Framework.ISO27001:
            continue
        for row in meta["matrix_rows"] or []:
            key = (row, meta["control_id"])
            existing = cells.get(key)
            if existing is None:
                cells[key] = {
                    "ce_pillar": row,
                    "iso_control": meta["control_id"],
                    "control_name": meta["control_name"],
                    "mapping_type": meta["mapping_type"],
                    "verified": meta["verified"],
                    "sources": [meta["source"]] if meta["source"] else [],
                    "rule_ids": [meta["rule_id"]],
                    "issue_codes": [meta["issue_code"]],
                }
                continue

            existing["rule_ids"].append(meta["rule_id"])
            existing["issue_codes"].append(meta["issue_code"])
            if meta["source"] and meta["source"] not in existing["sources"]:
                existing["sources"].append(meta["source"])
            if meta["verified"] and not existing["verified"]:
                # A sourced assertion always wins over a best-effort one, including
                # its mapping_type - the cell is Appendix Aii's to define.
                existing["verified"] = True
                existing["mapping_type"] = meta["mapping_type"]

    ordered = sorted(
        cells.values(),
        key=lambda c: (
            ISO_CONTROL_UNIVERSE.index(c["iso_control"]),
            c["ce_pillar"],
        ),
    )
    if verified is None:
        return ordered
    return [c for c in ordered if c["verified"] is verified]


def unverified_intersections() -> list[dict[str, Any]]:
    """Every intersection George still needs to confirm against his own source."""
    return iso_intersections(verified=False)


def verification_report() -> dict[str, int]:
    """Counts for rules/UNVERIFIED_MAPPINGS.md and the UI integrity banner."""
    every = iso_intersections()
    verified = [c for c in every if c["verified"]]
    return {
        "verified": len(verified),
        "unverified": len(every) - len(verified),
        "total_in_rulebase": len(every),
        "target_total": 47,  # George's full matrix; the gap is his to close.
        "still_to_source": 47 - len(every),
    }


# --------------------------------------------------------------------------------
# Stage 2 mapping
# --------------------------------------------------------------------------------

def build_finding_id(asset_id: str, issue_code: IssueCode) -> str:
    """Stable, human-readable finding id. Same inputs -> same id, always."""
    return f"F-{asset_id}-{issue_code.value}"


def _select_triggering_vulnerability(
    record: AssetRecord,
    prefer_dated: bool = False,
) -> Optional[RawVulnerability]:
    """Pick the vulnerability a vuln-linked finding should cite.

    Highest-CVSS unpatched vulnerability on the asset; falls back to the highest-CVSS
    vulnerability overall if every one is patched. Ties break on cve_id so the choice
    is deterministic rather than dependent on input ordering.

    prefer_dated=True restricts the first pass to unpatched vulnerabilities that carry
    a patch_released_date. This is for PATCH_MISSING, whose whole claim is "a vendor
    patch has been available for N days and was not applied" - a CVE with no recorded
    patch date cannot support that sentence, and citing one makes Stage 3 render "the
    patch was released None days ago". A dated CVE is the better citation even when a
    higher-scoring undated one exists, because the undated one is not evidence of an
    unapplied patch at all. Severity-led issues (AUTH_SCAN_FAILURE) leave this off, so
    they still cite the genuinely most severe finding.
    """
    if not record.vulnerabilities:
        return None

    def rank(v: RawVulnerability) -> tuple[float, str]:
        return (-v.cvss_score, v.cve_id)

    unpatched = [v for v in record.vulnerabilities if not v.patch_applied]

    if prefer_dated:
        dated_unpatched = [v for v in unpatched if v.patch_released_date is not None]
        if dated_unpatched:
            return sorted(dated_unpatched, key=rank)[0]

    pool = unpatched or list(record.vulnerabilities)
    return sorted(pool, key=rank)[0]


def _ordered_frameworks(mappings: Iterable[ControlMapping]) -> list[Framework]:
    """Distinct frameworks, first-appearance order. Never derived from a set."""
    out: list[Framework] = []
    for mapping in mappings:
        if mapping.framework not in out:
            out.append(mapping.framework)
    return out


def map_findings(
    records: list[AssetRecord], rulebase: RuleBase
) -> list[ComplianceFinding]:
    """Stage 2: turn validated assets into cross-framework compliance findings.

    One finding per (asset, issue_code). Issue codes with no rule are skipped rather
    than guessed at - but unmapped_issue_codes() asserts that set is empty, so a skip
    means the rule base regressed.

    Output order follows input record order, then the asset's issue_codes order, so
    the report and the UI list findings identically on every run.
    """
    findings: list[ComplianceFinding] = []

    for record in records:
        # Two selections: PATCH_MISSING needs a CVE with a patch date to support its
        # "released N days ago" claim; the others want the most severe outright.
        triggering = _select_triggering_vulnerability(record)
        triggering_dated = _select_triggering_vulnerability(record, prefer_dated=True)
        seen_codes: set[IssueCode] = set()

        for issue_code in record.issue_codes:
            # A duplicated code on one asset would otherwise produce two findings
            # sharing a finding_id, which would break the audit log's key.
            if issue_code in seen_codes:
                continue
            seen_codes.add(issue_code)

            rule = rulebase.by_issue(issue_code)
            if rule is None:
                continue

            cve: Optional[str] = None
            cvss: Optional[float] = None
            if issue_code in VULN_LINKED_ISSUES:
                chosen = (
                    triggering_dated
                    if issue_code is IssueCode.PATCH_MISSING
                    else triggering
                )
                if chosen is not None:
                    cve = chosen.cve_id
                    cvss = chosen.cvss_score

            findings.append(
                ComplianceFinding(
                    finding_id=build_finding_id(record.asset_id, issue_code),
                    asset=record,
                    issue_code=issue_code,
                    rule_id=rule.rule_id,
                    triggering_cve=cve,
                    triggering_cvss=cvss,
                    # Copy so a downstream mutation cannot reach back into the rule
                    # base and silently alter every later finding.
                    control_mappings=[m.model_copy() for m in rule.control_mappings],
                    frameworks_breached=_ordered_frameworks(rule.control_mappings),
                )
            )

    return findings


# --------------------------------------------------------------------------------
# Self-check
# --------------------------------------------------------------------------------

def _self_check() -> None:  # pragma: no cover - developer utility
    from datetime import date

    rulebase = load_rules()
    unmapped = unmapped_issue_codes(rulebase)
    print(f"rules loaded            : {len(rulebase.rules)}")
    print(f"issue codes in enum     : {len(list(IssueCode))}")
    print(f"unmapped issue codes    : {unmapped}")

    report = verification_report()
    print(
        f"intersections           : {report['verified']} verified, "
        f"{report['unverified']} unverified, {report['total_in_rulebase']} in rule base "
        f"({report['still_to_source']} of {report['target_total']} still to source)"
    )

    records = [
        AssetRecord(
            asset_id="A-001",
            hostname="web-01",
            operating_system="Ubuntu 22.04",
            ip_address="10.0.0.10",
            internet_facing=True,
            assessment_date=date(2025, 6, 1),
            issue_codes=[IssueCode.PATCH_MISSING],
            vulnerabilities=[
                RawVulnerability(
                    cve_id="CVE-2024-3094",
                    cvss_score=9.8,
                    description="Critical RCE",
                    published_date=date(2025, 5, 1),
                    patch_released_date=date(2025, 5, 18),
                    patch_applied=False,
                )
            ],
        )
    ]
    findings = map_findings(records, rulebase)
    print(f"findings                : {len(findings)}")
    for f in findings:
        print(f"  {f.finding_id} [{f.rule_id}] {[fw.value for fw in f.frameworks_breached]}")


if __name__ == "__main__":  # pragma: no cover
    _self_check()
