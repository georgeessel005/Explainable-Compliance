# Unverified mappings — confirm before submission

**Status: ACTION REQUIRED BEFORE SUBMISSION.**
This file exists so that nothing in the rule base is passed off as sourced when it is not.
It addresses Risk Note (iii) — checking mappings against the framework documentation.

---

## The headline numbers

| | Count |
|---|---:|
| Intersections in George's full interim-report matrix (Appendix Ai/Aii) | **47** |
| **Verified** — transcribed from Appendix Aii, authoritative | **15** |
| **Unverified** — best-effort engineering inference, NOT sourced | **9** |
| Total currently in `rules/ce_iso_mappings.yaml` | **24** |
| **Still to be sourced by George to reach 47** | **23** |

Read that as: **15 of the 47 are verified. 9 more are guesses that I have flagged. 23 are
simply not in the rule base yet.**

The rule base was deliberately **not** padded out to 47. Inventing 32 ISO control mappings and
presenting them as sourced would be an academic-integrity failure, so the gap is left open and
visible. Closing it to 47 is George's job, against his own Appendix Ai/Aii.

The engine does not need 47 to run. It needs full `IssueCode` coverage, which it has: all 15
issue codes resolve to a rule, so Stage 2 never hits an unmapped issue.

### What "unverified" does and does not mean

- It does **not** mean wrong. Each one is a reasoned, defensible inference.
- It **does** mean *unsourced*. No one has checked it against the interim-report matrix or the
  ISO/IEC 27001:2022 Annex A text.
- Anything unverified must be confirmed, corrected, or deleted before submission. Do not cite
  any of it as sourced in the write-up until it appears in the verified table below.

---

## The 15 verified intersections (authoritative — do not edit)

Transcribed verbatim from Appendix Aii. `P` = Primary, `S` = Secondary.

| CE pillar | ISO control | Control name | Type | Trigger (issue code) |
|---|---|---|---|---|
| Patch Management | A.8.8 | Management of technical vulnerabilities | Primary | PATCH_MISSING |
| Patch Management | A.8.32 | Change management | Secondary | PATCH_MISSING, PATCH_RECORD_ABSENT |
| Secure Configuration | A.8.9 | Configuration management | Primary | DEFAULT_CREDENTIALS |
| Secure Configuration | A.8.27 | Secure system architecture | Secondary | INSECURE_PROTOCOL |
| User Access Control | A.5.15 | Access control | Primary | EXCESSIVE_PRIVILEGES |
| User Access Control | A.5.16 | Identity management | Secondary | STALE_ACCOUNT |
| User Access Control | A.5.17 | Authentication information | Primary | PASSWORD_POLICY_NONCOMPLIANCE |
| User Access Control | A.8.5 | Secure authentication | Primary | MFA_ABSENT |
| Firewalls | A.8.20 | Networks security | Primary | UNRESTRICTED_INBOUND |
| Firewalls | A.8.21 | Security of network services | Secondary | UNMANAGED_SERVICE_EXPOSED |
| Firewalls | A.8.22 | Segregation of networks | Secondary | FLAT_NETWORK |
| Malware Protection | A.8.7 | Protection against malware | Primary | AV_SIGNATURE_OUTDATED |
| Malware Protection | A.8.16 | Monitoring activities | Secondary | NO_EDR_INGESTION |
| CE+ Vulnerability Scan | A.8.8 | Management of technical vulnerabilities | Primary | AUTH_SCAN_FAILURE, PATCH_MISSING |
| CE+ Authenticated Audit | A.5.15 | Access control | Secondary | INSUFFICIENT_SCAN_CREDENTIALS |

**Note on the two rows that carry two triggers.** The 15 verified rows of Appendix Aii yield 15
distinct matrix cells, but two cells are each asserted by two different issue codes, and the two
assertions agree:

- `Patch Management × A.8.32 = Secondary` — from the PATCH_RECORD_ABSENT row *and* from the
  FINDING #017 card.
- `CE+ Vulnerability Scan × A.8.8 = Primary` — from the AUTH_SCAN_FAILURE row *and* from the
  FINDING #017 card.

That the two sources agree on both cells is a consistency check on the transcription, not a
contradiction.

### One transcription judgement worth George's eye

FINDING #017 lists four control mappings (CE Patch Management P, CE+ Vulnerability Scan P,
ISO A.8.8 P, ISO A.8.32 S) but does not state which CE row each ISO control hangs off. The rule
base reads it as:

- A.8.8 → **Patch Management** *and* **CE+ Vulnerability Scan** rows (the latter independently
  corroborated by the AUTH_SCAN_FAILURE row, so it is safe);
- A.8.32 → **Patch Management** row only (corroborated by the PATCH_RECORD_ABSENT row).

The cell this reading deliberately does **not** assert is `CE+ Vulnerability Scan × A.8.32`.
It would follow from a naive cross-product of the card's four mappings, but nothing in the source
states it, so it is absent rather than invented. **If Appendix Ai shows that cell populated,
add it.** This is the only place where the shape of the #017 card required interpretation.

---

## The 9 unverified intersections — confirm each

Every row below is also flagged inline in `rules/ce_iso_mappings.yaml` with:

```
# UNVERIFIED - confirm against George interim-report matrix (Appendix Ai/Aii)
```

All 9 are typed **Secondary**: where the source is silent, the rule base claims the weaker
relationship rather than the stronger one. No unverified mapping asserts Primary.

| # | CE pillar | ISO control | Control name | Type | Trigger | Rule | Confirmed? |
|---|---|---|---|---|---|---|:---:|
| U01 | CE+ Authenticated Audit | A.5.17 | Authentication information | Secondary | INSUFFICIENT_SCAN_CREDENTIALS | CEP-AUDIT-001 | ☐ |
| U02 | Secure Configuration | A.5.17 | Authentication information | Secondary | DEFAULT_CREDENTIALS | CE-SECCONF-001 | ☐ |
| U03 | Firewalls | A.8.9 | Configuration management | Secondary | UNMANAGED_SERVICE_EXPOSED | CE-FW-002 | ☐ |
| U04 | Patch Management | A.8.9 | Configuration management | Secondary | PATCH_RECORD_ABSENT | CE-PATCH-002 | ☐ |
| U05 | CE+ Vulnerability Scan | A.8.16 | Monitoring activities | Secondary | AUTH_SCAN_FAILURE | CEP-VULN-001 | ☐ |
| U06 | User Access Control | A.8.16 | Monitoring activities | Secondary | EXCESSIVE_PRIVILEGES | CE-UAC-001 | ☐ |
| U07 | Secure Configuration | A.8.20 | Networks security | Secondary | INSECURE_PROTOCOL | CE-SECCONF-002 | ☐ |
| U08 | Malware Protection | A.8.23 | Web filtering | Secondary | AV_SIGNATURE_OUTDATED | CE-MAL-001 | ☐ |
| U09 | Firewalls | A.8.27 | Secure system architecture | Secondary | FLAT_NETWORK | CE-FW-003 | ☐ |

### Reasoning behind each, so it can be argued with

- **U01 — CE+ Authenticated Audit × A.5.17.** Provisioning and rotating the scan account's
  credential is authentication-information handling. Reasonable; unsourced.
- **U02 — Secure Configuration × A.5.17.** A vendor default password is unmanaged authentication
  information, not only a configuration defect. Strong inference, but the verified row names only
  A.8.9.
- **U03 — Firewalls × A.8.9.** A service exposed with no owner has drifted outside the managed
  baseline. Moderate.
- **U04 — Patch Management × A.8.9.** Patch state forms part of the recorded baseline
  configuration of an asset. Moderate.
- **U05 — CE+ Vulnerability Scan × A.8.16.** A scan that fails silently is a gap in monitoring
  coverage. Moderate.
- **U06 — User Access Control × A.8.16.** A.8.16 requires privileged activity to be monitored;
  over-privileged accounts are exactly the population it covers. Moderate.
- **U07 — Secure Configuration × A.8.20.** Cleartext protocols expose credentials in transit,
  which is a networks-security concern as well as an architectural one. Reasonable.
- **U08 — Malware Protection × A.8.23.** ⚠ **Weakest inference in the file — check this one
  first.** A.8.23 (Web filtering) sits in the stated control universe but has **no verified row**,
  so it would otherwise be a dead column in the matrix. It is placed against Malware Protection on
  the argument that web filtering is a complementary malware-delivery control. The true home of
  A.8.23 in George's matrix is unknown and may well be Firewalls. **Do not cite this without
  checking.**
- **U09 — Firewalls × A.8.27.** The absence of segmentation is an architectural decision, so
  A.8.27 plausibly applies from the Firewalls row as well as from the verified Secure
  Configuration row. Moderate.

---

## Confirming a mapping

1. Find the intersection in Appendix Ai/Aii.
2. **If the source confirms it:** in `rules/ce_iso_mappings.yaml`, set `verified: true`, add
   `source: Appendix Aii` (or the precise reference), delete the `# UNVERIFIED` comment, and fix
   `mapping_type` if the source says Primary. Then move the row into the verified table above and
   delete it from the table below it.
3. **If the source contradicts it:** correct `mapping_type`, or delete the mapping entirely.
   Deleting is safe — coverage is guaranteed at the *issue code* level, not the intersection
   level, so removing a secondary mapping cannot leave an issue unmapped.
4. **If the source has intersections not present here:** add them as new mappings with
   `verified: true` and a `source`. This is how the count moves toward 47.
5. Re-run the checks below and update the headline numbers in this file.

The counts here are not hand-maintained — regenerate them rather than editing them by hand:

```bash
./.venv/Scripts/python.exe -c "from src.mapping.engine import load_rules, verification_report, unverified_intersections; load_rules(); print(verification_report()); [print(c['ce_pillar'], 'x', c['iso_control'], c['mapping_type'].value) for c in unverified_intersections()]"
```

`verification_report()` returns `verified`, `unverified`, `total_in_rulebase`, `target_total`
(47) and `still_to_source`. The Streamlit heatmap surfaces the same split, and
`build_matrix(rulebase, verified_only=True)` renders only the 15 sourced cells if the write-up
needs a figure containing nothing but verified data.

---

## Scope guarantees the rule base enforces in code

- **Closed control universe.** `load_rules()` raises `RuleBaseError` if any rule references an ISO
  control outside `A.5.15, A.5.16, A.5.17, A.8.5, A.8.7, A.8.8, A.8.9, A.8.16, A.8.20, A.8.21,
  A.8.22, A.8.23, A.8.27, A.8.32`. A stray control cannot enter the matrix unnoticed.
- **Verified always wins.** If a best-effort mapping ever restates a sourced cell, the sourced
  assertion takes precedence, including its `mapping_type`. An unverified mapping cannot silently
  downgrade or overwrite an Appendix Aii cell.
- **Full issue coverage.** `unmapped_issue_codes(rulebase)` returns `[]` — all 15 `IssueCode`
  members resolve to a rule.
- **Blank ≠ unverified.** An empty heatmap cell means *not mapped at all*. Unverified mappings are
  rendered normally and are distinguished only here and in the YAML — the heatmap is not a guide
  to what is sourced. Use `verified_only=True` for that.

---

*Generated by Agent 2 (mapping engine) from `rules/ce_iso_mappings.yaml`. The 15 verified rows are
transcribed from George's Appendix Aii and must not be altered by any agent or tool.*
