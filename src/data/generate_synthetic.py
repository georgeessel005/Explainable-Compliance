"""
generate_synthetic.py  -  Synthetic enterprise asset dataset generator (Agent 1).

Produces mock security-scan records shaped like `AssetRecord` (src/models.py), plus a
small number of intentionally malformed records so Stage 1 rejection is demonstrable.

DETERMINISM CONTRACT
--------------------
The evaluation (Functional Correctness) and the Stage 5 report hash both depend on
identical input producing identical output, so this module is strictly reproducible:

* Randomness comes from a seeded `random.Random(seed)` instance. The global `random`
  module state is never touched.
* No date in the output is derived from `date.today()` / `datetime.now()`. Every date is
  offset from the fixed `BASE_ASSESSMENT_DATE` anchor below, so a run tomorrow produces
  byte-identical output to a run today, and the FINDING #017 reference case (patch
  released exactly 14 days before `assessment_date`) holds forever.

`generate()` is a pure function: it returns the records and writes nothing. `main()` is
the only writer, and the only place that prints.
"""
from __future__ import annotations

import json
import random
from datetime import date, timedelta
from pathlib import Path

from src.models import IssueCode, Severity

# ----------------------------------------------------------------------------------
# Fixed anchors  (never date.today() - see the determinism contract above)
# ----------------------------------------------------------------------------------

#: Every assessment_date in the dataset is this date minus a small deterministic offset.
BASE_ASSESSMENT_DATE = date(2025, 6, 30)

#: FINDING #017 reference case constants (blueprint Section 7).
REFERENCE_CVSS = 9.8
REFERENCE_PATCH_AGE_DAYS = 14
#: Reference assets sit at every Nth index so the case is reproduced several times.
REFERENCE_EVERY = 15
REFERENCE_OFFSET = 2

#: Repo root resolved from this file, so main() writes to the same path regardless of CWD.
#: src/data/generate_synthetic.py -> parents[2] == repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = _REPO_ROOT / "data" / "synthetic" / "assets.json"

ALL_ISSUE_CODES: list[IssueCode] = list(IssueCode)

SITES = ["lon", "man", "gla", "bri", "lee", "ncl"]
ROLES = ["web", "app", "db", "dc", "file", "mail", "vpn", "jump", "build", "print"]

#: Non-reference operating systems. Reference assets are always Ubuntu (see _make_reference_asset).
OS_CHOICES = [
    "Ubuntu 22.04 LTS",
    "Ubuntu 20.04 LTS",
    "Windows Server 2019",
    "Windows Server 2022",
    "Windows Server 2016",
    "RHEL 9.3",
    "RHEL 8.9",
    "Debian 12",
    "Windows 11 Pro 23H2",
    "Windows 10 Pro 22H2",
    "Amazon Linux 2023",
    "SUSE Linux Enterprise 15 SP5",
]

ENVIRONMENTS = ["production", "staging", "development", "test", "dr"]
ENVIRONMENT_WEIGHTS = [55, 15, 15, 10, 5]

CRITICALITIES = [
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]
CRITICALITY_WEIGHTS = [20, 40, 28, 12]

VULN_DESCRIPTIONS = [
    "Remote code execution in the HTTP request parser allows an unauthenticated attacker to execute arbitrary code.",
    "Heap-based buffer overflow in the TLS handshake routine leads to memory corruption.",
    "Improper authentication check permits session tokens to be reused after logout.",
    "Deserialisation of untrusted data allows arbitrary object instantiation.",
    "Path traversal in the file upload handler exposes files outside the web root.",
    "SQL injection in a reporting endpoint allows extraction of database contents.",
    "Privilege escalation via an unquoted service path in the installer.",
    "Cross-site scripting in the administrative console allows script injection.",
    "Information disclosure in verbose error responses reveals internal host names.",
    "Denial of service via unbounded resource allocation in the connection handler.",
    "Use-after-free in the image decoding library triggered by a crafted file.",
    "Missing bounds check in the SMB request handler permits out-of-bounds read.",
]

REFERENCE_VULN_DESCRIPTION = (
    "Remote code execution in an internet-facing service allows an unauthenticated "
    "attacker to execute arbitrary code with elevated privileges."
)


def _is_reference_index(index: int) -> bool:
    """Whether the asset at `index` is a FINDING #017 reference asset.

    Single source of truth for the placement rule: generate() builds against it and
    _assert_invariants() checks against it.
    """
    return index % REFERENCE_EVERY == REFERENCE_OFFSET


def _asset_index(asset_id: str) -> int:
    """Recover the generation index from an asset_id ("AST-0002" -> 2)."""
    return int(asset_id.split("-")[1])


def _vector_for(score: float) -> str:
    """A representative CVSS 3.1 vector for the score's severity band."""
    if score >= 9.0:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if score >= 7.0:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    if score >= 4.0:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
    return "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"


def _make_vulnerability(
    rng: random.Random,
    assessment_date: date,
    *,
    max_score: float = 8.8,
    force_unpatched: bool = False,
) -> dict:
    """One plausible RawVulnerability-shaped dict.

    `max_score` caps the CVSS so callers can guarantee the reference 9.8 CVE stays the
    highest-scoring unpatched vulnerability on a reference asset (Stage 2 selects the
    triggering CVE for PATCH_MISSING by highest CVSS among unpatched vulns).
    """
    score = round(rng.uniform(2.0, max_score), 1)
    published_date = assessment_date - timedelta(days=rng.randint(30, 900))
    cve_id = f"CVE-{published_date.year}-{rng.randint(1000, 99999)}"

    # Some vendors have not shipped a fix yet; those carry no patch_released_date.
    if not force_unpatched and rng.random() < 0.15:
        patch_released_date: date | None = None
        patch_applied = False
    else:
        # Clamp to the day BEFORE assessment_date, never assessment_date itself: a patch
        # released on the assessment day yields days_since_patch()==0, which reads as
        # "the vendor patch was released 0 days ago" in Stage 3 prose. published_date is
        # always >=30 days before assessment_date, so this can never precede publication.
        patch_released_date = min(
            published_date + timedelta(days=rng.randint(0, 45)),
            assessment_date - timedelta(days=1),
        )
        patch_applied = False if force_unpatched else rng.random() < 0.55

    vuln: dict = {
        "cve_id": cve_id,
        "cvss_score": score,
        "cvss_vector": _vector_for(score),
        "description": rng.choice(VULN_DESCRIPTIONS),
        "published_date": published_date.isoformat(),
        "patch_released_date": patch_released_date.isoformat() if patch_released_date else None,
        "patch_applied": patch_applied,
    }
    return vuln


def _pick_issue_codes(rng: random.Random, index: int, *, forced: IssueCode | None = None) -> list[IssueCode]:
    """A deterministic mix of issue codes.

    Round-robins a guaranteed code by index so that across a default run every member of
    the IssueCode enum appears at least once and the Stage 2 engine sees full coverage.
    """
    codes: list[IssueCode] = []
    if forced is not None:
        codes.append(forced)

    guaranteed = ALL_ISSUE_CODES[index % len(ALL_ISSUE_CODES)]
    if guaranteed not in codes:
        codes.append(guaranteed)

    for extra in rng.sample(ALL_ISSUE_CODES, rng.randint(0, 3)):
        if extra not in codes:
            codes.append(extra)

    # Stable, enum-declaration order so the output is reproducible.
    return sorted(codes, key=ALL_ISSUE_CODES.index)


def _make_reference_asset(rng: random.Random, index: int) -> dict:
    """The FINDING #017 reference case (blueprint Section 7).

    Internet-facing Ubuntu host, critical CVE at CVSS 9.8, vendor patch released exactly
    14 days before this asset's assessment_date, patch_applied False, PATCH_MISSING among
    the issue codes. The rest of the pipeline is validated against this scenario, so the
    shape here is deliberate rather than random.
    """
    assessment_date = BASE_ASSESSMENT_DATE - timedelta(days=rng.randint(0, 5))
    patch_released_date = assessment_date - timedelta(days=REFERENCE_PATCH_AGE_DAYS)
    published_date = patch_released_date - timedelta(days=7)

    reference_vuln = {
        "cve_id": f"CVE-{published_date.year}-{21000 + index}",
        "cvss_score": REFERENCE_CVSS,
        "cvss_vector": _vector_for(REFERENCE_CVSS),
        "description": REFERENCE_VULN_DESCRIPTION,
        "published_date": published_date.isoformat(),
        "patch_released_date": patch_released_date.isoformat(),
        "patch_applied": False,
    }

    # Extra noise vulns are capped below 9.8 so the reference CVE remains the highest
    # -scoring unpatched vulnerability, which is what Stage 2 keys PATCH_MISSING on.
    vulns = [reference_vuln]
    for _ in range(rng.randint(0, 2)):
        vulns.append(_make_vulnerability(rng, assessment_date, max_score=8.8))

    site = rng.choice(SITES)
    return {
        "asset_id": f"AST-{index:04d}",
        "hostname": f"{site}-web-{index:03d}",
        "operating_system": rng.choice(["Ubuntu 22.04 LTS", "Ubuntu 20.04 LTS"]),
        "ip_address": f"203.0.113.{rng.randint(2, 254)}",
        "internet_facing": True,
        "environment": "production",
        "criticality": rng.choice([Severity.HIGH, Severity.CRITICAL]).value,
        "assessment_date": assessment_date.isoformat(),
        "issue_codes": [c.value for c in _pick_issue_codes(rng, index, forced=IssueCode.PATCH_MISSING)],
        "vulnerabilities": vulns,
    }


def _make_asset(rng: random.Random, index: int) -> dict:
    """One ordinary (valid) asset record."""
    assessment_date = BASE_ASSESSMENT_DATE - timedelta(days=rng.randint(0, 5))
    internet_facing = rng.random() < 0.28
    codes = _pick_issue_codes(rng, index)

    vulns = [_make_vulnerability(rng, assessment_date) for _ in range(rng.randint(0, 3))]

    # PATCH_RECORD_ABSENT means the patch history for that vulnerability is unknown, so
    # it blanks patch_released_date. It MUST run before the PATCH_MISSING guard below:
    # ordered the other way round it clobbers the dated unpatched vuln that guard just
    # guaranteed, and an asset carrying both codes ends up with no patch date for Stage 2
    # to select (Stage 3 then renders "the vendor patch was released None days ago").
    if IssueCode.PATCH_RECORD_ABSENT in codes and vulns:
        vulns[0]["patch_released_date"] = None
        vulns[0]["patch_applied"] = False

    # Keep the record internally coherent: PATCH_MISSING means a vendor patch has been
    # available for N days and was not applied, so every asset emitting it must carry at
    # least one unpatched vulnerability with a patch_released_date set. Stage 2 selects
    # the triggering CVE from these; Stage 3 renders {days} from days_since_patch().
    if IssueCode.PATCH_MISSING in codes and not any(
        v["patch_released_date"] is not None and not v["patch_applied"] for v in vulns
    ):
        vulns.append(_make_vulnerability(rng, assessment_date, force_unpatched=True))

    site = rng.choice(SITES)
    role = rng.choice(ROLES)
    if internet_facing:
        ip = f"203.0.113.{rng.randint(2, 254)}"
    else:
        ip = f"10.{rng.randint(0, 40)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"

    return {
        "asset_id": f"AST-{index:04d}",
        "hostname": f"{site}-{role}-{index:03d}",
        "operating_system": rng.choice(OS_CHOICES),
        "ip_address": ip,
        "internet_facing": internet_facing,
        "environment": rng.choices(ENVIRONMENTS, weights=ENVIRONMENT_WEIGHTS, k=1)[0],
        "criticality": rng.choices(CRITICALITIES, weights=CRITICALITY_WEIGHTS, k=1)[0].value,
        "assessment_date": assessment_date.isoformat(),
        "issue_codes": [c.value for c in codes],
        "vulnerabilities": vulns,
    }


def _malformed_records() -> list[dict]:
    """Intentionally invalid records, one per Stage 1 rejection path.

    These ship in the SAME assets.json as the valid records: the loader must reject each
    one with a useful reason and carry on. Note AssetRecord and RawVulnerability both use
    `extra="forbid"`, so an unexpected key is a rejection path in its own right.
    """
    day = BASE_ASSESSMENT_DATE.isoformat()

    def _ok_vuln(**overrides) -> dict:
        base = {
            "cve_id": "CVE-2024-31210",
            "cvss_score": 7.5,
            "cvss_vector": _vector_for(7.5),
            "description": "Placeholder vulnerability for a deliberately malformed record.",
            "published_date": (BASE_ASSESSMENT_DATE - timedelta(days=40)).isoformat(),
            "patch_released_date": (BASE_ASSESSMENT_DATE - timedelta(days=20)).isoformat(),
            "patch_applied": False,
        }
        base.update(overrides)
        return base

    return [
        # 1. Malformed CVE identifier -> RawVulnerability.cve_id pattern violation.
        {
            "asset_id": "AST-9001",
            "hostname": "lon-web-901",
            "operating_system": "Ubuntu 22.04 LTS",
            "ip_address": "203.0.113.201",
            "internet_facing": True,
            "environment": "production",
            "criticality": "High",
            "assessment_date": day,
            "issue_codes": ["PATCH_MISSING"],
            "vulnerabilities": [_ok_vuln(cve_id="CVE-24-ABCDE")],
        },
        # 2. CVSS score above the 0..10 range -> cvss_score le=10 violation.
        {
            "asset_id": "AST-9002",
            "hostname": "man-db-902",
            "operating_system": "Windows Server 2019",
            "ip_address": "10.20.4.90",
            "internet_facing": False,
            "environment": "production",
            "criticality": "Critical",
            "assessment_date": day,
            "issue_codes": ["PATCH_MISSING"],
            "vulnerabilities": [_ok_vuln(cvss_score=11.5)],
        },
        # 3. Issue code outside the IssueCode enum -> enum membership violation.
        {
            "asset_id": "AST-9003",
            "hostname": "gla-app-903",
            "operating_system": "RHEL 9.3",
            "ip_address": "10.11.7.35",
            "internet_facing": False,
            "environment": "staging",
            "criticality": "Medium",
            "assessment_date": day,
            "issue_codes": ["PATCH_MISSING", "ROGUE_ISSUE_CODE"],
            "vulnerabilities": [],
        },
        # 4. Missing a required field (hostname) -> missing violation.
        {
            "asset_id": "AST-9004",
            "operating_system": "Debian 12",
            "ip_address": "10.12.9.44",
            "internet_facing": False,
            "environment": "development",
            "criticality": "Low",
            "assessment_date": day,
            "issue_codes": ["STALE_ACCOUNT"],
            "vulnerabilities": [],
        },
        # 5. Unexpected key on the asset -> AssetRecord extra="forbid" violation.
        {
            "asset_id": "AST-9005",
            "hostname": "bri-file-905",
            "operating_system": "Windows Server 2022",
            "ip_address": "10.14.2.18",
            "internet_facing": False,
            "environment": "production",
            "criticality": "Medium",
            "assessment_date": day,
            "issue_codes": ["MFA_ABSENT"],
            "vulnerabilities": [],
            "owner_team": "Infrastructure",
        },
        # 6. Unexpected key on the vulnerability -> RawVulnerability extra="forbid" violation.
        {
            "asset_id": "AST-9006",
            "hostname": "lee-mail-906",
            "operating_system": "Ubuntu 20.04 LTS",
            "ip_address": "203.0.113.202",
            "internet_facing": True,
            "environment": "production",
            "criticality": "High",
            "assessment_date": day,
            "issue_codes": ["INSECURE_PROTOCOL"],
            "vulnerabilities": [_ok_vuln(exploit_available=True)],
        },
        # 7. Unparseable assessment_date -> date parsing violation.
        {
            "asset_id": "AST-9007",
            "hostname": "ncl-jump-907",
            "operating_system": "Windows Server 2016",
            "ip_address": "10.19.6.7",
            "internet_facing": False,
            "environment": "dr",
            "criticality": "Medium",
            "assessment_date": "31/06/2025",
            "issue_codes": ["EXCESSIVE_PRIVILEGES"],
            "vulnerabilities": [],
        },
    ]


def _dated_unpatched(record: dict) -> list[dict]:
    """Vulns on `record` with a vendor patch released strictly before assessment_date and
    not applied. This is the set Stage 2 selects the PATCH_MISSING triggering CVE from."""
    assessment_date = date.fromisoformat(record["assessment_date"])
    return [
        v
        for v in record["vulnerabilities"]
        if v["patch_released_date"] is not None
        and not v["patch_applied"]
        and date.fromisoformat(v["patch_released_date"]) < assessment_date
    ]


def _assert_invariants(records: list[dict]) -> None:
    """Enforce the semantic invariants the rest of the pipeline relies on.

    Runs over the VALID records only (the malformed fixtures are exempt by construction).
    Raises rather than asserts so the guarantee survives `python -O`.
    """
    for record in records:
        codes = record["issue_codes"]

        # PATCH_MISSING entails "a vendor patch has been available for N days and was not
        # applied", so there must be something for Stage 2 to select and a real {days}
        # for Stage 3 to render.
        if IssueCode.PATCH_MISSING.value in codes and not _dated_unpatched(record):
            raise AssertionError(
                f"{record['asset_id']} emits PATCH_MISSING but has no unpatched "
                f"vulnerability with a patch_released_date strictly before "
                f"assessment_date ({record['assessment_date']})."
            )

        # FINDING #017 reference assets are what the rest of the pipeline is validated
        # against; their load-bearing fields are not allowed to drift.
        if _is_reference_index(_asset_index(record["asset_id"])):
            assessment_date = date.fromisoformat(record["assessment_date"])
            candidates = _dated_unpatched(record)
            top = max(candidates, key=lambda v: v["cvss_score"])
            if top["cvss_score"] != REFERENCE_CVSS:
                raise AssertionError(
                    f"{record['asset_id']}: reference CVE must be the highest-CVSS dated "
                    f"unpatched vuln, but Stage 2 would select {top['cve_id']} "
                    f"@ {top['cvss_score']}."
                )
            if [v["cvss_score"] for v in candidates].count(REFERENCE_CVSS) != 1:
                raise AssertionError(
                    f"{record['asset_id']}: reference CVSS {REFERENCE_CVSS} must be the "
                    f"STRICT maximum (tie makes Stage 2's selection ambiguous)."
                )
            days = (assessment_date - date.fromisoformat(top["patch_released_date"])).days
            if days != REFERENCE_PATCH_AGE_DAYS:
                raise AssertionError(
                    f"{record['asset_id']}: reference patch age must be exactly "
                    f"{REFERENCE_PATCH_AGE_DAYS} days, got {days}."
                )
            if not (record["internet_facing"] and "Ubuntu" in record["operating_system"]):
                raise AssertionError(
                    f"{record['asset_id']}: reference asset must be an internet-facing "
                    f"Ubuntu host, got internet_facing={record['internet_facing']} "
                    f"os={record['operating_system']!r}."
                )
            if IssueCode.PATCH_MISSING.value not in codes:
                raise AssertionError(
                    f"{record['asset_id']}: reference asset must emit PATCH_MISSING."
                )


#: Number of canonical malformed fixtures in `_malformed_records()`. `malformed` is
#: clamped to 0..MAX_MALFORMED, and selects the FIRST N of them.
MAX_MALFORMED = 7


def generate(n: int = 120, seed: int = 42, malformed: int = 7) -> list[dict]:
    """Build the synthetic dataset.

    Args:
        n: number of VALID asset records to produce. The intentionally malformed records
           are additional, so the returned list is longer than `n`.
        seed: seed for the local `random.Random` instance. The same seed always yields a
              byte-identical result.
        malformed: how many of the canonical malformed fixtures to interleave, taken as
              the FIRST N of `_malformed_records()` and clamped to 0..MAX_MALFORMED.
              `malformed=0` yields a wholly clean dataset (zero Stage 1 rejections).

    Returns:
        A list of plain JSON-serialisable dicts: `n` valid AssetRecord-shaped records with
        the malformed records interleaved at deterministic positions (interleaved rather
        than appended so that Stage 1 is shown recovering mid-stream).

    Determinism: the malformed fixtures are drawn in fixed order and inserted at positions
    computed from `n` and the fixture count, never from `rng`, so varying `malformed` does
    not perturb the valid records at all and `generate()` on the default arguments is
    byte-identical to every previous run.

    Pure: writes nothing. `main()` is the only writer.
    """
    rng = random.Random(seed)

    records: list[dict] = []
    for index in range(n):
        if _is_reference_index(index):
            records.append(_make_reference_asset(rng, index))
        else:
            records.append(_make_asset(rng, index))

    # Check the semantic invariants while the set is still all-valid: the malformed
    # fixtures below are deliberately inconsistent and are exempt by construction.
    _assert_invariants(records)

    # Interleave the bad records at fixed, evenly spread positions. Positions are computed
    # from n rather than drawn from rng, so they do not perturb the valid records at all.
    # The stride divides by the CHOSEN fixture count, so fewer malformed records spread
    # just as evenly across whatever n was asked for.
    count = max(0, min(MAX_MALFORMED, int(malformed)))
    bad_records = _malformed_records()[:count]
    if bad_records:
        stride = max(1, len(records) // (len(bad_records) + 1))
        for offset, bad in enumerate(bad_records):
            position = min(len(records), stride * (offset + 1) + offset)
            records.insert(position, bad)

    return records


def write_dataset(records: list[dict], path: str | Path = DATA_PATH) -> str:
    """Write `records` to `path` as JSON. Returns the path written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps the bytes (and therefore any hash of them) identical on Windows.
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(records, fh, indent=2)
        fh.write("\n")
    return str(target)


def main(n: int = 120, seed: int = 42, malformed: int = 7) -> None:
    """Generate the dataset and write it to data/synthetic/assets.json.

    Arguments mirror :func:`generate`; the defaults reproduce the frozen dataset the
    test suite pins by SHA-256.
    """
    records = generate(n=n, seed=seed, malformed=malformed)
    written = write_dataset(records)

    valid = sum(1 for r in records if str(r.get("asset_id", "")) < "AST-9000")
    print(f"Wrote {len(records)} records to {written}")
    print(f"  intended-valid:     {valid}")
    print(f"  intended-malformed: {len(records) - valid}")


if __name__ == "__main__":
    main()
