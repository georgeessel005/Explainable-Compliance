"""
conftest.py  -  Shared fixtures for the Agent 5 end-to-end pytest suite.

The expensive pipeline artefacts (ingestion result, rule base, findings, explanations)
are built once per session and shared read-only. Tests that need to MUTATE any of these
(the report and end-to-end tests mutate explanations and decisions) must take deep
copies -- the fixtures themselves are canonical and shared.

Ground truth being asserted against (verified independently before this suite was
written):

* data/synthetic/assets.json: 127 records = 120 valid + 7 deliberately malformed,
  interleaved mid-stream (not appended).
* 15 rules, full IssueCode coverage, 309 findings from the 120 valid records.
* Matrix: 7 CE pillars x 14 ISO controls, cells "P"/"S"/"".
* Two DISTINCT digests by design: report.sha256_hash is the PDF *file* digest;
  the PDF footer carries content_digest(report), the canonical committed-content
  digest. A file cannot contain its own hash.

No src/ file was patched by the tester: every behaviour asserted here passed against
the integrated build as delivered.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.explain.explainer import explain  # noqa: E402
from src.ingestion.loader import load_and_validate  # noqa: E402
from src.mapping.engine import load_rules, map_findings  # noqa: E402

DATA_PATH = REPO_ROOT / "data" / "synthetic" / "assets.json"
RULES_DIR = REPO_ROOT / "rules"

#: SHA-256 of the frozen synthetic dataset (Agent 1 output, seed=42). Pinned so a
#: silent regeneration with different content fails loudly here rather than skewing
#: every downstream count.
ASSETS_JSON_SHA256 = "f0297ba4a964fa12d46515daa8d0737323ce2b3f6ff3ab5d1298d2a470d7b2e0"

#: The 8 FINDING #017 reference assets (index % 15 == 2 across 120 valid records).
REFERENCE_ASSET_IDS = [
    "AST-0002", "AST-0017", "AST-0032", "AST-0047",
    "AST-0062", "AST-0077", "AST-0092", "AST-0107",
]


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: full-app AppTest flows (seconds, not milliseconds)"
    )


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def data_path() -> str:
    assert DATA_PATH.is_file(), (
        f"Synthetic dataset missing at {DATA_PATH}. Generate it with "
        "./.venv/Scripts/python.exe -m src.data.generate_synthetic"
    )
    return str(DATA_PATH)


@pytest.fixture(scope="session")
def ingestion(data_path):
    """Stage 1 output for the whole suite."""
    return load_and_validate(data_path)


@pytest.fixture(scope="session")
def rulebase():
    """Stage 2 rule base, loaded once."""
    return load_rules(str(RULES_DIR))


@pytest.fixture(scope="session")
def findings(ingestion, rulebase):
    """Stage 2 output for the whole suite. Treat as read-only."""
    return map_findings(ingestion.valid_records, rulebase)


@pytest.fixture(scope="session")
def findings_by_id(findings):
    return {f.finding_id: f for f in findings}


@pytest.fixture(scope="session")
def explanations(findings, rulebase):
    """Stage 3 output for the whole suite. Treat as read-only: deep-copy to mutate."""
    return [explain(f, rulebase=rulebase) for f in findings]
