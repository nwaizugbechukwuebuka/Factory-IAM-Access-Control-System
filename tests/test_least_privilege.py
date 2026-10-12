"""Tests for the IAM least-privilege findings engine."""

from pathlib import Path

import pytest

from src.detect_excessive_privileges import (
    detect_excessive_privileges,
    summarize_findings,
)
from src.load_data import load_iam_data

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"


@pytest.fixture
def datasets():
    """Load the synthetic factory IAM datasets."""
    return load_iam_data(DATA_DIR)


def test_detects_privileged_role_outside_it(datasets):
    """Non-IT users assigned privileged IT roles should be flagged."""
    findings = detect_excessive_privileges(datasets)

    matches = findings.loc[
        (findings["assignment_id"] == "A010") & (findings["rule_id"] == "LP001")
    ]

    assert len(matches) == 1
    assert matches.iloc[0]["severity"] == "Critical"


def test_detects_role_department_mismatch(datasets):
    """Roles inconsistent with the user's department should be flagged."""
    findings = detect_excessive_privileges(datasets)

    matches = findings.loc[
        (findings["assignment_id"] == "A014") & (findings["rule_id"] == "LP002")
    ]

    assert len(matches) == 1


def test_detects_cross_department_resource_access(datasets):
    """Unexpected role-to-resource access should be flagged."""
    findings = detect_excessive_privileges(datasets)

    matches = findings.loc[
        (findings["assignment_id"] == "A013") & (findings["rule_id"] == "LP003")
    ]

    assert len(matches) == 1


def test_detects_inactive_contractor_access(datasets):
    """Inactive contractor assignments should be flagged."""
    findings = detect_excessive_privileges(datasets)

    matches = findings.loc[
        (findings["assignment_id"] == "A008") & (findings["rule_id"] == "LP004")
    ]

    assert len(matches) == 1


def test_detects_disabled_account_access(datasets):
    """Disabled account assignments should be flagged."""
    findings = detect_excessive_privileges(datasets)

    matches = findings.loc[
        (findings["assignment_id"] == "A012") & (findings["rule_id"] == "LP004")
    ]

    assert len(matches) == 1


def test_legitimate_production_assignment_has_no_findings(datasets):
    """A compliant production assignment should not trigger these rules."""
    findings = detect_excessive_privileges(datasets)

    matches = findings.loc[findings["assignment_id"] == "A001"]

    assert matches.empty


def test_findings_have_required_fields(datasets):
    """Every finding must contain investigation and remediation details."""
    findings = detect_excessive_privileges(datasets)

    required_columns = {
        "finding_id",
        "rule_id",
        "severity",
        "user_id",
        "user_name",
        "assignment_id",
        "role_id",
        "role_name",
        "resource_id",
        "resource_name",
        "finding",
        "recommendation",
    }

    assert required_columns.issubset(findings.columns)

    if not findings.empty:
        assert findings["finding_id"].notna().all()
        assert findings["recommendation"].str.len().gt(0).all()


def test_finding_ids_are_unique(datasets):
    """Each rule-assignment pair should produce a unique finding ID."""
    findings = detect_excessive_privileges(datasets)

    assert findings["finding_id"].is_unique


def test_findings_are_sorted_by_severity(datasets):
    """Critical findings should appear before High findings."""
    findings = detect_excessive_privileges(datasets)

    if len(findings) > 1:
        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
        }

        actual_order = [severity_order[value] for value in findings["severity"]]

        assert actual_order == sorted(actual_order)


def test_summary_counts_findings(datasets):
    """Summary metrics should match the findings DataFrame."""
    findings = detect_excessive_privileges(datasets)
    summary = summarize_findings(findings)

    assert summary["total_findings"] == len(findings)
    assert summary["unique_affected_users"] == (findings["user_id"].nunique())
    assert sum(summary["severity_counts"].values()) == len(findings)


def test_missing_dataset_raises_error():
    """The engine should reject incomplete dataset collections."""
    with pytest.raises(ValueError, match="Missing required datasets"):
        detect_excessive_privileges({})
