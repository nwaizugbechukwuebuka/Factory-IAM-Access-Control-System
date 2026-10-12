"""Tests for factory IAM access-control decisions."""

from pathlib import Path

import pytest

from src.load_data import load_iam_data
from src.validate_access import (
    evaluate_access_assignment,
    evaluate_all_assignments,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"


@pytest.fixture
def datasets():
    """Load the synthetic factory IAM datasets."""
    return load_iam_data(DATA_DIR)


def get_assignment(datasets, assignment_id):
    """Retrieve an assignment by its identifier."""
    assignments = datasets["access_assignments"]

    match = assignments.loc[assignments["assignment_id"] == assignment_id]

    assert len(match) == 1

    return match.iloc[0].to_dict()


def test_active_user_with_mfa_is_allowed(datasets):
    """A compliant user should receive access."""
    assignment = get_assignment(datasets, "A001")

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "ALLOW"
    assert result["reasons"] == []


def test_inactive_user_is_denied(datasets):
    """An inactive contractor must not receive access."""
    assignment = get_assignment(datasets, "A008")

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any(
        "employment status is not active" in reason for reason in result["reasons"]
    )


def test_disabled_account_is_denied(datasets):
    """Disabled accounts must not receive access."""
    assignment = get_assignment(datasets, "A012")

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any("account is disabled" in reason for reason in result["reasons"])


def test_missing_mfa_is_denied_for_protected_resource(datasets):
    """Resources requiring MFA must reject users without MFA."""
    assignment = get_assignment(datasets, "A011")

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any("MFA is required" in reason for reason in result["reasons"])


def test_unknown_user_is_denied(datasets):
    """An assignment cannot grant access to an unknown user."""
    assignment = get_assignment(datasets, "A001")
    assignment["user_id"] = "U999"

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any("User does not exist" in reason for reason in result["reasons"])


def test_unknown_role_is_denied(datasets):
    """An assignment cannot reference an unknown role."""
    assignment = get_assignment(datasets, "A001")
    assignment["role_id"] = "R999"

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any("Role does not exist" in reason for reason in result["reasons"])


def test_unknown_resource_is_denied(datasets):
    """An assignment cannot reference an unknown resource."""
    assignment = get_assignment(datasets, "A001")
    assignment["resource_id"] = "RES999"

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any("Resource does not exist" in reason for reason in result["reasons"])


def test_missing_security_fields_are_denied(datasets):
    """Incomplete identity security information must fail closed."""
    assignment = get_assignment(datasets, "A001")

    datasets["users"] = datasets["users"].drop(columns=["account_enabled"])

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any(
        "security fields are incomplete" in reason for reason in result["reasons"]
    )


def test_invalid_mfa_value_is_denied(datasets):
    """Unrecognized MFA values must not produce an access grant."""
    assignment = get_assignment(datasets, "A001")

    datasets["users"].loc[
        datasets["users"]["user_id"] == "U001",
        "mfa_enabled",
    ] = "unknown"

    result = evaluate_access_assignment(assignment, datasets)

    assert result["decision"] == "DENY"
    assert any("MFA status is invalid" in reason for reason in result["reasons"])


def test_all_assignments_produce_decisions(datasets):
    """Every assignment must receive an explicit decision."""
    results = evaluate_all_assignments(datasets)

    assert len(results) == len(datasets["access_assignments"])
    assert set(results["decision"]).issubset({"ALLOW", "DENY"})


def test_missing_assignment_dataset_raises_error():
    """Batch evaluation requires an access assignment dataset."""
    with pytest.raises(ValueError, match="access_assignments"):
        evaluate_all_assignments({})
