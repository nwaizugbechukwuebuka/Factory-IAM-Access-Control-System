"""Tests for IAM data loading and validation."""

from pathlib import Path

import pandas as pd
import pytest

from src.load_data import load_iam_data, validate_iam_data


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"


def test_loads_all_five_datasets():
    """All expected IAM CSV files should load successfully."""
    datasets = load_iam_data(DATA_DIR)

    assert set(datasets) == {
        "users",
        "roles",
        "resources",
        "access_assignments",
        "access_reviews",
    }


def test_datasets_contain_records():
    """Each dataset should contain at least one record."""
    datasets = load_iam_data(DATA_DIR)

    for name, dataframe in datasets.items():
        assert not dataframe.empty, f"{name} dataset is empty"


def test_provided_datasets_pass_validation():
    """The original synthetic datasets should satisfy integrity checks."""
    datasets = load_iam_data(DATA_DIR)

    assert validate_iam_data(datasets) == []


def test_missing_file_raises_error(tmp_path):
    """Missing CSV files should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_iam_data(tmp_path)


def test_duplicate_user_ids_are_detected():
    """Duplicate user identifiers should produce a validation error."""
    datasets = load_iam_data(DATA_DIR)

    datasets["users"] = pd.concat(
        [
            datasets["users"],
            datasets["users"].iloc[[0]],
        ],
        ignore_index=True,
    )

    errors = validate_iam_data(datasets)

    assert any("duplicate user_id" in error for error in errors)


def test_unknown_user_reference_is_detected():
    """Assignments referencing nonexistent users should fail validation."""
    datasets = load_iam_data(DATA_DIR)
    datasets["access_assignments"].loc[0, "user_id"] = "U999"

    errors = validate_iam_data(datasets)

    assert any("unknown user_id 'U999'" in error for error in errors)


def test_invalid_boolean_value_is_detected():
    """Boolean fields must contain true or false."""
    datasets = load_iam_data(DATA_DIR)
    datasets["users"].loc[0, "mfa_enabled"] = "sometimes"

    errors = validate_iam_data(datasets)

    assert any("invalid Boolean value" in error for error in errors)


def test_invalid_date_is_detected():
    """Date fields must use the YYYY-MM-DD format."""
    datasets = load_iam_data(DATA_DIR)
    datasets["users"].loc[0, "last_login"] = "not-a-date"

    errors = validate_iam_data(datasets)

    assert any("invalid date" in error for error in errors)


def test_missing_required_column_is_detected():
    """Required columns cannot be removed silently."""
    datasets = load_iam_data(DATA_DIR)
    datasets["users"] = datasets["users"].drop(columns=["department"])

    errors = validate_iam_data(datasets)

    assert any(
        "missing required column 'department'" in error
        for error in errors
    )


def test_duplicate_assignment_ids_are_detected():
    """Access assignment IDs must be unique."""
    datasets = load_iam_data(DATA_DIR)

    datasets["access_assignments"] = pd.concat(
        [
            datasets["access_assignments"],
            datasets["access_assignments"].iloc[[0]],
        ],
        ignore_index=True,
    )

    errors = validate_iam_data(datasets)

    assert any(
        "duplicate assignment_id" in error
        for error in errors
    )