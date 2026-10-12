"""Tests for IAM access-review evaluation."""

from pathlib import Path

import pytest

from src.load_data import load_iam_data
from src.review_access import (
    evaluate_access_reviews,
    summarize_access_reviews,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"


@pytest.fixture
def datasets():
    """Load the synthetic IAM datasets."""
    return load_iam_data(DATA_DIR)


@pytest.fixture
def review_results(datasets):
    """Evaluate access reviews using a fixed evaluation date."""
    return evaluate_access_reviews(
        datasets,
        as_of_date="2026-10-12",
    )


def test_all_assignments_receive_review_outcomes(review_results, datasets):
    """Every assignment should receive a review result."""
    assert len(review_results) == len(datasets["access_assignments"])


def test_approved_review_recommends_retain(review_results):
    """A valid approved review should recommend retaining access."""
    result = review_results.loc[review_results["assignment_id"] == "A001"].iloc[0]

    assert result["review_status"] == "Approved"
    assert result["recommendation"] == "RETAIN"


def test_revoked_review_recommends_revoke(review_results):
    """A revoked review should recommend removing access."""
    result = review_results.loc[review_results["assignment_id"] == "A008"].iloc[0]

    assert result["review_status"] == "Lifecycle Violation"
    assert result["recommendation"] == "REVOKE"


def test_pending_review_requires_review(review_results):
    """A pending review should not automatically retain access."""
    result = review_results.loc[review_results["assignment_id"] == "A010"].iloc[0]

    assert result["review_status"] == "Pending"
    assert result["recommendation"] == "REVIEW"


def test_disabled_account_recommends_revoke(review_results):
    """Disabled accounts should be flagged regardless of review status."""
    result = review_results.loc[review_results["assignment_id"] == "A012"].iloc[0]

    assert result["review_status"] == "Lifecycle Violation"
    assert result["recommendation"] == "REVOKE"


def test_unreviewed_assignment_requires_review(datasets):
    """Assignments without review records should be flagged."""
    datasets["access_reviews"] = datasets["access_reviews"].loc[
        datasets["access_reviews"]["assignment_id"] != "A001"
    ]

    results = evaluate_access_reviews(
        datasets,
        as_of_date="2026-10-12",
    )

    result = results.loc[results["assignment_id"] == "A001"].iloc[0]

    assert result["review_status"] == "Not Reviewed"
    assert result["recommendation"] == "REVIEW"


def test_latest_review_decision_is_used(datasets):
    """The latest review should take precedence over older decisions."""
    additional_review = {
        "review_id": "REV099",
        "assignment_id": "A001",
        "reviewer_id": "U008",
        "review_date": "2026-10-01",
        "decision": "Revoked",
        "justification": "Access is no longer required.",
    }

    import pandas as pd

    datasets["access_reviews"] = pd.concat(
        [
            datasets["access_reviews"],
            pd.DataFrame([additional_review]),
        ],
        ignore_index=True,
    )

    results = evaluate_access_reviews(
        datasets,
        as_of_date="2026-10-12",
    )

    result = results.loc[results["assignment_id"] == "A001"].iloc[0]

    assert result["review_status"] == "Revoked"
    assert result["recommendation"] == "REVOKE"


def test_future_dated_review_requires_review(datasets):
    """Future-dated review decisions must not be treated as valid."""
    datasets["access_reviews"].loc[
        datasets["access_reviews"]["assignment_id"] == "A001",
        "review_date",
    ] = "2026-12-01"

    results = evaluate_access_reviews(
        datasets,
        as_of_date="2026-10-12",
    )

    result = results.loc[results["assignment_id"] == "A001"].iloc[0]

    assert result["review_status"] == "Future-Dated Review"
    assert result["recommendation"] == "REVIEW"


def test_invalid_decision_requires_review(datasets):
    """Unknown decision values must not authorize access."""
    datasets["access_reviews"].loc[
        datasets["access_reviews"]["assignment_id"] == "A001",
        "decision",
    ] = "Maybe"

    results = evaluate_access_reviews(
        datasets,
        as_of_date="2026-10-12",
    )

    result = results.loc[results["assignment_id"] == "A001"].iloc[0]

    assert result["review_status"] == "Invalid Decision"
    assert result["recommendation"] == "REVIEW"


def test_missing_justification_requires_review(datasets):
    """An approval without justification should be flagged."""
    datasets["access_reviews"].loc[
        datasets["access_reviews"]["assignment_id"] == "A001",
        "justification",
    ] = ""

    results = evaluate_access_reviews(
        datasets,
        as_of_date="2026-10-12",
    )

    result = results.loc[results["assignment_id"] == "A001"].iloc[0]

    assert result["review_status"] == "Incomplete Review"
    assert result["recommendation"] == "REVIEW"


def test_summary_counts_all_recommendations(review_results):
    """Summary recommendation counts should match the result rows."""
    summary = summarize_access_reviews(review_results)

    assert summary["total_assignments"] == len(review_results)
    assert sum(summary["recommendation_counts"].values()) == len(review_results)


def test_missing_required_dataset_raises_error():
    """Incomplete dataset collections should be rejected."""
    with pytest.raises(ValueError, match="Missing required datasets"):
        evaluate_access_reviews({})
