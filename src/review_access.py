"""Evaluate factory IAM access reviews and recertification status."""

from collections.abc import Mapping

import pandas as pd

DatasetCollection = Mapping[str, pd.DataFrame]

REVIEW_COLUMNS = [
    "assignment_id",
    "user_id",
    "full_name",
    "role_id",
    "resource_id",
    "review_status",
    "recommendation",
    "review_reason",
]

VALID_DECISIONS = {"approved", "revoked", "pending"}


def evaluate_access_reviews(
    datasets: DatasetCollection,
    as_of_date: str | pd.Timestamp | None = None,
) -> pd.DataFrame:
    """Evaluate review status and recommend access retention or revocation.

    The as_of_date parameter makes review evaluation deterministic
    and supports reproducible tests.
    """
    required = {
        "users",
        "access_assignments",
        "access_reviews",
    }
    missing = required - set(datasets)

    if missing:
        raise ValueError("Missing required datasets: " + ", ".join(sorted(missing)))

    users = datasets["users"]
    assignments = datasets["access_assignments"]
    reviews = datasets["access_reviews"]

    required_columns = {
        "users": {"user_id", "full_name", "employment_status", "account_enabled"},
        "access_assignments": {
            "assignment_id",
            "user_id",
            "role_id",
            "resource_id",
        },
        "access_reviews": {
            "assignment_id",
            "review_date",
            "decision",
            "justification",
        },
    }

    for dataset_name, columns in required_columns.items():
        absent = columns - set(datasets[dataset_name].columns)
        if absent:
            raise ValueError(
                f"{dataset_name} missing required columns: " + ", ".join(sorted(absent))
            )

    today = (
        pd.Timestamp(as_of_date).normalize()
        if as_of_date is not None
        else pd.Timestamp.now().normalize()
    )

    review_data = reviews.copy()
    review_data["_review_date"] = pd.to_datetime(
        review_data["review_date"],
        format="%Y-%m-%d",
        errors="coerce",
    )
    review_data["_decision"] = (
        review_data["decision"].astype(str).str.strip().str.lower()
    )

    # Latest review date wins. If dates tie, the last source row wins.
    review_data["_source_order"] = range(len(review_data))
    latest_reviews = (
        review_data.sort_values(
            ["_review_date", "_source_order"],
            na_position="first",
        )
        .drop_duplicates("assignment_id", keep="last")
        .set_index("assignment_id")
    )

    users_by_id = users.set_index("user_id", drop=False)

    results = []

    for _, assignment in assignments.iterrows():
        assignment_id = str(assignment["assignment_id"])
        user_id = str(assignment["user_id"])

        result = {
            "assignment_id": assignment_id,
            "user_id": user_id,
            "full_name": "",
            "role_id": str(assignment["role_id"]),
            "resource_id": str(assignment["resource_id"]),
            "review_status": "Not Reviewed",
            "recommendation": "REVIEW",
            "review_reason": "",
        }

        if user_id not in users_by_id.index:
            result["review_status"] = "Invalid Identity"
            result["recommendation"] = "REVOKE"
            result["review_reason"] = (
                "Assigned user does not exist in the identity dataset."
            )
            results.append(result)
            continue

        user = users_by_id.loc[user_id]

        if isinstance(user, pd.DataFrame):
            result["review_status"] = "Ambiguous Identity"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = (
                "Duplicate user identifiers prevent reliable evaluation."
            )
            results.append(result)
            continue

        result["full_name"] = str(user["full_name"])

        employment_status = str(user["employment_status"]).strip().lower()
        account_enabled = str(user["account_enabled"]).strip().lower()

        if employment_status != "active" or account_enabled != "true":
            result["review_status"] = "Lifecycle Violation"
            result["recommendation"] = "REVOKE"
            result["review_reason"] = (
                "Inactive identity or disabled account retains an assignment."
            )
            results.append(result)
            continue

        if assignment_id not in latest_reviews.index:
            result["review_status"] = "Not Reviewed"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = (
                "No access-review record exists for this assignment."
            )
            results.append(result)
            continue

        review = latest_reviews.loc[assignment_id]

        decision = str(review["_decision"])
        review_date = review["_review_date"]
        justification = str(review["justification"]).strip()

        if pd.isna(review_date):
            result["review_status"] = "Invalid Review Date"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = "Review date is missing or invalid."
        elif review_date.normalize() > today:
            result["review_status"] = "Future-Dated Review"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = "Review date is later than the evaluation date."
        elif decision not in VALID_DECISIONS:
            result["review_status"] = "Invalid Decision"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = f"Unrecognized review decision: {decision!r}."
        elif decision == "revoked":
            result["review_status"] = "Revoked"
            result["recommendation"] = "REVOKE"
            result["review_reason"] = (
                justification or "Reviewer marked access for revocation."
            )
        elif decision == "pending":
            result["review_status"] = "Pending"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = (
                justification or "Access review requires a decision."
            )
        elif not justification:
            result["review_status"] = "Incomplete Review"
            result["recommendation"] = "REVIEW"
            result["review_reason"] = (
                "Approval lacks a documented business justification."
            )
        else:
            result["review_status"] = "Approved"
            result["recommendation"] = "RETAIN"
            result["review_reason"] = justification

        results.append(result)

    return pd.DataFrame(results, columns=REVIEW_COLUMNS)


def summarize_access_reviews(
    review_results: pd.DataFrame,
) -> dict[str, object]:
    """Summarize access-review outcomes and recommendations."""
    recommendations = ["RETAIN", "REVOKE", "REVIEW"]

    recommendation_counts = {
        recommendation: int(review_results["recommendation"].eq(recommendation).sum())
        for recommendation in recommendations
    }

    status_counts = {
        str(status): int(count)
        for status, count in (
            review_results["review_status"].value_counts().sort_index().items()
        )
    }

    return {
        "total_assignments": len(review_results),
        "recommendation_counts": recommendation_counts,
        "status_counts": status_counts,
    }
