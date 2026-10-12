"""Evaluate factory IAM access assignments."""

from collections.abc import Mapping

import pandas as pd

DatasetCollection = Mapping[str, pd.DataFrame]


def _normalise(value: object) -> str:
    """Convert a value to a trimmed, lowercase string."""
    return str(value).strip().lower()


def _find_record(
    dataframe: pd.DataFrame,
    column: str,
    value: object,
) -> pd.Series | None:
    """Find a record by an exact, normalized identifier."""
    if column not in dataframe.columns:
        return None

    matches = dataframe[dataframe[column].astype(str).str.strip() == str(value).strip()]

    if len(matches) != 1:
        return None

    return matches.iloc[0]


def evaluate_access_assignment(
    assignment: Mapping[str, object],
    datasets: DatasetCollection,
) -> dict[str, object]:
    """Evaluate one assignment and return its access decision."""
    assignment_id = str(assignment.get("assignment_id", "")).strip()

    result: dict[str, object] = {
        "assignment_id": assignment_id,
        "user_id": str(assignment.get("user_id", "")).strip(),
        "role_id": str(assignment.get("role_id", "")).strip(),
        "resource_id": str(assignment.get("resource_id", "")).strip(),
        "decision": "DENY",
        "reasons": [],
    }

    reasons: list[str] = []

    required_datasets = {
        "users",
        "roles",
        "resources",
    }

    missing_datasets = required_datasets - set(datasets)

    if missing_datasets:
        reasons.append(
            "Missing required datasets: " + ", ".join(sorted(missing_datasets))
        )
        result["reasons"] = reasons
        return result

    user_id = result["user_id"]
    role_id = result["role_id"]
    resource_id = result["resource_id"]

    if not user_id or not role_id or not resource_id:
        reasons.append("Assignment contains a blank identifier.")

    user = _find_record(
        datasets["users"],
        "user_id",
        user_id,
    )

    role = _find_record(
        datasets["roles"],
        "role_id",
        role_id,
    )

    resource = _find_record(
        datasets["resources"],
        "resource_id",
        resource_id,
    )

    if user is None:
        reasons.append("User does not exist or has an ambiguous identifier.")

    if role is None:
        reasons.append("Role does not exist or has an ambiguous identifier.")

    if resource is None:
        reasons.append("Resource does not exist or has an ambiguous identifier.")

    if reasons:
        result["reasons"] = reasons
        return result

    # Fail closed if identity or resource security fields are unavailable.
    required_user_fields = {
        "employment_status",
        "account_enabled",
        "mfa_enabled",
    }
    required_resource_fields = {"requires_mfa"}

    if not required_user_fields.issubset(user.index):
        reasons.append("User security fields are incomplete.")

    if not required_resource_fields.issubset(resource.index):
        reasons.append("Resource security fields are incomplete.")

    if reasons:
        result["reasons"] = reasons
        return result

    employment_status = _normalise(user["employment_status"])
    account_enabled = _normalise(user["account_enabled"])
    mfa_enabled = _normalise(user["mfa_enabled"])
    requires_mfa = _normalise(resource["requires_mfa"])

    if employment_status != "active":
        reasons.append("User employment status is not active.")

    if account_enabled != "true":
        if account_enabled == "false":
            reasons.append("User account is disabled.")
        else:
            reasons.append("User account status is invalid.")

    if mfa_enabled not in {"true", "false"}:
        reasons.append("User MFA status is invalid.")
    elif requires_mfa not in {"true", "false"}:
        reasons.append("Resource MFA requirement is invalid.")
    elif requires_mfa == "true" and mfa_enabled != "true":
        reasons.append("MFA is required but not enabled for the user.")

    result["decision"] = "DENY" if reasons else "ALLOW"
    result["reasons"] = reasons

    return result


def evaluate_all_assignments(
    datasets: DatasetCollection,
) -> pd.DataFrame:
    """Evaluate every assignment and return a results DataFrame."""
    if "access_assignments" not in datasets:
        raise ValueError("Missing required dataset: access_assignments")

    results = [
        evaluate_access_assignment(
            assignment.to_dict(),
            datasets,
        )
        for _, assignment in datasets["access_assignments"].iterrows()
    ]

    return pd.DataFrame(
        results,
        columns=[
            "assignment_id",
            "user_id",
            "role_id",
            "resource_id",
            "decision",
            "reasons",
        ],
    )
