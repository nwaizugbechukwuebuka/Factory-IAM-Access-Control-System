"""Detect excessive privileges and IAM least-privilege violations."""

from collections.abc import Mapping

import pandas as pd

DatasetCollection = Mapping[str, pd.DataFrame]

PRIVILEGED_ROLES = {
    "R005": "IT Support",
    "R006": "Security Administrator",
    "R008": "Factory Manager",
}

ROLE_ALLOWED_DEPARTMENTS = {
    "R001": {"production"},
    "R002": {"maintenance"},
    "R003": {"quality"},
    "R004": {"finance"},
    "R005": {"it"},
    "R006": {"it"},
    "R007": {"warehouse"},
    "R008": {"operations", "management"},
}

ROLE_ALLOWED_RESOURCE_DEPARTMENTS = {
    "R001": {"production"},
    "R002": {"maintenance"},
    "R003": {"quality"},
    "R004": {"finance"},
    "R005": {"it"},
    "R006": {"it"},
    "R007": {"warehouse"},
    "R008": {"operations"},
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

FINDING_COLUMNS = [
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
]


def _normalise(value: object) -> str:
    """Return a normalized string for comparisons."""
    return str(value).strip().lower()


def _lookup(
    dataframe: pd.DataFrame,
    column: str,
    value: object,
) -> pd.Series | None:
    """Return a record only when exactly one matching identifier exists."""
    if column not in dataframe.columns:
        return None

    matches = dataframe[dataframe[column].astype(str).str.strip() == str(value).strip()]

    if len(matches) != 1:
        return None

    return matches.iloc[0]


def _create_finding(
    *,
    rule_id: str,
    severity: str,
    assignment: pd.Series,
    user: pd.Series,
    role: pd.Series,
    resource: pd.Series,
    finding: str,
    recommendation: str,
) -> dict[str, str]:
    """Create a consistently structured security finding."""
    return {
        "finding_id": (f"{rule_id}-{assignment['assignment_id']}"),
        "rule_id": rule_id,
        "severity": severity,
        "user_id": str(user.get("user_id", "")),
        "user_name": str(user.get("full_name", "")),
        "assignment_id": str(assignment.get("assignment_id", "")),
        "role_id": str(role.get("role_id", "")),
        "role_name": str(role.get("role_name", "")),
        "resource_id": str(resource.get("resource_id", "")),
        "resource_name": str(resource.get("resource_name", "")),
        "finding": finding,
        "recommendation": recommendation,
    }


def detect_excessive_privileges(
    datasets: DatasetCollection,
) -> pd.DataFrame:
    """Return findings for risky factory IAM access assignments.

    The rules implement illustrative portfolio policies. They should
    be reviewed against an organization's actual access-control policy
    before use in a production environment.
    """
    required_datasets = {
        "users",
        "roles",
        "resources",
        "access_assignments",
    }

    missing = required_datasets - set(datasets)

    if missing:
        raise ValueError("Missing required datasets: " + ", ".join(sorted(missing)))

    users = datasets["users"]
    roles = datasets["roles"]
    resources = datasets["resources"]
    assignments = datasets["access_assignments"]

    findings: list[dict[str, str]] = []

    for _, assignment in assignments.iterrows():
        user = _lookup(
            users,
            "user_id",
            assignment.get("user_id", ""),
        )
        role = _lookup(
            roles,
            "role_id",
            assignment.get("role_id", ""),
        )
        resource = _lookup(
            resources,
            "resource_id",
            assignment.get("resource_id", ""),
        )

        # Phase 3 validates referential integrity. If the input is
        # malformed, skip the assignment rather than inventing context.
        if user is None or role is None or resource is None:
            continue

        role_id = str(role.get("role_id", ""))
        user_department = _normalise(user.get("department", ""))
        resource_department = _normalise(resource.get("department", ""))
        employment_status = _normalise(user.get("employment_status", ""))
        account_enabled = _normalise(user.get("account_enabled", ""))

        # LP001: Privileged roles should be restricted to authorized
        # departments under this project's example policy.
        if role_id in {"R005", "R006"} and user_department != "it":
            findings.append(
                _create_finding(
                    rule_id="LP001",
                    severity="Critical",
                    assignment=assignment,
                    user=user,
                    role=role,
                    resource=resource,
                    finding=(
                        "Privileged IT or security role assigned "
                        "to a user outside the IT department."
                    ),
                    recommendation=(
                        "Verify business justification and approval. "
                        "Remove the privileged role if unauthorized."
                    ),
                )
            )

        # LP002: Role and user department should be compatible.
        allowed_departments = ROLE_ALLOWED_DEPARTMENTS.get(role_id)

        if (
            allowed_departments is not None
            and user_department not in allowed_departments
        ):
            findings.append(
                _create_finding(
                    rule_id="LP002",
                    severity="High",
                    assignment=assignment,
                    user=user,
                    role=role,
                    resource=resource,
                    finding=(
                        "Assigned role does not match the user's "
                        "department under the example IAM policy."
                    ),
                    recommendation=(
                        "Confirm the user's job responsibilities "
                        "and remove or replace the role if unnecessary."
                    ),
                )
            )

        # LP003: Restrict the resource departments accessible through
        # each role according to the example policy.
        allowed_resource_departments = ROLE_ALLOWED_RESOURCE_DEPARTMENTS.get(role_id)

        if (
            allowed_resource_departments is not None
            and resource_department not in allowed_resource_departments
        ):
            findings.append(
                _create_finding(
                    rule_id="LP003",
                    severity="High",
                    assignment=assignment,
                    user=user,
                    role=role,
                    resource=resource,
                    finding=(
                        "Role grants access to a resource outside "
                        "its expected department."
                    ),
                    recommendation=(
                        "Validate the access requirement and restrict "
                        "the assignment to approved resources."
                    ),
                )
            )

        # LP004: Inactive or disabled identities should not retain
        # active access assignments.
        if employment_status != "active" or account_enabled != "true":
            findings.append(
                _create_finding(
                    rule_id="LP004",
                    severity="High",
                    assignment=assignment,
                    user=user,
                    role=role,
                    resource=resource,
                    finding=(
                        "Access assignment belongs to an inactive "
                        "employee or disabled account."
                    ),
                    recommendation=(
                        "Revoke the assignment or verify the identity "
                        "lifecycle process and account status."
                    ),
                )
            )

    if not findings:
        return pd.DataFrame(columns=FINDING_COLUMNS)

    findings_df = pd.DataFrame(
        findings,
        columns=FINDING_COLUMNS,
    )

    findings_df["_severity_order"] = findings_df["severity"].map(SEVERITY_ORDER)

    findings_df = findings_df.sort_values(
        by=["_severity_order", "rule_id", "assignment_id"],
        kind="stable",
    )

    return findings_df.drop(columns="_severity_order").reset_index(drop=True)


def summarize_findings(
    findings: pd.DataFrame,
) -> dict[str, object]:
    """Summarize security findings by severity and rule."""
    severity_counts = {
        severity: int(findings["severity"].eq(severity).sum())
        for severity in SEVERITY_ORDER
    }

    rule_counts = {
        str(rule_id): int(count)
        for rule_id, count in findings["rule_id"].value_counts().sort_index().items()
    }

    return {
        "total_findings": len(findings),
        "unique_affected_users": (
            int(findings["user_id"].nunique()) if not findings.empty else 0
        ),
        "severity_counts": severity_counts,
        "rule_counts": rule_counts,
    }
