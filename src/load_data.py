"""Load and validate factory IAM datasets."""

from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

REQUIRED_COLUMNS = {
    "users": {
        "user_id",
        "full_name",
        "department",
        "employment_status",
        "mfa_enabled",
        "account_enabled",
        "last_login",
    },
    "roles": {
        "role_id",
        "role_name",
        "description",
        "privilege_level",
    },
    "resources": {
        "resource_id",
        "resource_name",
        "resource_type",
        "department",
        "requires_mfa",
        "sensitivity",
    },
    "access_assignments": {
        "assignment_id",
        "user_id",
        "role_id",
        "resource_id",
        "granted_date",
        "approved_by",
    },
    "access_reviews": {
        "review_id",
        "assignment_id",
        "reviewer_id",
        "review_date",
        "decision",
        "justification",
    },
}

PRIMARY_KEYS = {
    "users": "user_id",
    "roles": "role_id",
    "resources": "resource_id",
    "access_assignments": "assignment_id",
    "access_reviews": "review_id",
}

BOOLEAN_COLUMNS = {
    "users": ["mfa_enabled", "account_enabled"],
    "resources": ["requires_mfa"],
}

DATE_COLUMNS = {
    "users": ["last_login"],
    "access_assignments": ["granted_date"],
    "access_reviews": ["review_date"],
}


def load_iam_data(
    data_dir: str | Path = DATA_DIR,
) -> dict[str, pd.DataFrame]:
    """Load all five IAM CSV files into Pandas DataFrames."""
    directory = Path(data_dir)
    datasets = {}

    for dataset_name in REQUIRED_COLUMNS:
        file_path = directory / f"{dataset_name}.csv"

        if not file_path.is_file():
            raise FileNotFoundError(f"Required IAM dataset not found: {file_path}")

        datasets[dataset_name] = pd.read_csv(
            file_path,
            dtype=str,
            keep_default_na=False,
        )

    return datasets


def validate_iam_data(
    datasets: dict[str, pd.DataFrame],
) -> list[str]:
    """Return a list of data-integrity validation errors."""
    errors = []

    missing_datasets = set(REQUIRED_COLUMNS) - set(datasets)

    if missing_datasets:
        return [f"Missing dataset: {name}" for name in sorted(missing_datasets)]

    # Validate required columns.
    for dataset_name, required_columns in REQUIRED_COLUMNS.items():
        actual_columns = set(datasets[dataset_name].columns)
        missing_columns = required_columns - actual_columns

        for column in sorted(missing_columns):
            errors.append(f"{dataset_name}: missing required column '{column}'")

    # Stop checks that depend on columns when the schema is incomplete.
    for dataset_name, primary_key in PRIMARY_KEYS.items():
        df = datasets[dataset_name]

        if primary_key not in df.columns:
            continue

        values = df[primary_key].astype(str).str.strip()

        if values.eq("").any():
            errors.append(f"{dataset_name}: blank values in '{primary_key}'")

        duplicates = values[values.ne("") & values.duplicated(keep=False)].unique()

        for duplicate in sorted(duplicates):
            errors.append(f"{dataset_name}: duplicate {primary_key} '{duplicate}'")

    # Validate Boolean fields.
    valid_booleans = {"true", "false"}

    for dataset_name, columns in BOOLEAN_COLUMNS.items():
        df = datasets[dataset_name]

        for column in columns:
            if column not in df.columns:
                continue

            values = df[column].astype(str).str.strip().str.lower()

            invalid_values = sorted(set(values) - valid_booleans)

            for value in invalid_values:
                errors.append(
                    f"{dataset_name}: invalid Boolean value '{value}' in '{column}'"
                )

    # Validate date fields.
    for dataset_name, columns in DATE_COLUMNS.items():
        df = datasets[dataset_name]

        for column in columns:
            if column not in df.columns:
                continue

            values = df[column].astype(str).str.strip()
            parsed_dates = pd.to_datetime(
                values,
                format="%Y-%m-%d",
                errors="coerce",
            )

            invalid_mask = parsed_dates.isna()

            for index in df.index[invalid_mask]:
                errors.append(
                    f"{dataset_name}: invalid date in '{column}' at row {index + 2}"
                )

    # Validate foreign-key relationships.
    foreign_keys = [
        ("access_assignments", "user_id", "users", "user_id"),
        ("access_assignments", "role_id", "roles", "role_id"),
        ("access_assignments", "resource_id", "resources", "resource_id"),
        (
            "access_reviews",
            "assignment_id",
            "access_assignments",
            "assignment_id",
        ),
        ("access_reviews", "reviewer_id", "users", "user_id"),
    ]

    for source_name, source_column, target_name, target_column in foreign_keys:
        source_df = datasets[source_name]
        target_df = datasets[target_name]

        if (
            source_column not in source_df.columns
            or target_column not in target_df.columns
        ):
            continue

        valid_ids = set(target_df[target_column].astype(str).str.strip())

        source_values = source_df[source_column].astype(str).str.strip()

        for index, value in source_values.items():
            if not value:
                errors.append(
                    f"{source_name}: blank foreign key '{source_column}' "
                    f"at row {index + 2}"
                )
            elif value not in valid_ids:
                errors.append(
                    f"{source_name}: unknown {source_column} "
                    f"'{value}' at row {index + 2}"
                )

    return errors
