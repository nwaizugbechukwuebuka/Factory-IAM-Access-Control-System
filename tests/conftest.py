"""Shared pytest fixtures for the IAM Access Control System tests."""

from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"


@pytest.fixture
def iam_datasets() -> dict[str, pd.DataFrame]:
    """Load all five IAM datasets for use in tests."""
    dataset_files = {
        "users": "users.csv",
        "roles": "roles.csv",
        "resources": "resources.csv",
        "access_assignments": "access_assignments.csv",
        "access_reviews": "access_reviews.csv",
    }

    datasets: dict[str, pd.DataFrame] = {}

    for dataset_name, filename in dataset_files.items():
        file_path = DATA_DIR / filename

        if not file_path.is_file():
            raise FileNotFoundError(
                f"Required IAM dataset was not found: {file_path}"
            )

        datasets[dataset_name] = pd.read_csv(file_path)

    return datasets