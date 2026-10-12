# Factory IAM Access Control System

**Identity & Access Management | Security Engineering | Python Automation**

## Project Overview

The Factory IAM Access Control System is a Python-based security engineering project that demonstrates how organisations can assess user permissions, identify access-control risks, and prioritise access reviews.

Designed around a simulated manufacturing environment, the project analyses identities, roles, resources, access assignments, and review records to generate structured risk assessments and actionable recommendations.

The objective is to demonstrate how automation can support stronger access governance, improve visibility into potential security weaknesses, and make access reviews more consistent.

## Business Challenge

In manufacturing and enterprise environments, employees, contractors, and suppliers require access to different systems and resources. If these permissions are not reviewed regularly, organisations may face excessive privileges, outdated access assignments, and gaps in access governance.

Manual reviews can make it difficult to identify high-risk assignments and determine which issues require immediate attention.

This project addresses that challenge by demonstrating a repeatable, data-driven approach to access analysis and risk prioritisation.

## Key Capabilities

### 1. Identity and Access Analysis

Processes structured IAM datasets covering users, roles, resources, access assignments, and access reviews to support a consistent assessment of access permissions.

### 2. Excessive-Privilege Detection

Analyses access assignments to identify potential excessive privileges and support the principle of least privilege.

### 3. Automated Access Reviews

Evaluates access-review records and identifies assignments that may require retention, revocation, or further investigation.

### 4. Risk Scoring and Prioritisation

Applies configurable scoring rules to assess access-related findings. Risk scores range from 0 to 100 and are classified as Low, Moderate, High, or Critical.

The scoring model considers finding severity, lifecycle-related violations, pending or incomplete reviews, unreviewed access, and designated privileged roles.

### 5. Risk Register and Reporting

Consolidates assessment results into a structured risk register containing assignment details, review status, recommendations, risk scores, and contributing risk factors. Results can be exported to CSV for further analysis and reporting.

### 6. Automated Quality Assurance

Uses automated tests to verify risk-scoring rules, input validation, risk-register generation, and CSV export behaviour. Ruff supports consistent code-quality checks.

## Technology Stack

| Technology     | Application                       |
| -------------- | --------------------------------- |
| Python         | Security analysis and automation  |
| pandas         | IAM dataset processing            |
| pytest         | Automated testing                 |
| Ruff           | Code-quality and linting checks   |
| CSV            | Structured datasets and reporting |
| Git and GitHub | Version control                   |

## How It Works

The project follows a structured assessment workflow:

1. **Load:** Read the five IAM datasets covering users, roles, resources, access assignments, and access reviews.
2. **Validate:** Check data quality and identify records that require attention.
3. **Analyse:** Evaluate access assignments and identify potential excessive privileges.
4. **Review:** Assess access-review records and generate review outcomes.
5. **Prioritise:** Calculate risk scores using configurable rules.
6. **Report:** Generate a prioritised risk register and export the results for further investigation.

## Example Business Output

The risk register is designed to help security teams answer practical questions:

* Which access assignments present the highest assessed risk?
* Which assignments require an access review?
* Which findings contribute to an elevated risk score?
* Which assignments may require revocation or further investigation?
* How can access-related findings be organised for remediation?

By consolidating these details, the project demonstrates how technical analysis can support security governance and operational decision-making.

## Project Structure

```text
Factory-IAM-Access-Control-System/
├── data/
│   ├── users.csv
│   ├── roles.csv
│   ├── resources.csv
│   ├── access_assignments.csv
│   └── access_reviews.csv
├── src/
│   ├── risk_scoring.py
│   ├── detect_excessive_privileges.py
│   └── review_access.py
├── tests/
│   ├── conftest.py
│   └── test_risk_scoring.py
├── reports/
├── docs/
├── notebooks/
└── README.md
```

*This overview shows the principal project components; additional files may exist in the repository.*

## Running the Project

### Requirements

* Python 3.11 or a compatible Python version.
* Git.
* The dependencies specified by the project.

### Setup

Clone the repository:

```powershell
git clone https://github.com/nwaizugbechukwuebuka/Factory-IAM-Access-Control-System.git
cd Factory-IAM-Access-Control-System
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the core development dependencies:

```powershell
python -m pip install pandas pytest ruff
```

Run the automated tests:

```powershell
python -m pytest -v
```

Check code quality:

```powershell
python -m ruff check .
```

If the repository includes a `requirements.txt` file, install the project's declared dependencies using `python -m pip install -r requirements.txt` instead of installing only the packages listed above.

## Security and Governance

The project demonstrates selected IAM assessment techniques and illustrates how automated analysis can support access governance.

The risk-scoring weights and thresholds are configurable project rules, not a certified or universal risk standard. Recommendations should be evaluated against organisational policies before being used to make access decisions.

The current implementation is a portfolio project using simulated data. It does not connect to a live identity provider, change real user permissions, or automatically revoke access.

## Skills Demonstrated

* Identity and Access Management (IAM)
* Access-control assessment and least privilege
* Security risk scoring and prioritisation
* Access-review automation
* Python programming and pandas
* Data validation and structured reporting
* Automated testing with pytest
* Code quality with Ruff
* Git and GitHub version control

## Potential Future Enhancements

* Integration with an identity provider in a controlled test environment.
* Role-based access control and separation-of-duties analysis.
* Historical risk trends and dashboard visualisation.
* Scheduled access reviews and remediation tracking.
* Continuous integration for automated testing and quality checks.

## Author

**Tobiloba Nwaizugbe**

[![GitHub](https://img.shields.io/badge/GitHub-Project-181717.svg?style=flat\&logo=github)](https://github.com/nwaizugbechukwuebuka/Factory-IAM-Access-Control-System)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077b5.svg?style=flat\&logo=linkedin)](https://www.linkedin.com/in/chukwuebuka-tobiloba-nwaizugbe/)

---

*Developed as a portfolio project to demonstrate practical skills in IAM, security engineering, risk assessment, and Python automation.*
