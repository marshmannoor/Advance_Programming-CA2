# Northstar Issue & Vulnerability Tracker

A MySQL-backed information system for **Northstar Digital Services** (a fictional company). It lets service and security teams create, search, update, close, delete, and report on operational issues and security vulnerabilities.

## Specific requirements

The system must:

- Provide complete create, read, update, and delete (CRUD) workflows for issues and vulnerabilities.
- Validate required fields, text lengths, allowed values, ISO dates, CVE format, and CVSS range.
- Enforce integrity in Flask and MySQL, including unique CVE identifiers.
- Search titles/descriptions plus vulnerability assets and CVE IDs.
- Filter by status and priority/severity and sort through a safe allow-list.
- Record created/updated timestamps and automatic resolved/closed timestamps.
- Report status, priority/severity, open workload, and overdue totals.
- Provide a Streamlit UI while retaining a reusable Flask JSON API.
- Return suitable HTTP statuses and structured validation errors.

## Data requirements

### Issue

| Field | Type / rule |
|---|---|
| id | Auto-incrementing primary key |
| title | Required, 3–120 characters |
| description | Required, 5–2,000 characters |
| category | Software, Hardware, Network, Access, or Other |
| priority | Low, Medium, High, or Critical |
| status | Open, In Progress, Resolved, or Closed |
| reporter | Required, 2–80 characters |
| assignee | Optional, 2–80 characters |
| due_date | Optional date |
| timestamps | Created, updated, and resolved timestamps |

### Vulnerability

| Field | Type / rule |
|---|---|
| id | Auto-incrementing primary key |
| title | Required, 3–120 characters |
| description | Required, 5–2,000 characters |
| asset | Required affected system/asset |
| cve_id | Optional, unique CVE-YYYY-NNNN format |
| severity | Low, Medium, High, or Critical |
| cvss_score | Optional decimal from 0.0 to 10.0 |
| status | Open, Investigating, Mitigated, or Closed |
| owner | Optional remediation owner |
| remediation | Optional remediation plan/evidence |
| dates | Required discovered date; optional target date |
| timestamps | Created, updated, and closed timestamps |

MySQL uses InnoDB, UTF-8, primary keys, indexes, ENUM domains, CHECK constraints, and a unique CVE constraint. API queries are parameterised to prevent SQL injection. Sort columns are selected from server-side allow-lists.

## Architecture

~~~text
Streamlit frontend (port 8501)
            |
            | HTTP/JSON
            v
Flask REST API (port 5000)
            |
            | PyMySQL / parameterised SQL
            v
MySQL 8.4 (port 3306)
~~~

## Setup

Requirements: Python 3.10+, Docker Desktop (or an existing MySQL 8 server), and Git.

~~~powershell
git clone https://github.com/marshmannoor/ADVANCE-PROGRAMMING.git
cd ADVANCE-PROGRAMMING

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

docker compose up -d mysql
flask --app run.py init-db
~~~

The credentials in docker-compose.yml are development-only. For another server, set the variables shown in .env.example using secure values.

Run the API in terminal 1:

~~~powershell
.\.venv\Scripts\Activate.ps1
python run.py
~~~

Run Streamlit in terminal 2:

~~~powershell
.\.venv\Scripts\Activate.ps1
streamlit run streamlit_app.py
~~~

Open http://localhost:8501. The health endpoint is http://localhost:5000/health.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET, POST | /api/issues | Search/list or create issues |
| GET, PUT, PATCH, DELETE | /api/issues/{id} | Read, replace/update, or delete an issue |
| GET, POST | /api/vulnerabilities | Search/list or create vulnerabilities |
| GET, PUT, PATCH, DELETE | /api/vulnerabilities/{id} | Read, replace/update, or delete a vulnerability |
| GET | /api/reports/summary | Aggregated dashboard report |
| GET | /health | API health/company response |

List parameters include q, status, priority or severity, sort, order, and limit (maximum 100).

## Testing

Start MySQL and initialise the schema, then run:

~~~powershell
docker compose up -d mysql
flask --app run.py init-db
pytest -q
~~~

The suite covers validation and normalisation; issue CRUD/search/filter/delete; vulnerability CRUD and duplicate-CVE integrity; automatic closure timestamps; structured errors; health; and summary reports.

If MySQL is unavailable, integration tests are explicitly shown as skipped rather than falsely passing. On 12 July 2026, compilation succeeded and the database-independent result was **4 passed, 5 skipped** because the local Docker engine did not become available.

## Demonstration outline

1. Explain the company problem and three-tier architecture.
2. Start MySQL, Flask, and Streamlit.
3. Create an issue and demonstrate invalid-input feedback.
4. Search/filter, assign, and resolve it.
5. Create a vulnerability with CVE/CVSS details.
6. Demonstrate duplicate-CVE protection and remediation.
7. Show dashboard and overdue reporting.
8. Show tests and attributed Git history.

A fuller speaking guide is in docs/PRESENTATION.md.

## Development and attribution policy

Development uses incremental commits. Each commit message identifies one source category such as AI, SELF, or LIBRARY. Different origins must not be combined in one commit. A future student-authored change should use a message like: SELF: refine vulnerability form labels.

Third-party packages are dependencies, not copied source. Names and versions are recorded in requirements.txt and each remains under its own licence. No tutorial, Stack Overflow, or external repository code was copied.

## Code attribution summary

- **OpenAI Codex (GPT-5):** Requirements interpretation, Flask REST API, MySQL schema and Docker configuration, validation, Streamlit frontend, automated tests, README, and presentation guide. Generated specifically for this assignment in the repository workspace on 12 July 2026.
- **Student/self:** No source-code additions recorded yet. Later student-written commits should use the SELF prefix.
- **Third-party libraries:** Flask, PyMySQL, Requests, Streamlit, and pytest are used through their published APIs. Versions are pinned in requirements.txt; no library source is copied.
- **External copied code:** None.
