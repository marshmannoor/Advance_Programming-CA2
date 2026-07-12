# Week 12 presentation guide

## Slide 1 — Problem and users

Northstar Digital Services needs one controlled register for service incidents and security weaknesses. Users are service desk staff, infrastructure engineers, and security analysts.

## Slide 2 — Requirements

Explain CRUD, validation, integrity, search, filters, sorting, timestamps, overdue detection, and summary reporting. Explain why issues and vulnerabilities use separate workflows.

## Slide 3 — Architecture

Show Streamlit calling Flask over JSON, Flask using parameterised PyMySQL queries, and MySQL enforcing durable constraints.

## Slide 4 — Data model

Show both tables. Point out primary keys, indexed workflow fields, unique CVEs, enums, checks, and timestamps.

## Slide 5 — CRUD demonstration

Create an issue, read it, update its assignee/status, and delete a disposable record. Repeat create/update for a vulnerability.

## Slide 6 — Additional features

Demonstrate search, filters, safe sorting, CVE/CVSS validation, duplicate-CVE rejection, closure timestamps, charts, and overdue totals.

## Slide 7 — Testing

Run pytest -q with MySQL. Explain one validation test, one CRUD integration test, and one integrity test. Unavailable MySQL causes explicit skips rather than misleading passes.

## Slide 8 — Source control and attribution

Show the public GitHub repository and incremental history. Explain source prefixes and the README attribution summary.

## Likely technical questions

- **Why Flask and Streamlit?** Flask supplies a reusable API; Streamlit supplies an interface without database coupling.
- **How is SQL injection prevented?** Values are query parameters; identifiers come only from server allow-lists.
- **Where is validation performed?** Flask checks input and MySQL independently enforces types and constraints.
- **Why MySQL?** It represents a multi-user server-based company system better than a local embedded database.
- **What does PATCH do?** It updates only supplied fields; PUT validates a complete replacement.
- **How are reports calculated?** MySQL GROUP BY and date queries are returned as compact JSON.
- **What would production add?** Authentication/roles, TLS, secrets, migrations, pagination, audit events, backups, rate limiting, and a production WSGI server.
