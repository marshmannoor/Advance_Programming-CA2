"""Request validation for issue and vulnerability records."""

import re
from datetime import date

ISSUE_FIELDS = {
    "title", "description", "category", "priority", "status",
    "reporter", "assignee", "due_date",
}
VULNERABILITY_FIELDS = {
    "title", "description", "asset", "cve_id", "severity", "cvss_score",
    "status", "owner", "remediation", "discovered_date", "target_date",
}
ISSUE_OPTIONS = {
    "category": {"Software", "Hardware", "Network", "Access", "Other"},
    "priority": {"Low", "Medium", "High", "Critical"},
    "status": {"Open", "In Progress", "Resolved", "Closed"},
}
VULNERABILITY_OPTIONS = {
    "severity": {"Low", "Medium", "High", "Critical"},
    "status": {"Open", "Investigating", "Mitigated", "Closed"},
}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,10}$", re.IGNORECASE)


def _date_error(value, field):
    if value in (None, ""):
        return None
    try:
        date.fromisoformat(str(value))
    except ValueError:
        return f"{field} must use YYYY-MM-DD format."
    return None


def validate_payload(payload, kind, partial=False):
    """Return a dictionary of field errors for an API payload."""
    if not isinstance(payload, dict):
        return {"body": "A JSON object is required."}

    fields = ISSUE_FIELDS if kind == "issue" else VULNERABILITY_FIELDS
    options = ISSUE_OPTIONS if kind == "issue" else VULNERABILITY_OPTIONS
    required = (
        {"title", "description", "category", "priority", "reporter"}
        if kind == "issue"
        else {"title", "description", "asset", "severity", "discovered_date"}
    )
    errors = {}

    unknown = set(payload) - fields
    if unknown:
        errors["unknown_fields"] = f"Unsupported fields: {', '.join(sorted(unknown))}"

    if not partial:
        for field in required:
            if payload.get(field) in (None, ""):
                errors[field] = f"{field} is required."

    limits = {
        "title": (3, 120), "description": (5, 2000), "reporter": (2, 80),
        "assignee": (2, 80), "asset": (2, 120), "owner": (2, 80),
        "remediation": (0, 4000),
    }
    for field, (minimum, maximum) in limits.items():
        if field in payload and payload[field] not in (None, ""):
            size = len(str(payload[field]).strip())
            if size < minimum or size > maximum:
                errors[field] = f"{field} must contain {minimum}-{maximum} characters."

    for field, allowed in options.items():
        if field in payload and payload[field] not in allowed:
            errors[field] = f"{field} must be one of: {', '.join(sorted(allowed))}."

    date_fields = ["due_date"] if kind == "issue" else ["discovered_date", "target_date"]
    for field in date_fields:
        if field in payload:
            error = _date_error(payload[field], field)
            if error:
                errors[field] = error

    if kind == "vulnerability":
        if payload.get("cve_id"):
            payload["cve_id"] = str(payload["cve_id"]).upper()
            if not CVE_PATTERN.fullmatch(payload["cve_id"]):
                errors["cve_id"] = "cve_id must look like CVE-2026-1234."
        if payload.get("cvss_score") not in (None, ""):
            try:
                score = float(payload["cvss_score"])
                if not 0 <= score <= 10:
                    raise ValueError
                payload["cvss_score"] = score
            except (TypeError, ValueError):
                errors["cvss_score"] = "cvss_score must be a number from 0 to 10."

    return errors
