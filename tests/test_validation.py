from app.validation import validate_payload


def test_issue_requires_core_fields():
    errors = validate_payload({}, "issue")
    assert {"title", "description", "category", "priority", "reporter"} <= set(errors)


def test_issue_rejects_invalid_options_and_date():
    payload = {
        "title": "Email outage", "description": "Mail is unavailable",
        "category": "Finance", "priority": "Urgent", "reporter": "IT",
        "due_date": "tomorrow",
    }
    errors = validate_payload(payload, "issue")
    assert "category" in errors
    assert "priority" in errors
    assert "due_date" in errors


def test_vulnerability_normalises_valid_cve_and_cvss():
    payload = {
        "title": "Library flaw", "description": "A vulnerable dependency is installed",
        "asset": "Customer portal", "severity": "High",
        "discovered_date": "2026-07-12", "cve_id": "cve-2026-12345",
        "cvss_score": "8.1",
    }
    assert validate_payload(payload, "vulnerability") == {}
    assert payload["cve_id"] == "CVE-2026-12345"
    assert payload["cvss_score"] == 8.1


def test_vulnerability_rejects_bad_cve_and_score():
    payload = {
        "title": "Library flaw", "description": "A vulnerable dependency is installed",
        "asset": "Customer portal", "severity": "High",
        "discovered_date": "2026-07-12", "cve_id": "1234",
        "cvss_score": 12,
    }
    errors = validate_payload(payload, "vulnerability")
    assert "cve_id" in errors
    assert "cvss_score" in errors
