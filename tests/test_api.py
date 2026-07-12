ISSUE = {
    "title": "VPN connection failure",
    "description": "Remote employees cannot establish a VPN connection.",
    "category": "Network",
    "priority": "High",
    "reporter": "Service Desk",
    "assignee": "Network Team",
    "due_date": "2026-07-20",
}

VULNERABILITY = {
    "title": "Outdated web framework",
    "description": "The customer portal uses a vulnerable framework release.",
    "asset": "Customer Portal",
    "cve_id": "CVE-2026-12345",
    "severity": "Critical",
    "cvss_score": 9.4,
    "owner": "Security Team",
    "discovered_date": "2026-07-12",
    "target_date": "2026-07-18",
}


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["company"] == "Northstar Digital Services"


def test_issue_crud_search_and_filter(client):
    created = client.post("/api/issues", json=ISSUE)
    assert created.status_code == 201
    issue_id = created.json["id"]

    listed = client.get("/api/issues?q=VPN&priority=High&sort=title&order=asc")
    assert listed.status_code == 200
    assert listed.json["count"] == 1

    updated = client.patch(
        "/api/issues/" + str(issue_id),
        json={"status": "Resolved", "assignee": "Infrastructure Team"},
    )
    assert updated.status_code == 200
    assert updated.json["status"] == "Resolved"
    assert updated.json["resolved_at"] is not None

    fetched = client.get("/api/issues/" + str(issue_id))
    assert fetched.json["assignee"] == "Infrastructure Team"

    deleted = client.delete("/api/issues/" + str(issue_id))
    assert deleted.status_code == 204
    assert client.get("/api/issues/" + str(issue_id)).status_code == 404


def test_vulnerability_crud_and_duplicate_cve_integrity(client):
    first = client.post("/api/vulnerabilities", json=VULNERABILITY)
    assert first.status_code == 201

    duplicate = client.post("/api/vulnerabilities", json=VULNERABILITY)
    assert duplicate.status_code == 409

    vulnerability_id = first.json["id"]
    updated = client.patch(
        "/api/vulnerabilities/" + str(vulnerability_id),
        json={"status": "Closed", "remediation": "Framework upgraded and retested."},
    )
    assert updated.status_code == 200
    assert updated.json["closed_at"] is not None


def test_validation_errors_are_structured(client):
    response = client.post("/api/issues", json={"title": "x"})
    assert response.status_code == 422
    assert "details" in response.json
    assert "description" in response.json["details"]


def test_summary_report(client):
    client.post("/api/issues", json=ISSUE)
    client.post("/api/vulnerabilities", json=VULNERABILITY)
    response = client.get("/api/reports/summary")
    assert response.status_code == 200
    assert response.json["issues"]["by_status"]["Open"] == 1
    assert response.json["vulnerabilities"]["by_severity"]["Critical"] == 1
