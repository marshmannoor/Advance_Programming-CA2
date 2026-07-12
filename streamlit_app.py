"""Streamlit frontend for the Northstar Flask REST API."""

import os
from datetime import date

import requests
import streamlit as st

API_BASE = os.getenv("API_BASE_URL", "http://127.0.0.1:5000/api")
st.set_page_config(page_title="Northstar Risk Operations", page_icon="🧭", layout="wide")

st.markdown(
    """
    <style>
    .stApp {background: #f4f6f2; color: #17201c;}
    [data-testid="stMainBlockContainer"] {max-width: 1500px;}
    [data-testid="stSidebar"] {background: #123c31;}
    [data-testid="stSidebar"] * {color: #f4f8f5;}
    .block-container {padding-top: 2.5rem;}
    h1, h2, h3 {font-family: Georgia, serif;}
    div[data-testid="stMetric"] {background: white; border: 1px solid #dfe3de;
      border-radius: 12px; padding: 16px; box-shadow: 0 12px 35px rgba(24,44,35,.06);}
    .company {letter-spacing: .16em; color: #587067; font-size: .75rem; font-weight: 700;}
    .risk-card {background:white;border:1px solid #dfe3de;border-radius:12px;padding:18px;margin:8px 0;}
    .risk-card h3 {color:#17201c;}
    .risk-card p {color:#69736d;}
    [data-testid="stMetricLabel"], [data-testid="stMetricValue"] {color:#17201c;}
    [data-testid="stCaptionContainer"] {color:#69736d;}
    div[data-baseweb="input"] > div, div[data-baseweb="select"] > div, textarea {background:#ffffff !important;color:#17201c !important;}
    </style>
    """,
    unsafe_allow_html=True,
)


def as_date(value):
    """Convert an API ISO date to a Streamlit-compatible date."""
    if not value or isinstance(value, date):
        return value
    return date.fromisoformat(value)


def api_request(method, path, **kwargs):
    """Call the Flask API and show a useful error if it is unavailable."""
    try:
        response = requests.request(method, API_BASE + path, timeout=8, **kwargs)
    except requests.RequestException:
        st.error("The Flask API is unavailable. Start it with: python run.py")
        return None
    if response.status_code == 204:
        return {}
    try:
        body = response.json()
    except ValueError:
        body = {"error": "The API returned an invalid response."}
    if not response.ok:
        details = body.get("details", {})
        detail_text = " ".join(str(value) for value in details.values())
        st.error((body.get("error") or "Request failed.") + (" " + detail_text if detail_text else ""))
        return None
    return body


def heading(title, subtitle):
    st.markdown('<p class="company">NORTHSTAR DIGITAL SERVICES</p>', unsafe_allow_html=True)
    st.title(title)
    st.caption(subtitle)


def dashboard():
    heading("Risk overview", "Operational issues and security exposure at a glance.")
    report = api_request("GET", "/reports/summary")
    if report is None:
        return
    issues, vulnerabilities = report["issues"], report["vulnerabilities"]
    open_issues = issues["by_status"].get("Open", 0) + issues["by_status"].get("In Progress", 0)
    open_vulnerabilities = (
        vulnerabilities["by_status"].get("Open", 0)
        + vulnerabilities["by_status"].get("Investigating", 0)
    )
    columns = st.columns(4)
    columns[0].metric("Open issues", open_issues)
    columns[1].metric("Critical issues", issues["by_priority"].get("Critical", 0))
    columns[2].metric("Open vulnerabilities", open_vulnerabilities)
    columns[3].metric("Overdue total", issues["overdue"] + vulnerabilities["overdue"])

    left, right = st.columns(2)
    with left:
        st.subheader("Issue workload")
        if issues["by_status"]:
            st.bar_chart(issues["by_status"], horizontal=True)
        else:
            st.info("No issue data has been recorded.")
    with right:
        st.subheader("Security severity")
        if vulnerabilities["by_severity"]:
            st.bar_chart(vulnerabilities["by_severity"], horizontal=True)
        else:
            st.info("No vulnerability data has been recorded.")

    st.markdown(
        '<div class="risk-card"><h3>Keep risk moving</h3>'
        '<p>Assign owners, set target dates, and record remediation before closing work.</p></div>',
        unsafe_allow_html=True,
    )


def issue_fields(prefix, existing=None):
    existing = existing or {}
    left, right = st.columns(2)
    with left:
        title = st.text_input("Title *", existing.get("title", ""), key=prefix + "title")
        category = st.selectbox(
            "Category *", ["Software", "Hardware", "Network", "Access", "Other"],
            index=["Software", "Hardware", "Network", "Access", "Other"].index(existing.get("category", "Software")),
            key=prefix + "category",
        )
        reporter = st.text_input("Reporter *", existing.get("reporter", ""), key=prefix + "reporter")
        due_date = st.date_input("Due date", value=as_date(existing.get("due_date")), key=prefix + "due")
    with right:
        priorities = ["Low", "Medium", "High", "Critical"]
        statuses = ["Open", "In Progress", "Resolved", "Closed"]
        priority = st.selectbox("Priority *", priorities, index=priorities.index(existing.get("priority", "Medium")), key=prefix + "priority")
        status = st.selectbox("Status", statuses, index=statuses.index(existing.get("status", "Open")), key=prefix + "status")
        assignee = st.text_input("Assignee", existing.get("assignee") or "", key=prefix + "assignee")
    description = st.text_area("Description *", existing.get("description", ""), key=prefix + "description")
    return {
        "title": title, "description": description, "category": category,
        "priority": priority, "status": status, "reporter": reporter,
        "assignee": assignee or None, "due_date": due_date.isoformat() if due_date else None,
    }


def vulnerability_fields(prefix, existing=None):
    existing = existing or {}
    left, right = st.columns(2)
    with left:
        title = st.text_input("Title *", existing.get("title", ""), key=prefix + "title")
        asset = st.text_input("Affected asset *", existing.get("asset", ""), key=prefix + "asset")
        cve_id = st.text_input("CVE ID", existing.get("cve_id") or "", placeholder="CVE-2026-1234", key=prefix + "cve")
        discovered = st.date_input(
            "Discovered date *", value=as_date(existing.get("discovered_date")) or date.today(),
            key=prefix + "discovered",
        )
    with right:
        severities = ["Low", "Medium", "High", "Critical"]
        statuses = ["Open", "Investigating", "Mitigated", "Closed"]
        severity = st.selectbox("Severity *", severities, index=severities.index(existing.get("severity", "Medium")), key=prefix + "severity")
        status = st.selectbox("Status", statuses, index=statuses.index(existing.get("status", "Open")), key=prefix + "status")
        cvss = st.number_input("CVSS score", min_value=0.0, max_value=10.0, value=float(existing.get("cvss_score") or 0), step=0.1, key=prefix + "cvss")
        owner = st.text_input("Owner", existing.get("owner") or "", key=prefix + "owner")
        target = st.date_input("Target date", value=as_date(existing.get("target_date")), key=prefix + "target")
    description = st.text_area("Description *", existing.get("description", ""), key=prefix + "description")
    remediation = st.text_area("Remediation plan", existing.get("remediation") or "", key=prefix + "remediation")
    return {
        "title": title, "description": description, "asset": asset, "cve_id": cve_id or None,
        "severity": severity, "cvss_score": cvss, "status": status, "owner": owner or None,
        "remediation": remediation or None, "discovered_date": discovered.isoformat(),
        "target_date": target.isoformat() if target else None,
    }


def create_tab(resource):
    with st.form("create_" + resource, clear_on_submit=True):
        payload = issue_fields("create_i_") if resource == "issues" else vulnerability_fields("create_v_")
        submitted = st.form_submit_button("Create record", type="primary")
    if submitted:
        result = api_request("POST", "/" + resource, json=payload)
        if result is not None:
            st.success("Record created successfully.")
            st.rerun()


def update_tab(resource, records):
    if not records:
        st.info("Create a record before attempting an update.")
        return
    labels = {record["id"]: "#" + str(record["id"]) + " — " + record["title"] for record in records}
    selected = st.selectbox("Select a record", list(labels), format_func=lambda item: labels[item])
    current = next(record for record in records if record["id"] == selected)
    with st.form("update_" + resource + "_" + str(selected)):
        payload = issue_fields("update_i_" + str(selected), current) if resource == "issues" else vulnerability_fields("update_v_" + str(selected), current)
        submitted = st.form_submit_button("Save changes", type="primary")
    if submitted:
        result = api_request("PATCH", "/" + resource + "/" + str(selected), json=payload)
        if result is not None:
            st.success("Record updated successfully.")
            st.rerun()


def delete_tab(resource, records):
    if not records:
        st.info("There are no records to delete.")
        return
    labels = {record["id"]: "#" + str(record["id"]) + " — " + record["title"] for record in records}
    selected = st.selectbox("Select a record to delete", list(labels), format_func=lambda item: labels[item])
    st.warning("Deletion is permanent and cannot be undone.")
    confirmed = st.checkbox("I understand that this record will be permanently deleted.")
    if st.button("Delete record", type="primary", disabled=not confirmed):
        result = api_request("DELETE", "/" + resource + "/" + str(selected))
        if result is not None:
            st.success("Record deleted.")
            st.rerun()


def register(resource):
    issue_mode = resource == "issues"
    heading(
        "Issue register" if issue_mode else "Vulnerability register",
        "Track operational incidents from report to resolution."
        if issue_mode else "Prioritise security weaknesses and document remediation.",
    )
    first, second, third = st.columns([2, 1, 1])
    query = first.text_input("Search", placeholder="Search title, description, asset or CVE")
    statuses = ["Open", "In Progress", "Resolved", "Closed"] if issue_mode else ["Open", "Investigating", "Mitigated", "Closed"]
    status = second.selectbox("Status", ["All"] + statuses)
    level_key = "priority" if issue_mode else "severity"
    level = third.selectbox(level_key.title(), ["All", "Low", "Medium", "High", "Critical"])

    params = {"q": query, "sort": "updated_at", "order": "desc"}
    if status != "All":
        params["status"] = status
    if level != "All":
        params[level_key] = level
    result = api_request("GET", "/" + resource, params=params)
    if result is None:
        return
    records = result["data"]
    st.caption(str(result["count"]) + " record(s)")
    if records:
        visible = [
            "id", "title", "category", "priority", "status", "assignee", "due_date"
        ] if issue_mode else [
            "id", "title", "asset", "cve_id", "severity", "cvss_score", "status", "owner", "target_date"
        ]
        st.dataframe(records, column_order=visible, hide_index=True, use_container_width=True)
    else:
        st.info("No records match the current filters.")

    create, update, delete = st.tabs(["Create", "Update", "Delete"])
    with create:
        create_tab(resource)
    with update:
        update_tab(resource, records)
    with delete:
        delete_tab(resource, records)


with st.sidebar:
    st.title("🧭 Northstar")
    st.caption("Risk Operations")
    page = st.radio("Navigation", ["Overview", "Issues", "Vulnerabilities"], label_visibility="collapsed")
    st.divider()
    st.caption("Flask API: " + API_BASE)

if page == "Overview":
    dashboard()
elif page == "Issues":
    register("issues")
else:
    register("vulnerabilities")

