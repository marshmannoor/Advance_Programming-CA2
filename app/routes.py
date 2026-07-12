"""HTTP routes for the tracker API and browser interface."""

from datetime import date, datetime
from decimal import Decimal

import pymysql
from flask import Blueprint, jsonify, request

from .db import get_db
from .validation import ISSUE_FIELDS, VULNERABILITY_FIELDS, validate_payload

api = Blueprint("api", __name__)
pages = Blueprint("pages", __name__)

CONFIG = {
    "issues": {
        "kind": "issue",
        "fields": ISSUE_FIELDS,
        "default_status": "Open",
        "sort": {"id", "title", "priority", "status", "category", "due_date", "created_at", "updated_at"},
        "filter": "priority",
    },
    "vulnerabilities": {
        "kind": "vulnerability",
        "fields": VULNERABILITY_FIELDS,
        "default_status": "Open",
        "sort": {"id", "title", "severity", "status", "asset", "target_date", "created_at", "updated_at"},
        "filter": "severity",
    },
}


def json_value(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def serialize(row):
    return {key: json_value(value) for key, value in row.items()}


def error(message, status=400, details=None):
    body = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


def fetch_record(table, record_id):
    database = get_db()
    with database.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {table} WHERE id = %s", (record_id,))
        row = cursor.fetchone()
    return row



@api.get("/<resource>")
def list_records(resource):
    if resource not in CONFIG:
        return error("Unknown resource.", 404)
    config = CONFIG[resource]
    clauses, params = [], []

    search = request.args.get("q", "").strip()
    if search:
        search_fields = ["title", "description"]
        if resource == "vulnerabilities":
            search_fields += ["asset", "cve_id"]
        clauses.append("(" + " OR ".join(f"{field} LIKE %s" for field in search_fields) + ")")
        params.extend([f"%{search}%"] * len(search_fields))

    status = request.args.get("status", "").strip()
    if status:
        clauses.append("status = %s")
        params.append(status)

    filter_value = request.args.get(config["filter"], "").strip()
    if filter_value:
        clauses.append(f"{config['filter']} = %s")
        params.append(filter_value)

    sort = request.args.get("sort", "created_at")
    sort = sort if sort in config["sort"] else "created_at"
    order = "ASC" if request.args.get("order", "desc").lower() == "asc" else "DESC"
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 100)
    except ValueError:
        return error("limit must be an integer from 1 to 100.")

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM {resource}{where} ORDER BY {sort} {order} LIMIT %s"
    params.append(limit)

    database = get_db()
    with database.cursor() as cursor:
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    return jsonify({"data": [serialize(row) for row in rows], "count": len(rows)})


@api.get("/<resource>/<int:record_id>")
def get_record(resource, record_id):
    if resource not in CONFIG:
        return error("Unknown resource.", 404)
    row = fetch_record(resource, record_id)
    if not row:
        return error("Record not found.", 404)
    return jsonify(serialize(row))


@api.post("/<resource>")
def create_record(resource):
    if resource not in CONFIG:
        return error("Unknown resource.", 404)
    payload = request.get_json(silent=True)
    config = CONFIG[resource]
    errors = validate_payload(payload, config["kind"])
    if errors:
        return error("Validation failed.", 422, errors)

    values = {field: payload[field] for field in config["fields"] if field in payload}
    values.setdefault("status", config["default_status"])
    columns = list(values)
    placeholders = ", ".join(["%s"] * len(columns))
    sql = f"INSERT INTO {resource} ({', '.join(columns)}) VALUES ({placeholders})"
    database = get_db()
    try:
        with database.cursor() as cursor:
            cursor.execute(sql, [values[column] or None for column in columns])
            record_id = cursor.lastrowid
        database.commit()
    except pymysql.IntegrityError as exc:
        database.rollback()
        if exc.args[0] == 1062:
            return error("A vulnerability with that CVE ID already exists.", 409)
        return error("The record violates a database integrity rule.", 409)

    return jsonify(serialize(fetch_record(resource, record_id))), 201


@api.route("/<resource>/<int:record_id>", methods=["PUT", "PATCH"])
def update_record(resource, record_id):
    if resource not in CONFIG:
        return error("Unknown resource.", 404)
    existing = fetch_record(resource, record_id)
    if not existing:
        return error("Record not found.", 404)

    payload = request.get_json(silent=True)
    config = CONFIG[resource]
    partial = request.method == "PATCH"
    errors = validate_payload(payload, config["kind"], partial=partial)
    if errors:
        return error("Validation failed.", 422, errors)

    if not partial:
        values = {field: payload.get(field) for field in config["fields"]}
        values["status"] = values.get("status") or config["default_status"]
    else:
        values = {field: payload[field] for field in config["fields"] if field in payload}
    if not values:
        return error("No supported fields were supplied.", 422)

    assignments = [f"{field} = %s" for field in values]
    params = [values[field] or None for field in values]
    closing_field = "resolved_at" if resource == "issues" else "closed_at"
    closed_statuses = {"Resolved", "Closed"} if resource == "issues" else {"Closed"}
    if "status" in values:
        assignments.append(
            f"{closing_field} = " + ("CURRENT_TIMESTAMP" if values["status"] in closed_statuses else "NULL")
        )
    params.append(record_id)

    database = get_db()
    try:
        with database.cursor() as cursor:
            cursor.execute(
                f"UPDATE {resource} SET {', '.join(assignments)} WHERE id = %s",
                params,
            )
        database.commit()
    except pymysql.IntegrityError:
        database.rollback()
        return error("The update conflicts with an existing record or integrity rule.", 409)
    return jsonify(serialize(fetch_record(resource, record_id)))


@api.delete("/<resource>/<int:record_id>")
def delete_record(resource, record_id):
    if resource not in CONFIG:
        return error("Unknown resource.", 404)
    database = get_db()
    with database.cursor() as cursor:
        cursor.execute(f"DELETE FROM {resource} WHERE id = %s", (record_id,))
        deleted = cursor.rowcount
    database.commit()
    if not deleted:
        return error("Record not found.", 404)
    return "", 204


@api.get("/reports/summary")
def summary_report():
    database = get_db()
    with database.cursor() as cursor:
        cursor.execute("SELECT status, COUNT(*) AS total FROM issues GROUP BY status")
        issue_status = cursor.fetchall()
        cursor.execute("SELECT priority, COUNT(*) AS total FROM issues GROUP BY priority")
        issue_priority = cursor.fetchall()
        cursor.execute("SELECT status, COUNT(*) AS total FROM vulnerabilities GROUP BY status")
        vulnerability_status = cursor.fetchall()
        cursor.execute("SELECT severity, COUNT(*) AS total FROM vulnerabilities GROUP BY severity")
        vulnerability_severity = cursor.fetchall()
        cursor.execute(
            "SELECT COUNT(*) AS total FROM issues "
            "WHERE due_date < CURRENT_DATE AND status NOT IN ('Resolved','Closed')"
        )
        overdue_issues = cursor.fetchone()["total"]
        cursor.execute(
            "SELECT COUNT(*) AS total FROM vulnerabilities "
            "WHERE target_date < CURRENT_DATE AND status != 'Closed'"
        )
        overdue_vulnerabilities = cursor.fetchone()["total"]

    def grouped(rows, key):
        return {row[key]: row["total"] for row in rows}

    return jsonify({
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "issues": {
            "by_status": grouped(issue_status, "status"),
            "by_priority": grouped(issue_priority, "priority"),
            "overdue": overdue_issues,
        },
        "vulnerabilities": {
            "by_status": grouped(vulnerability_status, "status"),
            "by_severity": grouped(vulnerability_severity, "severity"),
            "overdue": overdue_vulnerabilities,
        },
    })

