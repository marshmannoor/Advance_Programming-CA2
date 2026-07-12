"""MySQL connection and schema management."""

import click
import pymysql
from flask import current_app, g
from pymysql.cursors import DictCursor

SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS issues (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(120) NOT NULL,
        description TEXT NOT NULL,
        category ENUM('Software','Hardware','Network','Access','Other') NOT NULL,
        priority ENUM('Low','Medium','High','Critical') NOT NULL,
        status ENUM('Open','In Progress','Resolved','Closed') NOT NULL DEFAULT 'Open',
        reporter VARCHAR(80) NOT NULL,
        assignee VARCHAR(80) NULL,
        due_date DATE NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        resolved_at DATETIME NULL,
        INDEX idx_issues_status (status),
        INDEX idx_issues_priority (priority),
        CHECK (CHAR_LENGTH(TRIM(title)) BETWEEN 3 AND 120),
        CHECK (CHAR_LENGTH(TRIM(description)) BETWEEN 5 AND 2000)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(120) NOT NULL,
        description TEXT NOT NULL,
        asset VARCHAR(120) NOT NULL,
        cve_id VARCHAR(20) NULL UNIQUE,
        severity ENUM('Low','Medium','High','Critical') NOT NULL,
        cvss_score DECIMAL(3,1) NULL,
        status ENUM('Open','Investigating','Mitigated','Closed') NOT NULL DEFAULT 'Open',
        owner VARCHAR(80) NULL,
        remediation TEXT NULL,
        discovered_date DATE NOT NULL,
        target_date DATE NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        closed_at DATETIME NULL,
        INDEX idx_vulnerabilities_status (status),
        INDEX idx_vulnerabilities_severity (severity),
        CHECK (cvss_score IS NULL OR (cvss_score BETWEEN 0 AND 10)),
        CHECK (CHAR_LENGTH(TRIM(title)) BETWEEN 3 AND 120),
        CHECK (CHAR_LENGTH(TRIM(description)) BETWEEN 5 AND 2000)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """
]


def get_db():
    if "db" not in g:
        g.db = pymysql.connect(
            host=current_app.config["MYSQL_HOST"],
            port=current_app.config["MYSQL_PORT"],
            user=current_app.config["MYSQL_USER"],
            password=current_app.config["MYSQL_PASSWORD"],
            database=current_app.config["MYSQL_DATABASE"],
            cursorclass=DictCursor,
            autocommit=False,
        )
    return g.db


def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def init_db():
    database = get_db()
    with database.cursor() as cursor:
        for statement in SCHEMA_STATEMENTS:
            cursor.execute(statement)
    database.commit()


@click.command("init-db")
def init_db_command():
    init_db()
    click.echo("Initialized the MySQL database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
