"""Shared fixtures for MySQL-backed API tests."""

import pytest
import pymysql

from app import create_app
from app.db import get_db, init_db


@pytest.fixture()
def app():
    application = create_app({"TESTING": True})
    try:
        with application.app_context():
            init_db()
            database = get_db()
            with database.cursor() as cursor:
                cursor.execute("DELETE FROM issues")
                cursor.execute("DELETE FROM vulnerabilities")
            database.commit()
    except pymysql.MySQLError as exc:
        pytest.skip("MySQL integration database is unavailable: " + str(exc))
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()
