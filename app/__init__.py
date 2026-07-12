"""Northstar Issue & Vulnerability Tracker application package."""

import os
from flask import Flask


def create_app(test_config=None):
    """Create and configure the Flask REST API."""
    app = Flask(__name__)
    app.config.from_mapping(
        MYSQL_HOST=os.getenv("MYSQL_HOST", "127.0.0.1"),
        MYSQL_PORT=int(os.getenv("MYSQL_PORT", "3306")),
        MYSQL_USER=os.getenv("MYSQL_USER", "northstar_user"),
        MYSQL_PASSWORD=os.getenv("MYSQL_PASSWORD", "northstar_password"),
        MYSQL_DATABASE=os.getenv("MYSQL_DATABASE", "northstar_tracker"),
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)

    from . import db
    db.init_app(app)

    from .routes import api
    app.register_blueprint(api, url_prefix="/api")

    @app.get("/health")
    def health():
        return {"status": "healthy", "company": "Northstar Digital Services"}

    return app
