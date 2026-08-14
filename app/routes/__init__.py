from flask import Flask

from .health import bp as health_bp
from .webhook import bp as webhook_bp


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(health_bp)
    app.register_blueprint(webhook_bp)

