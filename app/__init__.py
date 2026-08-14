from __future__ import annotations

from typing import Any

from flask import Flask

from config import Config

from .extensions import db, migrate


def create_app(
    config_object: type[Config] = Config,
    overrides: dict[str, Any] | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)
    if overrides:
        app.config.update(overrides)

    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)

    from .snmp.mib_registry import MibRegistry

    mib_registry = MibRegistry(
        package=app.config["SNMP_MIB_PACKAGE"],
        local_path=app.config["SNMP_MIB_PATH"],
    )
    mib_status = mib_registry.warm_up()
    app.extensions["snmp_mib_registry"] = mib_registry
    if not mib_status.ready:
        app.logger.error("Warm-up MIB en echec: %s", mib_status.error)

    from . import models  # noqa: F401
    from .cli import register_cli
    from .routes import register_blueprints

    register_blueprints(app)
    register_cli(app)
    return app
