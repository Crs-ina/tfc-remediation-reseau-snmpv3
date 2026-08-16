from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "oui", "on"}


def env_csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def database_uri() -> str:
    raw = os.getenv("DATABASE_URL", "sqlite:///data/remediation.db").strip()
    if not raw.startswith("sqlite:///"):
        return raw

    relative = raw.removeprefix("sqlite:///")
    path = Path(relative)
    if not path.is_absolute():
        path = BASE_DIR / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path.as_posix()}"


def config_path(environment_name: str, relative_default: str) -> Path:
    raw = os.getenv(environment_name, relative_default).strip()
    path = Path(raw)
    return path if path.is_absolute() else BASE_DIR / path


def optional_config_path(environment_name: str) -> Path | None:
    raw = os.getenv(environment_name, "").strip()
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else BASE_DIR / path


class Config:
    SQLALCHEMY_DATABASE_URI = database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False

    WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "").strip()
    # Zabbix and OKAPI are co-located in the laboratory. Gunicorn or Flask
    # reads these values; the route uses the source allow-list as defence in
    # depth and never logs the shared token.
    WEBHOOK_BIND_HOST = os.getenv("WEBHOOK_BIND_HOST", "127.0.0.1").strip()
    WEBHOOK_BIND_PORT = int(os.getenv("WEBHOOK_BIND_PORT", "5000"))
    WEBHOOK_ALLOWED_SOURCE_IPS = env_csv(
        "WEBHOOK_ALLOWED_SOURCE_IPS", "127.0.0.1,::1"
    )
    WEBHOOK_MAX_CONTENT_LENGTH = int(os.getenv("WEBHOOK_MAX_CONTENT_LENGTH", "65536"))
    REQUIRE_REMEDIATION_TAG = env_bool("REQUIRE_REMEDIATION_TAG", True)
    REMEDIATION_TAG_NAME = os.getenv("REMEDIATION_TAG_NAME", "remediation").strip()
    REMEDIATION_TAG_VALUE = os.getenv("REMEDIATION_TAG_VALUE", "enabled").strip()

    AUTOMATION_SCHEDULE_PATH = config_path(
        "AUTOMATION_SCHEDULE_PATH", "config/automation_schedule.json"
    )
    WHITELIST_PATH = config_path("WHITELIST_PATH", "config/whitelist.json")
    QUARANTINE_VLAN_ID = int(os.getenv("QUARANTINE_VLAN_ID", "18"))

    SNMP_WRITE_ENABLED = env_bool("SNMP_WRITE_ENABLED", False)
    DRY_RUN = env_bool("DRY_RUN", False)
    REMEDIATION_MAX_ATTEMPTS = int(os.getenv("REMEDIATION_MAX_ATTEMPTS", "2"))
    REMEDIATION_COOLDOWN_SECONDS = int(os.getenv("REMEDIATION_COOLDOWN_SECONDS", "60"))
    PORT_LOCK_DIR = config_path("PORT_LOCK_DIR", "data/port-locks")
    SNMP_MIB_PACKAGE = os.getenv("SNMP_MIB_PACKAGE", "pysnmp_mibs").strip()
    SNMP_MIB_PATH = optional_config_path("SNMP_MIB_PATH")
    SNMP_CAPABILITIES_PATH = config_path(
        "SNMP_CAPABILITIES_PATH", "config/snmp_capabilities.json"
    )
    QUARANTINE_VLAN_EXISTS = env_bool("QUARANTINE_VLAN_EXISTS", False)
    QUARANTINE_VLAN_ISOLATED = env_bool("QUARANTINE_VLAN_ISOLATED", False)

    SCHEMA_PATH = BASE_DIR / "schemas" / "zabbix_webhook_payload_schema_v1.0.json"
    PLAYBOOKS_DIR = BASE_DIR / "playbooks"
    MAX_CONTENT_LENGTH = WEBHOOK_MAX_CONTENT_LENGTH


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WEBHOOK_TOKEN = "test-secret"
