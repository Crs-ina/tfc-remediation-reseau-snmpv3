from pathlib import Path

import pytest

from app import create_app
from app.extensions import db


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def app(tmp_path):
    remediation_config = tmp_path / "remediation.json"
    remediation_config.write_text(
        '{"quarantine_vlan_id": 18}', encoding="utf-8"
    )
    application = create_app(
        overrides={
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
            "WEBHOOK_TOKEN": "test-secret",
            "SCHEMA_PATH": PROJECT_ROOT
            / "schemas"
            / "zabbix_webhook_payload_schema_v1.0.json",
            "PLAYBOOKS_DIR": PROJECT_ROOT / "playbooks",
            "AUTOMATION_SCHEDULE_PATH": PROJECT_ROOT
            / "config"
            / "automation_schedule.json",
            "WHITELIST_PATH": PROJECT_ROOT / "config" / "whitelist.json",
            "REMEDIATION_CONFIG_PATH": remediation_config,
            "QUARANTINE_VLAN_EXISTS": True,
            "QUARANTINE_VLAN_ISOLATED": True,
            "SNMP_WRITE_ENABLED": False,
            "DRY_RUN": False,
            "RUNTIME_SETTINGS_PATH": tmp_path / "runtime-settings.json",
            "SQLITE_BACKUP_DIR": tmp_path / "backups",
            "SNMP_MIB_PACKAGE": "pysnmp_mibs",
            "SNMP_MIB_PATH": None,
            "SNMP_CAPABILITIES_PATH": PROJECT_ROOT
            / "config"
            / "snmp_capabilities.json",
        }
    )
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
