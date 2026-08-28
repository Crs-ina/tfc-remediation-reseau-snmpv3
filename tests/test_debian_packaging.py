from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging" / "debian"


def test_debian_package_is_amd64_because_native_wheels_are_bundled():
    build_script = (PACKAGING / "build-deb.sh").read_text(encoding="utf-8")
    requirements = (PACKAGING / "requirements-runtime.txt").read_text(
        encoding="utf-8"
    )
    control = (PACKAGING / "DEBIAN" / "control.in").read_text(encoding="utf-8")

    assert 'ARCHITECTURE="amd64"' in build_script
    assert "--only-binary=:all:" in build_script
    assert "cryptography==50.0.0" in requirements
    assert "Architecture: @ARCHITECTURE@" in control


def test_debian_metadata_uses_the_confirmed_maintainer_and_python_dependency():
    control = (PACKAGING / "DEBIAN" / "control.in").read_text(encoding="utf-8")

    assert "Version: 1.0.0" in control
    assert "Maintainer: Christina Ngalula <christinangalula@2028.ulc-icam.com>" in control
    assert "Depends: python3 (>= 3.10), python3-venv, sudo, adduser, tzdata" in control


def test_secret_template_contains_only_real_empty_secret_variables():
    lines = (PACKAGING / "secrets.env.example").read_text(
        encoding="utf-8"
    ).splitlines()

    assert lines == [
        "WEBHOOK_TOKEN=",
        "SNMP_USERNAME=",
        "SNMP_AUTH_KEY=",
        "SNMP_PRIV_KEY=",
    ]
    assert "QUARANTINE_VLAN_ID" not in "\n".join(lines)


def test_service_and_cli_keep_backend_and_human_identity_separate():
    service = (PACKAGING / "okapi.service").read_text(encoding="utf-8")
    launcher = (PACKAGING / "okapi").read_text(encoding="utf-8")

    assert "User=okapi" in service
    assert "WorkingDirectory=/opt/okapi" in service
    assert "ExecStart=/opt/okapi/venv/bin/gunicorn" in service
    assert "exec /opt/okapi/venv/bin/python -m app.cli.entrypoint" in launcher
    assert "sudo" not in launcher
    assert "su " not in launcher


def test_mutable_json_files_are_debian_conffiles():
    conffiles = (PACKAGING / "DEBIAN" / "conffiles").read_text(
        encoding="utf-8"
    )

    assert "/etc/okapi/remediation.json" in conffiles
    assert "/etc/okapi/whitelist.json" in conffiles
    assert "/etc/okapi/automation_schedule.json" in conffiles
    assert "/etc/okapi/playbooks/playbook_index.json" in conffiles
