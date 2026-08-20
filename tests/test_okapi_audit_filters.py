from datetime import datetime, timezone

import pytest

from app.cli.okapi import _logs
from app.extensions import db
from app.models import Administrator, AuditLog


@pytest.fixture()
def audit_log_dataset(app):
    with app.app_context():
        administrator = Administrator(
            administrator_id="admin-exauce",
            system_username="exauceeadm",
        )
        db.session.add(administrator)
        db.session.add_all(
            [
                AuditLog(
                    log_id="log-vlan-human",
                    event_timestamp=datetime(2026, 8, 19, 23, 30, tzinfo=timezone.utc),
                    event_type="VLAN_HUMAN_EVENT",
                    incident_type="VLAN_POLICY_VIOLATION",
                    action_type="QUARANTINE_VLAN",
                    result_status="SUCCEEDED",
                    administrator=administrator,
                    equipment_name="SW-ARISTA-01",
                    port_index=2,
                    message="VLAN remediation approved.",
                ),
                AuditLog(
                    log_id="log-shutdown-system",
                    event_timestamp=datetime(2026, 8, 20, 14, 0, tzinfo=timezone.utc),
                    event_type="SHUTDOWN_SYSTEM_EVENT",
                    incident_type="network_loop",
                    action_type="SHUTDOWN_PORT",
                    result_status="SUCCEEDED",
                    equipment_name="SW-ARISTA-01",
                    port_index=3,
                    message="Automatic shutdown.",
                ),
                AuditLog(
                    log_id="log-next-local-day",
                    event_timestamp=datetime(2026, 8, 20, 23, 30, tzinfo=timezone.utc),
                    event_type="NEXT_LOCAL_DAY_EVENT",
                    incident_type="port_flapping",
                    action_type="SHUTDOWN_PORT",
                    result_status="FAILED",
                    administrator=administrator,
                    equipment_name="SW-CISCO-01",
                    port_index=4,
                    message="Shutdown failed.",
                ),
            ]
        )
        db.session.commit()
    return app


def _run_filter(
    app,
    monkeypatch,
    capsys,
    *,
    date: str = "",
    incident_type: str = "",
    action: str = "",
    result: str = "",
    administrator: str = "",
    switch: str = "",
    port: str = "",
) -> str:
    answers = iter(
        ["2", date, incident_type, action, result, administrator, switch, port]
    )
    monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: next(answers))
    with app.app_context():
        _logs()
    return capsys.readouterr().out


def test_single_incident_filter_is_partial_and_case_insensitive(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        incident_type="vLaN",
    )
    assert "VLAN_HUMAN_EVENT" in output
    assert "SHUTDOWN_SYSTEM_EVENT" not in output


def test_action_and_result_filters_accept_partial_values(
    audit_log_dataset, monkeypatch, capsys
):
    action_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        action="ShUt",
    )
    assert "SHUTDOWN_SYSTEM_EVENT" in action_output
    assert "NEXT_LOCAL_DAY_EVENT" in action_output
    assert "VLAN_HUMAN_EVENT" not in action_output

    result_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        result="fail",
    )
    assert "NEXT_LOCAL_DAY_EVENT" in result_output
    assert "SHUTDOWN_SYSTEM_EVENT" not in result_output


def test_one_letter_and_switch_name_filters_work_independently(
    audit_log_dataset, monkeypatch, capsys
):
    one_letter = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        action="q",
    )
    assert "VLAN_HUMAN_EVENT" in one_letter
    assert "SHUTDOWN_SYSTEM_EVENT" not in one_letter

    switch_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        switch="aris",
    )
    assert "VLAN_HUMAN_EVENT" in switch_output
    assert "SHUTDOWN_SYSTEM_EVENT" in switch_output
    assert "NEXT_LOCAL_DAY_EVENT" not in switch_output


def test_text_filter_never_searches_another_field(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        incident_type="arista",
    )
    assert "No audit logs found." in output


def test_administrator_name_is_partial_and_case_insensitive(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        administrator="ExAu",
    )
    assert "VLAN_HUMAN_EVENT" in output
    assert "NEXT_LOCAL_DAY_EVENT" in output
    assert "SHUTDOWN_SYSTEM_EVENT" not in output


@pytest.mark.parametrize("search", ["sys", "SYSTEM", "system", "s"])
def test_system_is_available_through_partial_administrator_search(
    audit_log_dataset, monkeypatch, capsys, search
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        administrator=search,
    )
    assert "SHUTDOWN_SYSTEM_EVENT" in output
    assert "VLAN_HUMAN_EVENT" not in output


def test_date_filter_uses_the_africa_kinshasa_calendar_day(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date="2026-08-20",
    )
    assert "VLAN_HUMAN_EVENT" in output
    assert "SHUTDOWN_SYSTEM_EVENT" in output
    assert "NEXT_LOCAL_DAY_EVENT" not in output


def test_multiple_non_empty_filters_are_combined_with_and(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date="2026-08-20",
        action="shut",
        switch="arista",
    )
    assert "SHUTDOWN_SYSTEM_EVENT" in output
    assert "VLAN_HUMAN_EVENT" not in output
    assert "NEXT_LOCAL_DAY_EVENT" not in output


def test_filtered_results_are_not_limited_to_the_latest_twenty(
    audit_log_dataset, monkeypatch, capsys
):
    with audit_log_dataset.app_context():
        db.session.add_all(
            [
                AuditLog(
                    log_id=f"bulk-log-{index:02d}",
                    event_timestamp=datetime(
                        2026, 8, 22, 8, index, tzinfo=timezone.utc
                    ),
                    event_type=f"BULK_EVENT_{index:02d}",
                    incident_type="bulk_test",
                    message="Bulk audit event.",
                )
                for index in range(21)
            ]
        )
        db.session.commit()

    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date="2026-08-22",
    )
    assert "BULK_EVENT_00" in output
    assert "BULK_EVENT_20" in output


def test_port_is_exact_and_latest_logs_are_unchanged(
    audit_log_dataset, monkeypatch, capsys
):
    port_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        port="3",
    )
    assert "SHUTDOWN_SYSTEM_EVENT" in port_output
    assert "VLAN_HUMAN_EVENT" not in port_output

    answers = iter(["1"])
    monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: next(answers))
    with audit_log_dataset.app_context():
        _logs()
    latest_output = capsys.readouterr().out
    assert "VLAN_HUMAN_EVENT" in latest_output
    assert "SHUTDOWN_SYSTEM_EVENT" in latest_output
    assert "NEXT_LOCAL_DAY_EVENT" in latest_output


@pytest.mark.parametrize(
    ("date", "port", "expected"),
    [
        ("20-08-2026", "", "Date must use YYYY-MM-DD."),
        ("", "Ethernet2", "Port must be a number."),
    ],
)
def test_invalid_date_and_port_are_reported(
    audit_log_dataset, monkeypatch, capsys, date, port, expected
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date=date,
        port=port,
    )
    assert expected in output
