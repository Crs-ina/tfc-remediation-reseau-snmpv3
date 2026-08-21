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
    search: str = "",
) -> str:
    answers = iter(["2", date, search])
    monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: next(answers))
    with app.app_context():
        _logs()
    return capsys.readouterr().out


def test_free_search_matches_incident_related_fields(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="vLaN policy",
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
        search="ShUt",
    )
    assert "SHUTDOWN_SYSTEM_EVENT" in action_output
    assert "NEXT_LOCAL_DAY_EVENT" in action_output
    assert "VLAN_HUMAN_EVENT" not in action_output

    result_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="fail",
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
        search="q",
    )
    assert "VLAN_HUMAN_EVENT" in one_letter
    assert "SHUTDOWN_SYSTEM_EVENT" not in one_letter

    switch_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="aris",
    )
    assert "VLAN_HUMAN_EVENT" in switch_output
    assert "SHUTDOWN_SYSTEM_EVENT" in switch_output
    assert "NEXT_LOCAL_DAY_EVENT" not in switch_output


def test_free_search_is_not_fixed_to_one_field(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="arista",
    )
    assert "VLAN_HUMAN_EVENT" in output
    assert "SHUTDOWN_SYSTEM_EVENT" in output
    assert "NEXT_LOCAL_DAY_EVENT" not in output


def test_administrator_name_is_partial_and_case_insensitive(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="ExAu",
    )
    assert "VLAN_HUMAN_EVENT" in output
    assert "NEXT_LOCAL_DAY_EVENT" in output
    assert "SHUTDOWN_SYSTEM_EVENT" not in output


@pytest.mark.parametrize("search", ["sys", "SYSTEM", "system"])
def test_system_is_available_through_partial_administrator_search(
    audit_log_dataset, monkeypatch, capsys, search
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search=search,
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


@pytest.mark.parametrize("period", ["2026", "2026-08"])
def test_date_filter_accepts_a_year_or_month(
    audit_log_dataset, monkeypatch, capsys, period
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date=period,
    )
    assert "VLAN_HUMAN_EVENT" in output
    assert "SHUTDOWN_SYSTEM_EVENT" in output
    assert "NEXT_LOCAL_DAY_EVENT" in output


def test_period_and_free_search_are_combined_and_phrase_words_are_flexible(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date="2026-08-20",
        search="shut arista",
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


def test_port_flapping_phrase_and_latest_logs_are_supported(
    audit_log_dataset, monkeypatch, capsys
):
    port_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="port flapping",
    )
    assert "NEXT_LOCAL_DAY_EVENT" in port_output
    assert "SHUTDOWN_SYSTEM_EVENT" not in port_output
    assert "VLAN_HUMAN_EVENT" not in port_output

    word_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="port",
    )
    assert "NEXT_LOCAL_DAY_EVENT" in word_output

    answers = iter(["1"])
    monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: next(answers))
    with audit_log_dataset.app_context():
        _logs()
    latest_output = capsys.readouterr().out
    assert "VLAN_HUMAN_EVENT" in latest_output
    assert "SHUTDOWN_SYSTEM_EVENT" in latest_output
    assert "NEXT_LOCAL_DAY_EVENT" in latest_output


@pytest.mark.parametrize(
    ("date", "expected"),
    [
        ("20-08-2026", "Date must use YYYY, YYYY-MM, or YYYY-MM-DD."),
        ("2026-13", "Date must use YYYY, YYYY-MM, or YYYY-MM-DD."),
    ],
)
def test_invalid_date_is_reported(
    audit_log_dataset, monkeypatch, capsys, date, expected
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date=date,
    )
    assert expected in output
