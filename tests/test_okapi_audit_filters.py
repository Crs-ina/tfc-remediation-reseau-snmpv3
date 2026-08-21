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
    incident: str = "0",
    date: str = "",
    switch: str = "0",
    port: str = "",
    remediation: str = "0",
    mode: str = "0",
    result: str = "0",
    administrator: str = "",
    search: str = "",
) -> str:
    answers = iter(
        [
            "2",
            incident,
            date,
            switch,
            port,
            remediation,
            mode,
            result,
            administrator,
            search,
        ]
    )
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
    assert "Incident       : VLAN_POLICY_VIOLATION" in output
    assert "Remediation    : Quarantine VLAN" in output
    assert "Incident       : network_loop" not in output


def test_action_and_result_filters_accept_partial_values(
    audit_log_dataset, monkeypatch, capsys
):
    action_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="ShUt",
    )
    assert "Incident       : network_loop" in action_output
    assert "Incident       : port_flapping" in action_output
    assert "Incident       : VLAN_POLICY_VIOLATION" not in action_output

    result_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="fail",
    )
    assert "Incident       : port_flapping" in result_output
    assert "Incident       : network_loop" not in result_output


def test_one_letter_and_switch_name_filters_work_independently(
    audit_log_dataset, monkeypatch, capsys
):
    one_letter = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="q",
    )
    assert "Incident       : VLAN_POLICY_VIOLATION" in one_letter
    assert "Incident       : network_loop" not in one_letter

    switch_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="aris",
    )
    assert "Incident       : VLAN_POLICY_VIOLATION" in switch_output
    assert "Incident       : network_loop" in switch_output
    assert "Incident       : port_flapping" not in switch_output


def test_free_search_is_not_fixed_to_one_field(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="arista",
    )
    assert "Incident       : VLAN_POLICY_VIOLATION" in output
    assert "Incident       : network_loop" in output
    assert "Incident       : port_flapping" not in output


def test_administrator_name_is_partial_and_case_insensitive(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="ExAu",
    )
    assert "Incident       : VLAN_POLICY_VIOLATION" in output
    assert "Incident       : port_flapping" in output
    assert "Incident       : network_loop" not in output


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
    assert "Incident       : network_loop" in output
    assert "Incident       : VLAN_POLICY_VIOLATION" not in output


def test_date_filter_uses_the_africa_kinshasa_calendar_day(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        date="2026-08-20",
    )
    assert "Incident       : VLAN_POLICY_VIOLATION" in output
    assert "Incident       : network_loop" in output
    assert "Incident       : port_flapping" not in output


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
    assert "Incident       : VLAN_POLICY_VIOLATION" in output
    assert "Incident       : network_loop" in output
    assert "Incident       : port_flapping" in output


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
    assert "Incident       : network_loop" in output
    assert "Incident       : VLAN_POLICY_VIOLATION" not in output
    assert "Incident       : port_flapping" not in output


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
    assert "OKAPI - INCIDENT & ACTION HISTORY (21 entries)" in output
    assert "[21/21]" in output
    assert "BULK_EVENT_00" not in output


def test_port_flapping_phrase_and_latest_logs_are_supported(
    audit_log_dataset, monkeypatch, capsys
):
    port_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="port flapping",
    )
    assert "Incident       : port_flapping" in port_output
    assert "Incident       : network_loop" not in port_output
    assert "Incident       : VLAN_POLICY_VIOLATION" not in port_output

    word_output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        search="port",
    )
    assert "Incident       : port_flapping" in word_output

    answers = iter(["1"])
    monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: next(answers))
    with audit_log_dataset.app_context():
        _logs()
    latest_output = capsys.readouterr().out
    assert "Incident       : VLAN_POLICY_VIOLATION" in latest_output
    assert "Incident       : network_loop" in latest_output
    assert "Incident       : port_flapping" in latest_output
    assert "Event         :" not in latest_output


def test_submenu_uses_filter_history_without_search_wording(
    audit_log_dataset, monkeypatch
):
    prompts: list[str] = []

    def answer(prompt, *_args, **_kwargs):
        prompts.append(prompt)
        return "B"

    monkeypatch.setattr("click.prompt", answer)
    with audit_log_dataset.app_context():
        _logs()

    assert prompts[0] == "[1] Latest history [2] Filter history [B] Back"
    assert "Search / filter history" not in prompts[0]


def test_any_keeps_filtering_and_one_small_port_hint_is_enough(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        port="Et4",
    )

    assert "Incident       : port_flapping" in output
    assert "Incident       : network_loop" not in output
    assert "Incident       : VLAN_POLICY_VIOLATION" not in output


def test_guided_filters_accept_partial_information_and_combine(
    audit_log_dataset, monkeypatch, capsys
):
    output = _run_filter(
        audit_log_dataset,
        monkeypatch,
        capsys,
        incident="flap",
        date="2026-08",
        switch="cisco",
        port="4",
        remediation="shutdown",
        mode="none",
        result="fail",
        administrator="ex",
    )

    assert "OKAPI - INCIDENT & ACTION HISTORY (1 entry)" in output
    assert "Incident       : port_flapping" in output
    assert "Result         : FAILED" in output


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
