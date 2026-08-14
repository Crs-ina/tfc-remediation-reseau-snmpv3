from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from app.services.calendar_policy import ScheduleDecision
from app.services.rules import PlaybookRepository, RuleContext, RuleEngine


PLAYBOOKS = Path(__file__).resolve().parents[1] / "playbooks"


def schedule(mode: str, reason: str) -> ScheduleDecision:
    return ScheduleDecision(
        mode=mode,
        reason=reason,
        local_datetime=datetime(2026, 8, 10, tzinfo=ZoneInfo("Africa/Kinshasa")),
    )


def evaluate(**overrides):
    values = {
        "incident_type": "network_loop",
        "target_confirmed": True,
        "identification_attempts": 1,
        "target_whitelisted": False,
        "schedule": schedule("AUTOMATIC", "night"),
        "automatic_allowed_actions": frozenset(
            {"SHUTDOWN_PORT", "QUARANTINE_VLAN"}
        ),
        "quarantine_vlan_exists": False,
        "quarantine_vlan_isolated": False,
    }
    values.update(overrides)
    engine = RuleEngine(PlaybookRepository(PLAYBOOKS))
    return engine.evaluate(RuleContext(**values))


def test_disruptive_loop_always_requires_human_approval():
    decision = evaluate()
    assert decision.state == "WAITING_ADMIN_APPROVAL"
    assert decision.execution_mode == "HUMAN_APPROVAL"
    assert decision.action == "SHUTDOWN_PORT"


def test_business_hours_wait_for_administrator():
    decision = evaluate(schedule=schedule("HUMAN_APPROVAL", "business_hours"))
    assert decision.state == "WAITING_ADMIN_APPROVAL"


def test_whitelist_always_blocks_action():
    decision = evaluate(target_whitelisted=True)
    assert decision.state == "ESCALATED"
    assert decision.execution_mode == "NONE"


def test_ip_conflict_requires_isolated_quarantine_vlan():
    decision = evaluate(incident_type="ip_address_conflict")
    assert decision.reason == "quarantine_vlan_precondition_failed"
    decision = evaluate(
        incident_type="ip_address_conflict",
        quarantine_vlan_exists=True,
        quarantine_vlan_isolated=True,
    )
    assert decision.state == "WAITING_ADMIN_APPROVAL"
    assert decision.execution_mode == "HUMAN_APPROVAL"


def test_physical_disconnection_never_changes_network():
    decision = evaluate(incident_type="physical_disconnection")
    assert decision.action == "NO_ACTION"
    assert decision.state == "ESCALATED_NO_REMEDIATION"


def test_unknown_incident_never_changes_network():
    decision = evaluate(incident_type="new_incident")
    assert decision.action == "NO_ACTION"
    assert decision.state == "ESCALATED_NO_REMEDIATION"
