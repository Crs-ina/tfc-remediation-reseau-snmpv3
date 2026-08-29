import pytest

from app.extensions import db
from app.services.remediation import RemediationError
from app.services.snmp_execution import (
    RollbackStateChangedError,
    execute_interface_admin_action,
    rollback_interface_admin_action,
)
from tests.test_snmp_execution import (
    FakeWriteClient,
    approve,
    build_waiting_remediation,
    enable_writes,
    snmp_config,
)


@pytest.mark.parametrize(
    ("action_type", "previous_status", "port_status", "read_values", "expected"),
    [
        ("SHUTDOWN_PORT", "UP", "up", [200, 1, 2], 2),
        ("REACTIVATE_PORT", "DOWN", "down", [200, 2, 1], 1),
    ],
)
def test_arista_lab_validated_ifadmin_actions_execute_without_capability_bypass(
    app,
    action_type,
    previous_status,
    port_status,
    read_values,
    expected,
):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.action_type = action_type
        remediation.previous_port_status = previous_status
        port.status = port_status
        db.session.commit()
        approve(incident)

        fake = FakeWriteClient(read_values)
        result = execute_interface_admin_action(
            incident,
            client=fake,
            snmp_config=snmp_config(),
        )

        assert result.observed_vlan == expected
        assert remediation.status == "SUCCEEDED"
        assert incident.processing_status == "REMEDIATED"
        assert fake.set_calls[0][1:] == (expected, True)
        assert port.status == ("up" if expected == 1 else "down")


def test_ifadmin_rollback_restores_saved_up_state_with_real_capability_gate(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.action_type = "SHUTDOWN_PORT"
        remediation.previous_port_status = "UP"
        port.status = "up"
        db.session.commit()
        approve(incident)

        execute_interface_admin_action(
            incident,
            client=FakeWriteClient([200, 1, 2]),
            snmp_config=snmp_config(),
        )

        rollback_client = FakeWriteClient([200, 2, 1])
        observed = rollback_interface_admin_action(
            remediation,
            administrator_id="admin-test",
            client=rollback_client,
            snmp_config=snmp_config(),
        )

        assert observed == 1
        assert rollback_client.set_calls[0][1:] == (1, True)
        assert remediation.status == "ROLLED_BACK"
        assert incident.processing_status == "ROLLED_BACK"
        assert port.status == "up"


def test_ifadmin_rollback_rejects_unsafe_saved_state_before_snmp(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.action_type = "SHUTDOWN_PORT"
        remediation.previous_port_status = "TESTING"
        remediation.applied_port_status = "DOWN"
        remediation.status = "SUCCEEDED"
        incident.processing_status = "REMEDIATED"
        port.status = "down"
        db.session.commit()

        fake = FakeWriteClient([])
        with pytest.raises(RemediationError, match="safe rollback value"):
            rollback_interface_admin_action(
                remediation,
                administrator_id="admin-test",
                client=fake,
                snmp_config=snmp_config(),
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_ifadmin_rollback_blocks_external_state_change(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.action_type = "SHUTDOWN_PORT"
        remediation.previous_port_status = "UP"
        port.status = "up"
        db.session.commit()
        approve(incident)

        execute_interface_admin_action(
            incident,
            client=FakeWriteClient([200, 1, 2]),
            snmp_config=snmp_config(),
        )

        rollback_client = FakeWriteClient([200, 1])
        with pytest.raises(RollbackStateChangedError):
            rollback_interface_admin_action(
                remediation,
                administrator_id="admin-test",
                client=rollback_client,
                snmp_config=snmp_config(),
            )

        assert rollback_client.set_calls == []
        assert remediation.status == "ROLLBACK_BLOCKED"
