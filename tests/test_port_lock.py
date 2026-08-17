import pytest

from app.services.port_lock import PortBusyError, port_write_lock


def test_same_port_cannot_be_locked_by_two_remediations(tmp_path) -> None:
    with port_write_lock(tmp_path, "sw-1", 2):
        with pytest.raises(PortBusyError):
            with port_write_lock(tmp_path, "sw-1", 2):
                raise AssertionError("the second remediation must not enter")
