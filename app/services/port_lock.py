"""Small cross-process lock used to serialize disruptive writes per port."""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class PortBusyError(RuntimeError):
    pass


@contextmanager
def port_write_lock(directory: Path, switch_id: str, port_index: int) -> Iterator[None]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    safe_switch = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in switch_id)
    path = directory / f"{safe_switch}-{int(port_index)}.lock"
    handle = path.open("a+b")
    try:
        _lock(handle)
        yield
    finally:
        _unlock(handle)
        handle.close()


def _lock(handle) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError) as exc:
        raise PortBusyError("Another remediation is already acting on this port.") from exc


def _unlock(handle) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
