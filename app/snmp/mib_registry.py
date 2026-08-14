from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.util import find_spec
from pathlib import Path
from threading import RLock
import warnings

from pysnmp.smi import builder, view
from pysnmp.smi.rfc1902 import ObjectIdentity

from .mib_catalog import MibObjectRef, REQUIRED_MIB_MODULES, WARMUP_OBJECTS


class MibRegistryError(RuntimeError):
    pass


class MibNotReadyError(MibRegistryError):
    pass


@dataclass(frozen=True)
class ResolvedMibObject:
    object_ref: MibObjectRef
    oid: tuple[int, ...]

    @property
    def symbolic_name(self) -> str:
        return self.object_ref.key


@dataclass(frozen=True)
class MibWarmupStatus:
    ready: bool
    package: str
    local_path: str | None
    resolved_objects: int
    warmed_at: str | None
    error: str | None


class MibRegistry:
    """Charge les MIB locales et met en cache leur resolution symbolique."""

    def __init__(
        self,
        *,
        package: str = "pysnmp_mibs",
        local_path: Path | None = None,
    ) -> None:
        self.package = package
        self.local_path = Path(local_path) if local_path else None
        self._builder: builder.MibBuilder | None = None
        self._view: view.MibViewController | None = None
        self._base_oids: dict[tuple[str, str], tuple[int, ...]] = {}
        self._status = MibWarmupStatus(
            ready=False,
            package=package,
            local_path=str(self.local_path) if self.local_path else None,
            resolved_objects=0,
            warmed_at=None,
            error="warmup_not_run",
        )
        self._lock = RLock()

    @property
    def status(self) -> MibWarmupStatus:
        return self._status

    def warm_up(self) -> MibWarmupStatus:
        with self._lock:
            try:
                if find_spec(self.package) is None:
                    raise MibRegistryError(
                        f"Paquet MIB preinstalle introuvable: {self.package}"
                    )
                mib_builder = builder.MibBuilder()
                sources: list[builder.AbstractMibSource] = [
                    builder.ZipMibSource(self.package)
                ]
                if self.local_path:
                    if not self.local_path.is_dir():
                        raise MibRegistryError(
                            f"Repertoire MIB local introuvable: {self.local_path}"
                        )
                    sources.insert(0, builder.DirMibSource(str(self.local_path)))
                mib_builder.add_mib_sources(*sources)
                # Le paquet precompile historique emet des avertissements de
                # compatibilite, sans empecher PySNMP 7 de charger les MIB.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    mib_builder.load_modules(*REQUIRED_MIB_MODULES)
                mib_view = view.MibViewController(mib_builder)

                self._base_oids.clear()
                for object_ref in WARMUP_OBJECTS:
                    self._resolve_base(object_ref, mib_view)

                self._builder = mib_builder
                self._view = mib_view
                self._status = MibWarmupStatus(
                    ready=True,
                    package=self.package,
                    local_path=(
                        str(self.local_path) if self.local_path else None
                    ),
                    resolved_objects=len(self._base_oids),
                    warmed_at=datetime.now(timezone.utc).isoformat(),
                    error=None,
                )
            except Exception as exc:
                self._builder = None
                self._view = None
                self._base_oids.clear()
                self._status = MibWarmupStatus(
                    ready=False,
                    package=self.package,
                    local_path=(
                        str(self.local_path) if self.local_path else None
                    ),
                    resolved_objects=0,
                    warmed_at=None,
                    error=str(exc),
                )
            return self._status

    def resolve(self, object_ref: MibObjectRef) -> ResolvedMibObject:
        if not self._status.ready or self._view is None:
            raise MibNotReadyError(
                f"Contexte MIB indisponible: {self._status.error}"
            )
        with self._lock:
            key = (object_ref.module, object_ref.symbol)
            base_oid = self._base_oids.get(key)
            if base_oid is None:
                base_oid = self._resolve_base(object_ref, self._view)
            return ResolvedMibObject(
                object_ref=object_ref,
                oid=base_oid + object_ref.indices,
            )

    def _resolve_base(
        self,
        object_ref: MibObjectRef,
        mib_view: view.MibViewController,
    ) -> tuple[int, ...]:
        key = (object_ref.module, object_ref.symbol)
        try:
            identity = ObjectIdentity(*key).resolve_with_mib(mib_view)
            oid = tuple(int(part) for part in identity.get_oid())
        except Exception as exc:
            raise MibRegistryError(
                f"Resolution MIB impossible pour {object_ref.key}: {exc}"
            ) from exc
        self._base_oids[key] = oid
        return oid
