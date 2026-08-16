from __future__ import annotations

import os
from dataclasses import dataclass, field

from .mib_catalog import DOT1Q_PVID, IF_ADMIN_STATUS, MibObjectRef
from .mib_registry import MibRegistry


class SnmpClientError(RuntimeError):
    pass


class SnmpUnsupportedObject(SnmpClientError):
    pass


class SnmpTransportError(SnmpClientError):
    pass


class SnmpWriteBlocked(SnmpClientError):
    pass


@dataclass(frozen=True)
class SnmpWalkEntry:
    object_ref: MibObjectRef
    oid: tuple[int, ...]
    suffix: tuple[int, ...]
    value: str


@dataclass(frozen=True)
class SnmpV3Config:
    host: str
    username: str
    auth_key: str = field(repr=False)
    priv_key: str = field(repr=False)
    port: int = 161
    auth_protocol: str = "SHA256"
    priv_protocol: str = "AES256"
    timeout_seconds: float = 2.0
    retries: int = 1

    @classmethod
    def from_env(cls, host: str | None = None) -> "SnmpV3Config":
        config = cls(
            host=(host or os.getenv("SNMP_HOST", "")).strip(),
            port=int(os.getenv("SNMP_PORT", "161")),
            username=os.getenv("SNMP_USERNAME", "").strip(),
            auth_key=os.getenv("SNMP_AUTH_KEY", ""),
            priv_key=os.getenv("SNMP_PRIV_KEY", ""),
            auth_protocol=os.getenv("SNMP_AUTH_PROTOCOL", "SHA256").strip().upper(),
            priv_protocol=os.getenv("SNMP_PRIV_PROTOCOL", "AES256").strip().upper(),
            timeout_seconds=float(os.getenv("SNMP_TIMEOUT_SECONDS", "2")),
            retries=int(os.getenv("SNMP_RETRIES", "1")),
        )
        config.validate()
        return config

    def validate(self) -> None:
        missing = [
            name
            for name, value in (
                ("SNMP_HOST", self.host),
                ("SNMP_USERNAME", self.username),
                ("SNMP_AUTH_KEY", self.auth_key),
                ("SNMP_PRIV_KEY", self.priv_key),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"Incomplete SNMPv3 configuration: {', '.join(missing)}")
        if self.auth_protocol != "SHA256":
            raise ValueError("SNMP_AUTH_PROTOCOL must be SHA256.")
        if self.priv_protocol != "AES256":
            raise ValueError("SNMP_PRIV_PROTOCOL must be AES256.")


class SnmpReadClient:
    """Client SNMPv3 authPriv limite aux lectures symboliques locales."""

    def __init__(self, config: SnmpV3Config, mib_registry: MibRegistry) -> None:
        self.config = config
        self.mib_registry = mib_registry

    async def read_scalar(self, object_ref: MibObjectRef) -> str:
        api = _pysnmp_api()
        engine = api["SnmpEngine"]()
        try:
            resolved = self.mib_registry.resolve(object_ref)
            target = await api["UdpTransportTarget"].create(
                (self.config.host, self.config.port),
                timeout=self.config.timeout_seconds,
                retries=self.config.retries,
            )
            result = await api["get_cmd"](
                engine,
                self._credentials(api),
                target,
                api["ContextData"](),
                api["ObjectType"](api["ObjectIdentity"](resolved.oid)),
            )
            return self._extract_value(result, api)
        finally:
            engine.close_dispatcher()

    async def read_first(
        self, column_ref: MibObjectRef
    ) -> tuple[str, str]:
        entries = await self.walk(column_ref, max_rows=1)
        if not entries:
            raise SnmpUnsupportedObject("No instance returned.")
        entry = entries[0]
        return ".".join(str(part) for part in entry.oid), entry.value

    async def walk(
        self,
        column_ref: MibObjectRef,
        *,
        max_rows: int = 4096,
    ) -> list[SnmpWalkEntry]:
        api = _pysnmp_api()
        engine = api["SnmpEngine"]()
        resolved = self.mib_registry.resolve(column_ref)
        entries: list[SnmpWalkEntry] = []
        try:
            target = await api["UdpTransportTarget"].create(
                (self.config.host, self.config.port),
                timeout=self.config.timeout_seconds,
                retries=self.config.retries,
            )
            iterator = api["walk_cmd"](
                engine,
                self._credentials(api),
                target,
                api["ContextData"](),
                api["ObjectType"](api["ObjectIdentity"](resolved.oid)),
                lexicographicMode=False,
            )
            async for result in iterator:
                error_indication, error_status, error_index, var_binds = result
                self._raise_protocol_errors(
                    error_indication, error_status, error_index
                )
                if not var_binds:
                    break
                name, value = var_binds[0]
                oid = tuple(int(part) for part in name)
                if oid[: len(resolved.oid)] != resolved.oid:
                    break
                if isinstance(
                    value,
                    (
                        api["NoSuchObject"],
                        api["NoSuchInstance"],
                        api["EndOfMibView"],
                    ),
                ):
                    break
                entries.append(
                    SnmpWalkEntry(
                        object_ref=column_ref,
                        oid=oid,
                        suffix=oid[len(resolved.oid) :],
                        value=value.prettyPrint(),
                    )
                )
                if len(entries) >= max_rows:
                    break
            return entries
        finally:
            engine.close_dispatcher()

    def _credentials(self, api: dict):
        auth_protocols = {"SHA256": api["usmHMAC192SHA256AuthProtocol"]}
        privacy_protocols = {"AES256": api["usmAesCfb256Protocol"]}
        return api["UsmUserData"](
            self.config.username,
            authKey=self.config.auth_key,
            privKey=self.config.priv_key,
            authProtocol=auth_protocols[self.config.auth_protocol],
            privProtocol=privacy_protocols[self.config.priv_protocol],
        )

    def _extract_value(self, result: tuple, api: dict) -> str:
        error_indication, error_status, error_index, var_binds = result
        self._raise_protocol_errors(error_indication, error_status, error_index)
        if not var_binds:
            raise SnmpUnsupportedObject("No value returned.")
        value = var_binds[0][1]
        if isinstance(
            value,
            (api["NoSuchObject"], api["NoSuchInstance"], api["EndOfMibView"]),
        ):
            raise SnmpUnsupportedObject(value.prettyPrint())
        return value.prettyPrint()

    @staticmethod
    def _raise_protocol_errors(error_indication, error_status, error_index) -> None:
        if error_indication:
            raise SnmpTransportError(str(error_indication))
        if error_status:
            index = int(error_index or 0)
            message = error_status.prettyPrint()
            if message in {"noSuchName", "noAccess", "notWritable"}:
                raise SnmpUnsupportedObject(f"{message} at index {index}")
            raise SnmpClientError(f"{message} at index {index}")


class SnmpRemediationClient(SnmpReadClient):
    """Controlled integer SET transport; capability policy is enforced upstream."""

    def __init__(
        self,
        config: SnmpV3Config,
        mib_registry: MibRegistry,
        *,
        dry_run: bool | None = None,
    ) -> None:
        super().__init__(config, mib_registry)
        if dry_run is None:
            raw = os.getenv("DRY_RUN", "false").strip().lower()
            dry_run = raw not in {"0", "false", "no", "non", "off"}
        self.dry_run = bool(dry_run)

    async def set_integer(
        self,
        object_ref: MibObjectRef,
        value: int,
        *,
        write_authorized: bool,
    ) -> str:
        if self.dry_run:
            raise SnmpWriteBlocked("DRY_RUN blocks every SNMP SET.")
        if not write_authorized:
            raise SnmpWriteBlocked("SET rejected without explicit authorization.")
        allowed_objects = {DOT1Q_PVID.key, IF_ADMIN_STATUS.key}
        if object_ref.key not in allowed_objects or not object_ref.indices:
            raise SnmpWriteBlocked(
                f"Object not enabled for a controlled SET: {object_ref.key}"
            )
        api = _pysnmp_api()
        engine = api["SnmpEngine"]()
        try:
            resolved = self.mib_registry.resolve(object_ref)
            target = await api["UdpTransportTarget"].create(
                (self.config.host, self.config.port),
                timeout=self.config.timeout_seconds,
                retries=self.config.retries,
            )
            result = await api["set_cmd"](
                engine,
                self._credentials(api),
                target,
                api["ContextData"](),
                api["ObjectType"](
                    api["ObjectIdentity"](resolved.oid),
                    api["Integer32"](int(value)),
                ),
            )
            return self._extract_value(result, api)
        finally:
            engine.close_dispatcher()


def _pysnmp_api() -> dict:
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            get_cmd,
            set_cmd,
            walk_cmd,
            usmAesCfb256Protocol,
            usmHMAC192SHA256AuthProtocol,
        )
        from pysnmp.proto.rfc1902 import Integer32
        from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject
    except ImportError as exc:
        raise RuntimeError(
            "PySNMP 7.1+ is required. Install the project dependencies."
        ) from exc

    return {
        "ContextData": ContextData,
        "ObjectIdentity": ObjectIdentity,
        "ObjectType": ObjectType,
        "SnmpEngine": SnmpEngine,
        "UdpTransportTarget": UdpTransportTarget,
        "UsmUserData": UsmUserData,
        "get_cmd": get_cmd,
        "set_cmd": set_cmd,
        "walk_cmd": walk_cmd,
        "usmAesCfb256Protocol": usmAesCfb256Protocol,
        "usmHMAC192SHA256AuthProtocol": usmHMAC192SHA256AuthProtocol,
        "Integer32": Integer32,
        "EndOfMibView": EndOfMibView,
        "NoSuchInstance": NoSuchInstance,
        "NoSuchObject": NoSuchObject,
    }
