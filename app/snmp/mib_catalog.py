from dataclasses import dataclass, replace


@dataclass(frozen=True)
class MibObjectRef:
    module: str
    symbol: str
    indices: tuple[int, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.module}::{self.symbol}"

    def with_indices(self, *indices: int) -> "MibObjectRef":
        return replace(self, indices=tuple(int(value) for value in indices))


@dataclass(frozen=True)
class MibProbe:
    object_ref: MibObjectRef
    source: str

    @property
    def mib(self) -> str:
        return self.object_ref.module

    @property
    def object_name(self) -> str:
        return self.object_ref.symbol


SYS_UP_TIME = MibObjectRef("SNMPv2-MIB", "sysUpTime", (0,))
SYS_NAME = MibObjectRef("SNMPv2-MIB", "sysName", (0,))
IF_NAME = MibObjectRef("IF-MIB", "ifName")
IF_DESCR = MibObjectRef("IF-MIB", "ifDescr")
IF_ADMIN_STATUS = MibObjectRef("IF-MIB", "ifAdminStatus")
IF_OPER_STATUS = MibObjectRef("IF-MIB", "ifOperStatus")
IF_LAST_CHANGE = MibObjectRef("IF-MIB", "ifLastChange")
DOT1D_TP_FDB_ADDRESS = MibObjectRef("BRIDGE-MIB", "dot1dTpFdbAddress")
DOT1D_TP_FDB_PORT = MibObjectRef("BRIDGE-MIB", "dot1dTpFdbPort")
DOT1D_BASE_PORT_IF_INDEX = MibObjectRef(
    "BRIDGE-MIB", "dot1dBasePortIfIndex"
)
DOT1D_STP_PORT_STATE = MibObjectRef("BRIDGE-MIB", "dot1dStpPortState")
DOT1Q_TP_FDB_PORT = MibObjectRef("Q-BRIDGE-MIB", "dot1qTpFdbPort")
DOT1Q_PVID = MibObjectRef("Q-BRIDGE-MIB", "dot1qPvid")
DOT1Q_VLAN_CURRENT_EGRESS_PORTS = MibObjectRef(
    "Q-BRIDGE-MIB", "dot1qVlanCurrentEgressPorts"
)
IP_NET_TO_PHYSICAL_ADDRESS = MibObjectRef(
    "IP-MIB", "ipNetToPhysicalPhysAddress"
)

REQUIRED_MIB_MODULES: tuple[str, ...] = (
    "SNMPv2-MIB",
    "IF-MIB",
    "BRIDGE-MIB",
    "Q-BRIDGE-MIB",
)

WARMUP_OBJECTS: tuple[MibObjectRef, ...] = (
    SYS_NAME,
    SYS_UP_TIME,
    DOT1Q_TP_FDB_PORT,
    DOT1D_BASE_PORT_IF_INDEX,
    IF_DESCR,
    DOT1Q_PVID,
)

MIB_PROBES: tuple[MibProbe, ...] = (
    MibProbe(IF_NAME, "RFC 2863"),
    MibProbe(IF_DESCR, "RFC 2863"),
    MibProbe(IF_ADMIN_STATUS, "RFC 2863"),
    MibProbe(IF_OPER_STATUS, "RFC 2863"),
    MibProbe(IF_LAST_CHANGE, "RFC 2863"),
    MibProbe(DOT1D_TP_FDB_ADDRESS, "RFC 4188"),
    MibProbe(DOT1D_TP_FDB_PORT, "RFC 4188"),
    MibProbe(DOT1D_BASE_PORT_IF_INDEX, "RFC 4188"),
    MibProbe(DOT1D_STP_PORT_STATE, "RFC 4188"),
    MibProbe(DOT1Q_TP_FDB_PORT, "RFC 4363"),
    MibProbe(DOT1Q_PVID, "RFC 4363"),
    MibProbe(DOT1Q_VLAN_CURRENT_EGRESS_PORTS, "RFC 4363"),
    MibProbe(IP_NET_TO_PHYSICAL_ADDRESS, "RFC 4293"),
)
