"""
NetMap SNMP v2 — на pysnmp (правильный ASN.1, walk, LLDP/FDB без багов).
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SnmpDevice:
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    sys_location: Optional[str] = None
    interfaces: list = field(default_factory=list)

@dataclass
class SnmpInterface:
    index: int
    name: str
    status: str  # "up" or "down"

@dataclass
class LldpNeighbor:
    local_port: int
    remote_name: str
    remote_port: str

@dataclass
class MacEntry:
    mac: str
    port: int
    vlan: Optional[int] = None

@dataclass
class SnmpTopology:
    device: SnmpDevice = field(default_factory=SnmpDevice)
    lldp_neighbors: list = field(default_factory=list)
    mac_table: list = field(default_factory=list)


class SnmpClient:
    """SNMP v2c клиент на pysnmp."""

    def __init__(self, community: str = "public", timeout: float = 2.0):
        self.community = community
        self.timeout = timeout

    def _cmdgen(self):
        from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData
        return SnmpEngine(), CommunityData(self.community, mpModel=1), UdpTransportTarget(('', 161), timeout=int(self.timeout), retries=0), ContextData()

    def probe(self, target: str) -> bool:
        from pysnmp.hlapi.v1arch import get_cmd as getCmd, ObjectType, ObjectIdentity
        try:
            g = getCmd(*self._cmdgen()[:2],
                       UdpTransportTarget((target, 161), timeout=int(self.timeout), retries=0),
                       *self._cmdgen()[3:],
                       ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
            errorIndication, errorStatus, errorIndex, varBinds = next(g)
            return errorIndication is None and errorStatus == 0
        except Exception:
            return False

    def discover(self, target: str) -> SnmpDevice:
        dev = SnmpDevice()
        dev.sys_name = self._get_string(target, '1.3.6.1.2.1.1.5.0')
        dev.sys_descr = self._get_string(target, '1.3.6.1.2.1.1.1.0')
        dev.sys_location = self._get_string(target, '1.3.6.1.2.1.1.6.0')

        for i in range(1, 53):
            name = self._get_string(target, f'1.3.6.1.2.1.2.2.1.2.{i}')
            if name is None:
                continue
            status_val = self._get_integer(target, f'1.3.6.1.2.1.2.2.1.8.{i}')
            status = "up" if status_val == 1 else "down"
            dev.interfaces.append(SnmpInterface(index=i, name=name, status=status))
        return dev

    def walk(self, target: str, base_oid: str) -> list:
        """Walk OID tree. Returns list of (oid_str, value)."""
        from pysnmp.hlapi.v1arch import next_cmd as nextCmd, ObjectType, ObjectIdentity
        results = []
        try:
            g = nextCmd(*self._cmdgen()[:2],
                        UdpTransportTarget((target, 161), timeout=int(self.timeout), retries=0),
                        *self._cmdgen()[3:],
                        ObjectType(ObjectIdentity(base_oid)),
                        lexicographicMode=False)
            for errorIndication, errorStatus, errorIndex, varBinds in g:
                if errorIndication or errorStatus:
                    break
                for varBind in varBinds:
                    oid_str = str(varBind[0])
                    val = varBind[1].prettyPrint()
                    if not oid_str.startswith(base_oid):
                        return results
                    results.append((oid_str, val))
        except Exception:
            pass
        return results

    def get_lldp_neighbors(self, target: str) -> list:
        """LLDP-соседи через pysnmp."""
        neighbors = []
        base = '1.0.8802.1.1.2.1.4.1.1'
        entries = {}

        for oid_str, val in self.walk(target, base):
            parts = [int(x) for x in oid_str.split('.')]
            base_parts = base.split('.')
            tail = parts[len(base_parts):]
            if len(tail) < 4:
                continue
            time_mark = tail[0]
            local_port = tail[1]
            rem_index = tail[2]
            column = tail[3]
            key = (time_mark, local_port, rem_index)

            if column == 6:  # lldpRemSysName
                entries.setdefault(key, {})["name"] = str(val)
            elif column == 4:  # lldpRemPortId
                entries.setdefault(key, {})["port"] = str(val)
            elif column == 5:  # lldpRemPortDesc
                entries.setdefault(key, {})["port_desc"] = str(val)

        for key, info in entries.items():
            local_port = key[1]
            name = info.get("name", "")
            port = info.get("port") or info.get("port_desc", "")
            neighbors.append((local_port, name, port))

        return neighbors

    def get_fdb(self, target: str) -> list:
        """MAC-таблица через pysnmp."""
        entries = []
        base = '1.3.6.1.2.1.17.7.1.2.2.1'
        for oid_str, val in self.walk(target, base):
            parts = [int(x) for x in oid_str.split('.')]
            base_parts = base.split('.')
            tail = parts[len(base_parts):]
            if len(tail) < 8:
                continue
            vlan = tail[0]
            mac_bytes = bytes(tail[1:7])
            mac = ":".join(f"{b:02x}" for b in mac_bytes)
            column = tail[7]

            if column == 2:  # dot1qTpFdbPort
                try:
                    port = int(val)
                    entries.append((vlan, mac, port))
                except ValueError:
                    pass
        return entries

    def discover_topology(self, target: str) -> SnmpTopology:
        return SnmpTopology(
            device=self.discover(target),
            lldp_neighbors=[LldpNeighbor(local_port=p, remote_name=n, remote_port=rp)
                            for p, n, rp in self.get_lldp_neighbors(target)],
            mac_table=[MacEntry(mac=m, port=p, vlan=v)
                       for v, m, p in self.get_fdb(target)],
        )

    def _get_string(self, target: str, oid: str) -> Optional[str]:
        from pysnmp.hlapi.v1arch import get_cmd as getCmd, ObjectType, ObjectIdentity
        try:
            g = getCmd(*self._cmdgen()[:2],
                       UdpTransportTarget((target, 161), timeout=int(self.timeout), retries=0),
                       *self._cmdgen()[3:],
                       ObjectType(ObjectIdentity(oid)))
            errorIndication, errorStatus, errorIndex, varBinds = next(g)
            if errorIndication or errorStatus:
                return None
            for varBind in varBinds:
                val = str(varBind[1])
                if val:
                    return val
        except Exception:
            pass
        return None

    def _get_integer(self, target: str, oid: str) -> Optional[int]:
        from pysnmp.hlapi.v1arch import get_cmd as getCmd, ObjectType, ObjectIdentity
        try:
            g = getCmd(*self._cmdgen()[:2],
                       UdpTransportTarget((target, 161), timeout=int(self.timeout), retries=0),
                       *self._cmdgen()[3:],
                       ObjectType(ObjectIdentity(oid)))
            errorIndication, errorStatus, errorIndex, varBinds = next(g)
            if errorIndication or errorStatus:
                return None
            for varBind in varBinds:
                return int(varBind[1])
        except Exception:
            pass
        return None
