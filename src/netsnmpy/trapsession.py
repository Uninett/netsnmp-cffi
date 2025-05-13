"""SNMP Trap session handling"""

import logging
import platform
from ipaddress import ip_address
from socket import AF_INET, AF_INET6, inet_ntop
from typing import Optional, Protocol

from netsnmpy import _netsnmp
from netsnmpy.annotations import IPAddress
from netsnmpy.constants import (
    NETSNMP_DS_LIB_APPTYPE,
    NETSNMP_DS_LIBRARY_ID,
    SNMP_DEFAULT_COMMUNITY_LEN,
    SNMP_DEFAULT_RETRIES,
    SNMP_DEFAULT_TIMEOUT,
    SNMP_DEFAULT_VERSION,
    SNMP_SESS_UNKNOWNAUTH,
    SNMP_TRAP_AUTHFAIL,
    SNMP_TRAP_COLDSTART,
    SNMP_TRAP_EGPNEIGHBORLOSS,
    SNMP_TRAP_ENTERPRISESPECIFIC,
    SNMP_TRAP_LINKDOWN,
    SNMP_TRAP_LINKUP,
    SNMP_TRAP_PORT,
    SNMP_TRAP_WARMSTART,
    SNMP_VERSION_1,
    SNMP_VERSION_2c,
)
from netsnmpy.errors import SNMPError, UnsupportedSnmpVersionError
from netsnmpy.netsnmp import VarBindList, parse_response_variables
from netsnmpy.oids import OID
from netsnmpy.session import Session, update_event_loop

_ffi = _netsnmp.ffi
_lib = _netsnmp.lib
_log = logging.getLogger(__name__)

# Local constants
IPADDR_SIZE = 4
IP6ADDR_SIZE = 16
IPADDR_OFFSET = 0
IP6ADDR_OFFSET = _ffi.sizeof("uint32_t")  # sin6_flowinfo
if "BSD" in platform.platform():
    SOCKADDR_TYPE = "bsd_sockaddr_in"
    SA_FAMILY_TYPE = "uint8_t"
else:
    SOCKADDR_TYPE = "linux_sockaddr_in"
    SA_FAMILY_TYPE = "unsigned short"
SOCKADDR_DATA_OFFSET = _ffi.offsetof(SOCKADDR_TYPE, "sa_data")

OBJID_SNMP_TRAPS = OID(".1.3.6.1.6.3.1.1.5")
OBJID_SNMP_TRAP_OID = OID(".1.3.6.1.6.3.1.1.4.1.0")
OBJID_SYSUPTIME = OID(".1.3.6.1.2.1.1.3.0")
GENERIC_TRAP_TYPE_MAP = {
    SNMP_TRAP_COLDSTART: "coldStart",
    SNMP_TRAP_WARMSTART: "warmStart",
    SNMP_TRAP_LINKDOWN: "linkDown",
    SNMP_TRAP_LINKUP: "linkUp",
    SNMP_TRAP_AUTHFAIL: "authenticationFailure",
    SNMP_TRAP_EGPNEIGHBORLOSS: "egpNeighborLoss",
    SNMP_TRAP_ENTERPRISESPECIFIC: "enterpriseSpecific",
}


class SNMPTrapObserver(Protocol):
    def __call__(self, trap: "SNMPTrap") -> None: ...


class SNMPTrapSession(Session):
    """A high-level wrapper around a Net-SNMP trap daemon session"""

    _ds_name = _ffi.new("char[]", __name__.encode("ascii"))

    def __init__(self, host: IPAddress, port: int = SNMP_TRAP_PORT):
        """Initializes a TrapSession.

        :param host: The IP address to listen to.
        :param port: The UDP port number to listen to.
        """
        super().__init__(host, port)
        # This subclass requires the host to be given as an IP address
        self.host = ip_address(host)
        self._observers = set()

    def open(self):
        """Opens the configured trap session and starts listening for traps."""

        # This "default store" (ds) string must be set before init_usm() is called,
        # otherwise that call will segfault
        _lib.netsnmp_ds_set_string(
            NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_APPTYPE, self._ds_name
        )
        _lib.init_usm()
        _lib.netsnmp_udp_ctor()
        _lib.netsnmp_udpipv6_ctor()
        _lib.init_snmp(_ffi.new("char[]", b"netsnmpy"))
        _lib.setup_engineID(_ffi.NULL, _ffi.NULL)
        transport = _lib.netsnmp_tdomain_transport(self.peer_name.encode(), 1, b"udp")
        if not transport:
            raise SNMPError(f"Unable to create transport {self.peer_name}")
        # for some reason, cffi is picky about the type of the transport pointer,
        # even though it's the same type:
        transport = _ffi.cast("struct netsnmp_transport_s*", transport)

        sess = _ffi.new("netsnmp_session*")
        _lib.snmp_sess_init(sess)
        self.session = sess

        sess.peername = _ffi.NULL
        sess.version = SNMP_DEFAULT_VERSION
        sess.community_len = SNMP_DEFAULT_COMMUNITY_LEN
        sess.retries = SNMP_DEFAULT_RETRIES
        sess.timeout = SNMP_DEFAULT_TIMEOUT
        sess.callback = _lib._netsnmp_session_callback

        self._callback_data = _ffi.new("struct _callback_data*")
        self._callback_data.session_id = id(self)
        sess.callback_magic = self._callback_data
        self.session_map[id(self)] = self
        _log.debug("Server session created session_id=%s", id(self))

        sess.isAuthoritative = SNMP_SESS_UNKNOWNAUTH
        # snmp_add is like snmp_open, but does not use peername from the session
        # struct itself, but rather from a supplied transport specification (i.e.
        # this is how we open a socket for listening for incoming traps):
        rc = _lib.snmp_add(sess, transport, _ffi.NULL, _ffi.NULL)
        if not rc:
            raise SNMPError("snmp_add")
        update_event_loop()

    def callback(self, reqid: int, pdu: _ffi.CData):
        """Handles incoming SNMP trap PDUs

        Calls to this method are usually triggered by the global callback function,
        when it has found the appropriate session object for an incoming response.

        :param reqid: The request ID of the incoming PDU.  This is useless for trap
                      PDUs, which are unsolicited, but the same callback interface is
                      used for processing responses to outgoing requests, where the
                      mapping a response to the correct request ID is important.
        :param pdu: The incoming PDU.
        """
        _log.debug("Received a trap: %s", pdu)
        trap = SNMPTrap.from_pdu(pdu)
        _log.debug("Parsed trap: %r", trap)
        for observer in self._observers:
            observer(trap)
        update_event_loop()

    def add_observer(self, observer: SNMPTrapObserver) -> None:
        """Adds an observer function.

        The observer will be called whenever a trap is received.
        """
        self._observers.add(observer)

    def remove_observer(self, observer: SNMPTrapObserver) -> None:
        """Removes a previously added observer function"""
        try:
            self._observers.remove(observer)
        except KeyError:
            pass


class SNMPTrap:
    """A high-level representation of an SNMP trap or inform PDU, in a structure
    agnostic to SNMP v1 and SNMP v2c differences.

    The `source` and the `agent` may be different values: Source should be the source
    IP address of the received packet, while SNMP v1 traps may additionally contain
    an agent IP address in the PDU (i.e. the packet could be sent from `source` on
    behalf of `agent`).  SNMP v2c traps do not have this distinction.
    """

    def __init__(
        self,
        source: IPAddress,
        agent: IPAddress,
        generic_type: str,
        trap_oid: OID,
        uptime: int,
        community: str,
        version: str,
        variables: VarBindList,
    ):
        self.source = source
        self.agent = agent
        self.generic_type = generic_type
        self.trap_oid = trap_oid
        self.uptime = uptime
        self.community = community
        self.variables = variables
        self.version = version

    def __repr__(self):
        return (
            f"<SNMPTrap version={self.version!r} trap_oid={self.trap_oid!r} "
            f"source={self.source!r} agent={self.agent!r} community={self.community!r} "
            f"uptime={self.uptime!r} generic_type={self.generic_type!r} "
            f"variables={self.variables}>"
        )

    @classmethod
    def from_pdu(cls, pdu: _ffi.CData) -> "SNMPTrap":
        """Creates an SNMPTrap object from a Net-SNMP pdu structure."""
        variables = parse_response_variables(pdu[0])

        source = cls.get_transport_addr(pdu)
        agent_addr = generic_type = trap_oid = uptime = None
        community = _ffi.string(pdu.community).decode()

        version = pdu.version
        if version == SNMP_VERSION_1:
            version = "1"
            agent_addr = ip_address(".".join(str(octet) for octet in pdu.agent_addr))
            trap_oid, generic_type = cls.get_v1_trap_type(pdu)
            uptime = pdu.time
        elif version == SNMP_VERSION_2c:
            # TODO: This would be relevant also for SNMPv3 traps
            version = "2c"
            # SNMP v2c traps contain the sysuptime and trap oid values as part of its
            # varbinds, so we pop them off the varbind list here:
            for oid, value in variables[:]:
                if oid == OBJID_SYSUPTIME:
                    uptime = value
                    variables.remove((oid, value))
                elif oid == OBJID_SNMP_TRAP_OID:
                    trap_oid = value
                    variables.remove((oid, value))
        else:
            raise UnsupportedSnmpVersionError("Unsupported SNMP version", version)

        return cls(
            source=source,
            agent=agent_addr,
            generic_type=generic_type,
            trap_oid=trap_oid,
            uptime=uptime,
            community=community,
            version=version,
            variables=variables,
        )

    @staticmethod
    def get_transport_addr(pdu: _ffi.CData) -> Optional[IPAddress]:
        """Retrieves the IP source address from the PDU's reference to an opaque
        transport data struct.

        Only works when assuming the opaque structure is sockaddr_in and
        sockaddr_in6. It should be as long as we are only using an IPv4 or
        IPv6-based netsnmp transport (the only ones supported by this library, anyway)

        :returns: The source IP address of the trap, or None if it cannot be determined.
        """
        if pdu.transport_data_length <= 1:
            return

        # peek the first part of the pdu's opaque transport data to determine socket
        # address family (we are assuming the transport_data is a sockaddr_in or
        # sockaddr_in6 structure and accessing it naughtily here. sockaddr
        # definitions vary between platforms, further complicating this).
        sockaddr = _ffi.cast(f"{SOCKADDR_TYPE}*", pdu.transport_data)
        family = sockaddr[0].sa_family
        if family not in (AF_INET, AF_INET6):
            return

        addr_size, offset = (
            (IPADDR_SIZE, SOCKADDR_DATA_OFFSET + IPADDR_OFFSET)
            if family == AF_INET
            else (IP6ADDR_SIZE, SOCKADDR_DATA_OFFSET + IP6ADDR_OFFSET)
        )

        buffer = _ffi.cast("char*", pdu.transport_data)
        data = _ffi.unpack(buffer, pdu.transport_data_length)
        addr = data[offset : offset + addr_size]
        return ip_address(inet_ntop(family, addr))

    @staticmethod
    def get_v1_trap_type(pdu: _ffi.CData) -> tuple[OID, str]:
        """Transforms trap type information from an SNMP-v1 pdu to something that
        is consistent with SNMP-v2c, as documented in RFC2576.

        :returns: A tuple of (snmp_trap_oid, generic_type)

        """
        enterprise = OID(_ffi.unpack(pdu.enterprise, pdu.enterprise_length))
        generic_type = pdu.trap_type

        # According to RFC2576 "Coexistence between Version 1, Version 2,
        # and Version 3 of the Internet-standard Network Management
        # Framework", we build snmpTrapOID from the snmp-v1 trap by
        # combining enterprise + 0 + specific trap parameter IF the
        # generic trap parameter is 6. If not, the traps are defined as
        # 1.3.6.1.6.3.1.1.5 + (generic trap parameter + 1)
        if generic_type == SNMP_TRAP_ENTERPRISESPECIFIC:
            snmp_trap_oid = enterprise + (0, pdu.specific_type)
        else:
            snmp_trap_oid = OBJID_SNMP_TRAPS + (generic_type + 1,)

        generic_type = GENERIC_TRAP_TYPE_MAP.get(
            generic_type, str(generic_type)
        ).upper()
        return snmp_trap_oid, generic_type
