"""SNMP Trap session handling"""

import logging
from ipaddress import ip_address

from netsnmpy import _netsnmp
from netsnmpy.constants import (
    NETSNMP_DS_LIB_APPTYPE,
    NETSNMP_DS_LIBRARY_ID,
    SNMP_DEFAULT_COMMUNITY_LEN,
    SNMP_DEFAULT_RETRIES,
    SNMP_DEFAULT_TIMEOUT,
    SNMP_DEFAULT_VERSION,
    SNMP_SESS_UNKNOWNAUTH,
    SNMP_TRAP_PORT,
)
from netsnmpy.errors import SNMPError
from netsnmpy.netsnmp import parse_response_variables
from netsnmpy.session import Session, update_event_loop
from netsnmpy.types import IPAddress

_ffi = _netsnmp.ffi
_lib = _netsnmp.lib
_log = logging.getLogger(__name__)


class SNMPTrapSession(Session):
    """A high-level wrapper around a Net-SNMP trap daemon session"""

    _ds_name = _ffi.new("char[]", __name__.encode("ascii"))

    def __init__(self, host: IPAddress, port: int = SNMP_TRAP_PORT):
        """Initializes a TrapSession.

        :param host: The IP address to listen to.
        :param port: The UDP port number to listen to.
        """
        super().__init__()
        self.host = ip_address(host)
        self.port = port

    @property
    def address(self) -> str:
        if self.host.version == 6:
            return f"[{self.host}]"
        return str(self.host)

    @property
    def peer_name(self) -> str:
        return f"{self.transport_domain}:{self.address}:{self.port}"

    @property
    def transport_domain(self) -> str:
        return "udp" if self.host.version == 4 else "udp6"

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
            raise SNMPError(f"Unable to create transport {self.peername}")
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
        """
        _log.debug("Received a trap: %s", pdu)
        variables = parse_response_variables(pdu[0])
        _log.debug("Trap variables: %r", variables)
        update_event_loop()
