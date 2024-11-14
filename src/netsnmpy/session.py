import logging
from ipaddress import IPv4Address, IPv6Address
from typing import Union

import _netsnmp
from pysnmp.proto.rfc1905 import VarBindList

from netsnmpy.constants import (
    SNMP_MSG_GET,
    SNMP_MSG_GETBULK,
    SNMP_MSG_GETNEXT,
    SNMP_VERSION_1,
    SNMP_VERSION_3,
    SNMPERR_TIMEOUT,
    SNMP_VERSION_2c,
    SNMP_VERSION_2p,
    SNMP_VERSION_2star,
    SNMP_VERSION_2u,
    SNMP_VERSION_sec,
)
from netsnmpy.netsnmp import (
    log_session_error,
    make_request_pdu,
    parse_response_variables,
)
from netsnmpy.oids import OID

_ffi = _netsnmp.ffi
_lib = _netsnmp.lib
_log = logging.getLogger(__name__)

# TODO: Move these constants to a separate module
STAT_SUCCESS = 0
STAT_ERROR = 1
STAT_TIMEOUT = 2

SNMP_VERSION_MAP = {
    "v1": SNMP_VERSION_1,
    "1": SNMP_VERSION_1,
    1: SNMP_VERSION_1,
    "v2c": SNMP_VERSION_2c,
    "2": SNMP_VERSION_2c,
    2: SNMP_VERSION_2c,
    "2c": SNMP_VERSION_2c,
    "v2u": SNMP_VERSION_2u,
    "v3": SNMP_VERSION_3,
    "3": SNMP_VERSION_3,
    3: SNMP_VERSION_3,
    "sec": SNMP_VERSION_sec,
    "2p": SNMP_VERSION_2p,
    "2star": SNMP_VERSION_2star,
}

Host = Union[str, IPv4Address, IPv6Address]
SnmpVersion = Union[str, int]


class SNMPSession:
    def __init__(
        self,
        host: Host,
        port: int = 161,
        community: str = "public",
        version: SnmpVersion = 1,
        timeout: float = 1.5,
        retries: int = 3,
    ):
        self.host = host
        self.port = port
        self.community = community
        if version not in SNMP_VERSION_MAP:
            raise ValueError(f"Invalid SNMP version: {version}")
        self.version = version
        self.timeout = timeout
        self.retries = retries
        self.session = None
        self._original_session = None

    def open(self):
        """Opens the SNMP session"""
        session = _ffi.new("netsnmp_session*")
        _lib.snmp_sess_init(session)
        session.version = SNMP_VERSION_MAP[self.version]
        # Net-SNMP uses microseconds for timeouts
        session.timeout = int(self.timeout * 1000000)
        session.retries = self.retries

        # TODO: This needs to be a bit more complicated for SNMPv3 compatibility:
        community = self.community.encode("utf-8")
        community_c = _ffi.new("char[]", community)
        session.community = community_c
        session.community_len = len(community)

        # TODO: This needs to be a bit more complicated for IPv6 compatibility:
        peername = f"udp:{self.host}:{self.port}".encode("utf-8")
        peername_c = _ffi.new("char[]", peername)
        session.peername = peername_c

        # Net-SNMP returns a copy of the session struct.  No modifications of the
        # original session struct will make a difference after this point.
        session_copy = _lib.snmp_open(session)
        if not session_copy:
            # TODO: Raise a better exception
            log_session_error("SNMPSession", session)
            raise Exception("snmp_open")
        self._original_session = session
        self.session = session_copy

    def close(self):
        """Closes the SNMP session"""
        if not self.session:
            return
        _lib.snmp_close(self.session)
        self.session = None
        self._original_session = None

    def get(self, *oids: OID) -> VarBindList:
        """Performs a synchronous SNMP GET request"""
        request = make_request_pdu(SNMP_MSG_GET, *oids)
        return self._send_and_wait_for_response(request)

    def getnext(self, *oids: OID) -> VarBindList:
        """Performs a synchronous SNMP GET-NEXT request"""
        request = make_request_pdu(SNMP_MSG_GETNEXT, *oids)
        return self._send_and_wait_for_response(request)

    def getbulk(self, *oids: OID, non_repeaters: int = 0, max_repetitions: int = 5):
        """Performs a synchronous SNMP GET-BULK request"""
        request = make_request_pdu(SNMP_MSG_GETBULK, *oids)
        # These two PDU fields are overloaded for GET-BULK requests
        request.errstat = non_repeaters
        request.errindex = max_repetitions
        return self._send_and_wait_for_response(request)

    def _send_and_wait_for_response(self, request: _ffi.CData) -> VarBindList:
        """Sends an SNMP request and blocks until a response is received"""
        response = _ffi.new("netsnmp_pdu**")
        code = _lib.snmp_synch_response(self.session, request, response)

        # TODO: Raise better exceptions
        # TODO: Handle errors in response packets
        if code == STAT_SUCCESS:
            response_pdu = response[0]
            variables = parse_response_variables(response_pdu)
            # Suspect the following is useless, since we allocated the PDU using CFFI
            # _lib.snmp_free_pdu(response_pdu)
            return variables
        elif code == STAT_TIMEOUT:
            raise TimeoutError("snmp_sess_synch_response")
        else:
            raise Exception(f"snmp_sess_synch_response == {code}")

    def walk(self, oid):
        raise NotImplementedError

    def set(self, oid, value, type):
        raise NotImplementedError

    def __del__(self):
        self.close()
