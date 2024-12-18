import asyncio
import logging
from asyncio import Future
from ipaddress import IPv4Address, IPv6Address
from typing import Union

import _netsnmp
from pysnmp.proto.rfc1905 import VarBindList

from netsnmpy.constants import (
    NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
    NETSNMP_CALLBACK_OP_TIMED_OUT,
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
from netsnmpy.errors import SNMPError
from netsnmpy.netsnmp import (
    fd_to_large_fd_set,
    log_session_error,
    make_request_pdu,
    parse_response_variables,
    snmp_select_info2,
)
from netsnmpy.oids import OID

_ffi = _netsnmp.ffi
_lib = _netsnmp.lib
_log = logging.getLogger(__name__)
_callback_log = logging.getLogger(__name__ + ".callback")
_fd_map = {}
_timeout_timer: asyncio.TimerHandle = None

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
    """A high-level wrapper around a Net-SNMP session"""

    # This keeps track of sessions to ensure the Net-SNMP callback function knows
    # which Python session object to associate incoming SNMP responses with
    session_map: dict[int, "SNMPSession"] = {}

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
        self._callback_data = None
        self._futures: dict[int, Future] = {}

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

        # Set up the callback function to handle incoming SNMP responses
        session.callback = _lib._netsnmp_session_callback
        self._callback_data = _ffi.new("struct _callback_data*")
        self._callback_data.session_id = id(self)
        session.callback_magic = self._callback_data

        # Net-SNMP returns a copy of the session struct.  No modifications of the
        # original session struct will make a difference after this point.
        session_copy = _lib.snmp_open(session)
        if not session_copy:
            # TODO: Raise a better exception
            log_session_error("SNMPSession", session)
            raise Exception("snmp_open")
        self._original_session = session
        self.session = session_copy
        self.session_map[id(self)] = self

        update_event_loop()

    def close(self):
        """Closes the SNMP session"""
        if not self.session:
            return
        _lib.snmp_close(self.session)
        self.session = None
        self._original_session = None
        self.session_map.pop(id(self), None)

        update_event_loop()

    def get(self, *oids: OID) -> VarBindList:
        """Performs a synchronous SNMP GET request"""
        request = make_request_pdu(SNMP_MSG_GET, *oids)
        return self._send_and_wait_for_response(request)

    async def aget(self, *oids: OID) -> VarBindList:
        """Performs an asynchronous SNMP GET request"""
        request = make_request_pdu(SNMP_MSG_GET, *oids)
        return await self._send_async(request, "get")

    def getnext(self, *oids: OID) -> VarBindList:
        """Performs a synchronous SNMP GET-NEXT request"""
        request = make_request_pdu(SNMP_MSG_GETNEXT, *oids)
        return self._send_and_wait_for_response(request)

    async def agetnext(self, *oids: OID) -> VarBindList:
        """Performs an asynchronous SNMP GET-NEXT request"""
        request = make_request_pdu(SNMP_MSG_GETNEXT, *oids)
        return await self._send_async(request, "getnext")

    def getbulk(self, *oids: OID, non_repeaters: int = 0, max_repetitions: int = 5):
        """Performs a synchronous SNMP GET-BULK request"""
        request = make_request_pdu(SNMP_MSG_GETBULK, *oids)
        # These two PDU fields are overloaded for GET-BULK requests
        request.errstat = non_repeaters
        request.errindex = max_repetitions
        return self._send_and_wait_for_response(request)

    async def agetbulk(
        self, *oids: OID, non_repeaters: int = 0, max_repetitions: int = 5
    ):
        """Performs an asynchronous SNMP GET-BULK request"""
        request = make_request_pdu(SNMP_MSG_GETBULK, *oids)
        # These two PDU fields are overloaded for GET-BULK requests
        request.errstat = non_repeaters
        request.errindex = max_repetitions
        return await self._send_async(request, "getbulk")

    def _send_async(
        self, request: _ffi.CData, send_type_for_logging: str = None
    ) -> Future:
        """Sends an SNMP request asynchronously"""
        code = _lib.snmp_send(self.session, request)
        self._handle_send_status(request, code, send_type_for_logging)

        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._futures[request.reqid] = future
        update_event_loop()

        return future

    def _handle_send_status(
        self, request: _ffi.CData, send_status: int, send_type_for_logging: str = None
    ):
        """Handles errors flagged by return values of `snmp_send` calls by raising an
        appropriate exception.

        :param send_status: The return value of the `snmp_send` call.  A value of 0
                            indicates an error.  Anything else is usually a request ID
                            and is ignored by this method.
        """
        if send_status != 0:
            return
        c_library_error = _ffi.new("int*")
        snmp_error = _ffi.new("int*")
        error_string = _ffi.new("char**")
        _lib.snmp_error(self.session, c_library_error, snmp_error, error_string)
        # On error we need to free the PDU struct ourselves
        _lib.snmp_free_pdu(request)

        if error_string[0] != _ffi.NULL:
            error_string = _ffi.string(error_string[0]).decode("utf-8")
        else:
            error_string = None
        msg_fmt = "%s: snmp_send cliberr=%s, snmperr=%s, errstring=%s"
        msg_args = (
            send_type_for_logging,
            c_library_error[0],
            snmp_error[0],
            error_string,
        )
        _log.debug(msg_fmt, *msg_args)
        if snmp_error[0] == SNMPERR_TIMEOUT:
            # TODO: Check whether this happens for initial SNMPv3 requests (i.e.
            #  Net-SNMP performs an asynchronouse engine ID discovery that could time
            #  out)
            raise TimeoutError()
        raise SNMPError(msg_fmt % msg_args)

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

    def callback(self, reqid: int, pdu: _ffi.CData):
        """Handles incoming SNMP responses and updates futures.

        Calls to this method are usually triggered by the global callback function,
        when it has found the appropriate session object for an incoming response.
        """
        _log.debug("Got a callback for session with %s", self.host)
        future = self._futures.pop(reqid, None)
        if future is None:
            _log.error("Received SNMP response for unknown request ID %s", reqid)
            return

        variables = parse_response_variables(pdu[0])
        future.set_result(variables)

    def handle_timeout(self, reqid: int):
        """Handles an SNMP timeout.

        This is usually called by the global callback function when a timeout occurs.
        It maps the request timeout to the appropriate future object and sets an
        exception on it.
        """
        _log.debug("Got a timeout for session with %s", self.host)
        future = self._futures.pop(reqid, None)
        if future is None:
            _log.error("Received timeout for unknown request ID %s", reqid)
            return

        future.set_exception(TimeoutError())

    def walk(self, oid):
        raise NotImplementedError

    def set(self, oid, value, type):
        raise NotImplementedError

    def __del__(self):
        self.close()


@_ffi.def_extern()
def _netsnmp_session_callback(
    operation: int, session: _ffi.CData, reqid: int, pdu: _ffi.CData, magic: _ffi.CData
) -> int:
    """Callback function to handle SNMP responses.

    Individual sessions, or even requests (using `snmp_async_send`), can define their
    own callback functions, but according to the CFFI docs, dynamic callbacks in Python
    are less efficient than statically declared ones.  This is why we use a single
    callback function and keep a session map in order to route incoming SNMP responses
    to the correct Python session object.
    """
    callback_data = _ffi.cast("_callback_data*", magic)
    session = SNMPSession.session_map.get(callback_data.session_id)
    if session is None:
        _callback_log.error("Received SNMP response for unknown session")
        return 1

    try:
        if operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
            session.callback(reqid, pdu)
        elif operation == NETSNMP_CALLBACK_OP_TIMED_OUT:
            session.handle_timeout(reqid)
        else:
            _callback_log.error("Unknown operation: %s", operation)
    except Exception as error:
        _callback_log.exception(
            "Session callback raised an unexpected exception: %s", error
        )
    return 1


class SNMPReader:
    """An SNMPReader is only responsible for calling the Net-SNMP read function
    when its associated socket is ready to be read from.
    """

    def __init__(self, fd: int):
        self.fd = fd

    def __call__(self):
        # TODO: Instead of creating and cleaning the fdset on every read operation, consider
        #  keeping it around for the lifetime of the SNMPReader
        fdset = fd_to_large_fd_set(self.fd)
        _lib.snmp_read2(fdset)
        _lib.netsnmp_large_fd_set_cleanup(fdset)


def update_event_loop():
    """Ensures the asyncio event loop is informed on which file descriptors to monitor
    for Net-SNMP events.
    """
    global _timeout_timer
    loop = asyncio.get_event_loop()
    fds, timeout = snmp_select_info2()
    _log.debug("event loop settings: fds=%r, timeout=%r", fds, timeout)
    # Add missing Net-SNMP file descriptors to the event loop
    for fd in fds:
        if fd not in _fd_map:
            reader = SNMPReader(fd)
            _fd_map[fd] = reader
            loop.add_reader(fd, reader)

    # Remove Net-SNMP file descriptors that have become obsolete
    current = set(_fd_map.keys())
    wanted = set(fds)
    to_remove = current - wanted
    for fd in to_remove:
        loop.remove_reader(fd)
        del _fd_map[fd]

    # Handle Net-SNMP timeouts in a timely manner ;-)
    if _timeout_timer:
        _timeout_timer.cancel()
        _timeout_timer = None
    if timeout is not None:
        _timeout_timer = loop.call_later(timeout, check_for_timeouts)


def check_for_timeouts():
    """Handles Net-SNMP socket timeouts"""
    global _timeout_timer
    _timeout_timer = None
    _lib.snmp_timeout()
    update_event_loop()
