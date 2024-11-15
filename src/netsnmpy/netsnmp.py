"""Low-level interface to the Net-SNMP library"""

import logging
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, List, Union

from netsnmpy.constants import (
    ASN_APP_DOUBLE,
    ASN_APP_FLOAT,
    ASN_BIT_STR,
    ASN_COUNTER,
    ASN_COUNTER64,
    ASN_GAUGE,
    ASN_INTEGER,
    ASN_IPADDRESS,
    ASN_NULL,
    ASN_OBJECT_ID,
    ASN_OCTET_STR,
    ASN_TIMETICKS,
    LOG_ALERT,
    LOG_CRIT,
    LOG_DEBUG,
    LOG_EMERG,
    LOG_ERR,
    LOG_INFO,
    LOG_NOTICE,
    LOG_WARNING,
    MAX_NAME_LEN,
    MAX_OID_LEN,
    NETSNMP_LOGHANDLER_CALLBACK,
    SNMP_CALLBACK_LIBRARY,
    SNMP_CALLBACK_LOGGING,
    SNMP_ENDOFMIBVIEW,
    SNMP_NOSUCHINSTANCE,
    SNMP_NOSUCHOBJECT,
)
from netsnmpy.oids import OID

from . import _netsnmp

# Re-usable type annotations:
OIDTuple = tuple[Union[int], ...]
ObjectIdentifier = Union[tuple[Union[int, str], ...], str]
VarBindList = List[tuple[OID, Any]]

_ffi = _netsnmp.ffi
_lib = _netsnmp.lib
_log = logging.getLogger(__name__)
_U_LONG_SIZE = _ffi.sizeof("unsigned long")


def get_version() -> tuple[Union[int, str], ...]:
    """Returns the version of the linked Net-SNMP library as a tuple"""
    _version_ptr = _lib.netsnmp_get_version()
    version = _ffi.string(_version_ptr).decode("utf-8")
    version_tuple = tuple(int(s) if s.isdigit() else s for s in version.split("."))
    return version_tuple


def load_mibs():
    """Loads all defined MIBs from Net-SNMP's configured locations.

    This function must be called before any MIBs can be used.  The simplest way to
    control where Net-SNMP looks for MIB files, and which ones it loads, is to set
    the environment variables MIBDIRS and MIBS before this function is called.
    """
    _lib.netsnmp_init_mib()
    _lib.read_all_mibs()


def oid_to_c(oid: OIDTuple) -> _ffi.CData:
    """Converts an OID to a C array"""
    return _ffi.new("oid[]", oid)


def symbol_to_oid(symbol: ObjectIdentifier) -> OID:
    """Converts an object identifier to a tuple of integers"""
    symbol = identifier_to_string(symbol)

    buffer = _ffi.new(f"oid[{MAX_OID_LEN}]")
    buffer_length = _ffi.new("size_t*", MAX_OID_LEN)
    input = _ffi.new("char[]", symbol.encode("utf-8"))
    success = _lib.snmp_parse_oid(input, buffer, buffer_length)

    if not success:
        raise ValueError(f"Could not look up object identifier: {symbol}")

    return OID(_ffi.unpack(buffer, buffer_length[0]))


def oid_to_symbol(oid: OID) -> str:
    """Looks up a symbolic name for `oid` from loaded MIBs"""
    input = oid_to_c(oid)
    buffer = _ffi.new("char[]", MAX_NAME_LEN)
    _lib.snprint_objid(buffer, MAX_NAME_LEN, input, len(oid))
    return _ffi.string(buffer).decode("utf-8")


def identifier_to_string(symbol: ObjectIdentifier) -> str:
    """Converts a symbolic object identifier (which may be a tuple of strings and ints)
    to a string representation, suitable for use with Net-SNMP MIB lookups.
    """
    if isinstance(symbol, tuple) and isinstance(symbol[0], str):
        mib_name = str(symbol[0])
        symbol = ".".join(str(n) for n in symbol[1:])
        return f"{mib_name}::{symbol}"
    return str(symbol)


#
# Functions and classes to decode C-level SNMP variable values Python objects
#
class SNMPErrorValue:
    """Base class for special SNMP varbind values"""

    def __init__(self, value: Any = None):
        pass

    def __repr__(self) -> str:
        return self.__class__.__name__


class NoSuchObject(SNMPErrorValue):
    def __str__(self):
        return "No Such Object available on this agent at this OID"


class NoSuchInstance(SNMPErrorValue):
    def __str__(self):
        return "No such instance currently exists at this OID"


class EndOfMibView(SNMPErrorValue):
    def __str__(self):
        return "No more variables left in this MIB View (It is past the end of the MIB tree)"


def decode_oid(var: _ffi.CData) -> tuple[int]:
    return tuple(_ffi.unpack(var.val.objid, var.val_len // _U_LONG_SIZE))


def decode_ip_address(var: _ffi.CData) -> Union[IPv4Address, IPv6Address]:
    return ip_address(_ffi.buffer(var.val.bitstring, var.val_len)[:])


def decode_bigint(var: _ffi.CData) -> int:
    # This could potentially be accomplished a lot faster using C
    counter = var.val.counter64
    return (counter.high << 32) + counter.low


def decode_string(var: _ffi.CData) -> bytes:
    if var.val_len:
        return _ffi.string(var.val.bitstring, var.val_len)
    return b""


DECODER_FUNCTION_MAP = {
    ASN_OCTET_STR: decode_string,
    ASN_INTEGER: lambda var: var.val.integer[0],
    ASN_NULL: lambda var: None,
    ASN_OBJECT_ID: decode_oid,
    ASN_BIT_STR: decode_string,
    ASN_IPADDRESS: decode_ip_address,
    ASN_COUNTER: lambda var: _ffi.cast("unsigned long *", var.val.integer)[0],
    ASN_GAUGE: lambda var: _ffi.cast("unsigned long *", var.val.integer)[0],
    ASN_TIMETICKS: lambda var: _ffi.cast("unsigned long *", var.val.integer)[0],
    ASN_COUNTER64: decode_bigint,
    ASN_APP_FLOAT: lambda var: var.val.floatVal[0],
    ASN_APP_DOUBLE: lambda var: var.val.doubleVal[0],
    SNMP_NOSUCHOBJECT: NoSuchObject,
    SNMP_NOSUCHINSTANCE: NoSuchInstance,
    SNMP_ENDOFMIBVIEW: EndOfMibView,
}


def decode_variable(var: _ffi.CData) -> tuple[OID, Union[int, bytes, None]]:
    """Decodes a variable binding from a Net-SNMP PDU to an equivalent Python object.

    :returns: A tuple of the variable OID and the decoded value.
    """
    oid = OID(_ffi.unpack(var.name, var.name_length))
    decode = DECODER_FUNCTION_MAP.get(var.type, None)
    if not decode:
        _log.debug("could not decode oid %s type %s", oid, var.type)
        return oid, None
    return oid, decode(var)


def parse_response_variables(pdu: _ffi.CData) -> VarBindList:
    result = []
    var = pdu.variables
    while var:
        oid, val = decode_variable(var)
        result.append((tuple(oid), val))
        var = var.next_variable
    return result


# Add log hooks to ensure Net-SNMP log output is emitted through a Python logger
LOG_LEVEL_MAP = {
    LOG_EMERG: logging.CRITICAL,
    LOG_ALERT: logging.CRITICAL,
    LOG_CRIT: logging.CRITICAL,
    LOG_ERR: logging.ERROR,
    LOG_WARNING: logging.WARNING,
    LOG_NOTICE: logging.INFO,
    LOG_INFO: logging.INFO,
    LOG_DEBUG: logging.DEBUG,
}


@_ffi.def_extern()
def python_log_callback(_major_id, _minor_id, serverarg, _clientarg):
    """Callback function to emit Net-SNMP log messages through Python's logging module"""
    log_message = _ffi.cast("struct snmp_log_message *", serverarg)
    level = LOG_LEVEL_MAP.get(log_message.priority, logging.DEBUG)
    message = _ffi.string(log_message.msg).decode("utf-8")
    _log.log(level, message.rstrip())
    return 0


def register_log_callback(enable_debug=False):
    """Registers a log callback with Net-SNMP to ensure log messages are emitted
    through Python's logging module.

    :param enable_debug: If True, enables full debug logging from Net-SNMP.
    """
    _lib.snmp_register_callback(
        SNMP_CALLBACK_LIBRARY,
        SNMP_CALLBACK_LOGGING,
        _lib.python_log_callback,
        _ffi.NULL,
    )

    _lib.netsnmp_register_loghandler(NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG)
    if enable_debug:
        _lib.snmp_set_do_debugging(1)


def log_session_error(subsystem: str, session: _ffi.CData):
    msg = _ffi.new("char[]", subsystem.encode("utf-8"))
    _lib.snmp_sess_perror(msg, session)


def make_request_pdu(operation: int, *oids: OID) -> _ffi.CData:
    """Creates and returns a new SNMP Request-PDU for the given operation and OIDs.

    The returned struct is allocated/owned by the Net-SNMP library, and will be
    automatically freed by the library following a successful `snmp_send` call.
    However, if `snmp_send` fails, the caller is responsible for freeing the PDU.
    """
    request = _lib.snmp_pdu_create(operation)
    for oid in oids:
        oid = oid_to_c(oid)
        _lib.snmp_add_null_var(request, oid, len(oid))
    return request
