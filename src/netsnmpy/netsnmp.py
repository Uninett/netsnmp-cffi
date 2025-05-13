"""Low-level interface to the Net-SNMP library"""

import logging
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, List, NamedTuple, Optional, Union

try:
    from netsnmpy import _netsnmp
except ImportError:
    raise ImportError("Cannot find the Net-SNMP shared library")

from netsnmpy.annotations import IPAddress
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

# Re-usable type annotations:
OIDTuple = tuple[Union[int], ...]
ObjectIdentifier = Union[tuple[Union[int, str], ...], str]
VarBindList = List["SNMPVariable"]

_ffi = _netsnmp.ffi
_lib = _netsnmp.lib
_log = logging.getLogger(__name__)
_U_LONG_SIZE = _ffi.sizeof("unsigned long")
MAX_FD_SIZE = 2048
MAX_SYMBOL_LENGTH = MAX_NAME_LEN * 2
TYPE_MODID = 24

MINIMAL_SUPPORTED_VERSION = (5, 9)
MINIMAL_SUPPORTED_VERSION_STR = ".".join(str(n) for n in MINIMAL_SUPPORTED_VERSION)


class ValueType(Enum):
    """Enumeration of SNMP variable types used by Net-SNMP"""

    INTEGER = "i"
    UNSIGNED32 = "u"
    COUNTER = "c"
    COUNTER64 = "C"
    TIMETICKS = "t"
    OCTETSTRING = "s"
    BITSTRING = "b"
    IPADDR = "a"
    OBJID = "o"


Variable = tuple[OID, Union[ValueType, str], Any]


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
    """Looks up a symbolic name for `oid` from loaded MIBs.

    If the symbol cannot be fully translated, a string representation of `oid` is
    returned.
    """
    oid_c = oid_to_c(oid)
    buffer = _ffi.new("char[]", MAX_SYMBOL_LENGTH)
    out_length = _lib.snprint_objid(buffer, MAX_SYMBOL_LENGTH, oid_c, len(oid))
    if out_length < 0:
        _log.error(
            "C buffer (%s bytes) is too small to translate %s to symbol",
            MAX_SYMBOL_LENGTH,
            oid,
        )
        return str(oid)
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


class SNMPVariable(NamedTuple):
    """Represents an SNMP variable (or varbind, in low-level-speak).

    A varbind is really just a tuple of an OID and a value, but the value can be
    interpreted in light of how the variable is defined in the corresponding MIB.

    E.g. the raw value might be an integer, but the MIB might define the variable as
    an enumeration of string values, in which case the value can also be interpreted
    as a string.
    """

    oid: OID
    value: Optional[Union[int, str, bytes, OID, IPAddress, SNMPErrorValue]]

    def __str__(self):
        enum_value = self.enum_value
        if enum_value:
            value = f"{self.enum_value}({self.value})"
        elif self.textual_convention == "DisplayString":
            value = f'{self.value.decode("utf-8")!r}'
        else:
            value = self.value
        return f"{self.symbolic_name} = {value}"

    @property
    def enum_value(self) -> Optional[str]:
        """Returns a symbolic representation of the variable's value, if possible"""
        enum = get_enums_for_object(self.oid)
        if enum:
            return enum.get(self.value)

    @property
    def textual_convention(self) -> Optional[str]:
        """Returns the textual convention of the variable's MIB object, if available"""
        subtree = get_subtree_for_object(self.oid)
        if subtree and subtree.tc_index > -1:
            descr = _lib.get_tc_descriptor(subtree.tc_index)
            return _ffi.string(descr).decode("utf-8")

    @property
    def symbolic_name(self) -> str:
        """Returns the symbolic name of the variable's OID"""
        return oid_to_symbol(self.oid)


def decode_oid(var: _ffi.CData) -> tuple[int]:
    return OID(_ffi.unpack(var.val.objid, var.val_len // _U_LONG_SIZE))


def decode_ip_address(var: _ffi.CData) -> Union[IPv4Address, IPv6Address]:
    return ip_address(_ffi.buffer(var.val.bitstring, var.val_len)[:])


def decode_bigint(var: _ffi.CData) -> int:
    # This could potentially be accomplished a lot faster using C
    counter = var.val.counter64
    return (counter.high << 32) + counter.low


def decode_string(var: _ffi.CData) -> bytes:
    if var.val_len:
        return bytes(_ffi.buffer(var.val.bitstring, var.val_len))
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


def decode_variable(var: _ffi.CData) -> SNMPVariable:
    """Decodes a variable binding from a Net-SNMP PDU to an equivalent Python object.

    :returns: A tuple of the variable OID and the decoded value.
    """
    oid = OID(_ffi.unpack(var.name, var.name_length))
    decode = DECODER_FUNCTION_MAP.get(var.type, None)
    if not decode:
        _log.debug("could not decode oid %s type %s", oid, var.type)
        return SNMPVariable(oid, None)
    return SNMPVariable(oid, decode(var))


def get_enums_for_varbind(var: _ffi.CData) -> Optional[dict[int, str]]:
    """Returns a dictionary of enumeration values for the given CData representing
    a variable binding.

    :returns: A ``dict`` if the MIB object is found and is defined as an enumeration,
              otherwise ``None`` is returned.
    """
    return get_enums_for_object(var.name, var.name_length)


def get_enums_for_object(
    oid: Union[_ffi.CData, OID], oid_length: Optional[int] = None
) -> Optional[dict[int, str]]:
    """Returns a dictionary of enumeration values for the given object identifier,
    based on loaded MIB data.

    :param oid: The object identifier to look up.  This can be a CData object
                representing a low level C value, or it can be a Python OID object.
    :param oid_length: The length of the OID: Required if ``oid`` is a CData object.
    :returns: A ``dict`` if the MIB object is found and is defined as an enumeration,
              otherwise ``None`` is returned.
    """
    subtree = get_subtree_for_object(oid, oid_length)
    if not subtree or not subtree.enums:
        return None

    enum = {}
    item = subtree.enums
    while item:
        enum[item.value] = _ffi.string(item.label).decode("utf-8")
        item = item.next
    return enum


def get_subtree_for_object(
    oid: Union[_ffi.CData, OID], oid_length: Optional[int] = None
) -> Optional[_ffi.CData]:
    """Returns a CData tree struct with MIB information about the supplied object ID,
    based on loaded MIB data.

    :param oid: The object identifier to look up.  This can be a CData object
                representing a low level C value, or it can be a Python OID object.
    :param oid_length: The length of the OID: Required if ``oid`` is a CData object.
    :returns: An optional CData object representing a `struct tree` from Net-SNMP.
    """
    if isinstance(oid, OID):
        oid_c = oid_to_c(oid)
        oid_length = len(oid)
    else:
        oid_c = oid
        if not oid_length:
            raise ValueError("oid_length must be provided when oid is a CData object")

    tree_head = _lib.get_tree_head()
    subtree = _lib.get_tree(oid_c, oid_length, tree_head)
    return subtree


def get_loaded_mibs() -> List[str]:
    """Returns a list of all loaded MIBs"""
    # This is a roundabout way to get the list of loaded MIBs, as Net-SNMP doesn't
    # provide public access to the module list (it can dump the list as debug messages,
    # but that's it.
    module_ids = set()

    def traverse_tree(node):
        if node.type == TYPE_MODID:
            module_ids.add(node.modid)
        if node.child_list:
            traverse_tree(node.child_list)
        if node.next_peer:
            traverse_tree(node.next_peer)

    # First, traverse the entire MIB tree (!) to collect distinct module IDs
    head = _lib.get_tree_head()
    if head:
        traverse_tree(head)

    # Now, convert the module IDs to module names
    buffer = _ffi.new("char[]", 256)
    module_names = []
    for modid in module_ids:
        _lib.module_name(modid, buffer)
        module_names.append(_ffi.string(buffer).decode("utf-8"))

    return module_names


ENCODER_FUNCTION_MAP = {
    ValueType.INTEGER: lambda var: _ffi.new("int*", var),
    ValueType.UNSIGNED32: lambda var: _ffi.new("unsigned int*", var),
    ValueType.COUNTER: lambda var: _ffi.new("unsigned long*", var),
    ValueType.COUNTER64: lambda var: _ffi.new("unsigned long long*", var),
    ValueType.TIMETICKS: lambda var: _ffi.new("unsigned long*", var),
    ValueType.OCTETSTRING: lambda var: _ffi.new("char[]", var),
    ValueType.BITSTRING: lambda var: _ffi.new("char[]", var),
    ValueType.IPADDR: lambda var: _ffi.new("unsigned long*", int(ip_address(var))),
    ValueType.OBJID: oid_to_c,
}


def encode_variable(value_type: Union[ValueType, str], value: Any) -> _ffi.CData:
    """Encodes a value for use in a Net-SNMP PDU.

    :param value_type: The SNMP type of the value
    :param value: The value to encode: Any Python object that is convertible to the
                  given `value_type`
    """
    encode = ENCODER_FUNCTION_MAP.get(value_type, None)
    if encode:
        return encode(value)
    raise ValueError(f"Unsupported value type: {value_type}")


def parse_response_variables(pdu: _ffi.CData) -> VarBindList:
    result = []
    var = pdu.variables
    while var:
        result.append(decode_variable(var))
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


def get_session_error_message(session: _ffi.CData) -> str:
    """Returns the last error message associated with the given SNMP session"""
    pperrmsg = _ffi.new("char**")
    _lib.snmp_error(session, _ffi.NULL, _ffi.NULL, pperrmsg)
    errmsg = _ffi.string(pperrmsg[0]).decode("utf-8")
    _lib.free(pperrmsg[0])
    return errmsg


def log_session_error(subsystem: str, session: _ffi.CData):
    msg = _ffi.new("char[]", subsystem.encode("utf-8"))
    _lib.snmp_sess_perror(msg, session)


def make_request_pdu(operation: int, *oids: OID) -> _ffi.CData:
    """Creates and returns a new SNMP Request-PDU for the given operation and OIDs,
    specifically for read operations (i.e. the varbinds will only contain OIDs and no
    values).

    The returned struct is allocated/owned by the Net-SNMP library, and will be
    automatically freed by the library following a successful `snmp_send` call.
    However, if `snmp_send` fails, the caller is responsible for freeing the PDU.
    """
    request = _lib.snmp_pdu_create(operation)
    for oid in oids:
        oid = oid_to_c(oid)
        _lib.snmp_add_null_var(request, oid, len(oid))
    return request


def make_pdu_with_variables(operation: int, *variables: Variable) -> _ffi.CData:
    """Creates and returns a new SNMP PDU for the given operation and variables,
    suitable for response PDUs or for sending SET requests. Each variable consists of
    a tuple of the OID, the (SNMP) type of the value, and the value itself.

    The returned struct is allocated/owned by the Net-SNMP library, and will be
    automatically freed by the library following a successful `snmp_send` call.
    However, if `snmp_send` fails, the caller is responsible for freeing the PDU.
    """
    request = _lib.snmp_pdu_create(operation)
    for oid, value_type, value in variables:
        oid = oid_to_c(oid)
        value_type = ValueType(value_type)
        encoded_value = encode_variable(value_type, value)
        _lib.snmp_add_var(
            request, oid, len(oid), value_type.value.encode("utf-8"), encoded_value
        )
    return request


def snmp_select_info2() -> tuple[List[int], float]:
    """Returns a list of session file descriptors opened by Net-SNMP that should be
    part of the list of read-descriptors added to a `select()` call when working
    asynchronously (i.e. the returned descriptors should all have active readers in
    an asyncio event loop).  Also returns Net-SNMP's recommended timeout value for a
    `select()` call.

    :returns: A tuple of the list of file descriptors and the timeout value to use.
    """
    fdset = _ffi.new("netsnmp_large_fd_set*")
    _lib.netsnmp_large_fd_set_init(fdset, MAX_FD_SIZE)
    maxfd = _ffi.new("int*", 0)
    timeout = _ffi.new("struct timeval*")
    timeout.tv_sec = 1  # 1 second
    timeout.tv_usec = 0  # 0 microseconds
    block = _ffi.new("int*", 0)

    fd_count = _lib.snmp_select_info2(maxfd, fdset, timeout, block)
    _log.debug("snmp_select_info2(...) = %d", fd_count)

    use_timeout = None
    if not block[0]:
        use_timeout = timeout.tv_sec + timeout.tv_usec / 1e6
    return large_fd_set_to_list(fdset, maxfd[0]), use_timeout


def large_fd_set_to_list(fdset: _ffi.CData, maxfd: int) -> List[int]:
    """Converts a large_fd_set to a list of file descriptor numbers.

    Also cleans up the incoming fdset to avoid memory leaks.
    """
    result = [fd for fd in range(maxfd) if _lib.netsnmp_large_fd_is_set(fd, fdset)]
    _lib.netsnmp_large_fd_set_cleanup(fdset)
    return result


def fd_to_large_fd_set(fd: int) -> _ffi.CData:
    """Converts a single file descriptor to a large_fd_set for use with `snmp_read2()`
    calls.

    The returned large_fd_set must be cleaned up with `netsnmp_large_fd_set_cleanup(
    fdset)` to avoid memory leaks.

    """
    fdset = _ffi.new("netsnmp_large_fd_set*")
    _lib.netsnmp_large_fd_set_init(fdset, MAX_FD_SIZE)
    _lib.netsnmp_large_fd_setfd(fd, fdset)
    return fdset


_version = get_version()
if _version < MINIMAL_SUPPORTED_VERSION:
    raise RuntimeError(
        f"Net-SNMP version {_version} is not supported. "
        f"Minimum supported version is {MINIMAL_SUPPORTED_VERSION_STR}"
    )
