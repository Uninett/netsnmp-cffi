import pytest

from netsnmpy.constants import SNMP_MSG_INFORM, SNMP_VERSION_2c
from netsnmpy.netsnmp import ValueType, encode_variable, oid_to_c
from netsnmpy.oids import OID
from netsnmpy.trapsession import SNMPTrap, _ffi, _netsnmp

_lib = _netsnmp.lib


class TestSNMPTrap:
    def test_given_trap_with_non_ascii_community_then_from_pdu_should_not_crash(
        self, pdu_with_garbage_community, garbage_community
    ):
        trap = SNMPTrap.from_pdu(pdu_with_garbage_community)
        assert isinstance(trap.community, bytes)
        assert trap.community == garbage_community


@pytest.fixture
def pdu_with_garbage_community(garbage_community):
    pdu = _lib.snmp_pdu_create(SNMP_MSG_INFORM)
    pdu.version = SNMP_VERSION_2c

    community_c = _ffi.new("char[]", garbage_community)
    pdu.community = community_c

    oid = oid_to_c(OID(".1.3.6.1.2.1.1.6.0"))
    value_type = ValueType.OCTETSTRING
    encoded_value = encode_variable(ValueType.OCTETSTRING, b"Milliways")
    _lib.snmp_add_var(
        pdu, oid, len(oid), value_type.value.encode("utf-8"), encoded_value
    )

    yield pdu


@pytest.fixture
def garbage_community():
    yield b"foo\xcbbar"
