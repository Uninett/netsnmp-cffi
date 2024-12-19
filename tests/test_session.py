import pytest

from netsnmpy import netsnmp, session


async def test_when_host_is_unreachable_then_agent_should_raise_timeout():
    netsnmp.load_mibs()
    sess = session.SNMPSession(
        host="127.42.42.42", port=1161, version=2, retries=1, timeout=0.5
    )
    sess.open()
    sys_descr = netsnmp.symbol_to_oid("SNMPv2-MIB::sysDescr.0")

    with pytest.raises(TimeoutError):
        await sess.aget(sys_descr)


async def test_it_should_getnext_sysdescr_from_localhost(simple_localhost_session):
    sys_descr = netsnmp.symbol_to_oid("SNMPv2-MIB::sysDescr")
    response = await simple_localhost_session.agetnext(sys_descr)
    assert len(response) == 1
    oid, value = response[0]
    assert sys_descr.is_a_prefix_of(oid)
    assert value.startswith(b"ProCurve")


@pytest.fixture
def simple_localhost_session(snmpsim, snmp_test_port):
    netsnmp.load_mibs()
    sess = session.SNMPSession(
        host="localhost", port=snmp_test_port, version=2, community="public"
    )
    sess.open()
    yield sess
    sess.close()
