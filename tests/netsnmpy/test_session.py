import pytest

from netsnmpy import netsnmp, session


async def test_when_host_is_unreachable_then_aget_should_raise_timeout():
    netsnmp.load_mibs()
    sess = session.SNMPSession(
        host="127.42.42.42", port=1161, version=2, retries=1, timeout=0.5
    )
    sess.open()
    sys_descr = netsnmp.symbol_to_oid("SNMPv2-MIB::sysDescr.0")

    with pytest.raises(TimeoutError):
        await sess.aget(sys_descr)
