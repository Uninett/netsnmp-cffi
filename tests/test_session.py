import errno
import gc
import resource

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


def test_too_many_sessions_should_raise_sensible_exception(temporary_soft_limit):
    session_count = temporary_soft_limit + 10
    print(f"Opening {session_count} sessions")
    sessions = []
    with pytest.raises(OSError) as excinfo:
        try:
            for _ in range(session_count):
                sess = session.SNMPSession(
                    "127.0.0.1", version="v2c", community="public"
                )
                sess.open()
                sessions.append(sess)
        except Exception:
            instance_count = sum(
                1 for obj in gc.get_objects() if isinstance(obj, session.SNMPSession)
            )
            print(f"Managed to create {instance_count} sessions before failing")
            raise
        finally:
            for sess in sessions:
                sess.close()

    assert excinfo.value.errno == errno.EMFILE


@pytest.fixture
def simple_localhost_session(snmpsim, snmp_test_port):
    netsnmp.load_mibs()
    sess = session.SNMPSession(
        host="localhost", port=snmp_test_port, version=2, community="public"
    )
    sess.open()
    yield sess
    sess.close()


@pytest.fixture
def temporary_soft_limit():
    """Fixture that temporarily lowers the soft limit of open file descriptors to
    1024, in cases where the current limit is higher than that. The limit is restored
    afterward.

    The fixture returns the currently set soft limit.
    """
    desired_soft_limit = 1024
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit > desired_soft_limit and desired_soft_limit < hard_limit:
        resource.setrlimit(resource.RLIMIT_NOFILE, (desired_soft_limit, hard_limit))
        yield desired_soft_limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))
    else:
        yield soft_limit
