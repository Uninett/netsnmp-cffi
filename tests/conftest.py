import asyncio
import os
from shutil import which

import pytest
import pytest_asyncio
from retry import retry

from netsnmpy.oids import OID


async def _verify_localhost_snmp_response(port: int):
    """Verifies that the snmpsimd fixture process is responding, by using SNMPSession
    directly to query it.
    """

    from netsnmpy import session

    try:
        sess = session.SNMPSession(host="localhost", port=port, version=2, timeout=5)
        sess.open()
        sysobjectid0 = OID(".1.3.6.1.2.1.1.2.0")
        return await sess.aget(sysobjectid0)
    finally:
        sess.close()


@pytest_asyncio.fixture(scope="session")
async def snmpsim(snmpsimd_path, snmp_fixture_directory, snmp_test_port):
    """Sets up an external snmpsimd process so that SNMP communication can be simulated
    by the test that declares a dependency to this fixture. Data fixtures are loaded
    from the snmp_fixtures subdirectory.
    """
    arguments = [
        f"--data-dir={snmp_fixture_directory}",
        "--log-level=error",
        f"--agent-udpv4-endpoint=127.0.0.1:{snmp_test_port}",
    ]
    print(f"Running {snmpsimd_path} with args: {arguments!r}")
    proc = await asyncio.create_subprocess_exec(snmpsimd_path, *arguments)

    @retry(Exception, tries=3, delay=0.5, backoff=2)
    async def _wait_for_snmpsimd():
        if await _verify_localhost_snmp_response(snmp_test_port):
            print("snmpsimd is responding to queries")
            return True
        else:
            raise TimeoutError("Still waiting for snmpsimd to listen for queries")

    await _wait_for_snmpsimd()

    yield
    proc.kill()


@pytest.fixture(scope="session")
def snmpsimd_path():
    snmpsimd = which("snmpsim-command-responder")
    assert snmpsimd, "Could not find snmpsim-command-responder"
    yield snmpsimd


@pytest.fixture(scope="session")
def snmp_fixture_directory():
    this_directory = os.path.dirname(__file__)
    fixture_dir = os.path.join(this_directory, "snmp_fixtures")
    assert os.path.isdir(fixture_dir)
    yield fixture_dir


@pytest.fixture(scope="session")
def snmp_test_port():
    yield 1024
