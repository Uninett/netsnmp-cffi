# netsnmp-cffi

This is a [CFFI](https://cffi.readthedocs.io/en/stable/)-based Python interface
for the [Net-SNMP C library](http://www.net-snmp.org/), enabling efficient
parallel SNMP communication with large amounts of devices from Python.  It
provides both asynchronous (asyncio) and synchronous interfaces.

This module is still a work in progress, and has been mainly developed to
replace PySNMP as the default SNMP library in [Zino
2](https://github.com/Uninett/zino) - the first releases of this library will
focus mainly on functionality used by Zino (which for the most part means that
SNMPv3 is not implemented yet).


## Usage examples

For a simple (asyncio) usage example, see
[asnmpget.py](./src/netsnmpy/programs/asnmpget.py).

## Developing netsnmp-cffi

### Running tests

[tox](https://tox.wiki/) and [pytest](https://pytest.org/) are used to run the
test suite. To run the test suite on all supported versions of Python, run:

```shell
tox
```

### Code style

netsnmp-cffi code should follow the [PEP-8](https://peps.python.org/pep-0008/) and
[PEP-257](https://peps.python.org/pep-0257/)
guidelines. [Ruff](https://docs.astral.sh/ruff/) is used for automatic code
formatting. The [pre-commit](https://pre-commit.com/) tool is used to enforce
code styles at commit-time.

Before you start hacking, enable pre-commit hooks in your cloned repository,
like so:

```shell
pre-commit install
```
