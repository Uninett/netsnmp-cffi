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

### Using towncrier to automatically produce the changelog
#### Before merging a pull request
To be able to automatically produce the changelog for a release one file for each
pull request (also called news fragment) needs to be added to the folder
`changelog.d/`.

The name of the file consists of three parts separated by a period:
1. The identifier: the issue number
or the pull request number. If we don't want to add a link to the resulting changelog
entry then a `+` followed by a unique short description.
2. The type of the change: we use `security`, `removed`, `deprecated`, `added`,
`changed` and `fixed`.
3. The file suffix, e.g. `.md`, towncrier does not care which suffix a fragment has.

So an example for a file name related to an issue/pull request would be `214.added.md`
or for a file without corresponding issue `+fixed-pagination-bug.fixed.md`.

This file can either be created manually with a file name as specified above and the
changelog text as content or one can use towncrier to create such a file as following:

```console
$ towncrier create -c "Changelog content" 214.added.md
```

When opening a pull request there will be a check to make sure that a news fragment is
added and it will fail if it is missing.

#### Before a release
To add all content from the `changelog.d/` folder to the changelog file simply run
```console
$ towncrier build --version {version}
```
This will also delete all files in `changelog.d/`.

To preview what the addition to the changelog file would look like add the flag
`--draft`. This will not delete any files or change `CHANGELOG.md`. It will only output
the preview in the terminal.

A few other helpful flags:
- `date DATE` - set the date of the release, default is today
- `keep` - do not delete the files in `changelog.d/`

More information about [towncrier](https://towncrier.readthedocs.io).
