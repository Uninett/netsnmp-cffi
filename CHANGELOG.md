# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This project uses [*towncrier*](https://towncrier.readthedocs.io/) and the
changes for the upcoming release can be found in
<https://github.com/Uninett/netsnmp-cffi/tree/master/changelog.d/>.

<!-- towncrier release notes start -->

## [0.1.3] - 2025-09-15

### Fixed

- Return raw community value bytestring rather than crashing trap handler if
  the incoming trap messages community cannot be decoded as ASCII
  ([#9](https://github.com/Uninett/netsnmp-cffi/pull/9))

## [0.1.2] - 2025-05-15

### Added

- Added 3.12 to list of supported Python versions

### Fixed

- Support trap origin discovery on BSD platforms ([#3](https://github.com/Uninett/netsnmp-cffi/issues/3))
- Cleaned up project requirements specifications
- Moved development and test requirements to `pyproject.toml`
- Updated module metadata to be PEP-639 compliant


## [0.1.1] - 2025-02-19

### Added

- Added tools to automatically build manylinux binary wheels.

### Fixed

- Fixed `pyproject.toml` license attributes to conform with package build
  tools.
- Make library import fail with helpful error message if Net-SNMP cannot be
  found or is older than supported.
- Fixed typo in variable reference that would mask the real error when SNMP
  session opening failed.

## [0.1.0] - 2025-02-11

First public release.
