"""Defines error classes for netsnmp-cffi"""


class SNMPError(Exception):
    """Base class for SNMP errors"""

    pass


class UnsupportedSnmpVersionError(SNMPError):
    """Raised when an unsupported SNMP version is encountered in incoming traps"""

    pass
