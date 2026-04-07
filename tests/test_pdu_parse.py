"""Tests for parsing raw BER-encoded SNMP packets into SNMPTrap objects."""

from ipaddress import IPv4Address, ip_address

import pytest

from netsnmpy.oids import OID
from netsnmpy.trapsession import parse_raw_trap

# A valid SNMPv2c trap PDU (coldStart with ifIndex.1=42, community=public, uptime=12345)
# Built using pysnmp's protocol API and BER encoder.
SNMPV2C_COLDSTART_TRAP = bytes.fromhex(
    "305402010104067075626c6963a74702034ff374020100020100303a300e06082b060102010103004302"
    "30393017060a2b06010603010104010006092b0601060301010501300f060a2b060102010202010101"
    "02012a"
)
SOURCE_ADDR = ip_address("192.168.1.1")


class TestParseRawTrap:
    def test_when_parsing_valid_v2c_trap_then_source_should_use_override_address(self):
        trap = parse_raw_trap(SNMPV2C_COLDSTART_TRAP, SOURCE_ADDR)
        assert trap.source == IPv4Address("192.168.1.1")

    def test_when_parsing_valid_v2c_trap_then_community_should_be_extracted(self):
        trap = parse_raw_trap(SNMPV2C_COLDSTART_TRAP, SOURCE_ADDR)
        assert trap.community == "public"

    def test_when_parsing_valid_v2c_trap_then_version_should_be_2c(self):
        trap = parse_raw_trap(SNMPV2C_COLDSTART_TRAP, SOURCE_ADDR)
        assert trap.version == "2c"

    def test_when_parsing_valid_v2c_trap_then_trap_oid_should_be_extracted(self):
        trap = parse_raw_trap(SNMPV2C_COLDSTART_TRAP, SOURCE_ADDR)
        assert trap.trap_oid == OID(".1.3.6.1.6.3.1.1.5.1")

    def test_when_parsing_valid_v2c_trap_then_uptime_should_be_extracted(self):
        trap = parse_raw_trap(SNMPV2C_COLDSTART_TRAP, SOURCE_ADDR)
        assert trap.uptime == 12345

    def test_when_parsing_valid_v2c_trap_then_varbinds_should_be_extracted(self):
        trap = parse_raw_trap(SNMPV2C_COLDSTART_TRAP, SOURCE_ADDR)
        assert len(trap.variables) == 1
        oid, value = trap.variables[0]
        assert oid == OID(".1.3.6.1.2.1.2.2.1.1.1")
        assert value == 42

    def test_given_malformed_data_then_parse_raw_trap_should_raise_value_error(self):
        with pytest.raises(ValueError, match="Failed to parse SNMP PDU"):
            parse_raw_trap(b"\x00\x01\x02\x03", SOURCE_ADDR)

    def test_given_empty_data_then_parse_raw_trap_should_raise_value_error(self):
        with pytest.raises(ValueError, match="Cannot parse empty SNMP data"):
            parse_raw_trap(b"", SOURCE_ADDR)
