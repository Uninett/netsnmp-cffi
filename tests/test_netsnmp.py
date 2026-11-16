import logging

import pytest

from netsnmpy import netsnmp
from netsnmpy.constants import LOG_EMERG, LOG_WARNING


def test_when_netsnmp_debug_logging_is_enabled_load_mibs_should_log_debug_msgs(caplog):
    with caplog.at_level(logging.DEBUG):
        netsnmp.register_log_callback(enable_debug=True)
        netsnmp.load_mibs()

    assert "netsnmpy.netsnmp" in caplog.text


def test_when_log_callback_is_registered_twice_it_should_emit_each_message_once(
    caplog, netsnmp_debugging_disabled
):
    with caplog.at_level(logging.DEBUG):
        netsnmp.register_log_callback()
        netsnmp.register_log_callback()
        _netsnmp_log(LOG_EMERG, "netsnmpy test message")

    messages = [record.getMessage() for record in caplog.records]
    assert messages.count("netsnmpy test message") == 1


def test_when_log_callback_is_already_registered_enable_debug_should_still_enable_debugging(  # noqa: E501
    netsnmp_debugging_disabled,
):
    netsnmp.register_log_callback()
    netsnmp.register_log_callback(enable_debug=True)

    assert netsnmp._lib.snmp_get_do_debugging()


def test_when_netsnmp_logs_a_warning_it_should_be_emitted_through_python_logging(
    caplog,
):
    with caplog.at_level(logging.DEBUG):
        netsnmp.register_log_callback()
        _netsnmp_log(LOG_WARNING, "netsnmpy test warning")

    assert ("netsnmpy.netsnmp", logging.WARNING, "netsnmpy test warning") in (
        caplog.record_tuples
    )


def test_when_probing_log_filtering_it_should_receive_but_not_emit_the_probe(caplog):
    netsnmp.register_log_callback()
    with caplog.at_level(logging.DEBUG):
        received = netsnmp._debug_messages_reach_log_callback()

    assert received
    assert netsnmp._LOG_PROBE_MESSAGE not in caplog.text


@pytest.fixture
def netsnmp_debugging_disabled():
    was_enabled = netsnmp._lib.snmp_get_do_debugging()
    netsnmp._lib.snmp_set_do_debugging(0)
    yield
    netsnmp._lib.snmp_set_do_debugging(was_enabled)


def _netsnmp_log(priority: int, text: str):
    message = netsnmp._ffi.new("char[]", text.encode("utf-8"))
    netsnmp._lib.snmp_log(priority, b"%s\n", message)


class TestDecodeString:
    def test_when_input_contains_nul_chars_it_should_include_them(self):
        bitstring = b"\x7f\x00\x00\x01"
        bitstring_c = netsnmp._ffi.new("u_char[]", bitstring)
        varbind = netsnmp._ffi.new("netsnmp_variable_list*")
        varbind.val.bitstring = bitstring_c
        varbind.val_len = len(bitstring)

        assert netsnmp.decode_string(varbind) == bitstring
