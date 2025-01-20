import logging

from netsnmpy import netsnmp


def test_when_netsnmp_debug_logging_is_enabled_load_mibs_should_log_debug_msgs(caplog):
    with caplog.at_level(logging.DEBUG):
        netsnmp.register_log_callback(enable_debug=True)
        netsnmp.load_mibs()

    assert "netsnmpy.netsnmp" in caplog.text


class TestDecodeString:
    def test_when_input_contains_nul_chars_it_should_include_them(self):
        bitstring = b"\x7f\x00\x00\x01"
        bitstring_c = netsnmp._ffi.new("u_char[]", bitstring)
        varbind = netsnmp._ffi.new("netsnmp_variable_list*")
        varbind.val.bitstring = bitstring_c
        varbind.val_len = len(bitstring)

        assert netsnmp.decode_string(varbind) == bitstring
