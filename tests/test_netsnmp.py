import logging

from netsnmpy import netsnmp


def test_when_netsnmp_debug_logging_is_enabled_load_mibs_should_log_debug_msgs(caplog):
    with caplog.at_level(logging.DEBUG):
        netsnmp.register_log_callback(enable_debug=True)
        netsnmp.load_mibs()

    assert "netsnmpy.netsnmp" in caplog.text
