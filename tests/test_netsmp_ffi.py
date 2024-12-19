from netsnmpy import netsnmp_ffi


def test_ffi_definitions_should_compile():
    """This test will generate some warning output from the C compiler; there's not
    much we can do about it - the warnings are from the Net-SNMP header files,
    and those are not under our control.
    """
    assert netsnmp_ffi.ffi.compile()
