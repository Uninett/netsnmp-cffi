import pytest

from netsnmpy.oids import OID


class TestOIDInit:
    def test_when_input_is_valid_oid_string_it_should_instantiate(self):
        assert OID(".1.3.6.1.2.1.31.1.1")

    def test_when_input_is_valid_oid_bytes_it_should_instantiate(self):
        assert OID(b".1.3.6.1.2.1.31.1.1")

    def test_when_input_is_invalid_oid_string_it_should_raise_valueerror(self):
        with pytest.raises(ValueError):
            OID("z0rk!")

    def test_when_input_is_integer_it_should_raise_typeerror(self):
        with pytest.raises(TypeError):
            OID(42)

    def test_when_input_is_integer_tuple_it_should_instantiate(self):
        assert OID((1, 3, 6, 1, 2, 1, 31, 1, 1))


class TestOIDAdd:
    def test_when_adding_two_oids_it_should_return_expected_oid(self):
        oid1 = OID(".1.2.3")
        oid2 = OID(".4.5.6")
        assert (oid1 + oid2) == OID(".1.2.3.4.5.6")

    def test_when_adding_a_valid_oid_string_it_should_return_expected_oid(self):
        oid = OID(".1.2.3")
        assert (oid + "4.5.6") == OID(".1.2.3.4.5.6")

    def test_when_adding_an_invalid_oid_string_it_should_raise_valueerror(self):
        oid = OID(".1.2.3")
        with pytest.raises(ValueError):
            oid + "z0rk!"


class TestOIDIsAPrefix:
    def test_when_oid_is_prefix_of_other_it_should_return_true(self):
        oid1 = OID(".1.2.3")
        oid2 = OID(".1.2.3.4.5.6")
        assert oid1.is_a_prefix_of(oid2)

    def test_when_oid_is_not_a_prefix_of_other_it_should_return_false(self):
        oid1 = OID(".1.2.3")
        oid2 = OID(".1.1.92.92")
        assert not oid1.is_a_prefix_of(oid2)


class TestOIDStripPrefix:
    def test_when_input_is_a_prefix_it_should_return_a_stripped_oid(self):
        oid1 = OID(".1.2.3")
        oid2 = OID(".1.2.3.4.5.6")
        expected = OID(".4.5.6")
        assert oid2.strip_prefix(oid1) == expected

    def test_when_input_is_not_a_prefix_it_should_return_itself(self):
        oid1 = OID(".2.3.4.5")
        oid2 = OID(".1.2.3.4.5.6")
        assert oid2.strip_prefix(oid1) == oid2


class TestOIDStrings:
    def test_str_should_return_expected_string(self):
        oid = OID(".1.2.3")
        assert str(oid) == ".1.2.3"

    def test_repr_should_return_expected_representation(self):
        oid = OID(".1.2.3.4")
        assert repr(oid) == "OID('.1.2.3.4')"
