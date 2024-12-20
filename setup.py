# We've found no useful way to add the cffi_modules definition to
# pyproject.toml, so we seem to be stuck with this setup.py for now
from setuptools import setup

setup(
    cffi_modules=["src/netsnmpy/netsnmp_ffi.py:ffi"],
)
