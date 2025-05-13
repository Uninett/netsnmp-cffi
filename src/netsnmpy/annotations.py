"""Typing definitions and data verification utilities"""

from ipaddress import IPv4Address, IPv6Address
from typing import Union

IPAddress = Union[IPv4Address, IPv6Address]
Host = Union[str, IPAddress]
InterfaceTuple = tuple[Host, int]
SnmpVersion = Union[str, int]
