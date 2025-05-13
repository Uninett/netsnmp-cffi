"""Example program of how to run a simple trap daemon using netsnmp-cffi"""

import argparse
import asyncio
import logging
import re
import socket
from functools import reduce
from ipaddress import ip_address
from signal import SIGINT, SIGTERM
from typing import Union

from netsnmpy import netsnmp, trapsession
from netsnmpy.annotations import InterfaceTuple
from netsnmpy.trapsession import SNMPTrap

ADDRESS_PATTERNS = (re.compile(r"(?P<addr>[0-9.]+) (:(?P<port>[0-9]+))?$", re.VERBOSE),)
if socket.has_ipv6:
    ADDRESS_PATTERNS += (
        re.compile(r"(?P<addr>[0-9a-fA-F:]+)$"),
        re.compile(r"\[(?P<addr>[^\]]+)\] (:(?P<port>[0-9]+))?$", re.VERBOSE),
    )


def main():
    args = parse_args()

    logging.basicConfig(level=logging.INFO)
    netsnmp.load_mibs()
    netsnmp.register_log_callback(enable_debug=True)

    loop = asyncio.get_event_loop()
    main_task = asyncio.ensure_future(run(args))
    for signal in [SIGINT, SIGTERM]:
        loop.add_signal_handler(signal, main_task.cancel)
    try:
        loop.run_until_complete(main_task)
    finally:
        loop.close()


async def run(args):
    for addr in args.address:
        sess = trapsession.SNMPTrapSession(addr.address, addr.port)
        sess.open()
        sess.add_observer(trap_observer)

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass


def trap_observer(trap: SNMPTrap) -> None:
    print(f"Received trap: {trap!r}")


def parse_args():
    parser = argparse.ArgumentParser(description="SNMP trap daemon")
    parser.add_argument(
        "address",
        nargs="*",
        help="Address to listen to (eg. ip:port)",
        type=InterfaceAddress,
        default=[InterfaceAddress("0.0.0.0:1162")],
    )
    return parser.parse_args()


class InterfaceAddress(tuple):
    """Represents a network interface address and port.

    Mostly useful to verify incoming listening interface specs (i.e. ip:port combos).
    """

    def __init__(self, address: Union[str, InterfaceTuple]):
        ipaddr = None
        port = 0
        if isinstance(address, tuple):
            if len(address) == 2:
                ipaddr, port = address
            else:
                raise ValueError("Address must be a tuple of (address, port)")
        else:
            address = address.strip()
            match = (pattern.match(address) for pattern in ADDRESS_PATTERNS)
            match = reduce(lambda x, y: x or y, match)
            if match:
                match = match.groupdict()
                ipaddr = match["addr"]
                port = match.get("port", 0)

        self.address = ip_address(ipaddr)
        self.port = int(port)

    def __str__(self):
        if self.address.version == 6:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


if __name__ == "__main__":
    main()
