"""Example program of how to run a simple SNMP GET request using netsnmp-cffi"""

import argparse
import asyncio
import logging

from netsnmpy import netsnmp, session


def main():
    args = parse_args()

    logging.basicConfig(level=logging.INFO)
    netsnmp.load_mibs()
    netsnmp.register_log_callback()

    asyncio.run(run(args))


async def run(args):
    sess = session.SNMPSession(
        host=args.host, port=args.port, version=args.version, community=args.community
    )
    sess.open()

    oids = [netsnmp.symbol_to_oid(obj) for obj in args.oid]
    try:
        varbinds = await sess.aget(*oids)
    except TimeoutError:
        print("Request timed out")
    else:
        for varbind in varbinds:
            print(varbind)


def parse_args():
    parser = argparse.ArgumentParser(description="SNMP GET request")
    parser.add_argument("host", help="SNMP agent host")
    parser.add_argument("--port", "-p", type=int, default=161, help="SNMP agent port")
    parser.add_argument(
        "--version", "-v", type=str, default="2c", help="SNMP agent port"
    )
    parser.add_argument(
        "--community", "-c", default="public", help="SNMP community string"
    )
    parser.add_argument("oid", nargs="+", help="MIB object to query for")
    return parser.parse_args()


if __name__ == "__main__":
    main()
