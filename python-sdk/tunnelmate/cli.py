from __future__ import annotations

import argparse
import json

from . import connect


def main() -> None:
    parser = argparse.ArgumentParser(prog="tunnelmate")
    sub = parser.add_subparsers(dest="command", required=True)
    peer = sub.add_parser("connect", help="connect to a closed tunnel")
    peer.add_argument("peer_address")
    peer.add_argument("--token", required=True)
    peer.add_argument("--listen", required=True, metavar="HOST:PORT")
    peer.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    peer.add_argument("--ca")
    peer.add_argument("--no-verify-ca", action="store_true")
    args = parser.parse_args()
    if args.command == "connect":
        host, port = args.listen.rsplit(":", 1)
        process = connect(
            args.peer_address,
            args.token,
            int(port),
            local_host=host,
            protocol=args.protocol,
            ca_path=args.ca,
            verify_ca=not args.no_verify_ca,
        )
        process.start()
        print(json.dumps({"status": "listening", "listen": args.listen}))
        process.wait()
