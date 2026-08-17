from __future__ import annotations

import argparse
import json

from . import connect


def main() -> None:
    parser = argparse.ArgumentParser(prog="tunnelmate")
    sub = parser.add_subparsers(dest="command", required=True)
    peer = sub.add_parser("connect", help="connect to a closed tunnel")
    peer.add_argument("peer_address")
    # --token puts a secret in /proc/PID/cmdline where every local user can
    # read it, so --token-file is the documented form and this stays only for
    # throwaway use.
    token_src = peer.add_mutually_exclusive_group(required=True)
    token_src.add_argument("--token", help="shared token (visible to other local users)")
    token_src.add_argument("--token-file", help="read the shared token from a protected file")
    peer.add_argument("--listen", required=True, metavar="HOST:PORT")
    peer.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    peer.add_argument("--ca")
    peer.add_argument("--no-verify-ca", action="store_true")
    args = parser.parse_args()
    if args.command == "connect":
        host, port = args.listen.rsplit(":", 1)
        token = args.token
        if token is None:
            with open(args.token_file, encoding="utf-8") as handle:
                # A file written with a here-doc or an editor ends in a
                # newline; sending it would fail authentication.
                token = handle.read().strip()
        process = connect(
            args.peer_address,
            token,
            int(port),
            local_host=host,
            protocol=args.protocol,
            ca_path=args.ca,
            verify_ca=not args.no_verify_ca,
        )
        process.start()
        print(json.dumps({"status": "listening", "listen": args.listen}))
        process.wait()
