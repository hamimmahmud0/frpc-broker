#!/usr/bin/env python3
"""Disk-free deterministic TCP hash server/client for extended tunnel tests."""

import argparse
import hashlib
import socket
import time

BLOCK = bytes(range(256)) * 256


def serve(host: str, port: int) -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        print(
            f"hash server listening on {host}:{listener.getsockname()[1]}", flush=True
        )
        while True:
            conn, _ = listener.accept()
            with conn:
                digest = hashlib.sha256()
                total = 0
                while chunk := conn.recv(65536):
                    digest.update(chunk)
                    total += len(chunk)
                conn.sendall(f"{total} {digest.hexdigest()}\n".encode())


def send(host: str, port: int, count: int) -> None:
    expected = hashlib.sha256()
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=30) as conn:
        conn.settimeout(120)
        left = count
        while left:
            chunk = BLOCK[: min(left, len(BLOCK))]
            conn.sendall(chunk)
            expected.update(chunk)
            left -= len(chunk)
        conn.shutdown(socket.SHUT_WR)
        response = b""
        while not response.endswith(b"\n"):
            response += conn.recv(4096)
    remote_count, remote_hash = response.decode().strip().split()
    elapsed = time.monotonic() - started
    assert int(remote_count) == count
    assert remote_hash == expected.hexdigest()
    print(
        f"bytes={count} seconds={elapsed:.3f} MiB/s={count / elapsed / 1048576:.2f} sha256={remote_hash}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bytes", type=int, default=6 * 1024**3)
    args = parser.parse_args()
    serve(args.host, args.port) if args.serve else send(
        args.host, args.port, args.bytes
    )


if __name__ == "__main__":
    main()
