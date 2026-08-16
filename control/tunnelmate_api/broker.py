from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any


class BrokerUnavailable(RuntimeError):
    pass


class BrokerError(RuntimeError):
    pass


class BrokerClient:
    def __init__(self, socket_path: Path, timeout: float = 3.0):
        self.socket_path = socket_path
        self.timeout = timeout

    async def call(self, op: str, **params: Any) -> dict[str, Any]:
        request = json.dumps({"op": op, **params}, separators=(",", ":")) + "\n"
        if len(request) > 16000:
            raise BrokerError("broker request too large")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self.socket_path)), self.timeout
            )
            writer.write(request.encode())
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), self.timeout)
            writer.close()
            await writer.wait_closed()
        except (OSError, TimeoutError) as exc:
            raise BrokerUnavailable(str(exc)) from exc
        if not raw or len(raw) > 1_000_000:
            raise BrokerError("invalid broker response")
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BrokerError("invalid broker JSON") from exc
        if response.get("status") != "ok":
            raise BrokerError(str(response.get("error", "broker operation failed")))
        return response

    async def health(self) -> bool:
        try:
            await self.call("health")
            return True
        except (BrokerUnavailable, BrokerError):
            return False
