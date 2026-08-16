from __future__ import annotations

from typing import Any

from .client import Peer, Tunnel, TunnelMateError
from .config import PeerConfig, TunnelConfig


def new(broker_url: str, conf: TunnelConfig | dict[str, Any]) -> Tunnel:
    return Tunnel(
        broker_url,
        conf if isinstance(conf, TunnelConfig) else TunnelConfig.model_validate(conf),
    )


def connect(
    peer_address: str,
    token: str,
    local_port: int,
    *,
    local_host: str = "127.0.0.1",
    protocol: str = "tcp",
    ca_path: str | None = None,
    verify_ca: bool = True,
) -> Peer:
    return Peer(
        PeerConfig(
            peer_address=peer_address,
            token=token,
            local_host=local_host,
            local_port=local_port,
            protocol=protocol,
            ca_path=ca_path,
            verify_ca=verify_ca,
        )
    )


__all__ = [
    "Peer",
    "PeerConfig",
    "Tunnel",
    "TunnelConfig",
    "TunnelMateError",
    "connect",
    "new",
]
