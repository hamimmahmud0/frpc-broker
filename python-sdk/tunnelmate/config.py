from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TunnelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = "127.0.0.1"
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    scope: Literal["open", "closed"] = "open"
    shared_token: str | None = Field(None, min_length=16, max_length=256)
    service_name: str | None = Field(None, min_length=1, max_length=160)
    service_id: str | None = Field(None, min_length=1, max_length=160)
    llms: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    ca_path: Path | None = None
    verify_ca: bool = True
    agent_binary: Path | None = None
    log_level: Literal["debug", "info", "warn", "error"] = "info"

    @field_validator("shared_token")
    @classmethod
    def shared_token_scope(cls, value: str | None) -> str | None:
        return value


class PeerConfig(BaseModel):
    peer_address: str
    token: str = Field(min_length=1, max_length=256)
    local_host: str = "127.0.0.1"
    local_port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    ca_path: Path | None = None
    verify_ca: bool = True
    peer_binary: Path | None = None
    log_level: Literal["debug", "info", "warn", "error"] = "info"
