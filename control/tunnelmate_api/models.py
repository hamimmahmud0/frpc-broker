from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

Protocol = Literal["tcp", "udp"]
Scope = Literal["open", "closed"]


class TunnelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Scope = "open"
    protocol: Protocol = "tcp"
    shared_token: str | None = Field(None, min_length=16, max_length=256)
    prefer_port: int | None = Field(None, ge=1024, le=65535)

    @field_validator("shared_token")
    @classmethod
    def token_only_closed(cls, value: str | None, info: Any) -> str | None:
        return value


class TunnelPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class AnnouncementCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tunnel_id: str = Field(min_length=8, max_length=32)
    service_name: str = Field(min_length=1, max_length=160)
    service_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    llms: str = Field(max_length=2048)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("llms")
    @classmethod
    def validate_llms(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("llms must be an http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("llms URL must not contain credentials")
        return value


class AnnouncementPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_name: str | None = Field(None, min_length=1, max_length=160)
    service_id: str | None = Field(
        None, min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    llms: str | None = Field(None, max_length=2048)
    attributes: dict[str, Any] | None = None
    enabled: bool | None = None

    @field_validator("llms")
    @classmethod
    def validate_llms(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return AnnouncementCreate.validate_llms(value)


class AdminAnnouncementPatch(AnnouncementPatch):
    verified: bool | None = None


class BlockIPCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: str = Field(min_length=3, max_length=80)
    reason: str = Field(default="", max_length=300)

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        import ipaddress

        return str(ipaddress.ip_network(value, strict=False))


def validate_attributes(value: Any, max_depth: int, max_keys: int, max_bytes: int) -> None:
    keys = 0

    def walk(node: Any, depth: int) -> None:
        nonlocal keys
        if depth > max_depth:
            raise ValueError("attributes nesting is too deep")
        if isinstance(node, dict):
            keys += len(node)
            if keys > max_keys:
                raise ValueError("attributes contain too many keys")
            for key, item in node.items():
                if not isinstance(key, str) or len(key) > 128:
                    raise ValueError("attribute keys must be short strings")
                walk(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)
        elif node is not None and not isinstance(node, (str, int, float, bool)):
            raise ValueError("attributes must contain JSON values")

    walk(value, 1)
    if len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()) > max_bytes:
        raise ValueError("attributes are too large")
