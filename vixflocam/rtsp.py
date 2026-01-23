from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


@dataclass(frozen=True)
class RtspConfig:
    host: str
    port: int = 554
    username: str = ""
    password: str = ""
    path: str = "stream1"


def build_rtsp_url(cfg: RtspConfig) -> str:
    host = cfg.host.strip()
    if not host:
        raise ValueError("host is required")

    path = cfg.path.strip().lstrip("/")
    if not path:
        path = "stream1"

    auth = ""
    if cfg.username:
        u = quote(cfg.username, safe="")
        p = quote(cfg.password, safe="")
        auth = f"{u}:{p}@"

    port = int(cfg.port) if cfg.port else 554
    return f"rtsp://{auth}{host}:{port}/{path}"
