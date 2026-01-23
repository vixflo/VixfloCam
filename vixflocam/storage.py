from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

from vixflocam.security import dpapi_decrypt_from_b64
from vixflocam.rtsp import RtspConfig, build_rtsp_url


@dataclass(frozen=True)
class Camera:
    id: str
    name: str
    # Preferred config (for easy editing)
    host: str = ""
    username: str = ""
    password_dpapi_b64: str = ""
    port: int = 554
    path: str = "stream1"
    # Optional: allow storing full URL (legacy/advanced)
    rtsp_url: str = ""
    onvif_port: int = 0

    def has_structured_config(self) -> bool:
        return bool(self.host and self.password_dpapi_b64)

    def password(self) -> str:
        if not self.password_dpapi_b64:
            return ""
        return dpapi_decrypt_from_b64(self.password_dpapi_b64).value

    def effective_rtsp_url(self) -> str:
        if self.rtsp_url:
            return self.rtsp_url
        cfg = RtspConfig(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password(),
            path=self.path,
        )
        return build_rtsp_url(cfg)


def _data_dir(base_dir: Path) -> Path:
    d = base_dir / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cameras_path(base_dir: Path) -> Path:
    return _data_dir(base_dir) / "cameras.json"


def load_cameras(base_dir: Path) -> List[Camera]:
    path = cameras_path(base_dir)
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    cams: List[Camera] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cam_id = str(item.get("id", "")).strip()
        name = str(item.get("name", "")).strip()

        # New format
        host = str(item.get("host", "")).strip()
        username = str(item.get("username", "")).strip()
        password_dpapi_b64 = str(item.get("password_dpapi_b64", "")).strip()
        port_raw = item.get("port", 554)
        path = str(item.get("path", "stream1")).strip() or "stream1"
        rtsp_url = str(item.get("rtsp_url", "")).strip()
        onvif_port_raw = item.get("onvif_port", 0)
        try:
            onvif_port = int(onvif_port_raw)
        except Exception:
            onvif_port = 0
        try:
            port = int(port_raw)
        except Exception:
            port = 554

        if cam_id and name and (rtsp_url or (host and password_dpapi_b64)):
            cams.append(
                Camera(
                    id=cam_id,
                    name=name,
                    host=host,
                    username=username,
                    password_dpapi_b64=password_dpapi_b64,
                    port=port,
                    path=path,
                    rtsp_url=rtsp_url,
                    onvif_port=onvif_port,
                )
            )
            continue
    return cams


def save_cameras(base_dir: Path, cameras: List[Camera]) -> None:
    path = cameras_path(base_dir)
    payload = [asdict(c) for c in cameras]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
