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
    # Per-camera event settings (override global AppSettings when not None)
    event_detect_motion: bool | None = None
    event_detect_person: bool | None = None
    event_record_seconds: int | None = None
    event_cooldown_seconds: int | None = None
    event_desktop_notifications: bool | None = None
    event_motion_keywords: tuple[str, ...] = ()
    event_person_keywords: tuple[str, ...] = ()

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

        # Per-camera event overrides (optional)
        def as_opt_bool(v: object) -> bool | None:
            if v is None:
                return None
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                return bool(v)
            if isinstance(v, str):
                s = v.strip().lower()
                if s in ("1", "true", "yes", "y", "on"):
                    return True
                if s in ("0", "false", "no", "n", "off"):
                    return False
            return None

        def as_opt_int(v: object) -> int | None:
            if v is None or v == "":
                return None
            try:
                return int(v)  # type: ignore[arg-type]
            except Exception:
                return None

        def as_keywords(v: object) -> tuple[str, ...]:
            # Accept ["a","b"], ("a","b"), or "a,b"
            if v is None:
                return ()
            if isinstance(v, (list, tuple)):
                out = []
                for x in v:
                    s = str(x).strip()
                    if s:
                        out.append(s)
                return tuple(out)
            if isinstance(v, str):
                parts = [p.strip() for p in v.replace(";", ",").split(",")]
                return tuple([p for p in parts if p])
            return ()

        event_detect_motion = as_opt_bool(item.get("event_detect_motion"))
        event_detect_person = as_opt_bool(item.get("event_detect_person"))
        event_desktop_notifications = as_opt_bool(item.get("event_desktop_notifications"))
        event_record_seconds = as_opt_int(item.get("event_record_seconds"))
        event_cooldown_seconds = as_opt_int(item.get("event_cooldown_seconds"))
        event_motion_keywords = as_keywords(item.get("event_motion_keywords"))
        event_person_keywords = as_keywords(item.get("event_person_keywords"))
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
                    event_detect_motion=event_detect_motion,
                    event_detect_person=event_detect_person,
                    event_record_seconds=event_record_seconds,
                    event_cooldown_seconds=event_cooldown_seconds,
                    event_desktop_notifications=event_desktop_notifications,
                    event_motion_keywords=event_motion_keywords,
                    event_person_keywords=event_person_keywords,
                )
            )
            continue
    return cams


def save_cameras(base_dir: Path, cameras: List[Camera]) -> None:
    path = cameras_path(base_dir)
    payload = [asdict(c) for c in cameras]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
