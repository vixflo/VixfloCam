from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppSettings:
    recordings_dir: str = ""  # empty = default under data/
    # Event detection/recording
    detect_motion: bool = True
    detect_person: bool = True
    event_record_seconds: int = 60
    event_cooldown_seconds: int = 20
    desktop_notifications: bool = True


def _settings_path(base_dir: Path) -> Path:
    d = base_dir / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d / "settings.json"


def load_settings(base_dir: Path) -> AppSettings:
    path = _settings_path(base_dir)
    if not path.exists():
        return AppSettings()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return AppSettings()

    if not isinstance(raw, dict):
        return AppSettings()

    rec = str(raw.get("recordings_dir", "") or "")

    def as_bool(val: object, default: bool) -> bool:
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return bool(val)
        if isinstance(val, str):
            v = val.strip().lower()
            if v in ("1", "true", "yes", "y", "on"):
                return True
            if v in ("0", "false", "no", "n", "off"):
                return False
        return default

    def as_int(val: object, default: int) -> int:
        try:
            return int(val)  # type: ignore[arg-type]
        except Exception:
            return default

    detect_motion = as_bool(raw.get("detect_motion", True), True)
    detect_person = as_bool(raw.get("detect_person", True), True)
    desktop_notifications = as_bool(raw.get("desktop_notifications", True), True)

    event_record_seconds = max(10, min(300, as_int(raw.get("event_record_seconds", 60), 60)))
    event_cooldown_seconds = max(5, min(300, as_int(raw.get("event_cooldown_seconds", 20), 20)))

    return AppSettings(
        recordings_dir=rec,
        detect_motion=detect_motion,
        detect_person=detect_person,
        event_record_seconds=event_record_seconds,
        event_cooldown_seconds=event_cooldown_seconds,
        desktop_notifications=desktop_notifications,
    )


def save_settings(base_dir: Path, settings: AppSettings) -> None:
    path = _settings_path(base_dir)
    payload = {
        "recordings_dir": settings.recordings_dir,
        "detect_motion": bool(settings.detect_motion),
        "detect_person": bool(settings.detect_person),
        "event_record_seconds": int(settings.event_record_seconds),
        "event_cooldown_seconds": int(settings.event_cooldown_seconds),
        "desktop_notifications": bool(settings.desktop_notifications),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
