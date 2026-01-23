from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppSettings:
    recordings_dir: str = ""  # empty = default under data/


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
    return AppSettings(recordings_dir=rec)


def save_settings(base_dir: Path, settings: AppSettings) -> None:
    path = _settings_path(base_dir)
    payload = {"recordings_dir": settings.recordings_dir}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
