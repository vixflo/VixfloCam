from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class EventEntry:
    ts: float
    camera_id: str
    camera_name: str
    kind: str  # "motion" | "person" | "unknown"
    topics: list[str]
    file: str  # path to recorded clip (may not exist yet)


def _events_path(base_dir: Path) -> Path:
    d = base_dir / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d / "events.json"


def load_events(base_dir: Path) -> list[EventEntry]:
    p = _events_path(base_dir)
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    out: list[EventEntry] = []
    for it in raw:
        if not isinstance(it, dict):
            continue
        try:
            ts = float(it.get("ts") or 0.0)
        except Exception:
            ts = 0.0
        camera_id = str(it.get("camera_id") or "")
        camera_name = str(it.get("camera_name") or "")
        kind = str(it.get("kind") or "unknown")
        topics_raw = it.get("topics") or []
        topics: list[str] = [str(x) for x in topics_raw] if isinstance(topics_raw, list) else []
        file = str(it.get("file") or "")
        if not camera_id:
            continue
        out.append(
            EventEntry(
                ts=ts,
                camera_id=camera_id,
                camera_name=camera_name,
                kind=kind,
                topics=topics,
                file=file,
            )
        )
    return out


def append_event(base_dir: Path, entry: EventEntry, *, max_events: int = 500) -> None:
    events = load_events(base_dir)
    events.append(entry)
    # Keep only the newest N
    events = sorted(events, key=lambda e: float(e.ts), reverse=True)[: int(max_events)]
    payload = [asdict(e) for e in events]
    _events_path(base_dir).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def now_ts() -> float:
    return float(time.time())

