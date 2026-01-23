from __future__ import annotations

import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from vixflocam.settings import load_settings
from vixflocam.storage import Camera, load_cameras
from vixflocam.vlc_player import VlcPlayer


@dataclass
class _Worker:
    thread: threading.Thread
    stop_flag: threading.Event


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)


def _recordings_dir(base_dir: Path) -> Path:
    settings = load_settings(base_dir)
    if settings.recordings_dir:
        return Path(settings.recordings_dir)
    return base_dir / "data" / "recordings"


def _run_camera_loop(base_dir: Path, cam: Camera, stop_flag: threading.Event) -> None:
    seg_len_s = 60
    max_files_per_cam = 500
    prefix = _safe_name(cam.name)
    out_dir = _recordings_dir(base_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    recorder: VlcPlayer | None = None
    try:
        recorder = VlcPlayer(headless=True)
    except Exception:
        recorder = None

    while not stop_flag.is_set():
        if recorder is None:
            time.sleep(2)
            continue

        ts = time.strftime("%Y%m%d_%H%M%S")
        out = out_dir / f"{prefix}_roll_{ts}.ts"

        try:
            recorder.stop()
            recorder.play(cam.effective_rtsp_url(), record_to=out)
        except Exception:
            time.sleep(2)
            continue

        t0 = time.monotonic()
        while (time.monotonic() - t0) < seg_len_s and not stop_flag.is_set():
            time.sleep(0.5)

        try:
            recorder.stop()
        except Exception:
            pass

        # Retention per camera prefix.
        try:
            files = sorted(out_dir.glob(f"{prefix}_roll_*.ts"), key=lambda p: p.stat().st_mtime, reverse=True)
            for p in files[max_files_per_cam:]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    continue
        except Exception:
            pass

    try:
        if recorder is not None:
            recorder.stop()
            recorder.release()
    except Exception:
        pass


def main() -> int:
    base_dir = Path(__file__).resolve().parents[1]
    cams = [c for c in load_cameras(base_dir) if (c.rtsp_url or c.has_structured_config())]
    if not cams:
        print("No cameras configured. Add cameras in the UI first (data/cameras.json).")
        return 2

    stop_all = threading.Event()

    def _handle_sig(_sig, _frame):
        stop_all.set()

    try:
        signal.signal(signal.SIGINT, _handle_sig)
        signal.signal(signal.SIGTERM, _handle_sig)
    except Exception:
        pass

    workers: list[_Worker] = []
    for cam in cams:
        ev = threading.Event()
        t = threading.Thread(target=_run_camera_loop, args=(base_dir, cam, ev), daemon=True)
        workers.append(_Worker(thread=t, stop_flag=ev))
        t.start()
        print(f"Rolling recording started: {cam.name}")

    print("Recorder running. Press Ctrl+C to stop.")

    try:
        while not stop_all.is_set():
            time.sleep(0.5)
    finally:
        for w in workers:
            w.stop_flag.set()
        time.sleep(0.5)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
