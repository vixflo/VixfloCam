from __future__ import annotations

import argparse
import time
from pathlib import Path

from vixflocam.onvif_events import OnvifEventConfig, OnvifEventPuller
from vixflocam.storage import load_cameras


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="VixfloCam ONVIF Events diagnostic (PullPoint + PullMessages).")
    ap.add_argument("--camera", default="", help="Filter by camera name substring (case-insensitive).")
    ap.add_argument("--tries", type=int, default=3, help="Number of PullMessages attempts per camera.")
    ap.add_argument("--sleep", type=float, default=0.5, help="Sleep between attempts (seconds).")
    ap.add_argument("--duration", type=float, default=0.0, help="Poll for N seconds (overrides --tries when >0).")
    ap.add_argument("--dump", default="", help="Write last PullMessages XML to this file (per camera, overwrites).")
    args = ap.parse_args(argv)

    base_dir = Path(".").resolve()
    cams = load_cameras(base_dir)
    if args.camera:
        needle = args.camera.strip().lower()
        cams = [c for c in cams if needle in (c.name or "").lower()]

    if not cams:
        print("No cameras matched.")
        return 2

    for cam in cams:
        if not (cam.host and cam.onvif_port and cam.password_dpapi_b64):
            print(f"- {cam.name}: SKIP (missing ONVIF host/port/credentials)")
            continue

        cfg = OnvifEventConfig(
            host=cam.host,
            port=int(cam.onvif_port),
            username=cam.username,
            password=cam.password(),
        )
        puller = OnvifEventPuller(cfg)

        print(f"\n== {cam.name} ({cam.host}:{cam.onvif_port}) ==")
        if float(args.duration or 0.0) > 0.0:
            end = time.monotonic() + float(args.duration)
            i = 0
            while time.monotonic() < end:
                i += 1
                topics = puller.pull_once()
                err = puller.last_error
                if err:
                    print(f"[{i}] FAILED: {err}")
                else:
                    if topics:
                        print(f"[{i}] OK: topics={len(topics)}")
                        for t in topics[:50]:
                            print(f"  - {t}")
                if args.dump and puller.last_pull_xml:
                    try:
                        dump_path = Path(str(args.dump)).resolve()
                        safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in cam.name)
                        out = dump_path
                        if dump_path.is_dir() or str(args.dump).endswith(("\\", "/")):
                            out = dump_path / f"onvif_events_{safe}.xml"
                        out.parent.mkdir(parents=True, exist_ok=True)
                        out.write_text(puller.last_pull_xml, encoding="utf-8")
                    except Exception:
                        pass
                time.sleep(max(0.0, float(args.sleep)))
            continue

        for i in range(max(1, int(args.tries))):
            topics = puller.pull_once()
            err = puller.last_error
            if err:
                print(f"[{i+1}] FAILED: {err}")
            else:
                print(f"[{i+1}] OK: topics={len(topics)}")
                if topics:
                    for t in topics[:50]:
                        print(f"  - {t}")
            if args.dump and puller.last_pull_xml:
                try:
                    dump_path = Path(str(args.dump)).resolve()
                    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in cam.name)
                    out = dump_path
                    if dump_path.is_dir() or str(args.dump).endswith(("\\", "/")):
                        out = dump_path / f"onvif_events_{safe}.xml"
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(puller.last_pull_xml, encoding="utf-8")
                    print(f"    dumped: {out}")
                except Exception as e:
                    print(f"    dump failed: {e}")
            time.sleep(max(0.0, float(args.sleep)))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
