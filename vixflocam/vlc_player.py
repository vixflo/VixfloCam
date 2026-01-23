from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import vlc


@dataclass
class VlcConfig:
    # valori mici ca să reducă latența și să ajute la reconectare
    network_caching_ms: int = 300
    live_caching_ms: int = 300
    clock_jitter: int = 0
    clock_sync: int = 0


def _maybe_add_vlc_dll_dir() -> None:
    """Ajută Windows să găsească libvlc dacă VLC e instalat în locația standard."""
    candidates = [
        Path(os.environ.get("VLC_HOME", "")),
        Path("C:/Program Files/VideoLAN/VLC"),
        Path("C:/Program Files (x86)/VideoLAN/VLC"),
    ]
    for d in candidates:
        if d and d.exists() and (d / "libvlc.dll").exists():
            try:
                os.add_dll_directory(str(d))
            except Exception:
                pass
            return


class VlcPlayer:
    def __init__(self, config: Optional[VlcConfig] = None, *, headless: bool = False):
        _maybe_add_vlc_dll_dir()
        self._config = config or VlcConfig()
        args = [
            "--no-video-title-show",
            "--no-snapshot-preview",
            "--quiet",
            f"--network-caching={self._config.network_caching_ms}",
            f"--live-caching={self._config.live_caching_ms}",
            f"--clock-jitter={self._config.clock_jitter}",
            f"--clock-synchro={self._config.clock_sync}",
        ]
        if headless:
            # Prevent VLC from creating its own window for recording.
            args.extend(["--vout=dummy", "--aout=dummy", "--no-video", "--no-audio"])
        instance = vlc.Instance(args)
        if instance is None:
            raise RuntimeError(
                "LibVLC init failed. Install VLC (64-bit) or set VLC_HOME to the VLC folder."
            )
        self._instance = instance
        self._headless = bool(headless)

        media_player = self._instance.media_player_new()
        if media_player is None:
            raise RuntimeError("LibVLC failed to create media player.")
        self._media_player = media_player
        self._event_cb: Callable[[str], None] | None = None

        self._evt_error = getattr(vlc.EventType, "MediaPlayerEncounteredError", None)
        self._evt_end = getattr(vlc.EventType, "MediaPlayerEndReached", None)

        em = self._media_player.event_manager()
        if self._evt_error is not None:
            em.event_attach(self._evt_error, self._handle_event)
        if self._evt_end is not None:
            em.event_attach(self._evt_end, self._handle_event)

        # defaults
        try:
            self.audio_set_volume(80)
        except Exception:
            pass

    def set_event_callback(self, cb: Callable[[str], None] | None) -> None:
        self._event_cb = cb

    def _handle_event(self, event: object) -> None:
        if self._event_cb is None:
            return
        try:
            etype = getattr(event, "type", None)
            if self._evt_error is not None and etype == self._evt_error:
                self._event_cb("error")
            elif self._evt_end is not None and etype == self._evt_end:
                self._event_cb("end")
        except Exception:
            return

    def set_hwnd(self, hwnd: int) -> None:
        self._media_player.set_hwnd(hwnd)

    def play(self, url: str, record_to: Path | None = None) -> None:
        media = self._instance.media_new(url)
        if media is None:
            raise RuntimeError("LibVLC failed to create media.")

        # Prefer RTSP over TCP for stability (especially over Wi-Fi).
        try:
            media.add_option(":rtsp-tcp")
        except Exception:
            pass

        # NU forțăm aspect ratio - lăsăm VLC să detecteze automat din stream
        # Aceasta este esențial pentru zoom corect fără distorsiuni

        # Mild audio boost: helps cameras that send low-level audio.
        # If the filter/options are not supported by the user's VLC build, VLC will ignore them.
        try:
            media.add_option(":audio-filter=compressor")
            media.add_option(":compressor-threshold=-24")
            media.add_option(":compressor-ratio=4")
            media.add_option(":compressor-attack=5")
            media.add_option(":compressor-release=150")
            media.add_option(":compressor-makeup-gain=12")
        except Exception:
            pass

        if record_to is not None:
            record_to.parent.mkdir(parents=True, exist_ok=True)
            dst = str(record_to).replace("\\", "/")
            # Recording pipeline:
            # - normal player: duplicate to display + file
            # - headless recorder: file only (no display sink)
            if self._headless:
                media.add_option(":sout=#std{access=file,mux=ts,dst='%s'}" % dst)
            else:
                media.add_option(":sout=#duplicate{dst=display,dst=std{access=file,mux=ts,dst='%s'}}" % dst)
            media.add_option(":sout-keep")

        self._media_player.set_media(media)
        self._media_player.play()

    def audio_set_volume(self, volume_0_100: int) -> None:
        # VLC supports amplification >100 (typically up to 200).
        vol = max(0, min(200, int(volume_0_100)))
        self._media_player.audio_set_volume(vol)

    def video_set_scale(self, scale: float) -> None:
        # In VLC:
        # - 0.0 means "auto fit to drawable"
        # - positive floats (including <1.0) are valid scaling factors.
        try:
            s = float(scale)
        except Exception:
            s = 0.0
        if s < 0.0:
            s = 0.0
        self._media_player.video_set_scale(s)

    def video_set_aspect_ratio(self, aspect: str | None) -> None:
        """Force display aspect ratio (e.g. '16:9'). Pass None/'' to clear."""
        try:
            if not aspect:
                self._media_player.video_set_aspect_ratio(None)
            else:
                self._media_player.video_set_aspect_ratio(str(aspect))
        except Exception:
            return

    def video_get_size(self) -> tuple[int, int]:
        # Returns decoded video dimensions if available.
        try:
            # python-vlc supports video_get_size(num)
            w, h = self._media_player.video_get_size(0)
            w_i = int(w or 0)
            h_i = int(h or 0)
            # VLC may briefly report nonsense like (1920, 1) while the stream is initializing.
            # Treat very small dimensions as "unknown" and let callers retry.
            if w_i >= 64 and h_i >= 64:
                return w_i, h_i
        except Exception:
            pass

        # Fallbacks: some VLC outputs return size late or via width/height getters.
        try:
            w = int(getattr(self._media_player, "video_get_width")())
            h = int(getattr(self._media_player, "video_get_height")())
            w = max(0, w)
            h = max(0, h)
            if w >= 64 and h >= 64:
                return w, h
            return 0, 0
        except Exception:
            return 0, 0

    def video_get_aspect(self) -> float | None:
        """Return display aspect ratio (DAR) if VLC knows it (e.g., 1.777... for 16:9)."""
        try:
            ar = self._media_player.video_get_aspect_ratio()
        except Exception:
            ar = None

        if not ar:
            return None

        try:
            if isinstance(ar, bytes):
                ar_s = ar.decode("utf-8", errors="ignore")
            else:
                ar_s = str(ar)
        except Exception:
            return None

        ar_s = ar_s.strip()
        if not ar_s:
            return None

        # Common format: "16:9" or "4:3".
        if ":" in ar_s:
            try:
                a, b = ar_s.split(":", 1)
                num = float(a.strip())
                den = float(b.strip())
                if den > 0:
                    val = num / den
                    if 0.2 < val < 10.0:
                        return val
            except Exception:
                return None

        # Sometimes VLC returns a float-like string.
        try:
            val = float(ar_s)
            if 0.2 < val < 10.0:
                return val
        except Exception:
            return None

        return None
    
    def video_get_real_aspect_ratio(self) -> float:
        """Obține aspect ratio real din dimensiunile video."""
        w, h = self.video_get_size()
        if w > 0 and h > 0:
            return float(w) / float(h)
        # Default pentru camere Tapo
        return 16.0 / 9.0

    def video_set_crop_geometry(self, geometry: str | None) -> None:
        # geometry format: "<w>x<h>+<x>+<y>". Empty/None clears crop.
        try:
            if not geometry:
                self._media_player.video_set_crop_geometry(None)
            else:
                self._media_player.video_set_crop_geometry(str(geometry))
        except Exception:
            return

    def audio_toggle_mute(self) -> None:
        self._media_player.audio_toggle_mute()

    def audio_set_mute(self, mute: bool) -> None:
        self._media_player.audio_set_mute(bool(mute))

    def audio_get_mute(self) -> bool:
        return bool(self._media_player.audio_get_mute())

    def stop(self) -> None:
        try:
            self._media_player.stop()
        except Exception:
            pass

    def release(self) -> None:
        try:
            self.stop()
        finally:
            try:
                self._media_player.release()
            except Exception:
                pass
            try:
                self._instance.release()
            except Exception:
                pass
