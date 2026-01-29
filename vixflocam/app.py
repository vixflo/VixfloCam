from __future__ import annotations

import ctypes
import logging
import sys
import threading
import time
import uuid
from math import gcd
from pathlib import Path

from ctypes import wintypes
from typing import cast

from PySide6 import QtCore, QtGui, QtWidgets

# Configurează logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vixflocam.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

from vixflocam.rtsp import RtspConfig, build_rtsp_url
from vixflocam.security import dpapi_encrypt_to_b64
from vixflocam.settings import AppSettings, load_settings, save_settings
from vixflocam.storage import Camera, load_cameras, save_cameras
from vixflocam.vlc_player import VlcPlayer
from vixflocam.onvif_events import OnvifEventConfig, OnvifEventPuller
from vixflocam.onvif_ptz import OnvifConfig, OnvifPtzClient, detect_onvif_port, diagnose_onvif
from vixflocam.events_store import EventEntry, append_event, load_events, now_ts


class AddCameraDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget | None = None, camera: Camera | None = None):
        super().__init__(parent)
        self.setWindowTitle("Add / Edit Camera")
        self.setModal(True)

        self._ui_bridge = _UiInvokeBridge()
        self._ui_bridge.invoke.connect(self._invoke_ui)

        self._camera_id: str | None = camera.id if camera else None

        self.name_edit = QtWidgets.QLineEdit()

        self.host_edit = QtWidgets.QLineEdit()
        self.host_edit.setPlaceholderText("192.168.1.50")

        self.user_edit = QtWidgets.QLineEdit()
        self.pass_edit = QtWidgets.QLineEdit()
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.port_edit = QtWidgets.QSpinBox()
        self.port_edit.setRange(1, 65535)
        self.port_edit.setValue(554)

        self.path_combo = QtWidgets.QComboBox()
        self.path_combo.setEditable(True)
        self.path_combo.addItems(["stream1", "stream2"])

        self.onvif_port = QtWidgets.QSpinBox()
        self.onvif_port.setRange(0, 65535)
        self.onvif_port.setValue(0)
        self.onvif_port.setToolTip("0 = off. Typical ONVIF ports: 2020, 80, 8899 (depends on camera).")

        self.detect_onvif_btn = QtWidgets.QPushButton("Detect ONVIF port")
        self.detect_onvif_btn.clicked.connect(self._detect_onvif)

        self.preview = QtWidgets.QLineEdit()
        self.preview.setReadOnly(True)

        self._update_preview_btn = QtWidgets.QPushButton("Preview URL")
        self._update_preview_btn.clicked.connect(self._update_preview)

        form = QtWidgets.QFormLayout()
        form.addRow("Name", self.name_edit)
        form.addRow("Host / IP", self.host_edit)
        form.addRow("Username", self.user_edit)
        form.addRow("Password", self.pass_edit)
        form.addRow("Port", self.port_edit)
        form.addRow("Stream path", self.path_combo)
        onvif_row = QtWidgets.QHBoxLayout()
        onvif_row.addWidget(self.onvif_port)
        onvif_row.addWidget(self.detect_onvif_btn)
        form.addRow("ONVIF port (0=off)", onvif_row)

        preview_row = QtWidgets.QHBoxLayout()
        preview_row.addWidget(self.preview, 1)
        preview_row.addWidget(self._update_preview_btn)
        form.addRow("RTSP Preview", preview_row)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

        if camera:
            self.name_edit.setText(camera.name)
            if camera.rtsp_url and not camera.host:
                # legacy: can't reliably split URL; user re-enters fields
                self.preview.setText(camera.rtsp_url)
            else:
                self.host_edit.setText(camera.host)
                self.user_edit.setText(camera.username)
                self.port_edit.setValue(camera.port or 554)
                self.path_combo.setCurrentText(camera.path or "stream1")
                self.onvif_port.setValue(int(camera.onvif_port or 0))
                self._update_preview()

        self.host_edit.textChanged.connect(self._update_preview)
        self.user_edit.textChanged.connect(self._update_preview)
        self.pass_edit.textChanged.connect(self._update_preview)
        self.port_edit.valueChanged.connect(self._update_preview)
        self.path_combo.currentTextChanged.connect(self._update_preview)

    def _invoke_ui(self, fn: object) -> None:
        try:
            if callable(fn):
                fn()
        except Exception:
            return

    def _detect_onvif(self) -> None:
        host = self.host_edit.text().strip()
        username = self.user_edit.text().strip()
        password = self.pass_edit.text()
        if not host or not password:
            QtWidgets.QMessageBox.warning(self, "Detect ONVIF", "Completează Host și Password înainte.")
            return

        self.detect_onvif_btn.setEnabled(False)
        self.detect_onvif_btn.setText("Detecting...")
        
        # Timeout global: dacă nu se termină în 15 secunde, considerăm că a eșuat
        timeout_triggered = [False]
        
        def on_global_timeout() -> None:
            if not timeout_triggered[0]:
                timeout_triggered[0] = True
                self.detect_onvif_btn.setEnabled(True)
                self.detect_onvif_btn.setText("Detect ONVIF port")
                QtWidgets.QMessageBox.warning(
                    self,
                    "Detect ONVIF",
                    "Operațiunea a depășit timpul maxim de așteptare.\n"
                    "Verifică conexiunea la cameră și încearcă din nou.",
                )
        
        QtCore.QTimer.singleShot(15000, on_global_timeout)

        def run() -> None:
            found = None
            try:
                found = detect_onvif_port(host, username, password)
            except Exception:
                found = None

            def finish() -> None:
                if timeout_triggered[0]:
                    return  # Timeout-ul a fost deja declanșat
                self.detect_onvif_btn.setEnabled(True)
                self.detect_onvif_btn.setText("Detect ONVIF port")
                if found is None:
                    QtWidgets.QMessageBox.information(
                        self,
                        "Detect ONVIF",
                        "Nu am detectat ONVIF pe porturile comune.\n"
                        "Verifică dacă ONVIF este activ în Tapo și dacă parola/user sunt corecte.",
                    )
                    return
                self.onvif_port.setValue(int(found))
                QtWidgets.QMessageBox.information(self, "Detect ONVIF", f"ONVIF detected on port: {found}")

            self._ui_bridge.invoke.emit(finish)

        threading.Thread(target=run, daemon=True).start()

    def _update_preview(self) -> None:
        try:
            cfg = RtspConfig(
                host=self.host_edit.text().strip(),
                port=int(self.port_edit.value()),
                username=self.user_edit.text().strip(),
                password=self.pass_edit.text(),
                path=self.path_combo.currentText().strip(),
            )
            self.preview.setText(build_rtsp_url(cfg))
        except Exception:
            self.preview.setText("")

    def get_camera(self) -> Camera:
        name = self.name_edit.text().strip()
        host = self.host_edit.text().strip()
        username = self.user_edit.text().strip()
        password = self.pass_edit.text()
        port = int(self.port_edit.value())
        path = self.path_combo.currentText().strip() or "stream1"
        onvif_port = int(self.onvif_port.value())

        if not name:
            raise ValueError("Name is required")
        if not host:
            raise ValueError("Host / IP is required")
        if not password:
            raise ValueError("Password is required")

        cam_id = self._camera_id or str(uuid.uuid4())
        return Camera(
            id=cam_id,
            name=name,
            host=host,
            username=username,
            password_dpapi_b64=dpapi_encrypt_to_b64(password),
            port=port,
            path=path,
            rtsp_url="",
            onvif_port=onvif_port,
        )


class _VlcEventBridge(QtCore.QObject):
    vlc_event = QtCore.Signal(str)


class _UiInvokeBridge(QtCore.QObject):
    invoke = QtCore.Signal(object)


class EventSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget | None, settings: AppSettings):
        super().__init__(parent)
        self.setWindowTitle("Event Settings")
        self.setModal(True)

        self.motion_chk = QtWidgets.QCheckBox("Detect motion")
        self.person_chk = QtWidgets.QCheckBox("Detect person")
        self.notify_chk = QtWidgets.QCheckBox("Desktop notifications")

        self.motion_chk.setChecked(bool(settings.detect_motion))
        self.person_chk.setChecked(bool(settings.detect_person))
        self.notify_chk.setChecked(bool(settings.desktop_notifications))

        self.record_secs = QtWidgets.QSpinBox()
        self.record_secs.setRange(10, 300)
        self.record_secs.setValue(int(getattr(settings, "event_record_seconds", 60) or 60))
        self.record_secs.setSuffix(" s")

        self.cooldown_secs = QtWidgets.QSpinBox()
        self.cooldown_secs.setRange(5, 300)
        self.cooldown_secs.setValue(int(getattr(settings, "event_cooldown_seconds", 20) or 20))
        self.cooldown_secs.setSuffix(" s")

        form = QtWidgets.QFormLayout()
        form.addRow(self.motion_chk)
        form.addRow(self.person_chk)
        form.addRow(self.notify_chk)
        form.addRow("Record duration", self.record_secs)
        form.addRow("Cooldown", self.cooldown_secs)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def updated_settings(self, base: AppSettings) -> AppSettings:
        base.detect_motion = bool(self.motion_chk.isChecked())
        base.detect_person = bool(self.person_chk.isChecked())
        base.desktop_notifications = bool(self.notify_chk.isChecked())
        base.event_record_seconds = int(self.record_secs.value())
        base.event_cooldown_seconds = int(self.cooldown_secs.value())
        return base


class CameraEventSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget | None, cam: Camera, defaults: AppSettings):
        super().__init__(parent)
        self.setWindowTitle(f"Event Settings - {cam.name}")
        self.setModal(True)
        self._cam = cam
        self._defaults = defaults

        def _label(val: object, fallback: object) -> str:
            return f"(default {fallback})" if val is None else "(override)"

        self.motion_chk = QtWidgets.QCheckBox(f"Detect motion {_label(cam.event_detect_motion, defaults.detect_motion)}")
        self.person_chk = QtWidgets.QCheckBox(f"Detect person {_label(cam.event_detect_person, defaults.detect_person)}")
        self.notify_chk = QtWidgets.QCheckBox(
            f"Desktop notifications {_label(cam.event_desktop_notifications, defaults.desktop_notifications)}"
        )

        self.motion_chk.setChecked(bool(defaults.detect_motion if cam.event_detect_motion is None else cam.event_detect_motion))
        self.person_chk.setChecked(bool(defaults.detect_person if cam.event_detect_person is None else cam.event_detect_person))
        self.notify_chk.setChecked(
            bool(defaults.desktop_notifications if cam.event_desktop_notifications is None else cam.event_desktop_notifications)
        )

        self.record_secs = QtWidgets.QSpinBox()
        self.record_secs.setRange(10, 300)
        rec = defaults.event_record_seconds if cam.event_record_seconds is None else cam.event_record_seconds
        self.record_secs.setValue(int(rec or 60))
        self.record_secs.setSuffix(" s")

        self.cooldown_secs = QtWidgets.QSpinBox()
        self.cooldown_secs.setRange(5, 300)
        cd = defaults.event_cooldown_seconds if cam.event_cooldown_seconds is None else cam.event_cooldown_seconds
        self.cooldown_secs.setValue(int(cd or 20))
        self.cooldown_secs.setSuffix(" s")

        self.motion_kw = QtWidgets.QLineEdit()
        self.motion_kw.setPlaceholderText("e.g. motion, cellmotiondetector, ismotion=true")
        self.motion_kw.setText(", ".join(list(cam.event_motion_keywords or ())))

        self.person_kw = QtWidgets.QLineEdit()
        self.person_kw.setPlaceholderText("e.g. person, human, people")
        self.person_kw.setText(", ".join(list(cam.event_person_keywords or ())))

        self.clear_overrides_btn = QtWidgets.QPushButton("Clear Overrides (use global defaults)")
        self.clear_overrides_btn.clicked.connect(self._clear_overrides)

        form = QtWidgets.QFormLayout()
        form.addRow(self.motion_chk)
        form.addRow(self.person_chk)
        form.addRow(self.notify_chk)
        form.addRow("Record duration", self.record_secs)
        form.addRow("Cooldown", self.cooldown_secs)
        form.addRow("Motion keywords", self.motion_kw)
        form.addRow("Person keywords", self.person_kw)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.clear_overrides_btn)
        layout.addWidget(buttons)

    def _clear_overrides(self) -> None:
        self.motion_chk.setChecked(bool(self._defaults.detect_motion))
        self.person_chk.setChecked(bool(self._defaults.detect_person))
        self.notify_chk.setChecked(bool(self._defaults.desktop_notifications))
        self.record_secs.setValue(int(self._defaults.event_record_seconds or 60))
        self.cooldown_secs.setValue(int(self._defaults.event_cooldown_seconds or 20))
        self.motion_kw.setText("")
        self.person_kw.setText("")

    @staticmethod
    def _parse_keywords(text: str) -> tuple[str, ...]:
        parts = [p.strip() for p in (text or "").replace(";", ",").split(",")]
        return tuple([p for p in parts if p])

    def updated_camera(self) -> Camera:
        # Always store explicit values (override); user can Clear Overrides to reset.
        return Camera(
            id=self._cam.id,
            name=self._cam.name,
            host=self._cam.host,
            username=self._cam.username,
            password_dpapi_b64=self._cam.password_dpapi_b64,
            port=self._cam.port,
            path=self._cam.path,
            rtsp_url=self._cam.rtsp_url,
            onvif_port=self._cam.onvif_port,
            event_detect_motion=bool(self.motion_chk.isChecked()),
            event_detect_person=bool(self.person_chk.isChecked()),
            event_record_seconds=int(self.record_secs.value()),
            event_cooldown_seconds=int(self.cooldown_secs.value()),
            event_desktop_notifications=bool(self.notify_chk.isChecked()),
            event_motion_keywords=self._parse_keywords(self.motion_kw.text()),
            event_person_keywords=self._parse_keywords(self.person_kw.text()),
        )


class _WinMouseHook:
    """Low-level mouse hook so wheel works even if VLC steals HWND messages."""

    def __init__(self, get_target_widget, on_wheel, on_pan_delta):
        self._get_target_widget = get_target_widget
        self._on_wheel = on_wheel
        self._on_pan_delta = on_pan_delta

        self._user32 = ctypes.windll.user32 if hasattr(ctypes, "windll") else None
        self._kernel32 = ctypes.windll.kernel32 if hasattr(ctypes, "windll") else None
        self._hook = None
        self._proc = None
        self._dragging = False
        self._last_pt: QtCore.QPoint | None = None
        self._move_pending = False
        self.last_error_code: int | None = None

    def start(self) -> bool:
        if not sys.platform.startswith("win"):
            return False
        if self._user32 is None or self._kernel32 is None:
            return False
        if self._hook is not None:
            return True

        WH_MOUSE_LL = 14
        WM_MOUSEMOVE = 0x0200
        WM_LBUTTONDOWN = 0x0201
        WM_LBUTTONUP = 0x0202
        WM_MOUSEWHEEL = 0x020A

        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        class MSLLHOOKSTRUCT(ctypes.Structure):
            _fields_ = [
                ("pt", POINT),
                ("mouseData", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_void_p),
            ]

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            LRESULT = ctypes.c_longlong
        else:
            LRESULT = ctypes.c_long
        LowLevelMouseProc = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

        # Set function prototypes to avoid 64-bit calling/arg mismatches.
        set_hook = getattr(self._user32, "SetWindowsHookExW", None)
        call_next = getattr(self._user32, "CallNextHookEx", None)
        unhook = getattr(self._user32, "UnhookWindowsHookEx", None)
        get_mod = getattr(self._kernel32, "GetModuleHandleW", None)
        get_last_error = getattr(self._kernel32, "GetLastError", None)
        if set_hook is None or call_next is None or unhook is None or get_mod is None:
            return False

        HHOOK = wintypes.HANDLE
        HINSTANCE = getattr(wintypes, "HINSTANCE", wintypes.HANDLE)
        HMODULE = getattr(wintypes, "HMODULE", wintypes.HANDLE)

        try:
            set_hook.restype = HHOOK
            set_hook.argtypes = [ctypes.c_int, LowLevelMouseProc, HINSTANCE, wintypes.DWORD]
            call_next.restype = LRESULT
            call_next.argtypes = [HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
            unhook.restype = wintypes.BOOL
            unhook.argtypes = [HHOOK]
            get_mod.restype = HMODULE
            get_mod.argtypes = [wintypes.LPCWSTR]
        except Exception:
            pass

        def inside_target(global_pt: QtCore.QPoint) -> bool:
            w = self._get_target_widget()
            if w is None or not w.isVisible():
                return False
            # Use mapFromGlobal to avoid DPI scaling mismatches.
            lp = w.mapFromGlobal(global_pt)
            return 0 <= lp.x() < w.width() and 0 <= lp.y() < w.height()

        def hook_proc(nCode, wParam, lParam):
            try:
                if nCode < 0:
                    return call_next(self._hook, nCode, wParam, lParam)
                msg = int(wParam)
                info = ctypes.cast(lParam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
                gpt = QtCore.QPoint(int(info.pt.x), int(info.pt.y))

                if msg == WM_MOUSEWHEEL:
                    # Use Qt cursor pos (DPI-consistent) on UI thread.
                    delta = ctypes.c_short((int(info.mouseData) >> 16) & 0xFFFF).value

                    def deliver() -> None:
                        try:
                            qt_gpt = QtGui.QCursor.pos()
                        except Exception:
                            qt_gpt = QtCore.QPoint(int(info.pt.x), int(info.pt.y))
                        if inside_target(qt_gpt):
                            self._on_wheel(int(delta), qt_gpt)

                    QtCore.QTimer.singleShot(0, deliver)

                elif msg == WM_LBUTTONDOWN:
                    def deliver_down() -> None:
                        try:
                            qt_gpt = QtGui.QCursor.pos()
                        except Exception:
                            qt_gpt = QtCore.QPoint(int(info.pt.x), int(info.pt.y))
                        if inside_target(qt_gpt):
                            self._dragging = True
                            self._last_pt = qt_gpt
                            self._move_pending = False

                    QtCore.QTimer.singleShot(0, deliver_down)

                elif msg == WM_MOUSEMOVE:
                    if self._dragging and self._last_pt is not None and not self._move_pending:
                        self._move_pending = True

                        def deliver_move() -> None:
                            self._move_pending = False
                            if not self._dragging or self._last_pt is None:
                                return
                            prev = self._last_pt
                            try:
                                cur = QtGui.QCursor.pos()
                            except Exception:
                                cur = QtCore.QPoint(int(info.pt.x), int(info.pt.y))
                            self._last_pt = cur
                            if inside_target(cur) or inside_target(prev):
                                self._on_pan_delta(cur, prev)

                        QtCore.QTimer.singleShot(0, deliver_move)

                elif msg == WM_LBUTTONUP:
                    def deliver_up() -> None:
                        self._dragging = False
                        self._last_pt = None
                        self._move_pending = False

                    QtCore.QTimer.singleShot(0, deliver_up)

            except BaseException:
                pass

            try:
                return call_next(self._hook, nCode, wParam, lParam)
            except Exception:
                return 0

        self._proc = LowLevelMouseProc(hook_proc)
        self.last_error_code = None
        try:
            self._hook = set_hook(WH_MOUSE_LL, self._proc, get_mod(None), 0)
        except Exception:
            self._hook = None

        ok = bool(self._hook)
        if not ok:
            try:
                if get_last_error is not None:
                    self.last_error_code = int(get_last_error())
            except Exception:
                self.last_error_code = None
        return ok

    def stop(self) -> None:
        if not sys.platform.startswith("win"):
            return
        if self._user32 is None:
            return
        if self._hook is None:
            return
        try:
            unhook = getattr(self._user32, "UnhookWindowsHookEx", None)
            if unhook is not None:
                unhook(self._hook)
        except Exception:
            pass
        self._hook = None
        self._proc = None


class VideoFrame(QtWidgets.QFrame):
    zoomWheel = QtCore.Signal(int, QtCore.QPoint)
    panDrag = QtCore.Signal(QtCore.QPoint)

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        # VLC will render directly into this widget.
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_NativeWindow, True)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_DontCreateNativeAncestors, True)
        self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.setMouseTracking(True)
        self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.setAutoFillBackground(True)
        pal = self.palette()
        pal.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(0, 0, 0))
        self.setPalette(pal)

        self._panning = False
        self._last_pan_pos: QtCore.QPoint | None = None
        self._last_wheel_ts: float = 0.0

    def _emit_zoom_wheel(self, delta_y: int, pos: QtCore.QPoint) -> None:
        now = time.monotonic()
        if now - self._last_wheel_ts < 0.05:
            return
        self._last_wheel_ts = now
        self.zoomWheel.emit(int(delta_y), pos)

    def _begin_pan(self, pos: QtCore.QPoint) -> None:
        self._panning = True
        self._last_pan_pos = pos
        self.setCursor(QtCore.Qt.CursorShape.ClosedHandCursor)
        self.setFocus()

    def _continue_pan(self, pos: QtCore.QPoint) -> None:
        if not self._panning or self._last_pan_pos is None:
            return
        delta = pos - self._last_pan_pos
        self._last_pan_pos = pos
        self.panDrag.emit(delta)

    def _end_pan(self) -> None:
        self._panning = False
        self._last_pan_pos = None
        self.unsetCursor()

    def wheelEvent(self, event: QtGui.QWheelEvent) -> None:
        self._emit_zoom_wheel(int(event.angleDelta().y()), event.position().toPoint())
        event.accept()

    def nativeEvent(self, eventType, message: int) -> tuple[bool, int]:
        # Best-effort fallback if the widget itself receives the native message.
        try:
            try:
                et = bytes(eventType.data()) if hasattr(eventType, "data") else bytes(eventType)
            except Exception:
                et = b""
            if et not in (b"windows_generic_MSG", b"windows_dispatcher_MSG"):
                return cast(tuple[bool, int], super().nativeEvent(eventType, message))

            msg = wintypes.MSG.from_address(int(message))
            WM_MOUSEMOVE = 0x0200
            WM_LBUTTONDOWN = 0x0201
            WM_LBUTTONUP = 0x0202
            WM_MOUSEWHEEL = 0x020A

            if msg.message == WM_MOUSEWHEEL:
                delta = ctypes.c_short((int(msg.wParam) >> 16) & 0xFFFF).value
                x = ctypes.c_short(int(msg.lParam) & 0xFFFF).value
                y = ctypes.c_short((int(msg.lParam) >> 16) & 0xFFFF).value
                local = self.mapFromGlobal(QtCore.QPoint(int(x), int(y)))
                self._emit_zoom_wheel(int(delta), local)
                return True, 0

            if msg.message == WM_LBUTTONDOWN:
                x = ctypes.c_short(int(msg.lParam) & 0xFFFF).value
                y = ctypes.c_short((int(msg.lParam) >> 16) & 0xFFFF).value
                self._begin_pan(QtCore.QPoint(int(x), int(y)))
                return True, 0

            if msg.message == WM_MOUSEMOVE:
                if self._panning and self._last_pan_pos is not None:
                    x = ctypes.c_short(int(msg.lParam) & 0xFFFF).value
                    y = ctypes.c_short((int(msg.lParam) >> 16) & 0xFFFF).value
                    self._continue_pan(QtCore.QPoint(int(x), int(y)))
                    return True, 0

            if msg.message == WM_LBUTTONUP:
                if self._panning:
                    self._end_pan()
                    return True, 0

        except Exception:
            pass

        return cast(tuple[bool, int], super().nativeEvent(eventType, message))

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self._begin_pan(event.position().toPoint())
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:
        if self._panning and self._last_pan_pos is not None:
            self._continue_pan(event.position().toPoint())
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.MouseButton.LeftButton and self._panning:
            self._end_pan()
            event.accept()
            return
        super().mouseReleaseEvent(event)


class InputOverlay(QtWidgets.QWidget):
    zoomWheel = QtCore.Signal(int, QtCore.QPoint)
    panDrag = QtCore.Signal(QtCore.QPoint)
    focusPos = QtCore.Signal(QtCore.QPoint)
    hoverPos = QtCore.Signal(QtCore.QPoint)

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAutoFillBackground(False)
        self.setMouseTracking(True)
        self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self._panning = False
        self._last_pan_global: QtCore.QPoint | None = None

    def wheelEvent(self, event: QtGui.QWheelEvent) -> None:
        # Emit global cursor position so handlers remain stable even if the video widget moves/resizes for zoom.
        try:
            gpt = event.globalPosition().toPoint()
        except Exception:
            gpt = QtGui.QCursor.pos()
        self.zoomWheel.emit(int(event.angleDelta().y()), gpt)
        event.accept()

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            self.focusPos.emit(pos)
            self._panning = True
            try:
                self._last_pan_global = event.globalPosition().toPoint()
            except Exception:
                self._last_pan_global = QtGui.QCursor.pos()
            self.setCursor(QtCore.Qt.CursorShape.ClosedHandCursor)
            self.setFocus()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:
        pos = event.position().toPoint()
        self.hoverPos.emit(pos)
        if self._panning and self._last_pan_global is not None:
            try:
                gpt = event.globalPosition().toPoint()
            except Exception:
                gpt = QtGui.QCursor.pos()
            delta = gpt - self._last_pan_global
            self._last_pan_global = gpt
            self.panDrag.emit(QtCore.QPoint(int(delta.x()), int(delta.y())))
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.MouseButton.LeftButton and self._panning:
            self._panning = False
            self._last_pan_global = None
            self.unsetCursor()
            event.accept()
            return
        super().mouseReleaseEvent(event)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, base_dir: Path):
        super().__init__()
        self._base_dir = base_dir
        self._settings: AppSettings = load_settings(self._base_dir)
        self.setWindowTitle("VixfloCam")
        self.resize(1100, 650)

        self._player: VlcPlayer | None = None
        self._current_camera: Camera | None = None
        self._pending_play_camera_id: str | None = None
        # Zoom/Pan state (TAPO model: simple center tracking)
        self._zoom_factor: float = 1.0  # 1.0 = no zoom, 8.0 = max zoom
        self._center_x: float = 0.5  # center position in normalized coords (0-1)
        self._center_y: float = 0.5
        self._last_mouse_pos: QtCore.QPoint | None = None
        self._zoom_apply_retry: int = 0
        self._last_video_size: tuple[int, int] = (0, 0)
        self._view_scale: float = 0.0
        self._last_wheel_event_ts: float = 0.0
        self._last_wheel_event_sig: tuple[int, int, int] | None = None
        self._prefer_qt_wheel_until: float = 0.0
        self._last_pan_event_ts: float = 0.0
        self._last_pan_event_sig: tuple[int, int] | None = None
        self._prefer_qt_pan_until: float = 0.0
        self._reconnect_attempts: int = 0
        self._reconnect_scheduled: bool = False
        self._last_vlc_error_ts: float = 0.0
        self._recording: bool = False
        self._record_path: Path | None = None
        self._viewing_event_file: Path | None = None
        self._event_prev_camera: Camera | None = None
        self._ptz_client: OnvifPtzClient | None = None
        self._ptz_for_camera_id: str | None = None
        self._ptz_connect_seq: int = 0
        self._ptz_connecting: bool = False
        self._ptz_diag_seq: int = 0
        self._ptz_no_support_ids: set[str] = set()
        self._ptz_worker_lock = threading.Lock()
        self._ptz_worker_evt = threading.Event()
        self._ptz_worker_stop = threading.Event()
        self._ptz_worker_latest_move: tuple[str, float, float] | None = None
        self._ptz_worker_stop_cam_id: str | None = None
        self._ptz_worker_thread = threading.Thread(target=self._ptz_worker_loop, daemon=True)
        self._ptz_worker_thread.start()
        self._ui_bridge = _UiInvokeBridge()
        self._ui_bridge.invoke.connect(self._invoke_ui)
        self._vlc_bridge = _VlcEventBridge()
        self._vlc_bridge.vlc_event.connect(self._on_vlc_event)

        self.cameras: list[Camera] = load_cameras(self._base_dir)

        self.list = QtWidgets.QListWidget()
        self.list.currentRowChanged.connect(self._on_camera_selected)

        # Video viewport (clips the native VLC child when we move/resize it for zoom/pan).
        self.video_viewport = QtWidgets.QFrame()
        self.video_viewport.setContentsMargins(0, 0, 0, 0)
        self.video_viewport.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.video_viewport.setAutoFillBackground(True)
        pal = self.video_viewport.palette()
        pal.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(0, 0, 0))
        self.video_viewport.setPalette(pal)
        self.video_viewport.setAttribute(QtCore.Qt.WidgetAttribute.WA_NativeWindow, True)
        self.video_viewport.setAttribute(QtCore.Qt.WidgetAttribute.WA_DontCreateNativeAncestors, True)
        self.video_viewport.setMouseTracking(True)

        # VLC will render directly into this widget (native child of the viewport).
        self.video = VideoFrame(self.video_viewport)
        self.video.setGeometry(self.video_viewport.rect())

        self.overlay = InputOverlay(self.video)
        self.overlay.setGeometry(self.video.rect())
        self.overlay.raise_()
        self.overlay.zoomWheel.connect(self._on_zoom_wheel_qt)
        self.overlay.panDrag.connect(self._on_pan_drag_qt)
        self.overlay.hoverPos.connect(self._on_hover_pos)
        self.video_viewport.installEventFilter(self)

        self._mouse_hook = _WinMouseHook(
            get_target_widget=lambda: self.video_viewport,
            on_wheel=self._on_global_wheel,
            on_pan_delta=self._on_global_pan,
        )

        # Controls (right side)
        self.vol_slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
        self.vol_slider.setRange(0, 200)
        self.vol_slider.setValue(120)
        self.vol_slider.valueChanged.connect(self._on_volume_changed)

        self.mute_chk = QtWidgets.QCheckBox("Mute")
        self.mute_chk.toggled.connect(self._on_mute_toggled)

        self.record_btn = QtWidgets.QPushButton("Start Recording")
        self.record_btn.setCheckable(True)
        self.record_btn.toggled.connect(self._on_record_toggled)

        self.event_rec_chk = QtWidgets.QCheckBox("Event Recording")
        self.event_rec_chk.toggled.connect(self._on_event_recording_toggled)

        self.rec_dir_btn = QtWidgets.QPushButton("Recordings Folder")
        self.rec_dir_btn.clicked.connect(self._choose_recordings_folder)

        self.events_btn = QtWidgets.QPushButton("Events")
        self.events_btn.clicked.connect(self._show_events_panel)

        self.event_settings_btn = QtWidgets.QPushButton("Event Settings")
        self.event_settings_btn.clicked.connect(self._show_event_settings)

        self.cam_event_settings_btn = QtWidgets.QPushButton("Cam Event Settings")
        self.cam_event_settings_btn.clicked.connect(self._show_camera_event_settings)

        self._event_rec_seq: int = 0
        self._event_recording_active: bool = False
        self._event_recording_enabled: bool = False
        self._event_record_stop_timer: QtCore.QTimer | None = None
        self._event_clip_recorder: VlcPlayer | None = None
        self._event_active_by_cam: set[str] = set()
        self._event_clip_recorders_by_cam: dict[str, VlcPlayer] = {}

        self._roll_seq: int = 0
        self._rolling_active: bool = False
        self._rolling_threads: dict[str, threading.Thread] = {}
        self._rolling_recorders: dict[str, VlcPlayer] = {}
        
        # PTZ command queue și debouncing
        self._ptz_move_timer: QtCore.QTimer | None = None
        self._ptz_command_queue: list[tuple[float, float]] = []
        self._ptz_last_command_ts: float = 0.0
        self._ptz_pending_move: tuple[float, float] | None = None
        self._ptz_pending_move_cam_id: str | None = None
        self._ptz_hold_dir: tuple[float, float] | None = None
        self._ptz_hold_timer = QtCore.QTimer(self)
        self._ptz_hold_timer.setInterval(250)
        self._ptz_hold_timer.timeout.connect(self._ptz_hold_tick)

        self.zoom_out_btn = QtWidgets.QPushButton("Zoom-")
        self.zoom_reset_btn = QtWidgets.QPushButton("Zoom 1:1")
        self.zoom_in_btn = QtWidgets.QPushButton("Zoom+")
        self.zoom_out_btn.clicked.connect(self._zoom_out)
        self.zoom_reset_btn.clicked.connect(self._zoom_reset)
        self.zoom_in_btn.clicked.connect(self._zoom_in)

        self.fill_chk = QtWidgets.QCheckBox("Fill")
        self.fill_chk.setChecked(True)
        self.fill_chk.setToolTip("Fill window (no black bars). Uncheck to fit full frame (letterbox).")
        self.fill_chk.toggled.connect(lambda _checked: self._apply_zoom())

        # PTZ controls (minimal)
        self.ptz_group = QtWidgets.QGroupBox("PTZ (ONVIF)")
        self.ptz_status = QtWidgets.QLabel("PTZ: disabled")
        self.ptz_diag = QtWidgets.QPushButton("PTZ Diagnostics")
        self.ptz_up = QtWidgets.QPushButton("↑")
        self.ptz_down = QtWidgets.QPushButton("↓")
        self.ptz_left = QtWidgets.QPushButton("←")
        self.ptz_right = QtWidgets.QPushButton("→")
        self.ptz_stop = QtWidgets.QPushButton("Stop")

        grid = QtWidgets.QGridLayout(self.ptz_group)
        grid.addWidget(self.ptz_status, 0, 0, 1, 2)
        grid.addWidget(self.ptz_diag, 0, 2)
        grid.addWidget(self.ptz_up, 1, 1)
        grid.addWidget(self.ptz_left, 2, 0)
        grid.addWidget(self.ptz_stop, 2, 1)
        grid.addWidget(self.ptz_right, 2, 2)
        grid.addWidget(self.ptz_down, 3, 1)

        # PTZ: trimite comenzi repetate cât timp butonul e ținut apăsat (mai robust decât o singură comandă).
        self.ptz_up.pressed.connect(lambda: self._ptz_begin_hold(0.0, 0.45))
        self.ptz_up.released.connect(self._ptz_end_hold)
        self.ptz_down.pressed.connect(lambda: self._ptz_begin_hold(0.0, -0.45))
        self.ptz_down.released.connect(self._ptz_end_hold)
        self.ptz_left.pressed.connect(lambda: self._ptz_begin_hold(-0.45, 0.0))
        self.ptz_left.released.connect(self._ptz_end_hold)
        self.ptz_right.pressed.connect(lambda: self._ptz_begin_hold(0.45, 0.0))
        self.ptz_right.released.connect(self._ptz_end_hold)
        self.ptz_stop.clicked.connect(self._ptz_end_hold)
        self.ptz_diag.clicked.connect(self._ptz_diagnostics)

        # Start disabled; we enable after a successful PTZ connect.
        self._set_ptz_controls_enabled(False)

        self.add_btn = QtWidgets.QPushButton("Add")
        self.edit_btn = QtWidgets.QPushButton("Edit")
        self.remove_btn = QtWidgets.QPushButton("Remove")
        self.add_btn.clicked.connect(self._add_camera)
        self.edit_btn.clicked.connect(self._edit_selected)
        self.remove_btn.clicked.connect(self._remove_selected)

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.edit_btn)
        btn_row.addWidget(self.remove_btn)
        btn_row.addStretch(1)

        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.addWidget(self.list, 1)
        left_layout.addLayout(btn_row)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Bottom area: live controls vs events page
        self._right_stack = QtWidgets.QStackedWidget()

        live_panel = QtWidgets.QWidget()
        live_layout = QtWidgets.QVBoxLayout(live_panel)
        live_layout.setContentsMargins(0, 0, 0, 0)

        ctrl_row = QtWidgets.QHBoxLayout()
        ctrl_row.addWidget(QtWidgets.QLabel("Volume"))
        ctrl_row.addWidget(self.vol_slider, 1)
        ctrl_row.addWidget(self.mute_chk)
        ctrl_row.addWidget(self.fill_chk)
        ctrl_row.addWidget(self.zoom_out_btn)
        ctrl_row.addWidget(self.zoom_reset_btn)
        ctrl_row.addWidget(self.zoom_in_btn)
        ctrl_row.addWidget(self.event_rec_chk)
        ctrl_row.addWidget(self.event_settings_btn)
        ctrl_row.addWidget(self.cam_event_settings_btn)
        ctrl_row.addWidget(self.rec_dir_btn)
        ctrl_row.addWidget(self.events_btn)
        ctrl_row.addWidget(self.record_btn)
        live_layout.addLayout(ctrl_row)
        live_layout.addWidget(self.ptz_group)

        events_panel = QtWidgets.QWidget()
        events_layout = QtWidgets.QVBoxLayout(events_panel)
        events_layout.setContentsMargins(0, 0, 0, 0)

        top_row = QtWidgets.QHBoxLayout()
        self.events_back_btn = QtWidgets.QPushButton("Back")
        self.events_back_btn.clicked.connect(self._show_live_panel)
        self.events_refresh_btn = QtWidgets.QPushButton("Refresh")
        self.events_refresh_btn.clicked.connect(self._refresh_events_list)
        self.events_play_btn = QtWidgets.QPushButton("Play Selected")
        self.events_play_btn.clicked.connect(self._play_selected_event)
        top_row.addWidget(self.events_back_btn)
        top_row.addWidget(self.events_refresh_btn)
        top_row.addStretch(1)
        top_row.addWidget(self.events_play_btn)
        events_layout.addLayout(top_row)

        self.events_list = QtWidgets.QListWidget()
        self.events_list.itemDoubleClicked.connect(lambda _it: self._play_selected_event())
        events_layout.addWidget(self.events_list, 1)

        self.topics_group = QtWidgets.QGroupBox("Live ONVIF Topics (selected camera)")
        self.topics_text = QtWidgets.QPlainTextEdit()
        self.topics_text.setReadOnly(True)
        self.topics_text.setMaximumBlockCount(500)
        self.topics_hint = QtWidgets.QLabel("Tip: folosește Cam Event Settings pentru cuvinte-cheie per cameră.")
        tg = QtWidgets.QVBoxLayout(self.topics_group)
        tg.addWidget(self.topics_text, 1)
        tg.addWidget(self.topics_hint)
        events_layout.addWidget(self.topics_group, 0)

        self._right_stack.addWidget(live_panel)
        self._right_stack.addWidget(events_panel)
        self._right_stack.setCurrentIndex(0)

        # Make the video vs controls area user-resizable (prevents "disproportion" when panels grow).
        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        right_splitter.addWidget(self.video_viewport)
        right_splitter.addWidget(self._right_stack)
        right_splitter.setStretchFactor(0, 1)
        right_splitter.setStretchFactor(1, 0)
        right_splitter.setChildrenCollapsible(True)
        try:
            right_splitter.setSizes([520, 180])
        except Exception:
            pass
        right_layout.addWidget(right_splitter, 1)

        splitter = QtWidgets.QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 780])

        self.setCentralWidget(splitter)

        self._refresh_list()

        # init player after window exists
        QtCore.QTimer.singleShot(0, self._ensure_player)
        # start low-level mouse hook after UI is shown
        QtCore.QTimer.singleShot(0, self._start_mouse_hook)

        self._tray: QtWidgets.QSystemTrayIcon | None = None
        QtCore.QTimer.singleShot(0, self._ensure_tray)

        self._last_onvif_topics_by_cam: dict[str, list[str]] = {}
        self._last_onvif_topics_ts_by_cam: dict[str, float] = {}
        self._topics_refresh_timer = QtCore.QTimer(self)
        self._topics_refresh_timer.setInterval(750)
        self._topics_refresh_timer.timeout.connect(self._refresh_topics_view)
        self._topics_refresh_timer.start()

    def _ensure_tray(self) -> None:
        try:
            if not QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
                return
        except Exception:
            return

        if self._tray is None:
            try:
                icon = self.windowIcon()
            except Exception:
                icon = QtGui.QIcon()
            self._tray = QtWidgets.QSystemTrayIcon(icon, self)
            self._tray.setToolTip("VixfloCam")
            try:
                self._tray.show()
            except Exception:
                pass

        # Respect user setting
        try:
            self._tray.setVisible(bool(getattr(self._settings, "desktop_notifications", True)))
        except Exception:
            pass

    def _notify_event(self, title: str, message: str) -> None:
        if not bool(getattr(self._settings, "desktop_notifications", True)):
            return
        if self._tray is None:
            self._ensure_tray()
        if self._tray is None:
            return
        try:
            self._tray.showMessage(str(title), str(message), QtWidgets.QSystemTrayIcon.MessageIcon.Information, 7000)
        except Exception:
            return

    def _notify_event_for_camera(self, cam: Camera, title: str, message: str) -> None:
        allow = self._effective_event_bool(cam, "event_desktop_notifications", bool(getattr(self._settings, "desktop_notifications", True)))
        if not allow:
            return
        # Keep global master switch, too.
        if not bool(getattr(self._settings, "desktop_notifications", True)):
            return
        self._notify_event(title, message)

    def _show_event_settings(self) -> None:
        dlg = EventSettingsDialog(self, self._settings)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        self._settings = dlg.updated_settings(self._settings)
        save_settings(self._base_dir, self._settings)
        self._ensure_tray()

    def _show_camera_event_settings(self) -> None:
        cam = self._current_camera
        if cam is None:
            QtWidgets.QMessageBox.information(self, "Event Settings", "Selectează o cameră înainte.")
            return
        dlg = CameraEventSettingsDialog(self, cam, self._settings)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        updated = dlg.updated_camera()
        # Replace in list + persist.
        for i, c in enumerate(self.cameras):
            if c.id == updated.id:
                self.cameras[i] = updated
                break
        save_cameras(self._base_dir, self.cameras)
        if self._current_camera is not None and self._current_camera.id == updated.id:
            self._current_camera = updated

    def _effective_event_bool(self, cam: Camera, name: str, default: bool) -> bool:
        val = getattr(cam, name, None)
        if val is None:
            return bool(default)
        return bool(val)

    def _effective_event_int(self, cam: Camera, name: str, default: int) -> int:
        val = getattr(cam, name, None)
        if val is None:
            return int(default)
        try:
            return int(val)
        except Exception:
            return int(default)

    def _invoke_ui(self, fn: object) -> None:
        try:
            if callable(fn):
                fn()
        except Exception:
            return

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        logger.info("Closing application...")
        try:
            self._ptz_worker_stop.set()
            self._ptz_worker_evt.set()
        except Exception:
            pass
        try:
            logger.debug("Stopping mouse hook...")
            self._mouse_hook.stop()
        except Exception as e:
            logger.error(f"Error stopping mouse hook: {e}")
        
        try:
            logger.debug("Stopping event recording...")
            # Ensure background event threads can exit without touching Qt objects.
            self._event_recording_enabled = False
            self._event_rec_seq += 1
            self._stop_event_recording()
            self._stop_rolling_segments()
        except Exception as e:
            logger.error(f"Error stopping event recording: {e}")
        
        try:
            logger.debug("Stopping player...")
            self._stop_player()
        except Exception as e:
            logger.error(f"Error stopping player: {e}")
        
        logger.info("Application closed successfully")
        super().closeEvent(event)
        
        # Forțează ieșirea dacă există thread-uri blocate
        QtCore.QTimer.singleShot(1000, lambda: sys.exit(0))

    def _ptz_worker_loop(self) -> None:
        while not self._ptz_worker_stop.is_set():
            # Wait for new PTZ work; keep a small timeout so stop feels responsive.
            self._ptz_worker_evt.wait(0.2)
            self._ptz_worker_evt.clear()
            if self._ptz_worker_stop.is_set():
                break

            with self._ptz_worker_lock:
                stop_cam_id = self._ptz_worker_stop_cam_id
                move = self._ptz_worker_latest_move
                # Stop has priority over move.
                self._ptz_worker_stop_cam_id = None
                self._ptz_worker_latest_move = None

            if stop_cam_id is not None:
                self._ptz_worker_do_stop(stop_cam_id)
                continue
            if move is not None:
                cam_id, x, y = move
                self._ptz_worker_do_move(cam_id, x, y)

    def _ptz_worker_do_move(self, cam_id: str, x: float, y: float) -> None:
        client = self._ptz_client
        if client is None or self._ptz_for_camera_id != cam_id:
            return

        try:
            client.continuous_move(float(x), float(y))
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            short = " ".join(msg.split())
            if len(short) > 120:
                short = short[:117] + "..."
            self._ui_bridge.invoke.emit(
                lambda cid=cam_id, s=short: self._ptz_set_status_if_current(cid, f"PTZ: move failed ({s})")
            )
            return

        self._ui_bridge.invoke.emit(
            lambda cid=cam_id: self._ptz_set_status_if_current(cid, self._ptz_status_text_moving())
        )

    def _ptz_worker_do_stop(self, cam_id: str) -> None:
        client = self._ptz_client
        if client is None or self._ptz_for_camera_id != cam_id:
            return

        try:
            client.stop()
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            short = " ".join(msg.split())
            if len(short) > 120:
                short = short[:117] + "..."
            self._ui_bridge.invoke.emit(
                lambda cid=cam_id, s=short: self._ptz_set_status_if_current(cid, f"PTZ: stop failed ({s})")
            )
            return

        self._ui_bridge.invoke.emit(
            lambda cid=cam_id: self._ptz_set_status_if_current(cid, self._ptz_status_text_connected())
        )

    def _ptz_status_text_connected(self) -> str:
        cam = self._current_camera
        if cam is None:
            return "PTZ: connected"
        return f"PTZ: connected (port {cam.onvif_port})"

    def _ptz_status_text_moving(self) -> str:
        cam = self._current_camera
        if cam is None:
            return "PTZ: moving"
        return f"PTZ: moving (port {cam.onvif_port})"

    def _ptz_set_status_if_current(self, cam_id: str, text: str) -> None:
        cam = self._current_camera
        if cam is None or cam.id != cam_id:
            return
        try:
            self.ptz_status.setText(str(text))
        except Exception:
            return

    def _start_mouse_hook(self) -> None:
        # Captures mouse wheel even when VLC owns the child HWND.
        try:
            ok = self._mouse_hook.start()
            if ok:
                self.statusBar().showMessage("Mouse hook active (wheel zoom)")
            else:
                code = getattr(self._mouse_hook, "last_error_code", None)
                if code:
                    self.statusBar().showMessage(f"Mouse hook NOT active (WinErr {code})")
                else:
                    self.statusBar().showMessage("Mouse hook NOT active (wheel zoom may fail)")
        except Exception:
            return

    def _on_global_wheel(self, delta_y: int, global_pt: QtCore.QPoint) -> None:
        self._on_zoom_wheel_hook(int(delta_y), global_pt)

    def _on_global_pan(self, global_cur: QtCore.QPoint, global_prev: QtCore.QPoint) -> None:
        if self._zoom_factor <= 1.0:
            return
        self._on_pan_drag_hook(global_cur - global_prev)

    def eventFilter(self, watched: QtCore.QObject, event: QtCore.QEvent) -> bool:
        if watched is self.video_viewport and event.type() == QtCore.QEvent.Type.Resize:
            try:
                self._apply_zoom()
            except Exception:
                pass
        return super().eventFilter(watched, event)

    def _refresh_list(self) -> None:
        self.list.clear()
        for cam in self.cameras:
            self.list.addItem(cam.name)

    def _ensure_player(self) -> None:
        # Player creation + attaching to the video widget must happen only once we have a real HWND.
        hwnd = int(self.video.winId())
        if hwnd == 0:
            QtCore.QTimer.singleShot(50, self._ensure_player)
            return

        if self._player is None:
            self._player = VlcPlayer()
            self._player.set_event_callback(lambda kind: self._vlc_bridge.vlc_event.emit(kind))

        # (Re)bind HWND in case the widget recreated its native handle.
        self._player.set_hwnd(hwnd)
        self._player.audio_set_volume(int(self.vol_slider.value()))
        self._player.audio_set_mute(bool(self.mute_chk.isChecked()))
        self._apply_zoom()

        # If a camera was selected before the HWND existed, start playback now.
        if (
            self._pending_play_camera_id
            and self._current_camera is not None
            and self._current_camera.id == self._pending_play_camera_id
        ):
            self._pending_play_camera_id = None
            QtCore.QTimer.singleShot(0, lambda: self._play_camera(self._current_camera) if self._current_camera else None)

    def _stop_player(self) -> None:
        if self._player is None:
            return
        self._player.stop()
        self._player.release()
        self._player = None

    def _play_camera(self, cam: Camera) -> None:
        # reset reconnect state when user explicitly (re)selects a camera
        self._reconnect_attempts = 0
        self._reconnect_scheduled = False
        self._current_camera = cam
        self._viewing_event_file = None
        
        # Resetează zoom când se schimbă camera
        self._zoom_factor = 1.0
        self._center_x = 0.5
        self._center_y = 0.5
        
        self._ensure_player()
        if self._player is None:
            self._pending_play_camera_id = cam.id
            return
        self._player.stop()
        record_to = self._record_path if self._recording else None
        try:
            url = cam.effective_rtsp_url()
            self._player.play(url, record_to=record_to)
            self._apply_zoom()
        except Exception as e:
            self._pending_play_camera_id = None
            QtWidgets.QMessageBox.warning(self, "Playback", f"Failed to start stream:\n{e}")
            return
        # PTZ connect is done lazily to avoid UI stalls.
        self._init_ptz_for_camera(cam)

    def _on_camera_selected(self, row: int) -> None:
        if row < 0 or row >= len(self.cameras):
            return
        cam = self.cameras[row]
        self._play_camera(cam)

    def _on_volume_changed(self, value: int) -> None:
        if self._player is None:
            return
        try:
            self._player.audio_set_volume(int(value))
        except Exception:
            return

    def _apply_zoom(self) -> None:
        """Aplică zoom/pan prin transformarea widget-ului video (stabil pe toate vout-urile VLC)."""
        # Zoom/pan is implemented by resizing/moving the native video widget inside a native viewport.
        # VLC then auto-fits the video to the widget; the viewport clips the overflowing area.
        if self._player is None:
            return

        vp_rect = self.video_viewport.rect()
        vp_w = int(vp_rect.width())
        vp_h = int(vp_rect.height())
        if vp_w <= 0 or vp_h <= 0:
            return

        # Get decoded video dimensions.
        try:
            vw, vh = self._player.video_get_size()
        except Exception:
            vw, vh = 0, 0

        self._last_video_size = (int(vw or 0), int(vh or 0))
        if vw <= 0 or vh <= 0:
            if self._zoom_apply_retry < 40:
                self._zoom_apply_retry += 1
                QtCore.QTimer.singleShot(200, self._apply_zoom)
            return
        self._zoom_apply_retry = 0

        fill = bool(self.fill_chk.isChecked())
        zoom = max(1.0, min(8.0, float(self._zoom_factor)))

        base_scale = max(float(vp_w) / float(vw), float(vp_h) / float(vh)) if fill else min(float(vp_w) / float(vw), float(vp_h) / float(vh))
        scale = max(0.000001, float(base_scale) * float(zoom))
        self._view_scale = float(scale)

        # Effective visible region in video pixels (in fit mode, black bars mean we see the full extent).
        vis_w_v = min(float(vw), float(vp_w) / scale)
        vis_h_v = min(float(vh), float(vp_h) / scale)
        half_u = max(0.0, min(0.5, vis_w_v / (2.0 * float(vw))))
        half_v = max(0.0, min(0.5, vis_h_v / (2.0 * float(vh))))

        if half_u >= 0.5:
            self._center_x = 0.5
        else:
            self._center_x = max(half_u, min(1.0 - half_u, float(self._center_x)))
        if half_v >= 0.5:
            self._center_y = 0.5
        else:
            self._center_y = max(half_v, min(1.0 - half_v, float(self._center_y)))

        video_w = max(1, int(round(float(vw) * scale)))
        video_h = max(1, int(round(float(vh) * scale)))
        origin_x = (float(vp_w) / 2.0) - (float(self._center_x) * float(vw) * scale)
        origin_y = (float(vp_h) / 2.0) - (float(self._center_y) * float(vh) * scale)

        try:
            self.video.setGeometry(int(round(origin_x)), int(round(origin_y)), video_w, video_h)
            self.overlay.setGeometry(self.video.rect())
            self.overlay.raise_()
        except Exception:
            pass

        # Ensure VLC is in auto-fit mode for the (resized) drawable.
        try:
            self._player.video_set_crop_geometry(None)
        except Exception:
            pass
        try:
            self._player.video_set_scale(0.0)
        except Exception:
            pass

        self.statusBar().showMessage(
            f"View: {'Fill' if fill else 'Fit'} | Zoom: {zoom:.2f}x | Video: {vw}x{vh} | Center: ({self._center_x:.2f},{self._center_y:.2f})"
        )

    def _zoom_in(self) -> None:
        self._zoom_factor = min(8.0, self._zoom_factor * 1.2)
        self._apply_zoom()

    def _zoom_out(self) -> None:
        self._zoom_factor = max(1.0, self._zoom_factor / 1.2)
        self._apply_zoom()

    def _zoom_reset(self) -> None:
        self._zoom_factor = 1.0
        self._center_x = 0.5
        self._center_y = 0.5
        self._apply_zoom()

    def _on_hover_pos(self, pos: QtCore.QPoint) -> None:
        self._last_mouse_pos = pos

    def _widget_pos_to_normalized(self, pos: QtCore.QPoint) -> tuple[float, float]:
        """Convertește poziția din viewport la coordonate normalizate video (0-1)."""
        vp_rect = self.video_viewport.rect()
        vp_w = int(vp_rect.width())
        vp_h = int(vp_rect.height())
        if vp_w <= 0 or vp_h <= 0:
            return (0.5, 0.5)

        vw, vh = self._last_video_size
        if vw <= 0 or vh <= 0:
            # Fallback: assume the viewport maps to the video.
            u = max(0.0, min(1.0, float(pos.x()) / max(1.0, float(vp_w))))
            v = max(0.0, min(1.0, float(pos.y()) / max(1.0, float(vp_h))))
            return (u, v)

        # Video widget geometry is relative to the viewport.
        g = self.video.geometry()
        w = int(g.width())
        h = int(g.height())
        if w <= 0 or h <= 0:
            return (0.5, 0.5)

        x_in = float(pos.x() - int(g.x()))
        y_in = float(pos.y() - int(g.y()))
        u = x_in / max(1.0, float(w))
        v = y_in / max(1.0, float(h))
        u = max(0.0, min(1.0, u))
        v = max(0.0, min(1.0, v))
        return (u, v)

    def _on_zoom_wheel_qt(self, delta_y: int, pos: QtCore.QPoint) -> None:
        # Prefer Qt-delivered input for a short time window (avoids double events when the hook is active).
        self._prefer_qt_wheel_until = time.monotonic() + 0.04
        vp = self.video_viewport.mapFromGlobal(pos)
        self._on_zoom_wheel(int(delta_y), vp)

    def _on_zoom_wheel_hook(self, delta_y: int, pos: QtCore.QPoint) -> None:
        if time.monotonic() < self._prefer_qt_wheel_until:
            return
        vp = self.video_viewport.mapFromGlobal(pos)
        self._on_zoom_wheel(int(delta_y), vp)

    def _on_zoom_wheel(self, delta_y: int, pos: QtCore.QPoint) -> None:
        """Zoom cu focus pe cursor - implementare TAPO."""
        self._last_mouse_pos = pos

        # Dedup: the same wheel event can arrive from Qt + low-level hook.
        now = time.monotonic()
        sig = (int(delta_y), int(pos.x() // 4), int(pos.y() // 4))
        if self._last_wheel_event_sig == sig and (now - self._last_wheel_event_ts) < 0.01:
            return
        self._last_wheel_event_sig = sig
        self._last_wheel_event_ts = now
        
        # Calculează steps (120 = 1 notch)
        steps = float(delta_y) / 120.0
        if steps == 0.0:
            return

        # Poziția cursorului în coordonate normalizate video (0-1)
        cursor_u, cursor_v = self._widget_pos_to_normalized(pos)
        
        # Factor zoom: 1.15 per step (smooth TAPO)
        old_zoom = self._zoom_factor
        factor = 1.15 ** steps
        new_zoom = max(1.0, min(8.0, old_zoom * factor))
        
        if abs(new_zoom - old_zoom) < 0.01:
            return
        
        # Formula TAPO pentru focus pe cursor:
        # Păstrăm punctul sub cursor la aceeași poziție pe ecran
        # new_center = cursor + (old_center - cursor) * (old_zoom / new_zoom)
        if old_zoom > 1.0:
            # Zoom existent: ajustăm centrul să păstreze cursorul fix
            self._center_x = cursor_u + (self._center_x - cursor_u) * (old_zoom / new_zoom)
            self._center_y = cursor_v + (self._center_y - cursor_v) * (old_zoom / new_zoom)
        else:
            # Primul zoom: centrăm pe cursor
            self._center_x = cursor_u
            self._center_y = cursor_v
        
        # Clamp center la [0, 1]
        self._center_x = max(0.0, min(1.0, self._center_x))
        self._center_y = max(0.0, min(1.0, self._center_y))
        
        self._zoom_factor = new_zoom
        self._apply_zoom()
        
        logger.debug(f"Zoom: {old_zoom:.2f}x -> {new_zoom:.2f}x at cursor ({cursor_u:.2f},{cursor_v:.2f})")

    def _on_pan_drag_qt(self, delta: QtCore.QPoint) -> None:
        # Prefer Qt-delivered drag deltas when available (reduces double pan from hook + Qt).
        self._prefer_qt_pan_until = time.monotonic() + 0.06
        self._on_pan_drag(delta)

    def _on_pan_drag_hook(self, delta: QtCore.QPoint) -> None:
        if time.monotonic() < self._prefer_qt_pan_until:
            return
        self._on_pan_drag(delta)

    def _on_pan_drag(self, delta: QtCore.QPoint) -> None:
        """Pan (glisare) - implementare TAPO completă."""
        if self._zoom_factor <= 1.0:
            return

        # Dedup: pan deltas can arrive from Qt + low-level hook.
        now = time.monotonic()
        sig = (int(delta.x()), int(delta.y()))
        if self._last_pan_event_sig == sig and (now - self._last_pan_event_ts) < 0.006:
            return
        self._last_pan_event_sig = sig
        self._last_pan_event_ts = now
        
        vw, vh = self._last_video_size
        if vw <= 0 or vh <= 0:
            return

        scale = float(getattr(self, "_view_scale", 0.0) or 0.0)
        if scale <= 0.0:
            return

        # Delta in full-video normalized coordinates.
        # Dragging right reveals the left side => invert sign for natural feel.
        delta_u = -float(delta.x()) / max(1.0, float(vw) * scale)
        delta_v = -float(delta.y()) / max(1.0, float(vh) * scale)

        # Aplică la center cu clamp la fiecare pas
        self._center_x = max(0.0, min(1.0, self._center_x + delta_u))
        self._center_y = max(0.0, min(1.0, self._center_y + delta_v))
        
        self._apply_zoom()
        logger.debug(f"Pan: delta=({delta.x()},{delta.y()}) -> center=({self._center_x:.3f},{self._center_y:.3f})")

    def _on_mute_toggled(self, checked: bool) -> None:
        if self._player is None:
            return
        try:
            self._player.audio_set_mute(bool(checked))
        except Exception:
            return

    def _recordings_dir(self) -> Path:
        if self._settings.recordings_dir:
            return Path(self._settings.recordings_dir)
        return self._base_dir / "data" / "recordings"

    def _choose_recordings_folder(self) -> None:
        cur = self._settings.recordings_dir or str(self._recordings_dir())
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Select recordings folder", cur)
        if not folder:
            return
        self._settings.recordings_dir = folder
        save_settings(self._base_dir, self._settings)

    def _start_rolling_segments(self) -> None:
        if self._rolling_active:
            return
        self._roll_seq += 1
        seq = self._roll_seq
        self._rolling_active = True

        cams = list(self.cameras)

        def safe_cam_name(cam: Camera) -> str:
            return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in cam.name)

        def run_for_cam(cam: Camera) -> None:
            recorder: VlcPlayer | None = None
            try:
                recorder = VlcPlayer(headless=True)
                self._rolling_recorders[cam.id] = recorder
            except Exception:
                recorder = None

            seg_len_s = 60
            max_files_per_cam = 500
            prefix = safe_cam_name(cam)

            while self._rolling_active and self._roll_seq == seq:
                # Do not compete with manual recording of the currently viewed camera.
                if self._recording and self._current_camera is not None and cam.id == self._current_camera.id:
                    time.sleep(2)
                    continue

                if recorder is None:
                    time.sleep(2)
                    continue

                ts = time.strftime("%Y%m%d_%H%M%S")
                out = self._recordings_dir() / f"{prefix}_roll_{ts}.ts"

                try:
                    recorder.stop()
                    recorder.play(cam.effective_rtsp_url(), record_to=out)
                except Exception:
                    time.sleep(2)
                    continue

                t0 = time.monotonic()
                while self._rolling_active and self._roll_seq == seq and (time.monotonic() - t0) < seg_len_s:
                    time.sleep(0.5)

                try:
                    recorder.stop()
                except Exception:
                    pass

                # Retention per camera prefix.
                try:
                    rec_dir = self._recordings_dir()
                    files = sorted(rec_dir.glob(f"{prefix}_roll_*.ts"), key=lambda p: p.stat().st_mtime, reverse=True)
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
            try:
                self._rolling_recorders.pop(cam.id, None)
            except Exception:
                pass

        # Start one thread per camera.
        self._rolling_threads = {}
        for cam in cams:
            # Must have either a full RTSP URL or structured config.
            if not (cam.rtsp_url or cam.has_structured_config()):
                continue
            t = threading.Thread(target=lambda c=cam: run_for_cam(c), daemon=True)
            self._rolling_threads[cam.id] = t
            t.start()

    def _stop_rolling_segments(self) -> None:
        if not self._rolling_active:
            return
        self._rolling_active = False
        self._roll_seq += 1
        try:
            for r in list(self._rolling_recorders.values()):
                try:
                    r.stop()
                except Exception:
                    continue
        except Exception:
            pass
        self._rolling_threads = {}
        self._rolling_recorders = {}

    def _on_event_recording_toggled(self, enabled: bool) -> None:
        self._event_rec_seq += 1
        seq = self._event_rec_seq
        self._event_recording_enabled = bool(enabled)

        if not enabled:
            self._stop_event_recording()
            self._stop_rolling_segments()
            return

        # Always start rolling segments for ALL cameras as a guarantee.
        self._start_rolling_segments()

        cams = list(self.cameras)
        any_onvif = any(bool(c.onvif_port and c.host and c.password_dpapi_b64) for c in cams)
        if not any_onvif:
            QtWidgets.QMessageBox.information(
                self,
                "Event Recording",
                "ONVIF Events nu este configurat pe nicio cameră (port/cred).\n"
                "Activez fallback: înregistrare continuă pe segmente (rolling clips) pentru toate camerele.",
            )
            return

        def run_for_cam(cam: Camera) -> None:
            if not cam.onvif_port or not cam.host or not cam.password_dpapi_b64:
                return

            puller: OnvifEventPuller | None = None
            last_trigger_ts = 0.0

            def ensure_puller() -> None:
                nonlocal puller
                try:
                    cfg = OnvifEventConfig(
                        host=cam.host,
                        port=int(cam.onvif_port),
                        username=cam.username,
                        password=cam.password(),
                    )
                    puller = OnvifEventPuller(cfg)
                except Exception:
                    puller = None

            ensure_puller()

            while self._event_rec_seq == seq and self._event_recording_enabled:
                if puller is None:
                    time.sleep(2)
                    ensure_puller()
                    continue

                try:
                    signals = puller.pull_once()
                except Exception:
                    signals = []

                if signals:
                    try:
                        self._last_onvif_topics_by_cam[cam.id] = [str(s) for s in signals]
                        self._last_onvif_topics_ts_by_cam[cam.id] = time.time()
                    except Exception:
                        pass

                if not signals and getattr(puller, "last_error", None):
                    time.sleep(1.0)
                    ensure_puller()
                    time.sleep(1.0)
                    continue

                if signals:
                    low_signals = [s.lower() for s in signals]
                    low = "\n".join(low_signals)

                    # Determine event kind and apply user filters.
                    default_person = bool(getattr(self._settings, "detect_person", True))
                    default_motion = bool(getattr(self._settings, "detect_motion", True))
                    want_person = self._effective_event_bool(cam, "event_detect_person", default_person)
                    want_motion = self._effective_event_bool(cam, "event_detect_motion", default_motion)

                    person_kw = [k.lower() for k in list(getattr(cam, "event_person_keywords", ()) or ())]
                    motion_kw = [k.lower() for k in list(getattr(cam, "event_motion_keywords", ()) or ())]

                    has_person = any(("person" in s or "people" in s or "human" in s) for s in low_signals) or ("person" in low) or ("human" in low)
                    has_motion = any(("motion" in s) for s in low_signals) or ("motion" in low) or ("cellmotiondetector" in low)
                    if person_kw:
                        has_person = has_person or any(any(k in s for k in person_kw) for s in low_signals)
                    if motion_kw:
                        has_motion = has_motion or any(any(k in s for k in motion_kw) for s in low_signals)

                    kind = "person" if has_person else ("motion" if has_motion else "unknown")
                    if kind == "person" and not want_person:
                        time.sleep(1)
                        continue
                    if kind == "motion" and not want_motion:
                        time.sleep(1)
                        continue

                    item_hits = False
                    for s in low_signals:
                        if "=" in s:
                            name, val = s.split("=", 1)
                            name = name.strip()
                            val = val.strip()
                            if val in ("true", "1", "yes") and name in (
                                "ismotion",
                                "motion",
                                "people",
                                "person",
                                "human",
                                "tamper",
                            ):
                                item_hits = True
                                break

                    topic_hits = (
                        ("cellmotiondetector" in low)
                        or ("motion" in low and "detector" in low)
                        or ("ruleengine" in low and "motion" in low)
                        or ("person" in low)
                        or ("human" in low)
                    )

                    if item_hits or topic_hits:
                        now = time.monotonic()
                        cooldown = float(
                            self._effective_event_int(
                                cam,
                                "event_cooldown_seconds",
                                int(getattr(self._settings, "event_cooldown_seconds", 20) or 20),
                            )
                        )
                        if now - last_trigger_ts > max(5.0, cooldown):
                            last_trigger_ts = now
                            topics = list(signals)
                            self._ui_bridge.invoke.emit(
                                lambda c=cam, k=kind, t=topics: self._trigger_event_recording_for_camera(c, kind=k, topics=t)
                            )

                time.sleep(1)

        for cam in cams:
            threading.Thread(target=lambda c=cam: run_for_cam(c), daemon=True).start()

    def _show_events_panel(self) -> None:
        self._right_stack.setCurrentIndex(1)
        self._refresh_events_list()
        self._refresh_topics_view()

    def _show_live_panel(self) -> None:
        self._right_stack.setCurrentIndex(0)
        # If the user was viewing an event clip, resume live.
        if self._viewing_event_file is not None:
            self._viewing_event_file = None
            if self._event_prev_camera is not None:
                self._play_camera(self._event_prev_camera)

    def _refresh_events_list(self) -> None:
        self.events_list.clear()

        # Prefer structured events if present.
        evs = load_events(self._base_dir)
        if evs:
            for e in evs:
                try:
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(e.ts)))
                except Exception:
                    ts = "unknown-time"
                kind = (e.kind or "event").upper()
                label = f"{ts}  [{kind}]  {e.camera_name}"
                item = QtWidgets.QListWidgetItem(label)
                item.setData(QtCore.Qt.ItemDataRole.UserRole, str(e.file or ""))
                self.events_list.addItem(item)
            return

        # Fallback: list raw recordings.
        rec_dir = self._recordings_dir()
        if not rec_dir.exists():
            return
        try:
            files = sorted(rec_dir.glob("*.ts"), key=lambda p: p.stat().st_mtime, reverse=True)
        except Exception:
            files = []
        for p in files:
            item = QtWidgets.QListWidgetItem(p.name)
            item.setData(QtCore.Qt.ItemDataRole.UserRole, str(p))
            self.events_list.addItem(item)

    def _refresh_topics_view(self) -> None:
        try:
            if getattr(self._right_stack, "currentIndex")() != 1:
                return
        except Exception:
            return
        cam = self._current_camera
        if cam is None:
            try:
                self.topics_text.setPlainText("Selectează o cameră pentru a vedea topic-urile.")
            except Exception:
                pass
            return
        topics = self._last_onvif_topics_by_cam.get(cam.id) or []
        ts = self._last_onvif_topics_ts_by_cam.get(cam.id)
        head = ""
        if ts:
            try:
                head = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
            except Exception:
                head = ""
        lines = []
        if head:
            lines.append(f"Last update: {head}")
            lines.append("")
        if topics:
            lines.extend(list(topics)[-200:])
        else:
            lines.append("No topics yet. Enable Event Recording and wait for camera events.")
        try:
            self.topics_text.setPlainText("\n".join(lines))
        except Exception:
            return

    def _play_selected_event(self) -> None:
        item = self.events_list.currentItem()
        if item is None:
            return
        path_s = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if not path_s:
            return
        p = Path(str(path_s))
        if not p.exists():
            QtWidgets.QMessageBox.information(self, "Events", "Fișierul nu mai există pe disc.")
            self._refresh_events_list()
            return

        # Remember which live camera to return to.
        self._event_prev_camera = self._current_camera
        self._viewing_event_file = p
        self._play_media_file(p)

    def _play_media_file(self, path: Path) -> None:
        self._ensure_player()
        if self._player is None:
            return
        try:
            self._player.stop()
            self._player.play(str(path.resolve()), record_to=None)
            self._apply_zoom()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Playback", f"Nu pot reda evenimentul:\n{e}")
            return

    def _trigger_event_recording(self) -> None:
        # Do not interfere with manual recording.
        if self._recording:
            return
        if self._event_recording_active:
            return
        if self._current_camera is None:
            return

        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(
            ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in self._current_camera.name
        )
        out = self._recordings_dir() / f"{safe_name}_event_{ts}.ts"

        self._event_recording_active = True
        try:
            if self._event_clip_recorder is None:
                self._event_clip_recorder = VlcPlayer(headless=True)
            self._event_clip_recorder.stop()
            self._event_clip_recorder.play(self._current_camera.effective_rtsp_url(), record_to=out)
        except Exception:
            self._event_recording_active = False
            return

        try:
            entry = EventEntry(
                ts=now_ts(),
                camera_id=self._current_camera.id,
                camera_name=self._current_camera.name,
                kind="unknown",
                topics=[],
                file=str(out),
            )
            append_event(self._base_dir, entry)
        except Exception:
            pass
        self._notify_event_for_camera(self._current_camera, "VixfloCam", f"EVENT: {self._current_camera.name}")

        if self._event_record_stop_timer is None:
            self._event_record_stop_timer = QtCore.QTimer(self)
            self._event_record_stop_timer.setSingleShot(True)
            self._event_record_stop_timer.timeout.connect(self._stop_event_recording)
        seconds = int(
            self._effective_event_int(
                self._current_camera,
                "event_record_seconds",
                int(getattr(self._settings, "event_record_seconds", 60) or 60),
            )
        )
        self._event_record_stop_timer.start(max(5000, min(300000, seconds * 1000)))

    def _trigger_event_recording_for_camera(self, cam: Camera, *, kind: str = "unknown", topics: list[str] | None = None) -> None:
        # Do not interfere with manual recording of the currently viewed camera.
        if self._recording and self._current_camera is not None and cam.id == self._current_camera.id:
            return
        if cam.id in self._event_active_by_cam:
            return

        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in cam.name)
        out = self._recordings_dir() / f"{safe_name}_event_{ts}.ts"

        self._event_active_by_cam.add(cam.id)
        try:
            rec = self._event_clip_recorders_by_cam.get(cam.id)
            if rec is None:
                rec = VlcPlayer(headless=True)
                self._event_clip_recorders_by_cam[cam.id] = rec
            rec.stop()
            rec.play(cam.effective_rtsp_url(), record_to=out)
        except Exception:
            self._event_active_by_cam.discard(cam.id)
            return

        # Persist event + notify
        try:
            entry = EventEntry(
                ts=now_ts(),
                camera_id=cam.id,
                camera_name=cam.name,
                kind=str(kind or "unknown"),
                topics=list(topics or []),
                file=str(out),
            )
            append_event(self._base_dir, entry)
        except Exception:
            pass

        try:
            k = str(kind or "event").upper()
        except Exception:
            k = "EVENT"
        self._notify_event_for_camera(cam, "VixfloCam", f"{k}: {cam.name}")

        seconds = int(
            self._effective_event_int(
                cam,
                "event_record_seconds",
                int(getattr(self._settings, "event_record_seconds", 60) or 60),
            )
        )
        QtCore.QTimer.singleShot(max(5000, min(300000, seconds * 1000)), lambda cid=cam.id: self._stop_event_recording_for_camera(cid))

    def _stop_event_recording_for_camera(self, camera_id: str) -> None:
        if camera_id not in self._event_active_by_cam:
            return
        self._event_active_by_cam.discard(camera_id)
        try:
            rec = self._event_clip_recorders_by_cam.get(camera_id)
            if rec is not None:
                rec.stop()
        except Exception:
            return

    def _stop_event_recording(self) -> None:
        if not self._event_recording_active:
            # Also stop any per-camera event clips.
            try:
                self._event_active_by_cam.clear()
                for r in list(self._event_clip_recorders_by_cam.values()):
                    try:
                        r.stop()
                    except Exception:
                        continue
                for r in list(self._event_clip_recorders_by_cam.values()):
                    try:
                        r.release()
                    except Exception:
                        continue
            except Exception:
                pass
            self._event_clip_recorders_by_cam = {}
            return
        self._event_recording_active = False
        try:
            if self._event_clip_recorder is not None:
                self._event_clip_recorder.stop()
        except Exception:
            return

        try:
            self._event_active_by_cam.clear()
            for r in list(self._event_clip_recorders_by_cam.values()):
                try:
                    r.stop()
                except Exception:
                    continue
            for r in list(self._event_clip_recorders_by_cam.values()):
                try:
                    r.release()
                except Exception:
                    continue
        except Exception:
            pass
        self._event_clip_recorders_by_cam = {}

    def _on_record_toggled(self, enabled: bool) -> None:
        if enabled:
            if self._current_camera is None:
                QtWidgets.QMessageBox.information(self, "Recording", "Selectează o cameră înainte.")
                self.record_btn.setChecked(False)
                return
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in self._current_camera.name)
            out = self._recordings_dir() / f"{safe_name}_{ts}.ts"
            self._recording = True
            self._record_path = out
            self.record_btn.setText("Stop Recording")
            # restart playback with recording enabled
            self._play_camera(self._current_camera)
            QtWidgets.QMessageBox.information(self, "Recording", f"Recording to:\n{out}")
        else:
            if not self._recording:
                return
            self._recording = False
            self._record_path = None
            self.record_btn.setText("Start Recording")
            if self._current_camera is not None:
                self._play_camera(self._current_camera)

    def _on_vlc_event(self, kind: str) -> None:
        # Controlled auto-reconnect with backoff to avoid hammering cameras.
        if self._current_camera is None:
            return
        now = time.monotonic()
        if kind == "error":
            self._last_vlc_error_ts = now
            self._reconnect_attempts += 1
        else:
            # treat end as a single reconnect attempt
            self._reconnect_attempts = max(self._reconnect_attempts, 1)

        if self._reconnect_attempts > 5:
            self._reconnect_scheduled = False
            QtWidgets.QMessageBox.warning(
                self,
                "Stream",
                "Stream keeps failing. Verify camera IP, username/password, and that RTSP is enabled.\n"
                "Tip: camera IP may change (DHCP).",
            )
            return

        if self._reconnect_scheduled:
            return
        self._reconnect_scheduled = True

        # Exponential backoff: 1.2s, 2.4s, 4.8s, ... up to 10s
        delay_ms = int(min(10000, 1200 * (2 ** (self._reconnect_attempts - 1))))

        def do_reconnect() -> None:
            self._reconnect_scheduled = False
            if self._current_camera is None:
                return
            try:
                # Call internal play without resetting attempts.
                self._ensure_player()
                if self._player is None:
                    return
                self._player.stop()
                record_to = self._record_path if self._recording else None
                url = self._current_camera.effective_rtsp_url()
                self._player.play(url, record_to=record_to)
            except Exception:
                return

        QtCore.QTimer.singleShot(delay_ms, do_reconnect)

    def _set_ptz_controls_enabled(self, enabled: bool) -> None:
        for b in (self.ptz_up, self.ptz_down, self.ptz_left, self.ptz_right, self.ptz_stop):
            b.setEnabled(bool(enabled))

    def _ptz_hold_tick(self) -> None:
        if self._ptz_hold_dir is None:
            return
        x, y = self._ptz_hold_dir
        self._ptz_move(x, y)

    def _ptz_begin_hold(self, x: float, y: float) -> None:
        self._ptz_hold_dir = (float(x), float(y))
        self._ptz_move(float(x), float(y))
        if not self._ptz_hold_timer.isActive():
            self._ptz_hold_timer.start()

    def _ptz_end_hold(self) -> None:
        self._ptz_hold_dir = None
        if self._ptz_hold_timer.isActive():
            self._ptz_hold_timer.stop()
        self._ptz_stop()

    def _init_ptz_for_camera(self, cam: Camera) -> None:
        # Reset state when switching cameras
        self._ptz_client = None
        self._ptz_for_camera_id = None
        self._ptz_connecting = False
        self._ptz_connect_seq += 1
        self._ptz_pending_move = None
        self._ptz_pending_move_cam_id = None
        self._ptz_hold_dir = None
        if self._ptz_hold_timer.isActive():
            self._ptz_hold_timer.stop()

        self._set_ptz_controls_enabled(False)

        if not cam.onvif_port:
            self.ptz_status.setText("PTZ: disabled (set ONVIF port)")
            return
        if not cam.host or not cam.password_dpapi_b64:
            self.ptz_status.setText("PTZ: missing host/password")
            return
        if cam.id in self._ptz_no_support_ids:
            self.ptz_status.setText("PTZ: not supported by camera")
            return

        # Allow user interactions while connecting; commands are queued until a client is ready.
        self._set_ptz_controls_enabled(True)

        # Auto-connect in background so the first PTZ command is responsive.
        self.ptz_status.setText(f"PTZ: connecting... (port {cam.onvif_port})")
        self._start_ptz_connect(cam)

    def _start_ptz_connect(self, cam: Camera) -> None:
        if not cam.onvif_port or not cam.host or not cam.password_dpapi_b64:
            return
        if self._ptz_connecting:
            return
        if self._ptz_client is not None and self._ptz_for_camera_id == cam.id:
            return

        self._ptz_connecting = True
        self._ptz_connect_seq += 1
        seq = self._ptz_connect_seq
        self.ptz_status.setText(f"PTZ: connecting... (port {cam.onvif_port})")
        t0 = time.monotonic()
        try:
            logger.debug("PTZ connect start: cam=%s host=%s port=%s seq=%s", cam.name, cam.host, cam.onvif_port, seq)
        except Exception:
            pass

        # Watchdog: if connect doesn't finish quickly, mark as timeout (ignore late results)
        def on_timeout() -> None:
            if self._ptz_connect_seq != seq:
                return
            if not self._ptz_connecting:
                return
            self._ptz_connecting = False
            self._ptz_client = None
            self._ptz_for_camera_id = None
            self.ptz_status.setText(f"PTZ: timeout (port {cam.onvif_port})")
            try:
                logger.debug(
                    "PTZ connect timeout: cam=%s host=%s port=%s seq=%s after=%.2fs",
                    cam.name,
                    cam.host,
                    cam.onvif_port,
                    seq,
                    time.monotonic() - t0,
                )
            except Exception:
                pass

        QtCore.QTimer.singleShot(15000, on_timeout)

        def connect() -> None:
            err: str | None = None
            client: OnvifPtzClient | None = None
            try:
                cfg = OnvifConfig(
                    host=cam.host,
                    port=int(cam.onvif_port),
                    username=cam.username,
                    password=cam.password(),
                )
                client = OnvifPtzClient(cfg)
            except Exception as e:
                err = str(e) or e.__class__.__name__

            def finish() -> None:
                if self._ptz_connect_seq != seq:
                    return
                self._ptz_connecting = False
                if client is None:
                    self._ptz_client = None
                    self._ptz_for_camera_id = None
                    if self._ptz_pending_move_cam_id == cam.id:
                        self._ptz_pending_move = None
                        self._ptz_pending_move_cam_id = None
                    if err:
                        short = " ".join(err.split())
                        if len(short) > 120:
                            short = short[:117] + "..."
                        low = short.lower()
                        if "no ptz" in low or "ptz service" in low or "missing ptz" in low:
                            self._ptz_no_support_ids.add(cam.id)
                            self._set_ptz_controls_enabled(False)
                            self.ptz_status.setText("PTZ: not supported by camera")
                            try:
                                logger.debug(
                                    "PTZ not supported: cam=%s host=%s port=%s after=%.2fs err=%s",
                                    cam.name,
                                    cam.host,
                                    cam.onvif_port,
                                    time.monotonic() - t0,
                                    short,
                                )
                            except Exception:
                                pass
                            return
                        self.ptz_status.setText(f"PTZ: not available ({short})")
                        try:
                            logger.debug(
                                "PTZ connect failed: cam=%s host=%s port=%s after=%.2fs err=%s",
                                cam.name,
                                cam.host,
                                cam.onvif_port,
                                time.monotonic() - t0,
                                short,
                            )
                        except Exception:
                            pass
                    else:
                        self.ptz_status.setText(f"PTZ: not available (port {cam.onvif_port})")
                        try:
                            logger.debug(
                                "PTZ connect failed: cam=%s host=%s port=%s after=%.2fs err=<none>",
                                cam.name,
                                cam.host,
                                cam.onvif_port,
                                time.monotonic() - t0,
                            )
                        except Exception:
                            pass
                    return
                self._ptz_client = client
                self._ptz_for_camera_id = cam.id
                self._ptz_no_support_ids.discard(cam.id)
                self.ptz_status.setText(f"PTZ: connected (port {cam.onvif_port})")
                self._set_ptz_controls_enabled(True)
                try:
                    logger.debug(
                        "PTZ connect ok: cam=%s host=%s port=%s after=%.2fs",
                        cam.name,
                        cam.host,
                        cam.onvif_port,
                        time.monotonic() - t0,
                    )
                except Exception:
                    pass

                # If a move was requested while connecting, apply it now.
                pending = self._ptz_pending_move if self._ptz_pending_move_cam_id == cam.id else None
                self._ptz_pending_move = None
                self._ptz_pending_move_cam_id = None
                if pending is not None and self._current_camera is not None and self._current_camera.id == cam.id:
                    x, y = pending
                    self._ptz_move(x, y)

            self._ui_bridge.invoke.emit(finish)

        threading.Thread(target=connect, daemon=True).start()

    def _ptz_diagnostics(self) -> None:
        cam = self._current_camera
        if cam is None or not cam.onvif_port:
            self.ptz_status.setText("PTZ: set ONVIF port first")
            return
        if not cam.host or not cam.password_dpapi_b64:
            self.ptz_status.setText("PTZ: missing host/password")
            return

        self.ptz_diag.setEnabled(False)
        self.ptz_diag.setText("Running...")
        self.ptz_status.setText(f"PTZ: diagnosing (port {cam.onvif_port})...")

        self._ptz_diag_seq += 1
        seq = self._ptz_diag_seq

        def on_timeout() -> None:
            if self._ptz_diag_seq != seq:
                return
            self.ptz_diag.setEnabled(True)
            self.ptz_diag.setText("PTZ Diagnostics")
            self.ptz_status.setText("PTZ: diagnostics timeout")

        QtCore.QTimer.singleShot(9000, on_timeout)

        def run() -> None:
            try:
                rep = diagnose_onvif(
                    cam.host,
                    int(cam.onvif_port),
                    cam.username,
                    cam.password(),
                    time_budget_s=8.0,
                )
            except Exception as e:
                rep = {"error": str(e) or e.__class__.__name__}

            def finish() -> None:
                if self._ptz_diag_seq != seq:
                    return
                # User might have switched cameras while diagnostics was running.
                if self._current_camera is None or self._current_camera.id != cam.id:
                    return
                self.ptz_diag.setEnabled(True)
                self.ptz_diag.setText("PTZ Diagnostics")
                if "error" in rep:
                    self.ptz_status.setText("PTZ: diagnostics error")
                    QtWidgets.QMessageBox.information(self, "PTZ Diagnostics", f"Error: {rep.get('error')}")
                    return
                if rep.get("tcp_connect_ok") is False:
                    self.ptz_status.setText("PTZ: port not reachable")
                    QtWidgets.QMessageBox.information(
                        self,
                        "PTZ Diagnostics",
                        "Port not reachable. Check camera IP/ONVIF port (usually 2020 for Tapo) and firewall.",
                    )
                    return
                if rep.get("timed_out"):
                    self.ptz_status.setText("PTZ: diagnostics timed out")
                    QtWidgets.QMessageBox.information(
                        self,
                        "PTZ Diagnostics",
                        "Timed out. Camera may be slow to respond or ONVIF is blocked/disabled.",
                    )
                    return
                ok_caps = bool(rep.get("device_service_ok"))
                ok_profiles = bool(rep.get("get_profiles_ok"))
                ptz_supported = bool(rep.get("ptz_supported", True))
                ok_status = bool(rep.get("ptz_getstatus_ok"))
                ok_stop = bool(rep.get("ptz_stop_ok"))

                if not ptz_supported:
                    self._ptz_no_support_ids.add(cam.id)
                    self._set_ptz_controls_enabled(False)
                else:
                    self._ptz_no_support_ids.discard(cam.id)
                    # Keep enabled (commands will still be queued until connect finishes).
                    self._set_ptz_controls_enabled(True)

                if not ok_caps:
                    self.ptz_status.setText("PTZ: ONVIF device_service failed")
                elif not ok_profiles:
                    self.ptz_status.setText("PTZ: ONVIF media GetProfiles failed")
                elif not ptz_supported:
                    self.ptz_status.setText("PTZ: not supported by camera")
                elif ok_status or ok_stop:
                    self.ptz_status.setText(f"PTZ: ONVIF OK (port {cam.onvif_port})")
                else:
                    self.ptz_status.setText("PTZ: PTZ calls failed (auth/profile/firmware)")

                lines: list[str] = []
                lines.append(f"Host: {rep.get('host')}  Port: {rep.get('port')}")
                lines.append(f"TCP connect: {rep.get('tcp_connect_ok')}")
                lines.append(f"DeviceService OK: {rep.get('device_service_ok')}")
                if rep.get("media_xaddr"):
                    lines.append(f"Media XAddr: {rep.get('media_xaddr')}")
                if rep.get("ptz_xaddr"):
                    lines.append(f"PTZ XAddr: {rep.get('ptz_xaddr')}")
                lines.append(f"GetProfiles OK: {rep.get('get_profiles_ok')}")
                lines.append(f"PTZ Supported: {rep.get('ptz_supported')}")
                lines.append(f"PTZ GetStatus OK: {rep.get('ptz_getstatus_ok')}")
                lines.append(f"PTZ Stop OK: {rep.get('ptz_stop_ok')}")

                tests = rep.get("tests")
                if isinstance(tests, list) and tests:
                    lines.append("")
                    lines.append("Recent attempts (step/status/wsse/auth):")
                    for t in tests[-8:]:
                        if not isinstance(t, dict):
                            continue
                        step = t.get("step")
                        status = t.get("status")
                        wsse = t.get("wsse")
                        auth = t.get("auth")
                        lines.append(f"- {step}: {status} ({wsse}, {auth})")

                QtWidgets.QMessageBox.information(self, "PTZ Diagnostics", "\n".join(lines))
                return

            self._ui_bridge.invoke.emit(finish)

        threading.Thread(target=run, daemon=True).start()

    def _ptz_move(self, x: float, y: float) -> None:
        cam = self._current_camera
        if cam is None or not cam.onvif_port:
            return
        if cam.id in self._ptz_no_support_ids:
            return
        if self._ptz_client is None or self._ptz_for_camera_id != cam.id:
            self._ptz_pending_move = (x, y)
            self._ptz_pending_move_cam_id = cam.id
            self._start_ptz_connect(cam)
            return
        client = self._ptz_client
        if client is None:
            return

        # Debouncing: nu trimite comenzi prea des (max 10 comenzi/secundă)
        now = time.monotonic()
        if now - self._ptz_last_command_ts < 0.1:
            # Queue-uiește comanda pentru mai târziu
            self._ptz_command_queue.append((x, y))
            if self._ptz_move_timer is None:
                self._ptz_move_timer = QtCore.QTimer(self)
                self._ptz_move_timer.setSingleShot(True)
                self._ptz_move_timer.timeout.connect(self._process_ptz_queue)
            if not self._ptz_move_timer.isActive():
                self._ptz_move_timer.start(100)
            return
        
        self._ptz_last_command_ts = now

        with self._ptz_worker_lock:
            self._ptz_worker_latest_move = (cam.id, float(x), float(y))
        self._ptz_worker_evt.set()

    def _process_ptz_queue(self) -> None:
        """Procesează comenzile PTZ din queue."""
        if not self._ptz_command_queue:
            return
        
        # Ia ultima comandă din queue (cea mai recentă)
        x, y = self._ptz_command_queue[-1]
        self._ptz_command_queue.clear()
        
        # Trimite comanda
        self._ptz_move(x, y)
    
    def _ptz_stop(self) -> None:
        cam = self._current_camera
        if cam is None:
            return
        if cam.id in self._ptz_no_support_ids:
            return
        
        # Golește queue-ul de comenzi
        self._ptz_command_queue.clear()
        self._ptz_pending_move = None
        self._ptz_pending_move_cam_id = None
        
        if self._ptz_client is None or self._ptz_for_camera_id != cam.id:
            return
        client = self._ptz_client
        if client is None:
            return

        with self._ptz_worker_lock:
            self._ptz_worker_latest_move = None
            self._ptz_worker_stop_cam_id = cam.id
        self._ptz_worker_evt.set()

    def _add_camera(self) -> None:
        dlg = AddCameraDialog(self, None)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        try:
            cam = dlg.get_camera()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Invalid", str(e))
            return
        self.cameras.append(cam)
        save_cameras(self._base_dir, self.cameras)
        self._refresh_list()
        self.list.setCurrentRow(len(self.cameras) - 1)

    def _edit_selected(self) -> None:
        row = self.list.currentRow()
        if row < 0 or row >= len(self.cameras):
            return
        current = self.cameras[row]
        dlg = AddCameraDialog(self, current)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        try:
            updated = dlg.get_camera()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Invalid", str(e))
            return

        self.cameras[row] = updated
        save_cameras(self._base_dir, self.cameras)
        self._refresh_list()
        self.list.setCurrentRow(row)

    def _remove_selected(self) -> None:
        row = self.list.currentRow()
        if row < 0 or row >= len(self.cameras):
            return
        cam = self.cameras[row]
        if self._current_camera and self._current_camera.id == cam.id:
            self._ensure_player()
            if self._player:
                self._player.stop()
            self._current_camera = None
        del self.cameras[row]
        save_cameras(self._base_dir, self.cameras)
        self._refresh_list()


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    base_dir = Path(__file__).resolve().parents[1]
    w = MainWindow(base_dir)
    w.show()
    return app.exec()
