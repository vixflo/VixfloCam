from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Any
from requests.auth import AuthBase

import logging
import xml.etree.ElementTree as ET

import base64
import hashlib
import os
import time


logger = logging.getLogger(__name__)


COMMON_ONVIF_PORTS: list[int] = [2020, 80, 8899, 8000, 8080, 8090]


_SOAP_GET_CAPABILITIES = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Body>
        <tds:GetCapabilities>
            <tds:Category>All</tds:Category>
        </tds:GetCapabilities>
    </s:Body>
</s:Envelope>
"""


_SOAP_GET_PROFILES = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
    <s:Body>
        <trt:GetProfiles />
    </s:Body>
</s:Envelope>
"""


def _soap_continuous_move(
    profile_token: str,
    x: float,
    y: float,
    *,
    z: float | None = None,
    timeout: str = "PT10S",
    pan_tilt_space: str | None = None,
    zoom_space: str | None = None,
) -> str:
    pt_space = f' space="{pan_tilt_space}"' if pan_tilt_space else ""
    z_space = f' space="{zoom_space}"' if zoom_space else ""
    z_xml = f'<tt:Zoom x="{float(z)}"{z_space} />' if z is not None else ""

    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                        xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\"
                        xmlns:tt=\"http://www.onvif.org/ver10/schema\">
    <s:Body>
        <tptz:ContinuousMove>
            <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
            <tptz:Velocity>
                <tt:PanTilt x=\"{float(x)}\" y=\"{float(y)}\"{pt_space} />
                {z_xml}
            </tptz:Velocity>
            <tptz:Timeout>{timeout}</tptz:Timeout>
        </tptz:ContinuousMove>
    </s:Body>
</s:Envelope>
"""


def _soap_stop(profile_token: str, *, pan_tilt: bool = True, zoom: bool = True) -> str:
    pt = "true" if pan_tilt else "false"
    z = "true" if zoom else "false"
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                        xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\">
    <s:Body>
        <tptz:Stop>
            <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
            <tptz:PanTilt>{pt}</tptz:PanTilt>
            <tptz:Zoom>{z}</tptz:Zoom>
        </tptz:Stop>
    </s:Body>
</s:Envelope>
"""


def _soap_get_status(profile_token: str) -> str:
    # Read-only probe (should NOT move the camera)
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                        xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\">
    <s:Body>
        <tptz:GetStatus>
            <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
        </tptz:GetStatus>
    </s:Body>
</s:Envelope>
"""


def _soap_relative_move(
    profile_token: str,
    dx: float,
    dy: float,
    *,
    dz: float | None = None,
    translation_space: str | None = None,
    speed_space: str | None = None,
) -> str:
    # Best-effort fallback: some firmwares implement RelativeMove but not ContinuousMove.
    t_space = f' space="{translation_space}"' if translation_space else ""
    s_space = f' space="{speed_space}"' if speed_space else ""
    dz_xml = f'<tt:Zoom x="{float(dz)}" />' if dz is not None else ""

    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                        xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\"
                        xmlns:tt=\"http://www.onvif.org/ver10/schema\">
    <s:Body>
        <tptz:RelativeMove>
            <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
            <tptz:Translation>
                <tt:PanTilt x=\"{float(dx)}\" y=\"{float(dy)}\"{t_space} />
                {dz_xml}
            </tptz:Translation>
            <tptz:Speed>
                <tt:PanTilt x=\"{float(dx)}\" y=\"{float(dy)}\"{s_space} />
                {dz_xml}
            </tptz:Speed>
        </tptz:RelativeMove>
    </s:Body>
</s:Envelope>
"""


def _soap_wsse_header(username: str, password: str, use_digest: bool) -> str:
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    nonce = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    if use_digest:
        digest = hashlib.sha1(nonce + created.encode("utf-8") + password.encode("utf-8")).digest()
        pwd = base64.b64encode(digest).decode("ascii")
        pwd_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
    else:
        pwd = password
        pwd_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"

    return f"""
<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
               xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <wsse:UsernameToken>
    <wsse:Username>{username}</wsse:Username>
    <wsse:Password Type="{pwd_type}">{pwd}</wsse:Password>
    <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
    <wsu:Created>{created}</wsu:Created>
  </wsse:UsernameToken>
</wsse:Security>
"""


def _soap_envelope_with_header(envelope: str, header_xml: str | None) -> str:
    if not header_xml:
        return envelope
    # inject header right before Body
    return envelope.replace("<s:Body>", f"<s:Header>{header_xml}</s:Header><s:Body>", 1)


def _looks_like_onvif_response(status: int, headers: dict[str, str], body: str) -> bool:
    # Many ONVIF devices answer with SOAP XML; sometimes 401 with Digest challenge.
    if status in (200, 400, 401, 403, 500):
        h = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        b = (body or "").lower()
        if "www.onvif.org" in b or "onvif" in b:
            return True
        if ("soap" in h and "xml" in h) or ("application/soap+xml" in h) or ("text/xml" in h):
            return True
    return False


def _extract_soap_fault(xml_text: str) -> str | None:
    """Best-effort SOAP Fault extraction for actionable error messages."""
    if not xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    # SOAP 1.1: Fault/faultstring
    for el in root.iter():
        if _strip_ns(el.tag) == "faultstring":
            txt = (el.text or "").strip()
            if txt:
                return txt

    # SOAP 1.2: Fault/Reason/Text
    in_fault = False
    in_reason = False
    for el in root.iter():
        name = _strip_ns(el.tag)
        if name == "Fault":
            in_fault = True
        if in_fault and name == "Reason":
            in_reason = True
        if in_reason and name == "Text":
            txt = (el.text or "").strip()
            if txt:
                return txt
    return None


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find_text_any_ns(root: ET.Element, path_last: str) -> str | None:
    for el in root.iter():
        if _strip_ns(el.tag) == path_last:
            if el.text and el.text.strip():
                return el.text.strip()
    return None


def _extract_xaddrs_from_capabilities(xml_text: str) -> tuple[str | None, str | None]:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None, None

    media_xaddr = None
    ptz_xaddr = None

    # Look for Media->XAddr and PTZ->XAddr regardless of namespace prefixes.
    for el in root.iter():
        if _strip_ns(el.tag) == "Media":
            media_xaddr = _find_text_any_ns(el, "XAddr")
        if _strip_ns(el.tag) == "PTZ":
            ptz_xaddr = _find_text_any_ns(el, "XAddr")

    return media_xaddr, ptz_xaddr


def _extract_first_profile_token(xml_text: str) -> str | None:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    for el in root.iter():
        if _strip_ns(el.tag) == "Profiles":
            token = el.attrib.get("token") or el.attrib.get("{http://www.onvif.org/ver10/schema}token")
            if token:
                return token
    return None


def _extract_profile_and_ptz_cfg_token(xml_text: str) -> tuple[str | None, str | None]:
    """Return (profile_token, ptz_configuration_token) if present."""
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None, None

    first_profile: str | None = None

    for prof in root.iter():
        if _strip_ns(prof.tag) != "Profiles":
            continue

        profile_token = prof.attrib.get("token") or prof.attrib.get("{http://www.onvif.org/ver10/schema}token")
        if profile_token and not first_profile:
            first_profile = profile_token

        ptz_cfg_token: str | None = None
        for el in prof.iter():
            if _strip_ns(el.tag) == "PTZConfiguration":
                ptz_cfg_token = el.attrib.get("token") or el.attrib.get("{http://www.onvif.org/ver10/schema}token")
                break

        if profile_token and ptz_cfg_token:
            return profile_token, ptz_cfg_token

    return first_profile, None


def _soap_get_configuration_options(configuration_token: str) -> str:
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\">
  <s:Body>
    <tptz:GetConfigurationOptions>
      <tptz:ConfigurationToken>{configuration_token}</tptz:ConfigurationToken>
    </tptz:GetConfigurationOptions>
  </s:Body>
</s:Envelope>
"""


def _extract_ptz_spaces_from_config_options(xml_text: str) -> dict[str, str]:
    """Extract best-effort PTZ spaces from GetConfigurationOptions response."""
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return {}

    uris: list[str] = []
    for el in root.iter():
        if _strip_ns(el.tag) == "URI":
            txt = (el.text or "").strip()
            if txt:
                uris.append(txt)

    def pick(*needles: str) -> str | None:
        for u in uris:
            if all(n.lower() in u.lower() for n in needles):
                return u
        return None

    out: dict[str, str] = {}
    # Pan/Tilt spaces (most important for arrow controls)
    v = pick("PanTiltSpaces", "Velocity") or pick("VelocityGenericSpace")
    t = pick("PanTiltSpaces", "Translation") or pick("TranslationGenericSpace")
    s = pick("PanTiltSpaces", "Speed") or pick("GenericSpeedSpace") or pick("SpeedSpace")
    if v:
        out["pan_tilt_velocity_space"] = v
    if t:
        out["pan_tilt_translation_space"] = t
    if s:
        out["pan_tilt_speed_space"] = s

    # Zoom spaces (optional; many cameras have no optical zoom)
    zv = pick("ZoomSpaces", "Velocity")
    zt = pick("ZoomSpaces", "Translation")
    zs = pick("ZoomSpaces", "Speed")
    if zv:
        out["zoom_velocity_space"] = zv
    if zt:
        out["zoom_translation_space"] = zt
    if zs:
        out["zoom_speed_space"] = zs

    return out


@dataclass(frozen=True)
class OnvifConfig:
    host: str
    port: int
    username: str
    password: str


class OnvifPtzClient:
    def __init__(self, cfg: OnvifConfig):
        import requests
        from requests.auth import HTTPBasicAuth, HTTPDigestAuth

        self._cfg = cfg
        self._session = requests.Session()
        self._session.verify = False
        # Timeout-uri mai generoase pentru stabilitate
        self._timeout = (2.0, 4.0)

        self._auth_digest = HTTPDigestAuth(cfg.username, cfg.password)
        self._auth_basic = HTTPBasicAuth(cfg.username, cfg.password)

        self._preferred_by_url: dict[str, tuple[str, str, str]] = {}
        self._last_error: str | None = None
        self._move_variant: str | None = None
        self._stop_variant: str | None = None
        self._ptz_cfg_token: str | None = None
        self._ptz_spaces: dict[str, str] = {}

        # Discover XAddrs
        device_urls = [
            f"http://{cfg.host}:{int(cfg.port)}/onvif/device_service",
            f"http://{cfg.host}:{int(cfg.port)}/onvif/Device_service",
        ]

        caps_xml = None
        for url in device_urls:
            caps_xml = self._try_post(url, _SOAP_GET_CAPABILITIES, action_hint="GetCapabilities")
            if caps_xml:
                self._device_service_url = url
                break

        if not caps_xml:
            raise RuntimeError("ONVIF: device service not reachable/auth failed")

        media_xaddr, ptz_xaddr = _extract_xaddrs_from_capabilities(caps_xml)
        if not media_xaddr:
            raise RuntimeError("ONVIF: missing Media service (no Media XAddr)")
        if not ptz_xaddr:
            raise RuntimeError("ONVIF: camera reports no PTZ service")

        self._media_url = media_xaddr
        self._ptz_url = ptz_xaddr

        profiles_xml = self._try_post(self._media_url, _SOAP_GET_PROFILES, action_hint="GetProfiles")
        if not profiles_xml:
            raise RuntimeError("ONVIF: media profiles not reachable/auth failed")

        token, ptz_cfg_token = _extract_profile_and_ptz_cfg_token(profiles_xml)
        if not token:
            raise RuntimeError("ONVIF: no profile token found")
        self._profile_token = token
        self._ptz_cfg_token = ptz_cfg_token

        # Best-effort: fetch supported PTZ spaces (helps some firmwares accept ContinuousMove/RelativeMove).
        if self._ptz_cfg_token:
            opts_xml = self._try_post(
                self._ptz_url,
                _soap_get_configuration_options(self._ptz_cfg_token),
                action_hint="GetConfigurationOptions",
            )
            if opts_xml:
                self._ptz_spaces = _extract_ptz_spaces_from_config_options(opts_xml)

    def _try_post(self, url: str, xml_body: str, action_hint: str) -> str | None:
        action_uri_map = {
            "GetCapabilities": "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            "GetProfiles": "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            "GetConfigurationOptions": "http://www.onvif.org/ver20/ptz/wsdl/GetConfigurationOptions",
            "ContinuousMove": "http://www.onvif.org/ver20/ptz/wsdl/ContinuousMove",
            "RelativeMove": "http://www.onvif.org/ver20/ptz/wsdl/RelativeMove",
            "Stop": "http://www.onvif.org/ver20/ptz/wsdl/Stop",
            "GetStatus": "http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
        }
        action_uri = action_uri_map.get(action_hint, action_hint)

        headers12 = {"Content-Type": f"application/soap+xml; charset=utf-8; action=\"{action_uri}\""}
        headers11 = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action_uri}"'}

        soap_versions: list[str] = ["1.1", "1.2"]
        wsse_names: list[str] = ["none"]
        auth_options: list[tuple[str, AuthBase | None]] = [("none", None)]
        if self._cfg.username or self._cfg.password:
            # IMPORTANT: do NOT cache WSSE headers; many devices reject replays/stale Created.
            wsse_names.extend(["wsse-digest", "wsse-text"])
            auth_options = [("digest", self._auth_digest), ("basic", self._auth_basic), ("none", None)]

        auth_by_name = dict(auth_options)

        all_keys: list[tuple[str, str, str]] = []
        for soap in soap_versions:
            for wsse_name in wsse_names:
                for auth_name, _auth in auth_options:
                    all_keys.append((soap, wsse_name, auth_name))

        preferred = self._preferred_by_url.get(url)
        if preferred in all_keys:
            all_keys = [preferred] + [k for k in all_keys if k != preferred]

        last_status: int | None = None
        last_detail: str | None = None

        for soap, wsse_name, auth_name in all_keys:
            wsse = None
            if wsse_name == "wsse-digest":
                wsse = _soap_wsse_header(self._cfg.username, self._cfg.password, use_digest=True)
            elif wsse_name == "wsse-text":
                wsse = _soap_wsse_header(self._cfg.username, self._cfg.password, use_digest=False)

            auth = auth_by_name.get(auth_name)

            body12 = _soap_envelope_with_header(xml_body, wsse)
            body11 = body12.replace(
                "http://www.w3.org/2003/05/soap-envelope",
                "http://schemas.xmlsoap.org/soap/envelope/",
            )
            headers, body = (headers11, body11) if soap == "1.1" else (headers12, body12)

            try:
                r = self._session.post(url, data=body, headers=headers, auth=auth, timeout=self._timeout)
                if r.status_code == 200 and r.text:
                    self._preferred_by_url[url] = (soap, wsse_name, auth_name)
                    self._last_error = None
                    return r.text

                last_status = r.status_code
                fault = _extract_soap_fault(r.text or "")
                last_detail = fault or (r.text or "").strip().replace("\r", " ").replace("\n", " ")[:200] or None

                # Keep trying other variants; many firmwares reject one of SOAP 1.1/1.2.
                continue
            except Exception as e:
                last_status = None
                last_detail = str(e) or e.__class__.__name__
                continue

        detail = f": {last_detail}" if last_detail else ""
        self._last_error = f"{action_hint} failed{detail}" if last_status is None else f"{action_hint} failed (HTTP {last_status}){detail}"
        logger.debug("ONVIF call failed: url=%s action=%s err=%s", url, action_hint, self._last_error)
        return None

    def continuous_move(self, x: float, y: float, z: float = 0.0) -> None:  # noqa: ARG002
        # Some firmwares require spaces or a Zoom element (even if zero). Try a small set and remember what works.
        generic_vel_space = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"
        pt_space = self._ptz_spaces.get("pan_tilt_velocity_space") or generic_vel_space
        z_space = self._ptz_spaces.get("zoom_velocity_space")

        variants: list[tuple[str, str]] = [
            (
                "cont-zoom-space",
                _soap_continuous_move(self._profile_token, x=x, y=y, z=float(z), timeout="PT10S", pan_tilt_space=pt_space, zoom_space=z_space),
            ),
            (
                "cont-nozoom-space",
                _soap_continuous_move(self._profile_token, x=x, y=y, z=None, timeout="PT10S", pan_tilt_space=pt_space),
            ),
            ("cont-zoom-nospace", _soap_continuous_move(self._profile_token, x=x, y=y, z=float(z), timeout="PT10S")),
            ("cont-nozoom-nospace", _soap_continuous_move(self._profile_token, x=x, y=y, z=None, timeout="PT10S")),
        ]

        if self._move_variant:
            variants = [v for v in variants if v[0] == self._move_variant] + [v for v in variants if v[0] != self._move_variant]

        for vid, xml_body in variants:
            if self._try_post(self._ptz_url, xml_body, action_hint="ContinuousMove"):
                self._move_variant = vid
                return

        # Fallback: RelativeMove (moves in small steps; used only if ContinuousMove is rejected).
        rel_space = self._ptz_spaces.get("pan_tilt_translation_space") or "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"
        speed_space = self._ptz_spaces.get("pan_tilt_speed_space")
        dx = float(x) * 0.15
        dy = float(y) * 0.15
        rel_xml = _soap_relative_move(
            self._profile_token,
            dx=dx,
            dy=dy,
            dz=None,
            translation_space=rel_space,
            speed_space=speed_space,
        )
        if self._try_post(self._ptz_url, rel_xml, action_hint="RelativeMove"):
            return

        raise RuntimeError(f"ONVIF: PTZ move failed ({self._last_error or 'unknown'})")

    def stop(self) -> None:
        variants: list[tuple[str, str]] = [
            ("stop-pan-zoom", _soap_stop(self._profile_token, pan_tilt=True, zoom=True)),
            ("stop-pan-only", _soap_stop(self._profile_token, pan_tilt=True, zoom=False)),
        ]
        if self._stop_variant:
            variants = [v for v in variants if v[0] == self._stop_variant] + [v for v in variants if v[0] != self._stop_variant]

        for vid, xml_body in variants:
            if self._try_post(self._ptz_url, xml_body, action_hint="Stop"):
                self._stop_variant = vid
                return

        raise RuntimeError(f"ONVIF: PTZ stop failed ({self._last_error or 'unknown'})")


def detect_onvif_port(
    host: str,
    username: str,
    password: str,
    ports: Iterable[int] | None = None,
    *,
    time_budget_s: float = 8.0,
) -> int | None:
    """Best-effort ONVIF port detection.

    Tries a small list of common ports with tight timeouts.
    Returns the first port where ONVIF Media service returns profiles.
    """

    # NOTE: We intentionally do not instantiate ONVIFCamera here because some devices/libraries
    # can hang longer than expected. This probe uses strict request timeouts.
    import requests  # type: ignore
    from requests.auth import HTTPDigestAuth, HTTPBasicAuth  # type: ignore
    import socket

    ports_to_try = list(ports) if ports is not None else COMMON_ONVIF_PORTS
    paths = ["/onvif/device_service", "/onvif/Device_service"]
    deadline = time.monotonic() + max(0.5, float(time_budget_s))

    session = requests.Session()
    session.verify = False
    # Preîntregim blocarea: timeout maxim per total session
    from requests.adapters import HTTPAdapter
    adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    action_uri = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"
    body12 = _SOAP_GET_CAPABILITIES
    body11 = body12.replace(
        "http://www.w3.org/2003/05/soap-envelope",
        "http://schemas.xmlsoap.org/soap/envelope/",
    )
    headers12 = {"Content-Type": f"application/soap+xml; charset=utf-8; action=\"{action_uri}\""}
    headers11 = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action_uri}"'}

    for port in ports_to_try:
        if time.monotonic() >= deadline:
            break
        # Quick TCP check first - fail fast if port is not open
        try:
            sock = socket.create_connection((host, int(port)), timeout=0.5)
            sock.close()
        except Exception:
            # Port not reachable, skip
            continue
        
        base = f"http://{host}:{int(port)}"
        for path in paths:
            if time.monotonic() >= deadline:
                break
            url = base + path

            auths: list[AuthBase | None] = []
            if username or password:
                auths.extend([HTTPDigestAuth(username, password), HTTPBasicAuth(username, password)])
            auths.append(None)

            for auth in auths:
                if time.monotonic() >= deadline:
                    break
                for headers, body in ((headers11, body11), (headers12, body12)):
                    if time.monotonic() >= deadline:
                        break
                    try:
                        r = session.post(url, data=body, headers=headers, auth=auth, timeout=(1.0, 2.5))
                        if r.status_code == 200 and _looks_like_onvif_response(r.status_code, dict(r.headers), r.text):
                            return int(port)
                    except Exception:
                        continue
    
    # Cleanup session
    try:
        session.close()
    except Exception:
        pass

    return None


def diagnose_onvif(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    time_budget_s: float = 8.0,
) -> dict[str, object]:
    """Structured diagnostics for ONVIF connectivity (no password included)."""

    import requests
    import socket
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth

    report: dict[str, Any] = {
        "host": host,
        "port": int(port),
        "tcp_connect_ok": False,
        "device_urls": [],
        "device_service_ok": False,
        "tests": [],
    }

    # Fast fail: if we can't open a TCP connection to the port, the SOAP probes will just timeout.
    try:
        sock = socket.create_connection((host, int(port)), timeout=1.0)
        sock.close()
        report["tcp_connect_ok"] = True
    except Exception as e:
        report["tcp_connect_error"] = str(e)
        return report

    session = requests.Session()
    session.verify = False
    # Configurează session pentru a evita blocarea
    from requests.adapters import HTTPAdapter
    adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    # Timeout-uri mai generoase pentru diagnostics
    timeout = (1.5, 3.0)

    device_urls = [
        f"http://{host}:{int(port)}/onvif/device_service",
        f"http://{host}:{int(port)}/onvif/Device_service",
    ]

    # Keep diagnostics bounded: try a small, high-signal set.
    auth_options = [
        ("digest", HTTPDigestAuth(username, password)),
        ("basic", HTTPBasicAuth(username, password)),
        ("none", None),
    ]
    wsse_options: list[str] = ["no-wsse"]
    if username or password:
        # IMPORTANT: do NOT cache WSSE headers; many devices reject replays/stale Created.
        wsse_options.extend(["wsse-digest", "wsse-text"])

    deadline = time.monotonic() + max(0.5, float(time_budget_s))

    def post_attempts(url: str, body: str, action: str, wsse_name: str, auth) -> list[dict[str, object]]:
        if time.monotonic() >= deadline:
            return [{"soap": "n/a", "status": None, "text": "time_budget_exceeded"}]

        action_uri_map = {
            "GetCapabilities": "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            "GetProfiles": "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            "PTZ_GetStatus": "http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
            "PTZ_Stop": "http://www.onvif.org/ver20/ptz/wsdl/Stop",
        }
        action_uri = action_uri_map.get(action, action)

        headers12 = {"Content-Type": f"application/soap+xml; charset=utf-8; action=\"{action_uri}\""}
        headers11 = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action_uri}"'}

        out: list[dict[str, object]] = []
        for soap, headers in (("1.1", headers11), ("1.2", headers12)):
            if time.monotonic() >= deadline:
                break
            try:
                wsse = None
                if wsse_name == "wsse-digest":
                    wsse = _soap_wsse_header(username, password, use_digest=True)
                elif wsse_name == "wsse-text":
                    wsse = _soap_wsse_header(username, password, use_digest=False)

                body12 = _soap_envelope_with_header(body, wsse)
                body2 = (
                    body12.replace(
                        "http://www.w3.org/2003/05/soap-envelope",
                        "http://schemas.xmlsoap.org/soap/envelope/",
                    )
                    if soap == "1.1"
                    else body12
                )
                r = session.post(url, data=body2, headers=headers, auth=auth, timeout=timeout)
                out.append({"soap": soap, "status": r.status_code, "text": (r.text or "")})
                if r.status_code == 200 and r.text:
                    break
            except Exception as e:
                out.append({"soap": soap, "status": None, "text": str(e) or e.__class__.__name__})
        return out

    report["device_urls"] = device_urls

    caps_xml: str | None = None
    device_url_ok: str | None = None
    for url in device_urls:
        for wsse_name in wsse_options:
            for auth_name, auth in auth_options:
                attempts = post_attempts(url, _SOAP_GET_CAPABILITIES, "GetCapabilities", wsse_name, auth)
                for a in attempts:
                    text = str(a.get("text") or "")
                    status = a.get("status")
                    report["tests"].append(
                        {
                            "step": "GetCapabilities",
                            "url": url,
                            "soap": a.get("soap"),
                            "wsse": wsse_name,
                            "auth": auth_name,
                            "status": status,
                            "body_snippet": text[:200],
                        }
                    )
                    if status == 200 and text:
                        caps_xml = text
                        device_url_ok = url
                        break
                if caps_xml:
                    break
            if caps_xml:
                break
        if caps_xml:
            break

    if not caps_xml:
        if time.monotonic() >= deadline:
            report["timed_out"] = True
        return report

    report["device_service_ok"] = True
    report["device_service_url"] = device_url_ok

    media_xaddr, ptz_xaddr = _extract_xaddrs_from_capabilities(caps_xml)
    report["media_xaddr"] = media_xaddr
    report["ptz_xaddr"] = ptz_xaddr
    report["ptz_supported"] = bool(ptz_xaddr)

    # Media is required for profiles/token. PTZ may be missing on fixed cameras.
    if not media_xaddr:
        return report

    profiles_xml: str | None = None
    for wsse_name in wsse_options:
        for auth_name, auth in auth_options:
            attempts = post_attempts(media_xaddr, _SOAP_GET_PROFILES, "GetProfiles", wsse_name, auth)
            for a in attempts:
                text = str(a.get("text") or "")
                status = a.get("status")
                report["tests"].append(
                    {
                        "step": "GetProfiles",
                        "url": media_xaddr,
                        "soap": a.get("soap"),
                        "wsse": wsse_name,
                        "auth": auth_name,
                        "status": status,
                        "body_snippet": text[:200],
                    }
                )
                if status == 200 and text:
                    profiles_xml = text
                    break
            if profiles_xml:
                break
        if profiles_xml:
            break

    report["get_profiles_ok"] = bool(profiles_xml)
    token = _extract_first_profile_token(profiles_xml) if profiles_xml else None
    report["profile_token"] = token
    if not token:
        if time.monotonic() >= deadline:
            report["timed_out"] = True
        return report

    # No PTZ endpoint advertised => stop here (camera likely has no PTZ).
    if not ptz_xaddr:
        return report

    # SAFETY: Diagnostics MUST NOT move the camera.
    # We only probe read-only status and a Stop (which is also safe).
    for step, soap in (
        ("PTZ_GetStatus", _soap_get_status(token)),
        ("PTZ_Stop", _soap_stop(token)),
    ):
        ok = False
        for wsse_name in wsse_options:
            for auth_name, auth in auth_options:
                attempts = post_attempts(ptz_xaddr, soap, step, wsse_name, auth)
                for a in attempts:
                    text = str(a.get("text") or "")
                    status = a.get("status")
                    report["tests"].append(
                        {
                            "step": step,
                            "url": ptz_xaddr,
                            "soap": a.get("soap"),
                            "wsse": wsse_name,
                            "auth": auth_name,
                            "status": status,
                            "body_snippet": text[:200],
                        }
                    )
                    if status == 200:
                        ok = True
                        break
                if ok:
                    break
            if ok:
                break
        report[f"{step.lower()}_ok"] = ok

    if time.monotonic() >= deadline:
        report["timed_out"] = True
    
    # Cleanup session
    try:
        session.close()
    except Exception:
        pass

    return report
