from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Any
from requests.auth import AuthBase

import xml.etree.ElementTree as ET

import base64
import hashlib
import os
import time


COMMON_ONVIF_PORTS: list[int] = [80, 2020, 8000, 8080, 8090, 8899]


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


def _soap_continuous_move(profile_token: str, x: float, y: float, timeout: str = "PT1S") -> str:
        return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                        xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\"
                        xmlns:tt=\"http://www.onvif.org/ver10/schema\">
    <s:Body>
        <tptz:ContinuousMove>
            <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
            <tptz:Velocity>
                <tt:PanTilt x=\"{float(x)}\" y=\"{float(y)}\" />
            </tptz:Velocity>
            <tptz:Timeout>{timeout}</tptz:Timeout>
        </tptz:ContinuousMove>
    </s:Body>
</s:Envelope>
"""


def _soap_stop(profile_token: str) -> str:
        return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                        xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\">
    <s:Body>
        <tptz:Stop>
            <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
            <tptz:PanTilt>true</tptz:PanTilt>
            <tptz:Zoom>true</tptz:Zoom>
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
    if status in (200, 401, 403):
        h = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        b = (body or "").lower()
        if "www.onvif.org" in b or "onvif" in b:
            return True
        if "soap" in h and "xml" in h:
            return True
        if status in (401, 403) and ("www-authenticate" in h) and ("digest" in h or "basic" in h):
            # Not a proof, but strongly suggests an auth-protected service.
            return True
    return False


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

        self._wsse_text = _soap_wsse_header(cfg.username, cfg.password, use_digest=False) if (cfg.username or cfg.password) else None
        self._wsse_digest = _soap_wsse_header(cfg.username, cfg.password, use_digest=True) if (cfg.username or cfg.password) else None

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
        if not media_xaddr or not ptz_xaddr:
            raise RuntimeError("ONVIF: missing Media/PTZ capabilities")

        self._media_url = media_xaddr
        self._ptz_url = ptz_xaddr

        profiles_xml = self._try_post(self._media_url, _SOAP_GET_PROFILES, action_hint="GetProfiles")
        if not profiles_xml:
            raise RuntimeError("ONVIF: media profiles not reachable/auth failed")

        token = _extract_first_profile_token(profiles_xml)
        if not token:
            raise RuntimeError("ONVIF: no profile token found")
        self._profile_token = token

    def _try_post(self, url: str, xml_body: str, action_hint: str) -> str | None:
        action_uri_map = {
            "GetCapabilities": "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            "GetProfiles": "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            "ContinuousMove": "http://www.onvif.org/ver20/ptz/wsdl/ContinuousMove",
            "Stop": "http://www.onvif.org/ver20/ptz/wsdl/Stop",
            "GetStatus": "http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
        }
        action_uri = action_uri_map.get(action_hint, action_hint)

        headers12 = {"Content-Type": f"application/soap+xml; charset=utf-8; action=\"{action_uri}\""}
        headers11 = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action_uri}"'}
        # Keep this fast: PTZ buttons should not feel laggy.
        # Order: most likely successes first.
        attempts: list[tuple[str | None, AuthBase | None]] = [
            (None, self._auth_digest),
            (self._wsse_digest, self._auth_digest),
            (None, self._auth_basic),
            (None, None),
        ]
        for wsse, auth in attempts:
            body12 = _soap_envelope_with_header(xml_body, wsse)
            body11 = body12.replace(
                "http://www.w3.org/2003/05/soap-envelope",
                "http://schemas.xmlsoap.org/soap/envelope/",
            )
            try:
                # Try SOAP 1.2 then SOAP 1.1; different firmwares require different variants.
                for headers, body in ((headers12, body12), (headers11, body11)):
                    r = self._session.post(url, data=body, headers=headers, auth=auth, timeout=self._timeout)
                    if r.status_code == 200 and r.text:
                        return r.text
                    if r.text and _looks_like_onvif_response(r.status_code, dict(r.headers), r.text):
                        pass
            except Exception:
                continue
        return None

    def continuous_move(self, x: float, y: float, z: float = 0.0) -> None:  # noqa: ARG002
        xml_body = _soap_continuous_move(self._profile_token, x=x, y=y, timeout="PT1S")
        if not self._try_post(self._ptz_url, xml_body, action_hint="ContinuousMove"):
            raise RuntimeError("ONVIF: PTZ move failed")

    def stop(self) -> None:
        xml_body = _soap_stop(self._profile_token)
        if not self._try_post(self._ptz_url, xml_body, action_hint="Stop"):
            raise RuntimeError("ONVIF: PTZ stop failed")


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

            auths: list[AuthBase | None] = [None]
            if username or password:
                auths.extend([HTTPDigestAuth(username, password), HTTPBasicAuth(username, password)])

            for auth in auths:
                if time.monotonic() >= deadline:
                    break
                for headers, body in ((headers12, body12), (headers11, body11)):
                    if time.monotonic() >= deadline:
                        break
                    try:
                        r = session.post(url, data=body, headers=headers, auth=auth, timeout=(1.0, 2.5))
                        if _looks_like_onvif_response(r.status_code, dict(r.headers), r.text):
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

    wsse_digest = _soap_wsse_header(username, password, use_digest=True) if (username or password) else None

    # Keep diagnostics bounded: try a small, high-signal set.
    auth_options = [
        ("digest", HTTPDigestAuth(username, password)),
        ("basic", HTTPBasicAuth(username, password)),
        ("none", None),
    ]
    wsse_options = [
        ("no-wsse", None),
        ("wsse-digest", wsse_digest),
    ]

    deadline = time.monotonic() + max(0.5, float(time_budget_s))

    def post_attempts(url: str, body: str, action: str, wsse: str | None, auth) -> list[dict[str, object]]:
        if time.monotonic() >= deadline:
            return [{"soap": "n/a", "status": None, "text": "time_budget_exceeded"}]

        action_uri_map = {
            "GetCapabilities": "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            "GetProfiles": "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            "PTZ_GetStatus": "http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
            "PTZ_Stop": "http://www.onvif.org/ver20/ptz/wsdl/Stop",
        }
        action_uri = action_uri_map.get(action, action)

        body12 = _soap_envelope_with_header(body, wsse)
        body11 = body12.replace(
            "http://www.w3.org/2003/05/soap-envelope",
            "http://schemas.xmlsoap.org/soap/envelope/",
        )
        headers12 = {"Content-Type": f"application/soap+xml; charset=utf-8; action=\"{action_uri}\""}
        headers11 = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action_uri}"'}

        out: list[dict[str, object]] = []
        for soap, headers, body2 in (("1.2", headers12, body12), ("1.1", headers11, body11)):
            if time.monotonic() >= deadline:
                break
            try:
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
        for wsse_name, wsse in wsse_options:
            for auth_name, auth in auth_options:
                attempts = post_attempts(url, _SOAP_GET_CAPABILITIES, "GetCapabilities", wsse, auth)
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
    if not media_xaddr or not ptz_xaddr:
        return report

    profiles_xml: str | None = None
    for wsse_name, wsse in wsse_options:
        for auth_name, auth in auth_options:
            attempts = post_attempts(media_xaddr, _SOAP_GET_PROFILES, "GetProfiles", wsse, auth)
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

    # SAFETY: Diagnostics MUST NOT move the camera.
    # We only probe read-only status and a Stop (which is also safe).
    for step, soap in (
        ("PTZ_GetStatus", _soap_get_status(token)),
        ("PTZ_Stop", _soap_stop(token)),
    ):
        ok = False
        for wsse_name, wsse in wsse_options:
            for auth_name, auth in auth_options:
                attempts = post_attempts(ptz_xaddr, soap, step, wsse, auth)
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
