from __future__ import annotations

from dataclasses import dataclass
import time
import xml.etree.ElementTree as ET

from vixflocam.onvif_ptz import OnvifConfig, _soap_wsse_header, _soap_envelope_with_header, _strip_ns


# Minimal ONVIF Events PullPoint implementation (best-effort).
# This is used for event-driven recording (motion/person topics) without running ML locally.


@dataclass(frozen=True)
class OnvifEventConfig:
    host: str
    port: int
    username: str
    password: str


_SOAP_GET_CAPABILITIES = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">
  <s:Body>
    <tds:GetCapabilities>
      <tds:Category>All</tds:Category>
    </tds:GetCapabilities>
  </s:Body>
</s:Envelope>
"""


def _soap_create_pullpoint_subscription() -> str:
    return """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\">
  <s:Body>
    <tev:CreatePullPointSubscription>
      <tev:InitialTerminationTime>PT1M</tev:InitialTerminationTime>
    </tev:CreatePullPointSubscription>
  </s:Body>
</s:Envelope>
"""


def _soap_pull_messages(timeout: str = "PT5S", limit: int = 10) -> str:
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\">
  <s:Body>
    <tev:PullMessages>
      <tev:Timeout>{timeout}</tev:Timeout>
      <tev:MessageLimit>{int(limit)}</tev:MessageLimit>
    </tev:PullMessages>
  </s:Body>
</s:Envelope>
"""


def _extract_events_xaddr(capabilities_xml: str) -> str | None:
    try:
        root = ET.fromstring(capabilities_xml)
    except Exception:
        return None

    # Look for Capabilities/Events/XAddr
    found_events = False
    for el in root.iter():
        name = _strip_ns(el.tag)
        if name == "Events":
            found_events = True
        if found_events and name == "XAddr":
            txt = (el.text or "").strip()
            if txt.startswith("http"):
                return txt
    # fallback: any XAddr containing '/onvif/' and 'events'
    for el in root.iter():
        if _strip_ns(el.tag) == "XAddr":
            txt = (el.text or "").strip()
            if "events" in txt.lower():
                return txt
    return None


def _extract_subscription_reference(create_xml: str) -> str | None:
    try:
        root = ET.fromstring(create_xml)
    except Exception:
        return None
    for el in root.iter():
        if _strip_ns(el.tag) == "Address":
            txt = (el.text or "").strip()
            if txt.startswith("http"):
                return txt
    return None


def _extract_topics(pull_xml: str) -> list[str]:
    topics: list[str] = []
    try:
        root = ET.fromstring(pull_xml)
    except Exception:
        return topics

    for el in root.iter():
        if _strip_ns(el.tag) == "Topic":
            txt = (el.text or "").strip()
            if txt:
                topics.append(txt)

    # Also extract SimpleItem(Name,Value) pairs; many cameras encode motion/person this way.
    for el in root.iter():
        if _strip_ns(el.tag) == "SimpleItem":
            name = (el.attrib.get("Name") or "").strip()
            value = (el.attrib.get("Value") or "").strip()
            if name or value:
                topics.append(f"{name}={value}")
    return topics


class OnvifEventPuller:
    def __init__(self, cfg: OnvifEventConfig):
        import requests
        from requests.auth import HTTPDigestAuth, HTTPBasicAuth

        self._cfg = cfg
        self._session = requests.Session()
        self._session.verify = False
        self._timeout = (1.0, 2.0)
        self._auth_digest = HTTPDigestAuth(cfg.username, cfg.password)
        self._auth_basic = HTTPBasicAuth(cfg.username, cfg.password)
        self._wsse = _soap_wsse_header(cfg.username, cfg.password, use_digest=True) if (cfg.username or cfg.password) else None

        self._device_urls = [
            f"http://{cfg.host}:{int(cfg.port)}/onvif/device_service",
            f"http://{cfg.host}:{int(cfg.port)}/onvif/Device_service",
        ]
        self._events_xaddr: str | None = None
        self._sub_url: str | None = None
        self._last_init_ts: float = 0.0
        self.last_error: str | None = None

    def _post(self, url: str, xml: str, action: str) -> str | None:
        # Some cameras require SOAP 1.1 (text/xml + SOAPAction) instead of SOAP 1.2.
        action_uri_map = {
            "GetCapabilities": "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            "CreatePullPointSubscription": "http://www.onvif.org/ver10/events/wsdl/CreatePullPointSubscription",
            "PullMessages": "http://www.onvif.org/ver10/events/wsdl/PullMessages",
        }
        action_uri = action_uri_map.get(action, action)

        body12 = _soap_envelope_with_header(xml, self._wsse)
        headers12 = {"Content-Type": "application/soap+xml; charset=utf-8"}

        body11 = body12.replace(
            "http://www.w3.org/2003/05/soap-envelope",
            "http://schemas.xmlsoap.org/soap/envelope/",
        )
        headers11 = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{action_uri}"',
        }

        for headers, body in ((headers12, body12), (headers11, body11)):
            for auth in (self._auth_digest, self._auth_basic, None):
                try:
                    r = self._session.post(url, data=body, headers=headers, auth=auth, timeout=self._timeout)
                    if r.status_code == 200 and r.text:
                        self.last_error = None
                        return r.text
                    self.last_error = f"HTTP {r.status_code}"
                except Exception as e:
                    self.last_error = str(e) or e.__class__.__name__
                    continue
        return None

    def _ensure_initialized(self) -> bool:
        # Keep existing subscription for a while (server termination is PT1M).
        # Re-init at most once every ~50s to avoid hammering.
        if self._sub_url and (time.monotonic() - self._last_init_ts) < 50:
            return True

        caps_xml = None
        for du in self._device_urls:
            caps_xml = self._post(du, _SOAP_GET_CAPABILITIES, "GetCapabilities")
            if caps_xml:
                break
        if not caps_xml:
            self._events_xaddr = None
            self._sub_url = None
            self._last_init_ts = time.monotonic()
            self.last_error = self.last_error or "GetCapabilities failed"
            return False

        self._events_xaddr = _extract_events_xaddr(caps_xml)
        if not self._events_xaddr:
            self._sub_url = None
            self._last_init_ts = time.monotonic()
            self.last_error = self.last_error or "No Events XAddr"
            return False

        create_xml = self._post(self._events_xaddr, _soap_create_pullpoint_subscription(), "CreatePullPointSubscription")
        if not create_xml:
            self._sub_url = None
            self._last_init_ts = time.monotonic()
            self.last_error = self.last_error or "CreatePullPointSubscription failed"
            return False

        sub = _extract_subscription_reference(create_xml)
        self._sub_url = sub
        self._last_init_ts = time.monotonic()
        return bool(self._sub_url)

    def pull_once(self) -> list[str]:
        if not self._ensure_initialized():
            return []
        assert self._sub_url is not None

        pull_xml = self._post(self._sub_url, _soap_pull_messages(), "PullMessages")
        if not pull_xml:
            # force re-init next time
            self._sub_url = None
            return []
        return _extract_topics(pull_xml)
