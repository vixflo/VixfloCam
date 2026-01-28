import unittest


class SmokeTests(unittest.TestCase):
    def test_rtsp_url_encodes_credentials(self):
        from vixflocam.rtsp import RtspConfig, build_rtsp_url

        cfg = RtspConfig(
            host="192.168.0.10",
            username="user",
            password="p@ss:word/with?chars",
            port=554,
            path="stream1",
        )
        url = build_rtsp_url(cfg)
        self.assertIn("user:", url)
        # '@' must be encoded, ':' in password must be encoded, '/' must be encoded
        self.assertIn("%40", url)
        self.assertIn("%3A", url)
        self.assertIn("%2F", url)
        self.assertTrue(url.startswith("rtsp://"))

    def test_dpapi_roundtrip(self):
        # Windows-only, but the project targets Windows.
        from vixflocam.security import dpapi_decrypt_from_b64, dpapi_encrypt_to_b64

        secret = "Forsaken24@2026"
        enc = dpapi_encrypt_to_b64(secret)
        dec = dpapi_decrypt_from_b64(enc)
        self.assertEqual(dec.value, secret)

    def test_wsse_header_builds(self):
        from vixflocam.onvif_ptz import _soap_wsse_header

        h_text = _soap_wsse_header("u", "p", use_digest=False)
        self.assertIn("UsernameToken", h_text)
        self.assertIn("PasswordText", h_text)
        self.assertIn("<wsse:Username>u</wsse:Username>", h_text)

        h_digest = _soap_wsse_header("u", "p", use_digest=True)
        self.assertIn("PasswordDigest", h_digest)
        self.assertIn("<wsse:Username>u</wsse:Username>", h_digest)

    def test_onvif_diagnostics_returns_shape(self):
        from vixflocam.onvif_ptz import diagnose_onvif

        # Point at a non-ONVIF endpoint (localhost). Use a port that typically fails fast.
        report = diagnose_onvif("127.0.0.1", 1, "u", "p")
        self.assertIsInstance(report, dict)
        self.assertEqual(report.get("host"), "127.0.0.1")
        self.assertEqual(report.get("port"), 1)
        self.assertIn("tests", report)
        self.assertIsInstance(report["tests"], list)

    def test_extract_soap_fault(self):
        from vixflocam.onvif_ptz import _extract_soap_fault

        soap11 = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>InvalidArgVal</faultstring>
    </s:Fault>
  </s:Body>
</s:Envelope>
"""
        self.assertEqual(_extract_soap_fault(soap11), "InvalidArgVal")

        soap12 = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>s:Sender</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en">NotAuthorized</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>
"""
        self.assertEqual(_extract_soap_fault(soap12), "NotAuthorized")

    def test_extract_profile_and_ptz_cfg_token(self):
        from vixflocam.onvif_ptz import _extract_profile_and_ptz_cfg_token

        xml = """<root>
  <Profiles token="p1">
    <PTZConfiguration token="ptz1" />
  </Profiles>
</root>
"""
        profile, cfg = _extract_profile_and_ptz_cfg_token(xml)
        self.assertEqual(profile, "p1")
        self.assertEqual(cfg, "ptz1")

        xml2 = """<root>
  <Profiles token="p1" />
  <Profiles token="p2"><PTZConfiguration token="ptz2" /></Profiles>
</root>
"""
        profile2, cfg2 = _extract_profile_and_ptz_cfg_token(xml2)
        self.assertEqual(profile2, "p2")
        self.assertEqual(cfg2, "ptz2")

    def test_extract_ptz_spaces_from_config_options(self):
        from vixflocam.onvif_ptz import _extract_ptz_spaces_from_config_options

        xml = """<root>
  <URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace</URI>
  <URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace</URI>
  <URI>http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace</URI>
</root>
"""
        spaces = _extract_ptz_spaces_from_config_options(xml)
        self.assertIn("pan_tilt_velocity_space", spaces)
        self.assertIn("pan_tilt_translation_space", spaces)
        self.assertIn("pan_tilt_speed_space", spaces)

    def test_zoom_view_math(self):
        """Sanity-check zoom math (widget-scale + viewport clipping)."""
        vw, vh = 2560, 1440  # 16:9
        vp_w, vp_h = 820, 399  # wider than 16:9 (like the screenshot/logs)

        # Fill mode: scale to cover viewport => width matches, height exceeds.
        base_fill = max(vp_w / vw, vp_h / vh)
        w_fill = int(round(vw * base_fill))
        h_fill = int(round(vh * base_fill))
        self.assertEqual(w_fill, vp_w)
        self.assertGreater(h_fill, vp_h)

        # Fit mode: scale to fit inside viewport => height matches, width is smaller.
        base_fit = min(vp_w / vw, vp_h / vh)
        w_fit = int(round(vw * base_fit))
        h_fit = int(round(vh * base_fit))
        self.assertEqual(h_fit, vp_h)
        self.assertLess(w_fit, vp_w)

        # Extra zoom makes the scaled video larger than the viewport in both dimensions.
        zoom = 1.8
        scale = base_fill * zoom
        self.assertGreater(vw * scale, vp_w)
        self.assertGreater(vh * scale, vp_h)


if __name__ == "__main__":
    unittest.main()
