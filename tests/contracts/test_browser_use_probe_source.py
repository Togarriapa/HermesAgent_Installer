import base64
import unittest
from unittest.mock import patch

from hermes_installer.components import browser_use_qualification_probe as probe


class BrowserUseProbeSourceTests(unittest.TestCase):
    def test_screenshot_is_validated_and_capped_before_decode(self):
        with patch.object(probe.base64, "b64decode", side_effect=AssertionError("decoded oversized payload")) as decode:
            with self.assertRaises(ValueError):
                probe._decode_screenshot("A" * (probe._MAX_SCREENSHOT_BASE64_CHARS + 1))
            decode.assert_not_called()

    def test_screenshot_requires_png_signature_and_bounded_decoded_size(self):
        for body in (b"not png" * 20, b"\x89PNG\r\n\x1a\n" + b"x" * 56,
                     b"\x89PNG\r\n\x1a\n" + b"x" * (probe._MAX_SCREENSHOT_BYTES + 1)):
            payload = base64.b64encode(body).decode("ascii")
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                probe._decode_screenshot(payload)

    def test_screenshot_accepts_bounded_png_bytes(self):
        body = b"\x89PNG\r\n\x1a\n" + b"x" * 80
        payload = base64.b64encode(body).decode("ascii")
        self.assertEqual(body, probe._decode_screenshot(payload))


if __name__ == "__main__":
    unittest.main()
