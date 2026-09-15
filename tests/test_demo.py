"""The one-command demo must pass all of its own checks and print no credential."""

from __future__ import annotations

import io
import re
import unittest

from zeropw import demo


class DemoTestCase(unittest.TestCase):
    def test_demo_passes_all_checks_without_printing_secrets(self) -> None:
        out = io.StringIO()
        runner = demo.Demo(out)
        code = runner.run()
        text = out.getvalue()
        self.assertEqual(code, 0, text)
        self.assertNotIn("[FAIL]", text)
        self.assertNotIn(runner.synthetic, text)
        self.assertNotIn("zpwc_", text.replace("zpwc_...", ""))
        self.assertNotIn("zpw1.", text)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertGreaterEqual(len(re.findall(r"\[PASS\]", text)), 25)


if __name__ == "__main__":
    unittest.main()
