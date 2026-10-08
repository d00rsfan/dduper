#!/usr/bin/env python3
"""No privileges or Btrfs writes: exercise the real callers with failing helpers."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
APP = REPO / "target/release/dduper"


class CallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dduper-caller-")
        self.work = Path(self.temp.name)
        self.a, self.b = self.work / "a", self.work / "b"
        self.a.write_bytes(b"a" * 8192)
        self.b.write_bytes(b"a" * 8192)
        self.helper = self.work / "helper"

    def tearDown(self):
        self.temp.cleanup()

    def run_case(self, body, status, message):
        self.helper.write_text("#!/usr/bin/env python3\n" + body)
        self.helper.chmod(0o700)
        for command in ([str(APP)], [sys.executable, str(REPO / "dduper")]):
            with self.subTest(command=command):
                p = subprocess.run(command + ["--device", "/dev/test", "--files", str(self.a), str(self.b), "--dry-run"],
                    cwd=self.work, env={**os.environ, "DDUPER_BTRFS": str(self.helper)}, capture_output=True, text=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(str(self.a), p.stderr)
                self.assertIn(status, p.stderr)
                self.assertIn(message, p.stderr)
                self.assertIn("checksums unavailable", p.stderr)
                self.assertNotIn("panicked", p.stderr)
                self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(self.b.read_bytes(), b"a" * 8192)

    def test_helper_failure_preserves_stderr_and_status(self):
        self.run_case("import sys\nprint('lookup failed', file=sys.stderr)\nsys.exit(7)\n", "exit status: 7", "lookup failed")

    def test_successful_empty_output_is_error(self):
        self.run_case("pass\n", "exit status: 0", "missing/invalid protocol")

    def test_truncated_output_is_error(self):
        self.run_case("print('dduper-csum-v1 4096 8192 2')\nprint('a'*64)\n", "exit status: 0", "expected 2 blocks, got 1")

    def test_unavailable_status_is_error(self):
        self.run_case("import sys\nprint('NODATASUM', file=sys.stderr)\nsys.exit(2)\n", "exit status: 2", "NODATASUM")

    def test_missing_helper(self):
        for command in ([str(APP)], [sys.executable, str(REPO / "dduper")]):
            p = subprocess.run(command + ["--device", "/dev/test", "--files", str(self.a), str(self.b), "--dry-run"],
                cwd=self.work, env={**os.environ, "DDUPER_BTRFS": str(self.helper)}, capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("exit status unavailable", p.stderr)
            self.assertIn(str(self.a), p.stderr)

    def test_old_database_does_not_add_targets(self):
        # An existing Python/Rust DB may contain paths outside this invocation.
        (self.work / "dduper.db").write_bytes(b"old database left untouched")
        self.helper.write_text("#!/usr/bin/env python3\nprint('dduper-csum-v1 4096 8192 2')\nprint('a'*64)\nprint('b'*64)\n")
        self.helper.chmod(0o700)
        p = subprocess.run([str(APP), "--device", "/dev/test", "--files", str(self.a), str(self.b), "--dry-run"],
            cwd=self.work, env={**os.environ, "DDUPER_BTRFS": str(self.helper)}, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("available for dedupe: 8", p.stdout)
        self.assertEqual((self.work / "dduper.db").read_bytes(), b"old database left untouched")


if __name__ == "__main__":
    unittest.main()
