import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "install.sh"
BASH = shutil.which("bash")


@unittest.skipIf(os.name == "nt" or not BASH, "installer guard integration requires Linux Bash")
class LegacyInstallGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.home = root / "home"
        self.cwd = root / "cwd"
        self.bin = root / "path-stubs"
        self.home.mkdir()
        self.cwd.mkdir()
        self.bin.mkdir()
        self.log = root / "commands.log"
        self.log.write_text("", encoding="utf-8")
        for command in ("sudo", "systemctl", "grep", "git", "dirname", "basename",
                        "chmod", "pip", "mkdir", "ln", "cp"):
            marker = "printf '%s\\n' 'STUB_SUDO_REACHED' >&2\n" if command == "sudo" else ""
            stub = self.bin / command
            stub.write_text("#!/bin/sh\nprintf '%s\\n' '" + command +
                            "' >> \"$COMMAND_LOG\"\n" + marker + "exit 97\n", encoding="utf-8")
            os.chmod(stub, 0o755)
        self.env = os.environ.copy()
        self.env.update({"HOME": str(self.home), "PATH": str(self.bin),
                         "COMMAND_LOG": str(self.log)})

    def tearDown(self):
        self.temp.cleanup()

    def run_installer(self, *args):
        return subprocess.run(
            [str(Path(BASH).resolve()), str(SCRIPT), *args], cwd=self.cwd,
            env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=5, check=False)

    def assert_no_legacy_side_effects(self):
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")
        self.assertFalse((self.home / "printer_data" / "config").exists())
        self.assertFalse((self.home / "klipper-toolchanger-easy").exists())

    def test_default_invalid_and_multiple_arguments_exit_before_commands(self):
        for args in ((), ("--unknown",), ("--legacy-unsafe", "extra"),
                     ("--help", "extra")):
            with self.subTest(args=args):
                result = self.run_installer(*args)
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, "")
                self.assertIn("Usage: install.sh --legacy-unsafe", result.stderr)
                self.assert_no_legacy_side_effects()

    def test_help_is_read_only(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage: install.sh --legacy-unsafe", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertNotIn("[WARNING]", result.stdout)
        self.assert_no_legacy_side_effects()

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "legacy preflight exits before sudo when the test process is root")
    def test_legacy_flag_warns_then_enters_preflight(self):
        result = self.run_installer("--legacy-unsafe")
        self.assertEqual(result.returncode, 255)
        warning = result.stderr.index("[WARNING] Legacy installer")
        sudo_reached = result.stderr.index("STUB_SUDO_REACHED")
        self.assertLess(warning, sudo_reached)
        self.assertIn("[ERROR] Klipper service not found", result.stdout)
        self.assertEqual(sorted(self.log.read_text(encoding="utf-8").splitlines()),
                         ["grep", "sudo"])
        self.assertFalse((self.home / "printer_data" / "config").exists())
