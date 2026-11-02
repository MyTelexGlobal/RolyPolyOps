"""Installer privilege-boundary checks without modifying the operating system."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control import install


class InstallationAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.state = self.base / "data"
        self.config = self.base / "config"
        self.units = self.base / "units"
        self.units.mkdir()
        self.commands = []
        self.original_lstat = Path.lstat

    def tearDown(self):
        self.temp.cleanup()

    def lstat(self, path):
        value = self.original_lstat(path)
        if path == self.config:
            fields = list(value)
            fields[4] = 0
            return os.stat_result(fields)
        return value

    def perform(self, uid=1000):
        with patch.object(install, "STATE", self.state), patch.object(install, "CONFIG_DIR", self.config), patch.object(install, "UNIT_DIR", self.units), patch.object(install, "copy_source"), patch.object(install.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=uid, pw_gid=uid)), patch.object(install, "command", side_effect=lambda args: self.commands.append(args)), patch.object(install.os, "chown") as chown, patch.object(Path, "lstat", new=lambda path: self.lstat(path)):
            install.controller("https://control.example.test", False)
            return chown.call_args_list

    def test_catalog_initialization_uses_unprivileged_account(self):
        self.state.mkdir()
        outside = self.base / "outside"
        outside.write_text("unchanged")
        (self.state / "attacker-link").symlink_to(outside)
        changes = self.perform()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].args[0], self.state)
        self.assertEqual(changes[0].kwargs, {"follow_symlinks": False})
        init = next(args for args in self.commands if "init" in args)
        self.assertEqual(init[:4], ["runuser", "-u", "rolypolyops-control", "--"])
        self.assertEqual(outside.read_text(), "unchanged")
        self.assertFalse((self.state / "installation.json").exists())
        self.assertTrue((self.config / "control-installation.json").is_file())

    def test_control_account_cannot_be_root(self):
        with self.assertRaisesRegex(ValueError, "unprivileged"):
            self.perform(uid=0)
        self.assertFalse(any("init" in args for args in self.commands))

    def test_data_root_symlink_is_rejected(self):
        target = self.base / "outside"
        target.mkdir()
        self.state.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "data directory"):
            self.perform()
        self.assertFalse(any("init" in args for args in self.commands))


if __name__ == "__main__":
    unittest.main()
