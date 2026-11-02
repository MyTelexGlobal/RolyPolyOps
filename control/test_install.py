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

    def test_unit_and_shell_control_characters_are_rejected_before_writes(self):
        for value in ["https://control.example.test\nExecStartPre=/bin/false", "https://control.example.test;id", "https://control.example.test`id`", "https://control.example.test/ops?token=secret", "https://user:pass@control.example.test"]:
            with self.assertRaises(ValueError):
                install.checked_url(value, {"", "/"})


class GenericPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.commands=[]

    def probe(self,args):
        if args[:2] == ['docker','version']:
            return '29.1.3'
        if args[:2] == ['docker','info']:
            return '["name=seccomp", "name=cgroupns"]'
        if args[:3] == ['docker','compose','version']:
            return '2.40.0'
        if args[:2] == ['restic','version']:
            return 'restic 0.18.0 compiled with go'
        if len(args)>2 and args[1]=='-c':
            return '46.0.5 6.0.3'
        if args[:3] == ['docker','image','inspect']:
            return '[]'
        raise AssertionError(args)

    def run_prerequisites(self,probe=None,which=None):
        with patch.object(install.shutil,'which',side_effect=which or (lambda name:'/usr/bin/'+name)), patch.object(install,'output',side_effect=probe or self.probe), patch.object(install,'command',side_effect=lambda args:self.commands.append(args)), patch.object(install,'supported_packages',return_value=True):
            return install.agent_prerequisites()

    def test_working_runtime_never_installs_upgrades_or_restarts_docker(self):
        self.assertEqual(self.run_prerequisites(),install.sys.executable)
        self.assertEqual(self.commands,[])

    def test_old_existing_docker_is_rejected_without_replacement(self):
        def probe(args):
            return '28.0.0' if args[:2]==['docker','version'] else self.probe(args)
        with self.assertRaisesRegex(ValueError,'existing installation preserved'):
            self.run_prerequisites(probe)
        self.assertEqual(self.commands,[])

    def test_rootless_daemon_is_rejected(self):
        def probe(args):
            return '["name=rootless"]' if args[:2]==['docker','info'] else self.probe(args)
        with self.assertRaisesRegex(ValueError,'rootful Docker'):
            self.run_prerequisites(probe)
        self.assertEqual(self.commands,[])

    def test_absent_restic_installs_only_missing_package(self):
        self.run_prerequisites(which=lambda name:None if name=='restic' else '/usr/bin/'+name)
        self.assertEqual(self.commands,[['apt-get','update'],['apt-get','install','-y','--no-upgrade','--no-install-recommends','restic']])

    def test_missing_crypto_bootstraps_supported_library_before_agent_start(self):
        probes=[]
        def probe(args):
            if len(args)>2 and args[1]=='-c':
                probes.append(args[0])
                if len(probes)<4:
                    raise install.subprocess.CalledProcessError(1,args)
                return '46.0.5 6.0.3'
            return self.probe(args)
        with patch.object(Path,'is_symlink',return_value=False):
            python=self.run_prerequisites(probe)
        self.assertEqual(python,str(install.RUNTIME/'bin/python3'))
        self.assertIn([python,'-m','pip','install','--only-binary=:all:','cryptography==46.0.5','PyYAML==6.0.3'],self.commands)
        self.assertFalse(any('docker.io' in arg for args in self.commands for arg in args))

    def test_pinned_helper_pull_only_when_absent(self):
        def probe(args):
            if args[:3]==['docker','image','inspect']:
                raise install.subprocess.CalledProcessError(1,args)
            return self.probe(args)
        self.run_prerequisites(probe)
        self.assertEqual(self.commands,[['docker','pull',install.HELPER]])
        self.assertIn('@sha256:',install.HELPER)

    def test_copy_installs_all_generic_modules_and_web_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            source=base/'source';source.mkdir()
            modules=('controller.py','agent.py','install.py','compose_control.py','compose_engine.py','compose_storage.py','compose_seal.py','compose_helper.py')
            for name in modules:
                (source/name).write_text('# '+name)
            (source/'web').mkdir()
            (source/'web'/'wizard.js').write_text('sealed form')
            destination=base/'installed'/'control'
            with patch.object(install,'__file__',str(source/'install.py')),patch.object(install,'DEST',destination):
                install.copy_source()
            for name in modules:
                self.assertEqual((destination/name).read_text(),'# '+name)
                self.assertEqual((destination/name).stat().st_mode & 0o777,0o644)
            self.assertEqual((destination/'web'/'wizard.js').read_text(),'sealed form')


if __name__ == "__main__":
    unittest.main()
