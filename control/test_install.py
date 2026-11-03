"""Installer privilege-boundary checks without modifying the operating system."""
import os
import io
import json
from contextlib import ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

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
        with patch.object(install,'isolation_prerequisites'), patch.object(install.shutil,'which',side_effect=which or (lambda name:'/usr/bin/'+name)), patch.object(install,'output',side_effect=probe or self.probe), patch.object(install,'command',side_effect=lambda args:self.commands.append(args)), patch.object(install,'supported_packages',return_value=True):
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
            modules=('controller.py','agent.py','install.py','compose_control.py','compose_engine.py','compose_storage.py','compose_seal.py','compose_helper.py','compose_transport.py','compose_storage_worker.py','compose_storage_bridge.py')
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


class StorageIsolationPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name)
        self.python=self.base/'python3';self.python.write_text('system interpreter');self.python.chmod(0o755)
        self.controllers=self.base/'cgroup.controllers';self.controllers.write_text('cpu memory pids')

    def tearDown(self):
        self.temp.cleanup()

    def check(self,version='systemd 252 (252.39)',python='3.11.9',platform='linux',uid=0,which=None):
        with patch.object(install.sys,'platform',platform),patch.object(install.os,'geteuid',return_value=uid),patch.object(install,'SYSTEM_PYTHON',self.python),patch.object(install,'CGROUP_CONTROLLERS',self.controllers),patch.object(install.shutil,'which',side_effect=which or (lambda name:'/usr/bin/'+name)),patch.object(install,'output',side_effect=lambda args:version if args[0]=='systemctl' else python):
            install.isolation_prerequisites()

    def test_supported_systemd_cgroup_and_system_python_pass(self):
        self.check()

    def test_missing_or_old_isolation_never_uses_a_fallback(self):
        for options in ({'version':'systemd 251'},{'version':'unreadable'},{'python':'3.10.9'},{'platform':'darwin'},{'uid':1000},{'which':lambda name:None if name=='systemd-run' else '/usr/bin/'+name}):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError,'Missing or unsupported prerequisite'):
                    self.check(**options)
        self.controllers.unlink()
        with self.assertRaisesRegex(ValueError,'cgroup v2'):
            self.check()


class WorkerAccountTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name)
        self.config=self.base/'config';self.config.mkdir(mode=0o700)
        self.accounts={};self.groups={};self.commands=[]
        self.stack=ExitStack()
        real_lstat=Path.lstat;real_fstat=os.fstat
        def owned(value,uid=0):
            fields=list(value);fields[4]=uid;return os.stat_result(fields)
        self.stack.enter_context(patch.object(install,'CONFIG_DIR',self.config))
        self.stack.enter_context(patch.object(install,'validate_storage_marker_parents'))
        self.stack.enter_context(patch.object(Path,'lstat',lambda path:owned(real_lstat(path)) if path==self.config else real_lstat(path)))
        self.stack.enter_context(patch.object(install.os,'fstat',side_effect=lambda fd:owned(real_fstat(fd))))
        self.stack.enter_context(patch.object(install.pwd,'getpwnam',side_effect=lambda user:self.lookup(self.accounts,user)))
        self.stack.enter_context(patch.object(install.pwd,'getpwall',side_effect=lambda:list(self.accounts.values())))
        self.stack.enter_context(patch.object(install.grp,'getgrnam',side_effect=lambda name:self.lookup(self.groups,name)))
        self.stack.enter_context(patch.object(install.grp,'getgrgid',side_effect=lambda gid:next(g for g in self.groups.values() if g.gr_gid==gid)))
        self.stack.enter_context(patch.object(install.grp,'getgrall',side_effect=lambda:list(self.groups.values())))
        self.stack.enter_context(patch.object(install.os,'getgrouplist',side_effect=lambda user,gid:[gid]))
        self.stack.enter_context(patch.object(install,'command',side_effect=self.command))
        self.addCleanup(self.stack.close);self.addCleanup(self.temp.cleanup)

    @staticmethod
    def lookup(mapping,key):
        if key not in mapping:raise KeyError(key)
        return mapping[key]

    def add(self,user='rolypolyops-storage',uid=991,gid=992,**extra):
        self.accounts[user]=SimpleNamespace(pw_name=user,pw_uid=uid,pw_gid=gid,pw_shell='/usr/sbin/nologin',pw_dir='/nonexistent',**extra)
        self.groups[user]=SimpleNamespace(gr_name=user,gr_gid=gid,gr_mem=[])

    def command(self,args):
        self.commands.append(args)
        self.assertEqual(args[0],'useradd')
        index=len(self.accounts)
        self.add(args[-1],uid=991+2*index,gid=992+2*index)

    def test_account_and_pin_creation_are_idempotent_without_other_config_changes(self):
        (self.config/'control-installation.json').write_text('control sentinel')
        (self.config/'lab.env').write_text('demo sentinel')
        pin=install.ensure_storage_worker('rolypolyops-storage')
        self.assertEqual(pin,{'user':'rolypolyops-storage','uid':991,'gid':992})
        marker=self.config/'storage-worker.json';before=marker.read_bytes()
        self.assertEqual(marker.stat().st_mode & 0o777,0o600)
        self.assertEqual(install.ensure_storage_worker('rolypolyops-storage'),pin)
        self.assertEqual(marker.read_bytes(),before)
        self.assertEqual(len(self.commands),1)
        self.assertEqual((self.config/'control-installation.json').read_text(),'control sentinel')
        self.assertEqual((self.config/'lab.env').read_text(),'demo sentinel')
        self.assertNotIn('docker',str(self.commands))

    def test_unmarked_account_and_group_collisions_are_not_adopted(self):
        self.add()
        with self.assertRaisesRegex(ValueError,'collision'):
            install.ensure_storage_worker('rolypolyops-storage')
        self.accounts.clear()
        with self.assertRaisesRegex(ValueError,'collision'):
            install.ensure_storage_worker('rolypolyops-storage')
        self.assertEqual(self.commands,[])
        self.assertFalse((self.config/'storage-worker.json').exists())

    def test_pin_uid_gid_and_exclusive_nonlogin_boundary_are_enforced(self):
        install.ensure_storage_worker('rolypolyops-storage')
        account=self.accounts['rolypolyops-storage']
        for attribute,value in [('pw_uid',0),('pw_gid',0),('pw_uid',993),('pw_shell','/bin/bash'),('pw_dir','/home/worker')]:
            before=getattr(account,attribute);setattr(account,attribute,value)
            with self.subTest(attribute=attribute,value=value):
                with self.assertRaises(ValueError):
                    install.ensure_storage_worker('rolypolyops-storage')
            setattr(account,attribute,before)
        self.groups['rolypolyops-storage'].gr_mem=['foreign']
        with self.assertRaisesRegex(ValueError,'exclusive'):
            install.ensure_storage_worker('rolypolyops-storage')
        self.groups['rolypolyops-storage'].gr_mem=[]
        with patch.object(install.os,'getgrouplist',return_value=[992,999]):
            with self.assertRaisesRegex(ValueError,'exclusive'):
                install.ensure_storage_worker('rolypolyops-storage')
        self.accounts['foreign']=SimpleNamespace(pw_name='foreign',pw_gid=992)
        with self.assertRaisesRegex(ValueError,'exclusive'):
            install.ensure_storage_worker('rolypolyops-storage')
        self.assertEqual(len(self.commands),1)

    def test_two_scoped_markers_do_not_access_default_authority(self):
        default=self.config/'storage-worker.json';default.write_text('default sentinel')
        first=self.base/'instance-a'/'storage-worker.json';first.parent.mkdir()
        second=self.base/'instance-b'/'storage-worker.json';second.parent.mkdir()
        original=install.trusted_json;seen=[]
        def selected(path):
            seen.append(path)
            if path==default:raise AssertionError('default marker accessed')
            return original(path)
        with patch.object(install,'trusted_json',side_effect=selected),patch.object(install,'trusted_config_directory',side_effect=AssertionError('default directory accessed')):
            a=install.ensure_storage_worker('storage-a',marker_path=str(first))
            b=install.ensure_storage_worker('storage-b',marker_path=str(second))
            self.assertEqual(install.ensure_storage_worker('storage-a',marker_path=str(first)),a)
        self.assertNotEqual(a['uid'],b['uid'])
        self.assertEqual(json.loads(first.read_text()),a)
        self.assertEqual(json.loads(second.read_text()),b)
        self.assertEqual(default.read_text(),'default sentinel')
        self.assertNotIn(default,seen)
        self.assertEqual(len(self.commands),2)

    def test_missing_scoped_marker_never_falls_back_or_adopts_account(self):
        self.add('storage-a')
        alternate=self.base/'instance-a'/'storage-worker.json';alternate.parent.mkdir()
        install.atomic(self.config/'storage-worker.json',{'user':'storage-a','uid':991,'gid':992})
        with self.assertRaisesRegex(ValueError,'collision'):
            install.ensure_storage_worker('storage-a',marker_path=str(alternate))
        self.assertFalse(alternate.exists())
        self.assertEqual(self.commands,[])

    def test_boolean_uid_or_gid_is_not_a_numeric_identity(self):
        self.add('storage-a',uid=1,gid=1)
        alternate=self.base/'instance-a'/'storage-worker.json';alternate.parent.mkdir()
        for key in ('uid','gid'):
            pin={'user':'storage-a','uid':1,'gid':1};pin[key]=True
            install.atomic(alternate,pin)
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError,'marker mismatch'):
                    install.ensure_storage_worker('storage-a',marker_path=str(alternate))
        self.assertEqual(self.commands,[])

    def test_marker_permissions_owner_and_symlinks_fail_closed(self):
        install.ensure_storage_worker('rolypolyops-storage')
        marker=self.config/'storage-worker.json'
        marker.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'Untrusted'):
            install.ensure_storage_worker('rolypolyops-storage')
        marker.chmod(0o600)
        real_fstat=os.fstat
        def foreign(fd):
            value=list(real_fstat(fd));value[4]=123;return os.stat_result(value)
        with patch.object(install.os,'fstat',side_effect=foreign):
            with self.assertRaisesRegex(ValueError,'Untrusted'):
                install.ensure_storage_worker('rolypolyops-storage')
        marker.unlink();outside=self.base/'outside';outside.write_text('unchanged');marker.symlink_to(outside)
        with self.assertRaises((OSError,ValueError)):
            install.ensure_storage_worker('rolypolyops-storage')
        self.assertEqual(outside.read_text(),'unchanged')


class IsolatedAgentInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
        self.config=self.base/'config';self.config.mkdir(mode=0o700)
        self.units=self.base/'units';self.units.mkdir()
        self.agent_config=self.config/'agent.json'
        self.source=self.base/'source';self.source.mkdir()
        self.events=[]
        class TransportError(Exception):
            def __init__(self,code,unknown=False):
                self.code,self.unknown=code,unknown
                super().__init__('RAW_PRIVATE_SECRET')
        self.error=TransportError
        self.module=SimpleNamespace(DEFAULT_WORKER_USER='rolypolyops-storage',TransportError=TransportError,probe_runtime=Mock(side_effect=self.probe))
        self.stack=ExitStack()
        self.stack.enter_context(patch.object(install,'AGENT_CONFIG',self.agent_config))
        self.stack.enter_context(patch.object(install,'UNIT_DIR',self.units))
        self.stack.enter_context(patch.object(install,'validate_source',side_effect=lambda:self.source))
        self.stack.enter_context(patch.object(install,'trusted_config_directory'))
        self.stack.enter_context(patch.object(install,'validate_storage_marker_parents'))
        self.stack.enter_context(patch.object(install,'validate_storage_worker_marker',side_effect=lambda value:Path(value)))
        actual_json=install.read_json
        self.stack.enter_context(patch.object(install,'trusted_json',side_effect=lambda path:actual_json(path)))
        self.stack.enter_context(patch.object(install,'agent_prerequisites',return_value='/root/agent-venv/bin/python3'))
        self.stack.enter_context(patch.object(install,'transport_module',return_value=self.module))
        self.worker=self.stack.enter_context(patch.object(install,'ensure_storage_worker',side_effect=lambda user,**kwargs:self.events.append(('account',user,kwargs))))
        self.copy=self.stack.enter_context(patch.object(install,'copy_source',side_effect=lambda:self.events.append(('copy',))))
        self.stack.enter_context(patch.object(install,'install_package_policy'))
        self.stack.enter_context(patch.object(install,'command',side_effect=lambda args:self.events.append(('command',args))))
        opener=SimpleNamespace(open=self.enroll)
        self.open=self.stack.enter_context(patch.object(install.urllib.request,'build_opener',return_value=opener))
        self.addCleanup(self.stack.close);self.addCleanup(self.temp.cleanup)

    def probe(self,**kwargs):
        self.events.append(('probe',kwargs));return {'ready':True}

    def enroll(self,*args,**kwargs):
        self.events.append(('enroll',))
        return io.BytesIO(json.dumps({'nodeId':'00000000-0000-4000-8000-000000000001','token':'enrollment-result','role':'primary','storageWorkerUser':'root','storageWorkerMarker':'/remote/untrusted-worker.json'}).encode())

    def test_probe_precedes_enrollment_and_installed_source_replacement(self):
        install.agent('https://control.example.test/ops','code')
        names=[entry[0] for entry in self.events]
        self.assertLess(names.index('account'),names.index('probe'))
        self.assertLess(names.index('probe'),names.index('enroll'))
        self.assertLess(names.index('probe'),names.index('copy'))
        self.module.probe_runtime.assert_called_once_with(worker_user='rolypolyops-storage',source_dir=self.source,timeout=30)
        self.assertEqual(json.loads(self.agent_config.read_text())['storageWorkerUser'],'rolypolyops-storage')
        self.assertNotIn('storageWorkerMarker',json.loads(self.agent_config.read_text()))
        unit=(self.units/'rolypolyops-agent.service').read_text()
        self.assertIn('Type=simple',unit)
        self.assertIn('ExecStart=/root/agent-venv/bin/python3',unit)
        self.assertNotIn('User=rolypolyops-storage',unit)
        self.assertNotIn('PrivateNetwork',unit)
        self.assertNotIn('enrollment-result',unit)

    def test_failed_or_unverified_probe_does_not_consume_enrollment_or_replace_source(self):
        for failure in (self.error('network_isolation_unavailable'),self.error('transport_cleanup_unverified',True),None):
            with self.subTest(failure=type(failure).__name__):
                self.events.clear()
                self.module.probe_runtime.side_effect=failure
                self.module.probe_runtime.return_value={'ready':False}
                with self.assertRaisesRegex(ValueError,'storage isolation') as result:
                    install.agent('https://control.example.test/ops','code')
                self.assertNotIn('RAW_PRIVATE_SECRET',str(result.exception))
                self.assertNotIn('enroll',[event[0] for event in self.events])
                self.copy.assert_not_called()
                self.assertFalse(self.agent_config.exists())
                self.assertEqual(list(self.units.iterdir()),[])

    def test_reinstall_preserves_registration_and_root_selected_worker(self):
        existing={'controller':'https://control.example.test/ops','nodeId':'old-node','token':'old-token','role':'recovery','storageWorkerUser':'own-test-storage'}
        self.agent_config.write_text(json.dumps(existing));self.agent_config.chmod(0o600)
        install.agent('https://control.example.test/ops',None)
        self.assertEqual(json.loads(self.agent_config.read_text()),existing)
        self.assertNotIn('enroll',[event[0] for event in self.events])
        self.module.probe_runtime.assert_called_once_with(worker_user='own-test-storage',source_dir=self.source,timeout=30)
        self.worker.assert_called_once_with('own-test-storage')

    def test_reenrollment_keeps_root_local_worker_selection(self):
        existing={'controller':'https://control.example.test/ops','nodeId':'old-node','token':'old-token','role':'recovery','storageWorkerUser':'own-test-storage'}
        self.agent_config.write_text(json.dumps(existing));self.agent_config.chmod(0o600)
        install.agent('https://control.example.test/ops','new-code',replace=True)
        current=json.loads(self.agent_config.read_text())
        self.assertNotEqual(current['token'],existing['token'])
        self.assertEqual(current['storageWorkerUser'],'own-test-storage')
        self.module.probe_runtime.assert_called_once_with(worker_user='own-test-storage',source_dir=self.source,timeout=30)

    def test_root_scoped_marker_survives_reinstall_and_reenrollment(self):
        marker=str(self.base/'scoped'/'storage-worker.json')
        original={'controller':'https://control.example.test/ops','nodeId':'old-node','token':'old-token','role':'recovery','storageWorkerUser':'own-test-storage','storageWorkerMarker':marker,'operatorNote':'keep'}
        self.agent_config.write_text(json.dumps(original));self.agent_config.chmod(0o600)
        install.agent('https://control.example.test/ops',None)
        self.assertEqual(json.loads(self.agent_config.read_text()),original)
        self.module.probe_runtime.assert_called_once_with(worker_user='own-test-storage',source_dir=self.source,timeout=30,marker_path=marker)
        self.worker.assert_called_once_with('own-test-storage',marker_path=marker)
        self.module.probe_runtime.reset_mock();self.worker.reset_mock()
        install.agent('https://control.example.test/ops','replacement',replace=True)
        current=json.loads(self.agent_config.read_text())
        self.assertEqual(current['storageWorkerMarker'],marker)
        self.assertEqual(current['storageWorkerUser'],'own-test-storage')
        self.assertEqual(current['operatorNote'],'keep')
        self.assertNotEqual(current['token'],original['token'])
        self.module.probe_runtime.assert_called_once_with(worker_user='own-test-storage',source_dir=self.source,timeout=30,marker_path=marker)

    def test_bad_root_marker_is_rejected_before_prerequisites_or_account(self):
        for marker in (None,False,[],{},'relative','/etc/../marker','/etc/marker\n'):
            self.agent_config.write_text(json.dumps({'controller':'https://control.example.test/ops','storageWorkerMarker':marker}))
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(ValueError,'invalid_storage_worker_marker'):
                    install.agent('https://control.example.test/ops','code')
        self.worker.assert_not_called()
        self.module.probe_runtime.assert_not_called()
        self.copy.assert_not_called()

    def test_wrong_controller_or_missing_code_fails_before_probe(self):
        with self.assertRaisesRegex(ValueError,'enrollment code'):
            install.agent('https://control.example.test/ops',None)
        self.agent_config.write_text(json.dumps({'controller':'https://other.example/ops'}))
        with self.assertRaisesRegex(ValueError,'another controller'):
            install.agent('https://control.example.test/ops','code')
        self.module.probe_runtime.assert_not_called()
        self.worker.assert_not_called()


class StorageModulePackagingTests(unittest.TestCase):
    def test_installed_worker_module_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);source=base/'source';source.mkdir()
            for name in install.SOURCE_MODULES:(source/name).write_text('# '+name)
            destination=base/'installed'/'control';destination.mkdir(parents=True)
            outside=base/'outside';outside.write_text('unchanged')
            (destination/'compose_storage_worker.py').symlink_to(outside)
            with patch.object(install,'__file__',str(source/'install.py')),patch.object(install,'DEST',destination):
                with self.assertRaisesRegex(ValueError,'Untrusted installed code file'):
                    install.copy_source()
            self.assertEqual(outside.read_text(),'unchanged')
            self.assertFalse((destination/'controller.py').exists())

    def test_missing_worker_module_is_rejected_before_destination_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary)/'source';source.mkdir()
            for name in install.SOURCE_MODULES:
                if name!='compose_storage_worker.py':(source/name).write_text('# '+name)
            destination=Path(temporary)/'absent'/'control'
            with patch.object(install,'__file__',str(source/'install.py')),patch.object(install,'DEST',destination):
                with self.assertRaisesRegex(ValueError,'complete trusted'):
                    install.copy_source()
            self.assertFalse(destination.parent.exists())


if __name__ == "__main__":
    unittest.main()
