#!/usr/bin/env python3
# coding: utf-8
"""Run the unchanged bash installer inside a Linux filesystem sandbox.

Requires bubblewrap and an enabled user/mount namespace. Never writes to the
host's panel directories; /www and /tmp are private mounts for every command.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BWRAP = shutil.which("bwrap")
PYTHON = shutil.which("python3")
BASH = shutil.which("bash")


class InstallCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="btwaf-ce-install-check-")
        self.addCleanup(self.tmp.cleanup)
        self.www = Path(self.tmp.name) / "www"
        self.server = self.www / "server/nginx"
        self.conf = self.server / "conf/nginx.conf"
        self.binary = self.server / "sbin/nginx"
        self.vhost = self.www / "server/panel/vhost/nginx"
        self.vhost.mkdir(parents=True)
        self.write(self.conf, "events {}\nhttp {}\n")
        self.write(self.server / "version.pl", "Tengine 3.1.0\n")
        self.write(self.server / "version_check.pl", "tengine\n")
        self.write(self.binary, '''#!%s
import json, os, sys
from pathlib import Path
with open('/www/calls.jsonl', 'a') as out:
    out.write(json.dumps({'kind': 'nginx', 'args': sys.argv[1:]}) + '\\n')
if sys.argv[1:] == ['-V']:
    sys.stderr.write('Tengine version: Tengine/3.1.0\\nconfigure arguments: --prefix=/www/server/nginx\\n')
    sys.exit(0)
args = sys.argv[1:]
if '-t' not in args or '-c' not in args:
    sys.exit(2)
conf = Path(args[args.index('-c') + 1])
text = conf.read_text()
assert str(conf).startswith('/tmp/'), 'expected a private probe config'
assert 'lua_shared_dict' in text and 'init_worker_by_lua_file' in text and 'access_by_lua_file' in text
if os.environ.get('FIXTURE_LUA') == 'missing':
    sys.stderr.write('unknown directive "lua_shared_dict"\\n')
    sys.exit(1)
sys.stderr.write('nginx: configuration test is successful\\n')
''' % PYTHON, executable=True)

    def write(self, path, text, executable=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if executable:
            path.chmod(0o755)

    def sandbox_command(self):
        return [
            BWRAP, "--unshare-all", "--die-with-parent", "--tmpfs", "/",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind-try", "/opt", "/opt", "--ro-bind", "/etc", "/etc",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--ro-bind", str(ROOT), "/repo", "--bind", str(self.www), "/www",
            "--chdir", "/repo", BASH, "install.sh", "check",
        ]

    def run_check(self, env=None):
        inherited = {key: value for key, value in os.environ.items() if not key.startswith("BTWAF_CE_")}
        inherited.update(env or {})
        inherited["PYTHONDONTWRITEBYTECODE"] = "1"
        inherited["PYTHONIOENCODING"] = "utf-8"
        before = self.conf.read_bytes() if self.conf.exists() else None
        result = subprocess.run(self.sandbox_command(), env=inherited,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                encoding="utf-8", timeout=30)
        after = self.conf.read_bytes() if self.conf.exists() else None
        self.assertEqual(after, before, result.stdout)
        self.assertFalse((self.vhost / "btwaf_ce.conf").exists(), result.stdout)
        print("\n[bash install.sh check] exit=%d\n%s" % (result.returncode, result.stdout), flush=True)
        return result

    def calls(self):
        path = self.www / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Tengine 3.1.0", result.stdout)
        self.assertIn("Lua 指令检测通过", result.stdout)
        self.assertNotIn("No such file or directory", result.stdout)
        self.assertEqual([call['args'][0] for call in self.calls() if call['kind'] == 'nginx'], ['-V', '-t'])

    def test_check_runs_with_system_python_when_panel_python_absent(self):
        self.assert_success(self.run_check())

    def test_check_uses_panel_python_shell_function_and_ignores_old_path_variables(self):
        panel_python = self.www / "server/panel/pyenv/bin/python3"
        self.write(panel_python, '''#!%s
import json, os, sys
with open('/www/calls.jsonl', 'a') as out:
    out.write(json.dumps({'kind': 'panel-python', 'args': sys.argv[1:]}) + '\\n')
os.execv(%r, [%r] + sys.argv[1:])
''' % (PYTHON, PYTHON, PYTHON), executable=True)
        result = self.run_check({
            "BTWAF_CE_TEST_MODE": "1", "BTWAF_CE_SERVER_ROOT": "/manual/tengine",
            "BTWAF_CE_NGINX_BIN": "/manual/tengine", "BTWAF_CE_NGINX_CONF": "/manual/nginx.conf",
            "BTWAF_CE_NGINX_INIT": "/manual/init", "BTWAF_CE_VHOST_DIR": "/manual/vhost",
            "BTWAF_CE_PANEL_ROOT": "/manual/panel", "BTWAF_CE_NGINX_PREFIX": "/manual/prefix",
            "BTWAF_CE_DATA_DIR": "/manual/data", "BTWAF_CE_LOG_DIR": "/manual/logs",
            "BTWAF_CE_LUA_DIR": "/manual/lua", "BTWAF_CE_INSTALL_LOG": "/manual/install.log",
        })
        self.assert_success(result)
        python_calls = [call['args'] for call in self.calls() if call['kind'] == 'panel-python']
        self.assertEqual(len(python_calls), 1)
        self.assertEqual(python_calls[0], ['/repo/wafcore/nginx.py', 'check', '--bin',
                                         '/www/server/nginx/sbin/nginx', '--conf', '/www/server/nginx/conf/nginx.conf'])
        self.assertNotIn('/manual/prefix', self.calls()[-1]['args'])

    def test_check_fails_for_missing_nginx_binary(self):
        self.binary.unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("未找到 Web 服务器（/www/server/nginx/sbin/nginx）", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_check_fails_for_missing_main_config(self):
        self.conf.unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("未找到 Web 服务器主配置", result.stdout)
        self.assertFalse(self.conf.exists())

    def test_check_fails_for_unloaded_lua_module(self):
        result = self.run_check({"FIXTURE_LUA": "missing"})
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('unknown directive "lua_shared_dict"', result.stdout)
        self.assertIn("未启用可用的 Lua 模块", result.stdout)


if __name__ == "__main__":
    if not sys.platform.startswith("linux") or not BWRAP or not PYTHON or not BASH:
        sys.exit("Installer shell regression requires Linux, bubblewrap, python3 and bash (no silent skip).")
    unittest.main(verbosity=2)
