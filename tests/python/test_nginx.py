# coding: utf-8
"""Nginx/OpenResty/Tengine Lua capability probe and BaoTa path regression tests."""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from wafcore import nginx as N
from wafcore import util as U


class PathsTest(unittest.TestCase):
    def resolve(self, env=None, banner="", test_mode=True):
        values = {"BTWAF_CE_TEST_MODE": "1"} if test_mode else {}
        values.update(env or {})
        with mock.patch.dict(os.environ, values, clear=True), \
                mock.patch.object(U, "run", return_value=(0, "", banner)):
            return tuple(path.replace("\\", "/") for path in N.resolve_paths())

    def test_baota_paths_remain_nginx_layout_for_tengine_version(self):
        files = (
            "/www/server/nginx/sbin/nginx", "/www/server/nginx/conf/nginx.conf",
            "/www/server/tengine/sbin/nginx", "/www/server/tengine/conf/nginx.conf",
            "/etc/init.d/nginx", "/etc/init.d/tengine",
        )
        self.assertEqual(self.resolve(env={
            "BTWAF_CE_NGINX_BIN": "/tmp/manual/tengine/sbin/nginx",
            "BTWAF_CE_NGINX_INIT": "/etc/init.d/tengine",
        }, banner="Tengine/3.1.0", test_mode=False), (
            "/www/server/nginx/sbin/nginx", "/www/server/nginx/conf/nginx.conf", "/etc/init.d/nginx",
        ))
        with mock.patch.dict(os.environ, {"BTWAF_CE_TEST_MODE": "1"}, clear=True), \
                mock.patch.object(N.os.path, "isfile", side_effect=lambda path: path.replace("\\", "/") in files), \
                mock.patch.object(N.os, "access", return_value=True), \
                mock.patch.object(U, "run", return_value=(0, "", "Tengine/3.1.0")):
            self.assertEqual(tuple(path.replace("\\", "/") for path in N.resolve_paths()), (
                "/www/server/nginx/sbin/nginx", "/www/server/nginx/conf/nginx.conf", "/etc/init.d/nginx",
            ))
            self.assertEqual(N.resolve_vhost_dir(), "/www/server/panel/vhost/nginx")

    def test_production_mode_ignores_path_overrides_but_test_mode_accepts_them(self):
        values = {
            "BTWAF_CE_NGINX_BIN": "/tmp/manual/tengine/sbin/nginx",
            "BTWAF_CE_NGINX_CONF": "/tmp/manual/tengine/conf/nginx.conf",
            "BTWAF_CE_NGINX_INIT": "/etc/init.d/tengine",
            "BTWAF_CE_SERVER_ROOT": "/tmp/manual/tengine",
        }
        self.assertEqual(tuple(path.replace("\\", "/") for path in self.resolve(env=values, test_mode=False)), (
            "/www/server/nginx/sbin/nginx", "/www/server/nginx/conf/nginx.conf", "/etc/init.d/nginx",
        ))
        with mock.patch.dict(os.environ, dict(values, BTWAF_CE_TEST_MODE="1"), clear=True):
            self.assertEqual(tuple(path.replace("\\", "/") for path in N.resolve_paths()), (
                "/tmp/manual/tengine/sbin/nginx", "/tmp/manual/tengine/conf/nginx.conf", "/etc/init.d/tengine",
            ))

    def test_explicit_binary_and_config_overrides_are_preserved_for_isolated_tests(self):
        self.assertEqual(self.resolve(env={
            "BTWAF_CE_NGINX_BIN": "/tmp/tengine/sbin/nginx",
            "BTWAF_CE_NGINX_CONF": "/tmp/tengine/conf/nginx.conf",
        }), ("/tmp/tengine/sbin/nginx", "/tmp/tengine/conf/nginx.conf", "/etc/init.d/nginx"))

    def test_explicit_service_and_vhost_overrides_are_preserved(self):
        env = {
            "BTWAF_CE_TEST_MODE": "1", "BTWAF_CE_NGINX_BIN": "/tmp/nginx",
            "BTWAF_CE_NGINX_CONF": "/tmp/nginx.conf", "BTWAF_CE_NGINX_INIT": "/tmp/nginx-init",
            "BTWAF_CE_VHOST_DIR": "/tmp/vhost",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(N.resolve_paths(), ("/tmp/nginx", "/tmp/nginx.conf", "/tmp/nginx-init"))
            self.assertEqual(N.resolve_vhost_dir(), "/tmp/vhost")

    def test_vhost_prefers_panel_nginx_include_or_fixed_panel_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = os.path.join(tmp, "nginx.conf")
            with open(conf, "w", encoding="utf-8") as handle:
                handle.write('http { include "/www/server/panel/vhost/nginx/*.conf"; }')
            with mock.patch.dict(os.environ, {
            "BTWAF_CE_TEST_MODE": "1", "BTWAF_CE_NGINX_CONF": conf,
        }, clear=True):
                self.assertEqual(N.resolve_vhost_dir(), "/www/server/panel/vhost/nginx")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(N.os.path, "isfile", return_value=False):
            self.assertEqual(N.resolve_vhost_dir(), "/www/server/panel/vhost/nginx")

    def test_custom_paths_generate_metadata_without_claiming_host_lua_directives(self):
        with tempfile.TemporaryDirectory() as tmp:
            lua = os.path.join(tmp, "lua dir")
            env = dict(os.environ, BTWAF_CE_TEST_MODE="1", BTWAF_CE_DATA_DIR=tmp,
                       BTWAF_CE_LOG_DIR=os.path.join(tmp, "logs"),
                       BTWAF_CE_LUA_DIR=lua, PYTHONIOENCODING="utf-8")
            code = "from wafcore import paths; paths.write_runtime_paths(); print(paths.CONF_TEXT)"
            result = subprocess.run([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"' + lua.replace("\\", "/") + '/init.lua"', result.stdout)
            self.assertNotIn("init_by_lua", result.stdout)
            self.assertNotIn("lua_package_path", result.stdout)
            with open(os.path.join(lua, "runtime_paths.lua"), encoding="utf-8") as handle:
                metadata = handle.read()
            self.assertIn(tmp.replace("\\", "/"), metadata)
            self.assertIn("log_dir", metadata)


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="btwaf_ce_nginx_test_")
        self.addCleanup(self.tmp.cleanup)
        N.clear_cache()
        self.addCleanup(N.clear_cache)
        self.conf = self.write("nginx.conf", "events {} http {}\n")

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_version_banners_do_not_decide_lua_support(self):
        for banner, name, version in (
            ("Tengine version: Tengine/3.1.0\nnginx version: nginx/1.24.0", "Tengine", "3.1.0"),
            ("nginx version: openresty/1.27.1.2", "OpenResty", "1.27.1.2"),
            ("nginx version: nginx/1.24.0", "Nginx", "1.24.0"),
        ):
            server = "nginx version: nginx/1.24.0 (Tengine/3.1.0)" if name == "Tengine" else banner
            with self.subTest(name=name), mock.patch.object(U, "run", return_value=(0, "", server)), \
                    mock.patch.object(U, "nginx_test", return_value=(True, "successful")) as probe:
                result = N.check_env("/opt/nginx", self.conf)
                self.assertEqual((result["name"], result["version"], result["lua"]), (name, version, True))
                probe.assert_called_once()
                self.assertFalse(os.path.exists(probe.call_args[0][1]))

    def test_compiled_but_not_loaded_module_fails(self):
        banner = "Tengine/3.1.0\nconfigure arguments: --add-dynamic-module=/src/lua-nginx-module"
        with mock.patch.object(U, "run", return_value=(0, "", banner)), \
                mock.patch.object(U, "nginx_test", return_value=(False, 'unknown directive "lua_shared_dict"')):
            result = N.check_env("/opt/nginx", self.conf)
        self.assertFalse(result["lua"])
        self.assertIn("unknown directive", result["detail"])

    def test_failed_binary_is_not_accepted_even_with_lua_in_output(self):
        with mock.patch.object(U, "run", return_value=(1, "lua_nginx_module", "failed")), \
                mock.patch.object(U, "nginx_test") as probe:
            self.assertFalse(N.check_env("/opt/nginx", self.conf)["lua"])
            probe.assert_not_called()

    def test_probe_copies_load_order_and_library_paths_but_not_handlers(self):
        self.write("modules/lua.conf", 'load_module modules/ndk_http_module.so;\nload_module modules/custom.so;\n')
        self.write("conf.d/libraries.conf", 'lua_package_path "/opt/lualib/?.lua;;";\nlua_package_cpath "/opt/lualib/?.so;;";\n')
        self.write("nginx.conf", '''# load_module modules/disabled.so;
include modules/*.conf;
events {}
http {
    include conf.d/*.conf;
    init_by_lua_file /other-plugin/init.lua;
    access_by_lua_block { error("must not execute") }
    server { location / { lua_package_path "/location-only/?.lua"; } }
}
''')
        captures = []

        def probe(binary, conf, prefix=None):
            with open(conf, encoding="utf-8") as handle:
                captures.append(handle.read())
            self.assertEqual(prefix, "/opt/tengine")
            return True, "successful"

        with open(self.conf, "rb") as handle:
            before = handle.read()
        with mock.patch.object(U, "run", return_value=(0, "", "Tengine/3.1.0 --prefix='/opt/tengine'")), \
                mock.patch.object(U, "nginx_test", side_effect=probe):
            self.assertTrue(N.check_env("/opt/nginx", self.conf)["lua"])
        text = captures[0]
        self.assertLess(text.index("ndk_http_module"), text.index("custom.so"))
        self.assertIn("/opt/lualib/?.lua;;", text)
        self.assertIn("/opt/lualib/?.so;;", text)
        for unexpected in ("disabled.so", "other-plugin", "must not execute", "location-only"):
            self.assertNotIn(unexpected, text)
        for expected in ("init_by_lua_file", "init_worker_by_lua_file", "access_by_lua_file", "lua_shared_dict"):
            self.assertIn(expected, text)
        with open(self.conf, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_legacy_dso_preserves_path_and_module_stubs(self):
        self.write("stubs.conf", "module_stub ngx_core_module;\nmodule_stub ngx_http_lua_module;\n")
        self.write("nginx.conf", '''dso {
    path /opt/tengine/modules;
    include stubs.conf;
    load ngx_http_lua_module.so;
}
events {} http {}
''')
        main, http = N._probe_directives(self.conf)
        self.assertEqual(len(main), 1)
        for value in ("dso {", "path /opt/tengine/modules", "module_stub ngx_http_lua_module", "load ngx_http_lua_module.so"):
            self.assertIn(value, main[0])
        self.assertEqual(http, [])

    def test_multiline_directives_and_includes_use_main_conf_root(self):
        self.write("parts/modules.conf", 'include "more modules.conf";\n')
        self.write("more modules.conf", 'load_module\n  "modules/with spaces.so"\n;\n')
        self.write("nginx.conf", 'include parts/modules.conf; events {} http {}\n')
        main, _ = N._probe_directives(self.conf)
        self.assertEqual(len(main), 1)
        self.assertIn("modules/with spaces.so", main[0])

    def test_lua_strings_and_comments_cannot_inject_module_directives(self):
        self.write("nginx.conf", '''events {} http {
    init_by_lua_block {
        -- } load_module /bad1.so;
        --[=[ } load_module /bad2.so; ]=]
        local a = [==[ } load_module /bad3.so; ]==]
        local b = { a = "} load_module /bad4.so;", nested = {} }
    }
    lua_package_path "/valid/?.lua;;";
    server { location ~ "a{1,3}" { return 200 "} ; #"; } }
}
''')
        main, http = N._probe_directives(self.conf)
        self.assertEqual(main, [])
        self.assertEqual(http, ['lua_package_path "/valid/?.lua;;";'])

    def test_missing_include_and_malformed_config_fail_cleanly(self):
        for text in ('include missing.conf; events {} http {}', 'events {} http {', 'http { lua_package_path "bad; }'):
            self.write("nginx.conf", text)
            with self.subTest(text=text), mock.patch.object(U, "run", return_value=(0, "", "Tengine/3.1.0")):
                result = N.check_env("/opt/nginx", self.conf)
                self.assertFalse(result["lua"])
                self.assertIn("探测失败", result["detail"])

    def test_prefix_quoting(self):
        for value, expected in (
            ("--prefix=/opt/tengine", "/opt/tengine"),
            ("--prefix='/opt/with spaces'", "/opt/with spaces"),
            ('--prefix="/opt/with spaces"', "/opt/with spaces"),
            (r"--prefix=/opt/with\ spaces", "/opt/with spaces"),
        ):
            self.assertEqual(N._prefix_from_banner("configure arguments: " + value), expected)

    def test_runtime_prefix_overrides_build_prefix(self):
        with mock.patch.dict(os.environ, {"BTWAF_CE_NGINX_PREFIX": "/srv/runtime"}), \
                mock.patch.object(U, "run", return_value=(0, "", "Tengine/3.1.0 --prefix=/build")), \
                mock.patch.object(U, "nginx_test", return_value=(True, "successful")) as probe:
            self.assertTrue(N.check_env("/opt/nginx", self.conf)["lua"])
            self.assertEqual(probe.call_args[1]["prefix"], "/srv/runtime")

    def test_status_cache_expires_and_diagnostics_always_reprobes(self):
        result = {"name": "Tengine", "version": "3.1.0", "lua": True, "detail": "ok"}
        with mock.patch.object(N, "_check_env", return_value=result) as probe, \
                mock.patch.object(N.time, "monotonic", return_value=0) as clock:
            N.check_env("/opt/nginx", self.conf, cached=True)
            first = N.check_env("/opt/nginx", self.conf, cached=True)
            self.assertEqual(probe.call_count, 1)
            first["lua"] = False
            self.assertTrue(N.check_env("/opt/nginx", self.conf, cached=True)["lua"])
            N.check_env("/opt/nginx", self.conf)
            self.assertEqual(probe.call_count, 2)
            clock.return_value = 31
            N.check_env("/opt/nginx", self.conf, cached=True)
            self.assertEqual(probe.call_count, 3)
            self.write("nginx.conf", "events {} http { access_log off; }\n")
            N.check_env("/opt/nginx", self.conf, cached=True)
            self.assertEqual(probe.call_count, 4)

    def test_repeated_includes_preserve_order_and_cycles_fail(self):
        self.write("modules.conf", "load_module modules/lua.so;")
        self.write("nginx.conf", "include modules.conf; include modules.conf; events {} http {}")
        main, _ = N._probe_directives(self.conf)
        self.assertEqual(main, ["load_module modules/lua.so;"] * 2)
        self.write("modules.conf", "include nginx.conf;")
        with self.assertRaisesRegex(ValueError, "循环"):
            N._probe_directives(self.conf)

    def test_invalid_include_and_missing_semicolon_are_not_silently_ignored(self):
        for text in ('include a.conf b.conf;', 'http { lua_package_path "x" }'):
            self.write("nginx.conf", text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                N._probe_directives(self.conf)


class CommandTest(unittest.TestCase):
    def test_cli_paths_uses_same_resolver(self):
        env = dict(os.environ, BTWAF_CE_NGINX_BIN="/tmp/tengine/sbin/nginx", BTWAF_CE_NGINX_CONF="/tmp/tengine/conf/nginx.conf",
                   BTWAF_CE_NGINX_INIT="/tmp/nginx-init", BTWAF_CE_VHOST_DIR="/tmp/vhost")
        env.update({"BTWAF_CE_TEST_MODE": "1"})
        result = subprocess.run([sys.executable, os.path.join(ROOT, "wafcore", "nginx.py"), "paths"],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["/tmp/tengine/sbin/nginx", "/tmp/tengine/conf/nginx.conf", "/tmp/nginx-init", "/tmp/vhost"])

    def test_cli_failed_check_returns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, os.path.join(ROOT, "wafcore", "nginx.py"), "check",
                                     "--bin", os.path.join(tmp, "absent-nginx"), "--conf", os.path.join(tmp, "nginx.conf")],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env=dict(os.environ, BTWAF_CE_TEST_MODE="1", PYTHONIOENCODING="utf-8"))
        self.assertEqual(result.returncode, 1)
        output = result.stdout.decode("utf-8")
        self.assertIn("无法执行", output)

    def test_check_cli_matches_probe_verdict(self):
        with mock.patch.object(N, "check_env", return_value={"name": "Tengine", "version": "3.1.0", "lua": False, "detail": "未加载 Lua"}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(N.main(["check", "--bin", "/opt/nginx", "--conf", "/opt/nginx.conf"]), 1)
            self.assertIn("Tengine 3.1.0", out.getvalue())

    def test_custom_service_name_is_preserved_for_systemd(self):
        with mock.patch.object(U.os.path, "exists", return_value=False), \
                mock.patch.object(U, "run", return_value=(0, "reloaded", "")) as run:
            self.assertTrue(U.reload_nginx("/etc/init.d/tengine-prod")[0])
            self.assertEqual(run.call_args[0][0], ["/usr/bin/systemctl", "reload", "tengine-prod"])

    def test_nginx_test_uses_runtime_prefix_and_requires_successful_exit(self):
        with mock.patch.object(U, "run", return_value=(0, "", "configuration test is successful")) as run:
            self.assertTrue(U.nginx_test("/opt/nginx", "/opt/nginx.conf", prefix="/opt/tengine")[0])
            self.assertEqual(run.call_args[0][0], ["/opt/nginx", "-t", "-p", "/opt/tengine", "-c", "/opt/nginx.conf"])
        with mock.patch.object(U, "run", return_value=(1, "successful", "failed")):
            self.assertFalse(U.nginx_test("/opt/nginx", "/opt/nginx.conf")[0])

    def test_tengine_systemd_reload_does_not_use_nginx_service(self):
        with mock.patch.object(U.os.path, "exists", return_value=False), \
                mock.patch.object(U, "run", return_value=(0, "reloaded", "")) as run:
            self.assertTrue(U.reload_nginx("/etc/init.d/tengine")[0])
            self.assertEqual(run.call_args[0][0], ["/usr/bin/systemctl", "reload", "tengine"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
