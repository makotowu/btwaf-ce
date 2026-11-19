#!/usr/bin/env python
# coding: utf-8
"""btwaf_ce 后端纯函数单元测试（阶段 A）。

用法（从仓库根目录）：

    python tests/python/test_backend.py

约束：
- 只依赖标准库（unittest/json/os/...），不 import 面板 `public`。
- 导入业务模块前用 mock.patch 替换 paths.py 的常量与派生路径，
  使测试只写临时目录，不通过环境变量改变生产代码行为。
- 每个用例 setUp 清空临时数据/日志目录，保证用例互不污染。
- 退出码 0 = 全绿；非 0 = 有失败。
"""
import atexit
import json
import os
import shutil
import sys
import tempfile
import unittest

from unittest import mock

# ---------------------------------------------------------------------------
# 1) 准备临时目录（业务模块导入前由 mock 替换路径）
# ---------------------------------------------------------------------------
_TMP_ROOT = tempfile.mkdtemp(prefix="btwaf_ce_test_")
DATA_DIR = os.path.join(_TMP_ROOT, "btwaf_data")
LOG_DIR = os.path.join(_TMP_ROOT, "btwaf_logs")
NGINX_ROOT = os.path.join(_TMP_ROOT, "no-nginx")
NGINX_BIN = os.path.join(NGINX_ROOT, "sbin", "nginx")
NGINX_CONF = os.path.join(NGINX_ROOT, "conf", "nginx.conf")
NGINX_INIT = os.path.join(NGINX_ROOT, "init.d", "nginx")
VHOST_DIR = os.path.join(_TMP_ROOT, "vhost", "nginx")


def _cleanup_tmp():
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


atexit.register(_cleanup_tmp)

# ---------------------------------------------------------------------------
# 2) 导入被测模块（btwaf_ce 插件根目录加入 sys.path）
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from wafcore import paths as P  # noqa: E402

_lua_dir = os.path.join(DATA_DIR, "lua")
_path_constants = {
    "DATA_DIR": DATA_DIR, "LOG_DIR": LOG_DIR, "RUNTIME_LUA_DIR": _lua_dir,
    "NGINX_BIN": NGINX_BIN, "NGINX_CONF": NGINX_CONF, "NGINX_INIT": NGINX_INIT,
    "VHOST_DIR": VHOST_DIR, "CONF_PATH": os.path.join(VHOST_DIR, "btwaf_ce.conf"),
    "GLOBAL_CONFIG": os.path.join(DATA_DIR, "config.json"),
    "SITE_CONFIG": os.path.join(DATA_DIR, "site.json"),
    "HOSTS_CONFIG": os.path.join(DATA_DIR, "hosts.json"),
    "CUSTOM_RULES": os.path.join(DATA_DIR, "rule", "custom.json"),
    "STATE_FILE": os.path.join(DATA_DIR, "data", "state.json"),
    "BLOCK_LOG": os.path.join(DATA_DIR, "data", "block.log"),
    "UNBAN_LOG": os.path.join(DATA_DIR, "data", "unban.log"),
    "PERF_FILE": os.path.join(DATA_DIR, "data", "perf.json"),
    "BLOCK_PAGE": os.path.join(DATA_DIR, "data", "blockpage.html"),
    "PLUGIN_LOG": os.path.join(DATA_DIR, "logs", "plugin.log"),
    "WAF_LOG": os.path.join(LOG_DIR, "waf.log"),
    "RULES_INDEX": os.path.join(_lua_dir, "rules", "index.json"),
}
_path_patch = mock.patch.multiple(P, **_path_constants)
_path_patch.start()
atexit.register(_path_patch.stop)
_conf_patch = mock.patch.object(P, "CONF_TEXT", P._conf_text())
_conf_patch.start()
atexit.register(_conf_patch.stop)

from wafcore import config as C  # noqa: E402
from wafcore import engine as E  # noqa: E402
from wafcore import firewall as F  # noqa: E402
from wafcore import geo as G  # noqa: E402
from wafcore import logs as L  # noqa: E402
from wafcore import nginx as N  # noqa: E402
from wafcore import rules as R  # noqa: E402
from wafcore import sites as S  # noqa: E402
from wafcore import state as ST  # noqa: E402
from wafcore import util as U  # noqa: E402
import btwaf_ce_main as MAIN  # noqa: E402

try:  # Windows 控制台编码兜底
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ---------------------------------------------------------------------------
# 3) 测试辅助
# ---------------------------------------------------------------------------
def write_json(path, obj):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, indent=2))
    return path


def write_lines(path, records):
    """records 元素为 dict（json.dumps 后写一行）或原始字符串。"""
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            if isinstance(rec, str):
                f.write(rec + "\n")
            else:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def read_lines_json(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def make_waf_records():
    """构造 4 条覆盖 sqli/xss/cc/blacklist 的 waf.log 记录。"""
    return [
        {
            "time": 100,
            "site": "a.com",
            "host": "a.com",
            "ip": "1.1.1.1",
            "method": "GET",
            "uri": "/x.php",
            "query": "id=1%27",
            "status": 403,
            "action": "block",
            "score": 5,
            "sensitivity": 2,
            "hits": [
                {
                    "module": "sqli",
                    "rule": "crs-942100",
                    "name": "SQL Injection Attack",
                    "score": 5,
                    "tier": 1,
                    "src": "crs",
                }
            ],
            "ua": "sqlmap/1.7",
            "referer": "",
            "ctype": "",
            "body_len": 0,
            "snippet": "id=1'",
            "block_time": 0,
            "rule_source": "crs",
            "req_id": "r1",
        },
        {
            "time": 200,
            "site": "b.com",
            "host": "b.com",
            "ip": "2.2.2.2",
            "method": "GET",
            "uri": "/",
            "query": "",
            "status": 444,
            "action": "cc",
            "score": 0,
            "sensitivity": 2,
            "hits": [],
            "ua": "Mozilla/5.0",
            "referer": "",
            "ctype": "",
            "body_len": 0,
            "snippet": "",
            "block_time": 300,
            "rule_source": "",
            "req_id": "r2",
        },
        {
            "time": 300,
            "site": "a.com",
            "host": "a.com",
            "ip": "1.1.1.1",
            "method": "POST",
            "uri": "/login",
            "query": "",
            "status": 200,
            "action": "allow",
            "score": 3,
            "sensitivity": 2,
            "hits": [
                {
                    "module": "xss",
                    "rule": "crs-941100",
                    "name": "XSS Attack",
                    "score": 3,
                    "tier": 1,
                    "src": "crs",
                }
            ],
            "ua": "curl/8.0",
            "referer": "",
            "ctype": "application/x-www-form-urlencoded",
            "body_len": 10,
            "snippet": "q=<script>",
            "block_time": 0,
            "rule_source": "crs",
            "req_id": "r3",
        },
        {
            "time": 400,
            "site": "a.com",
            "host": "a.com",
            "ip": "3.3.3.3",
            "method": "GET",
            "uri": "/admin",
            "query": "",
            "status": 403,
            "action": "blacklist",
            "score": 0,
            "sensitivity": 2,
            "hits": [],
            "ua": "nikto",
            "referer": "",
            "ctype": "",
            "body_len": 0,
            "snippet": "",
            "block_time": 0,
            "rule_source": "",
            "req_id": "r4",
        },
    ]


class FakeQuery(object):
    """模拟 public.M(table).field(...).select() 的链式查询。"""

    def __init__(self, rows, raise_on_field=False):
        self._rows = rows
        self._raise = raise_on_field

    def field(self, _fields):
        if self._raise:
            raise RuntimeError("field() 不可用")
        return self

    def select(self):
        return list(self._rows)


class FakeDB(object):
    """模拟 public.M：db("sites") / db("domain")。"""

    def __init__(self, tables, raise_on_field=False):
        self.tables = tables
        self._raise = raise_on_field

    def __call__(self, table):
        if table not in self.tables:
            raise RuntimeError("未知数据表：%s" % table)
        return FakeQuery(self.tables[table], self._raise)


def make_sites_db(raise_on_field=False):
    return FakeDB(
        {
            "sites": [
                {"id": 1, "name": "www.example.com", "path": "/www/wwwroot/a", "status": 1},
                {"id": 2, "name": "m.example.com", "path": "/www/wwwroot/b", "status": 1},
            ],
            "domain": [
                {"pid": 1, "name": "www.example.com", "port": 80},
                {"pid": 1, "name": "api.example.com", "port": 80},
                {"pid": 1, "name": "shop.example.com:8080", "port": 8080},
                {"pid": 2, "name": "m.example.com", "port": 80},
            ],
        },
        raise_on_field=raise_on_field,
    )


class BaseCase(unittest.TestCase):
    """每个用例前清空临时数据/日志/conf 目录。"""

    def setUp(self):
        for d in (DATA_DIR, LOG_DIR, VHOST_DIR):
            shutil.rmtree(d, ignore_errors=True)
        os.makedirs(DATA_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# 4) paths / mock 隔离
# ---------------------------------------------------------------------------
class PathsTest(BaseCase):
    def test_mock_paths_are_isolated(self):
        self.assertEqual(P.DATA_DIR, DATA_DIR)
        self.assertEqual(P.LOG_DIR, LOG_DIR)
        self.assertEqual(P.NGINX_BIN, NGINX_BIN)
        self.assertEqual(P.GLOBAL_CONFIG, os.path.join(DATA_DIR, "config.json"))
        self.assertEqual(P.WAF_LOG, os.path.join(LOG_DIR, "waf.log"))
        self.assertEqual(P.RULES_INDEX, os.path.join(DATA_DIR, "lua", "rules", "index.json"))
        self.assertEqual(P.CONF_PATH, os.path.join(VHOST_DIR, "btwaf_ce.conf"))
        self.assertEqual(P.PLUGIN_DIR, _PLUGIN_DIR)

    def test_conf_hash_stable_and_normalized(self):
        h1 = P.conf_hash()
        self.assertEqual(h1, P.conf_hash())
        # 去首尾空白/空行后哈希不变
        self.assertEqual(E.hash_text(P.CONF_TEXT), h1)
        self.assertEqual(E.hash_text("  " + P.CONF_TEXT.replace("\n", "  \n") + "\n\n"), h1)


# ---------------------------------------------------------------------------
# 5) util 纯函数
# ---------------------------------------------------------------------------
class UtilValidIpTest(BaseCase):
    def test_valid_ip(self):
        for ok in ("1.2.3.4", "0.0.0.0", "255.255.255.255", "::1", "2001:db8::1"):
            self.assertTrue(U.valid_ip(ok), ok)
        for bad in ("", None, "1.2.3", "1.2.3.256", "1.2.3.4.5", "abc", "1.2.3.4:80", "  ", 123):
            self.assertFalse(U.valid_ip(bad), bad)

    def test_valid_cidr(self):
        for ok in ("10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0", "255.255.255.255/32", " 10.0.0.0/8 "):
            self.assertTrue(U.valid_cidr(ok), ok)
        for bad in ("", None, "10.0.0.0", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/abc", "300.0.0.0/8", "2001:db8::/32"):
            self.assertFalse(U.valid_cidr(bad), bad)

    def test_valid_ip_or_cidr_and_regex(self):
        self.assertTrue(U.valid_ip_or_cidr("1.2.3.4"))
        self.assertTrue(U.valid_ip_or_cidr("10.0.0.0/8"))
        self.assertFalse(U.valid_ip_or_cidr("evil"))
        self.assertTrue(U.valid_regex(r"\bunion\b"))
        self.assertFalse(U.valid_regex("("))


class UtilSanitizeTest(BaseCase):
    def test_sanitize_block_page(self):
        html = '<html><script>alert(1)</script><body onload="x()">hi</body></html>'
        clean, removed = U.sanitize_block_page(html)
        self.assertTrue(removed)
        self.assertNotIn("<script", clean.lower())
        self.assertNotIn("onload=", clean.lower())
        self.assertIn("data-removed=", clean)
        self.assertIn("hi", clean)

    def test_sanitize_block_page_javascript_and_iframe(self):
        clean, removed = U.sanitize_block_page(
            '<a href="javascript:alert(1)">x</a><iframe src="//evil"></iframe>'
        )
        self.assertNotIn("javascript:", clean.lower())
        self.assertNotIn("<iframe", clean.lower())
        self.assertGreaterEqual(len(removed), 2)
        self.assertEqual(U.sanitize_block_page(None), ("", []))

    def test_sanitize_block_page_truncates_64k(self):
        clean, _removed = U.sanitize_block_page("A" * 70000)
        self.assertLessEqual(len(clean), 65536)


class UtilMiscTest(BaseCase):
    def test_safe_join(self):
        root = os.path.join(_TMP_ROOT, "join-root")
        self.assertEqual(U.safe_join(root, "a", "b.txt"), os.path.join(root, "a", "b.txt"))
        self.assertEqual(U.safe_join(root, "a", "..", "b.txt"), os.path.join(root, "b.txt"))
        with self.assertRaises(ValueError):
            U.safe_join(root, "..", "escape.txt")
        with self.assertRaises(ValueError):
            U.safe_join(root, os.path.join(_TMP_ROOT, "other.txt"))

    def test_truncate(self):
        self.assertEqual(U.truncate("a" * 600, 512), "a" * 512)
        self.assertEqual(U.truncate("a\tb\nc\x00d", 100), "a b c d")
        self.assertEqual(U.truncate(None, 8), "")
        self.assertEqual(len(U.truncate("中文" * 500, 10)), 10)

    def test_safe_int_and_human_size(self):
        self.assertEqual(U.safe_int("12", 0), 12)
        self.assertEqual(U.safe_int("x", 7), 7)
        self.assertEqual(U.safe_int(999, 0, 0, 100), 100)
        self.assertEqual(U.safe_int(-5, 0, 0, 100), 0)
        self.assertEqual(U.safe_int(3.9, 0), 3)
        self.assertEqual(U.human_size(0), "0 B")
        self.assertEqual(U.human_size(2048), "2.0 KB")

    def test_run_nonexistent_binary_does_not_raise(self):
        rc, out, err = U.run([os.path.join(_TMP_ROOT, "definitely-not-exists", "bin")], timeout=5)
        self.assertEqual(rc, -1)
        self.assertTrue(err)


# ---------------------------------------------------------------------------
# 6) config：默认值 / 深合并 / clean_lists / 站点继承 / 自定义规则
# ---------------------------------------------------------------------------
class ConfigDefaultsTest(BaseCase):
    def test_clean_global_matches_defaults(self):
        cfg, warnings = C.clean_global({})
        self.assertEqual(warnings, [])
        self.assertEqual(set(cfg.keys()), set(C.DEFAULT_GLOBAL.keys()))
        self.assertEqual(cfg["schema"], 1)
        self.assertEqual(cfg["version"], P.VERSION)
        self.assertIs(cfg["enabled"], True)
        self.assertIs(cfg["observe"], False)
        self.assertEqual(cfg["sensitivity"], 2)
        self.assertEqual(cfg["block"], {"status": 403, "use_custom": False, "page": ""})
        self.assertEqual(cfg["scan"]["body_limit"], 1048576)
        self.assertEqual(cfg["cc"]["status"], 444)
        self.assertEqual(cfg["attack_block"]["block_time"], 1800)
        self.assertEqual(set(cfg["modules"].keys()), set(C.MODULE_KEYS))
        for key in C.MODULE_KEYS:
            self.assertEqual(cfg["modules"][key], {"open": True, "tier": 1})
        self.assertEqual(
            set(cfg["lists"].keys()),
            {"ip_black", "ip_white", "url_black", "url_white", "ua_black", "ua_white", "param_white"},
        )
        self.assertEqual(cfg["rule_exclude"], {"crs": [], "ce": []})
        self.assertEqual(cfg["trusted_proxies"], [])
        self.assertIn("googlebot", cfg["crawler"]["allow"])
        self.assertIs(cfg["crawler"]["block_fake"], True)
        self.assertIs(cfg["fail_open"], True)
        self.assertIs(cfg["whitelist_first"], True)
        self.assertEqual(cfg["update_time"], 0)

    def test_clean_global_range_validation(self):
        cfg, warnings = C.clean_global(
            {
                "sensitivity": 9,
                "block": {"status": 500, "page": "<script>alert(1)</script>"},
                "scan": {"body_limit": 999999999, "arg_limit": 1, "max_args": 0},
                "log": {"retain_days": 9999, "rotate_size": 1, "snippet": 999999},
                "cc": {"status": 200, "cycle": 5, "limit": 0, "block_time": 1},
                "attack_block": {"cycle": 1, "limit": 0, "block_time": 1},
                "modules": {"sqli": {"open": False, "tier": 9}},
                "crawler": {"allow": "not-a-list"},
            }
        )
        self.assertEqual(cfg["sensitivity"], 3)
        self.assertEqual(cfg["block"]["status"], 403)
        self.assertNotIn("<script", cfg["block"]["page"].lower())
        self.assertTrue(any("拦截状态码" in w for w in warnings))
        self.assertTrue(any("拦截页" in w for w in warnings))
        self.assertEqual(cfg["scan"]["body_limit"], 52428800)
        self.assertEqual(cfg["scan"]["arg_limit"], 256)
        self.assertEqual(cfg["scan"]["max_args"], 1)
        self.assertEqual(cfg["log"]["retain_days"], 365)
        self.assertEqual(cfg["log"]["rotate_size"], 1048576)
        self.assertEqual(cfg["log"]["snippet"], 4096)
        self.assertEqual(cfg["cc"]["status"], 444)
        self.assertEqual(cfg["cc"]["cycle"], 10)
        self.assertEqual(cfg["cc"]["limit"], 2)
        self.assertEqual(cfg["cc"]["block_time"], 10)
        self.assertEqual(cfg["attack_block"]["cycle"], 10)
        self.assertEqual(cfg["attack_block"]["limit"], 1)
        self.assertIs(cfg["modules"]["sqli"]["open"], False)
        self.assertEqual(cfg["modules"]["sqli"]["tier"], 3)
        self.assertEqual(cfg["modules"]["xss"], {"open": True, "tier": 1})
        self.assertGreater(len(cfg["crawler"]["allow"]), 0)

    def test_clean_global_tolerates_non_dict_subconfig(self):
        # QA-2 回归：损坏/手工改坏的 config.json 不得让 load_global 抛异常（fail_open）。
        for bad in (
            {"modules": {"xss": True}},
            {"cc": "broken"},
            {"scan": []},
            {"attack_block": 1},
            {"block": "x"},
            {"modules": {"sqli": "bad"}, "cc": "x", "cdn": 1, "lists": {"ip_black": "x"}},
        ):
            cfg, _warnings = C.clean_global(bad)
            self.assertIsInstance(cfg, dict)
            self.assertEqual(set(cfg["modules"].keys()), set(C.MODULE_KEYS))
            self.assertIsInstance(cfg["cc"], dict)
        self.assertIsInstance(C.clean_site({"modules": {"xss": "bad"}}), dict)
        self.assertIsInstance(C.clean_site({"cc": 1, "cdn": "x", "lists": []}), dict)
        # 写坏 config.json 后 load_global 仍返回可用配置
        U.write_text(P.GLOBAL_CONFIG, '{"modules": {"xss": true}, "cc": "broken"}')
        loaded = C.load_global()
        self.assertEqual(loaded["sensitivity"], 2)
        self.assertEqual(set(loaded["modules"].keys()), set(C.MODULE_KEYS))
        # effective_site 的输入链是 load_global/load_sites（已清洗），不应抛
        eff = C.effective_site(loaded, C.clean_site({"modules": {"xss": "bad"}}))
        self.assertIn("xss", eff["modules"])
        self.assertEqual(eff["modules"]["xss"]["open"], True)

    def test_bool_coercion(self):
        cfg, _ = C.clean_global(
            {"enabled": "0", "observe": "yes", "fail_open": 0, "whitelist_first": "on"}
        )
        self.assertIs(cfg["enabled"], False)
        self.assertIs(cfg["observe"], True)
        self.assertIs(cfg["fail_open"], False)
        self.assertIs(cfg["whitelist_first"], True)

    def test_load_save_global_roundtrip(self):
        self.assertEqual(C.load_global()["sensitivity"], 2)  # 缺文件 -> 默认
        saved, warnings = C.save_global({"sensitivity": 3, "enabled": False})
        self.assertEqual(saved["sensitivity"], 3)
        self.assertIs(saved["enabled"], False)
        self.assertGreater(saved["update_time"], 0)
        self.assertTrue(os.path.isfile(P.GLOBAL_CONFIG))
        loaded = C.load_global()
        self.assertEqual(loaded["sensitivity"], 3)
        self.assertIs(loaded["enabled"], False)

    def test_default_data_files(self):
        S.default_data_files()
        for p in (
            P.GLOBAL_CONFIG,
            P.SITE_CONFIG,
            P.HOSTS_CONFIG,
            P.CUSTOM_RULES,
            P.BLOCK_LOG,
            P.UNBAN_LOG,
            P.STATE_FILE,
            P.PLUGIN_LOG,
        ):
            self.assertTrue(os.path.isfile(p), p)
        self.assertEqual(U.read_json(P.GLOBAL_CONFIG)["sensitivity"], 2)
        # 已存在配置不被覆盖
        U.write_json(P.GLOBAL_CONFIG, {"sensitivity": 3})
        S.default_data_files()
        self.assertEqual(U.read_json(P.GLOBAL_CONFIG)["sensitivity"], 3)


class DeepMergeTest(BaseCase):
    def test_nested_merge_list_replace_none_skip(self):
        base = {"a": {"b": 1, "c": 2}, "l": [1, 2], "keep": "x"}
        out = C.deep_merge(base, {"a": {"b": 9, "d": 3}, "l": [3], "keep": None})
        self.assertEqual(out["a"], {"b": 9, "c": 2, "d": 3})
        self.assertEqual(out["l"], [3])
        self.assertEqual(out["keep"], "x")
        self.assertNotIn("keep", [k for k, v in out.items() if v is None])
        # 不修改入参
        self.assertEqual(base["a"], {"b": 1, "c": 2})
        self.assertEqual(base["l"], [1, 2])

    def test_non_dict_inputs(self):
        self.assertEqual(C.deep_merge(None, {"a": 1}), {"a": 1})
        self.assertEqual(C.deep_merge({"a": 1}, None), {"a": 1})
        self.assertEqual(C.deep_merge([1], {"a": 1}), {"a": 1})
        out = C.deep_merge({"a": {"b": 1}}, {"a": None})
        self.assertEqual(out, {"a": {"b": 1}})


class CleanListsTest(BaseCase):
    def test_ip_and_cidr_filtering(self):
        out = C.clean_lists(
            {
                "ip_black": [
                    "1.2.3.4",
                    " 1.2.3.4 ",
                    "10.0.0.0/8",
                    "10.0.0.0/33",
                    "999.1.1.1",
                    "not-ip",
                    "",
                    "1.2.3.4",
                    "::1",
                    "  ",
                ],
                "ip_white": ["8.8.8.8", "192.168.0.0/16"],
            }
        )
        self.assertEqual(out["ip_black"], ["1.2.3.4", "10.0.0.0/8", "::1"])
        self.assertEqual(out["ip_white"], ["8.8.8.8", "192.168.0.0/16"])

    def test_url_and_ua_limits(self):
        long_url = "~" + ("a" * 600)
        too_long_ua = "u" * 1025
        out = C.clean_lists(
            {
                "url_black": ["^/admin", "~^/a.{600}$", long_url, "^/ok", "^/ok"],
                "ua_black": ["sqlmap", too_long_ua, 123],
                "param_white": ["id", "name", ""],
            }
        )
        self.assertEqual(out["url_black"], ["^/admin", "~^/a.{600}$", "^/ok"])
        self.assertEqual(out["ua_black"], ["sqlmap", "123"])
        self.assertEqual(out["param_white"], ["id", "name"])

    def test_cap_2000(self):
        out = C.clean_lists({"ua_black": ["ua-%d" % i for i in range(2100)]})
        self.assertEqual(len(out["ua_black"]), 2000)

    def test_invalid_container(self):
        out = C.clean_lists(None)
        for key in out:
            self.assertEqual(out[key], [])
        out2 = C.clean_lists({"ip_black": "1.2.3.4"})
        self.assertEqual(out2["ip_black"], [])


class CleanSiteTest(BaseCase):
    def test_default_site_entry(self):
        entry = C.default_site_entry()
        self.assertIs(entry["open"], True)
        self.assertEqual(entry["sensitivity"], 0)
        self.assertIsNone(entry["observe"])
        self.assertEqual(len(entry["modules"]), len(C.MODULE_KEYS))
        self.assertEqual(entry["modules"]["sqli"], {"open": True, "tier": 0})
        self.assertIsNone(entry["cc"]["open"])
        self.assertIn("disable_php_path", entry)
        self.assertEqual(entry["custom_rules"], [])

    def test_clean_site_validation(self):
        entry = C.clean_site(
            {
                "sensitivity": 9,
                "observe": True,
                "modules": {"sqli": {"open": False, "tier": 9}, "xss": None},
                "cc": {"open": None, "cycle": 999999, "limit": -1, "status": 999},
                "cdn": {"open": True, "headers": ["CF-Connecting-IP", ""], "trusted": ["1.2.3.4", "bad"]},
                "lists": {"ip_black": ["1.2.3.4", "x"]},
                "disable_ext": ["sql", "", "bak"],
                "custom_rules": ["custom-1", 2],
            }
        )
        self.assertEqual(entry["sensitivity"], 3)
        self.assertIs(entry["observe"], True)
        self.assertEqual(entry["modules"]["sqli"], {"open": False, "tier": 3})
        self.assertEqual(entry["modules"]["xss"], {"open": True, "tier": 0})
        self.assertIsNone(entry["cc"]["open"])
        self.assertEqual(entry["cc"]["cycle"], 3600)
        self.assertEqual(entry["cc"]["limit"], 0)
        self.assertEqual(entry["cc"]["status"], 503)
        self.assertEqual(entry["cdn"]["headers"], ["cf-connecting-ip"])
        self.assertEqual(entry["cdn"]["trusted"], ["1.2.3.4"])
        self.assertEqual(entry["lists"]["ip_black"], ["1.2.3.4"])
        self.assertEqual(entry["disable_ext"], ["sql", "bak"])
        self.assertEqual(entry["custom_rules"], ["custom-1", "2"])

    def test_clean_site_observe_none(self):
        self.assertIsNone(C.clean_site({})["observe"])
        self.assertIs(C.clean_site({"observe": "false"})["observe"], False)


class EffectiveSiteTest(BaseCase):
    def test_inheritance_and_override(self):
        g, _ = C.clean_global({"sensitivity": 2, "lists": {"ip_black": ["1.1.1.1"]}})
        s = C.clean_site(
            {
                "sensitivity": 0,
                "observe": None,
                "modules": {"sqli": {"open": False, "tier": 0}, "rce": {"open": True, "tier": 3}},
                "lists": {"ip_black": ["2.2.2.2"], "ua_black": ["nikto"]},
                "rule_exclude": {"crs": ["crs-1"], "ce": ["ce-1"]},
                "cc": {"limit": 5},
                "disable_ext": ["sql"],
            }
        )
        eff = C.effective_site(g, s)
        self.assertEqual(eff["sensitivity"], 2)  # 站点 0 -> 继承
        self.assertIs(eff["observe"], False)  # None -> 继承
        self.assertEqual(eff["modules"]["sqli"], {"open": False, "tier": 1})  # tier 0 -> 继承 1
        self.assertEqual(eff["modules"]["rce"], {"open": True, "tier": 3})
        self.assertEqual(eff["lists"]["ip_black"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(eff["lists"]["ua_black"], ["nikto"])
        self.assertEqual(eff["rule_exclude"]["crs"], ["crs-1"])
        self.assertEqual(eff["rule_exclude"]["ce"], ["ce-1"])
        self.assertEqual(eff["cc"]["limit"], 5)
        self.assertEqual(eff["cc"]["cycle"], 60)  # 站点 0 -> 继承全局
        self.assertEqual(eff["disable_ext"], ["sql"])

    def test_site_sensitivity_and_observe_override(self):
        g, _ = C.clean_global({})
        s = C.clean_site({"sensitivity": 3, "observe": True})
        eff = C.effective_site(g, s)
        self.assertEqual(eff["sensitivity"], 3)
        self.assertIs(eff["observe"], True)


class CustomRuleTest(BaseCase):
    def test_valid_custom_rule(self):
        ok, msg = C.valid_custom_rule({"value": "sqlmap", "operator": "contains"})
        self.assertTrue(ok, msg)
        self.assertFalse(C.valid_custom_rule({"value": "  "})[0])
        self.assertFalse(C.valid_custom_rule({"value": "(", "operator": "regexp"})[0])
        self.assertFalse(C.valid_custom_rule({"value": "abc", "operator": "gt"})[0])
        self.assertTrue(C.valid_custom_rule({"value": "10", "operator": "gt"})[0])
        self.assertTrue(
            C.valid_custom_rule({"field": "ip", "value": "1.2.3.4,10.0.0.0/8"})[0]
        )
        self.assertFalse(C.valid_custom_rule({"field": "ip", "value": "1.2.3.999"})[0])
        self.assertFalse(C.valid_custom_rule("not-a-dict")[0])

    def test_next_custom_id(self):
        self.assertEqual(C.next_custom_id([]), "custom-1")
        self.assertEqual(C.next_custom_id([{"id": "custom-1"}, {"id": "custom-3"}]), "custom-2")
        self.assertEqual(C.next_custom_id([{"id": "custom-2"}]), "custom-1")
        self.assertEqual(
            C.next_custom_id([{"id": "custom-1"}, {"id": "custom-2"}, {"id": "custom-3"}]), "custom-4"
        )
        self.assertEqual(C.next_custom_id([{"id": "bogus"}, {"id": "custom-x"}]), "custom-1")

    def test_clean_custom_rule(self):
        rule = C.clean_custom_rule(
            {
                "name": "拦截 sqlmap",
                "field": "bogus",
                "operator": "bogus",
                "action": "bogus",
                "value": "x" * 3000,
                "priority": 99999,
                "status": 9999,
                "score": 0,
                "sites": ["a.com", "", "b.com"],
                "header": "User-Agent",
            }
        )
        self.assertEqual(rule["field"], "uri")
        self.assertEqual(rule["operator"], "contains")
        self.assertEqual(rule["action"], "block")
        self.assertEqual(len(rule["value"]), 2048)
        self.assertEqual(rule["priority"], 1000)
        self.assertEqual(rule["status"], 599)
        self.assertEqual(rule["score"], 1)
        self.assertEqual(rule["sites"], ["a.com", "b.com"])
        self.assertEqual(rule["name"], "拦截 sqlmap")

    def test_clean_custom_rule_header(self):
        rule = C.clean_custom_rule({"field": "header", "header": "User-Agent"})
        self.assertEqual(rule["header"], "user-agent")
        self.assertEqual(rule["scope"], "global")


# ---------------------------------------------------------------------------
# 7) logs：parse_line / query_logs / stat / trend / block_list / unban
# ---------------------------------------------------------------------------
class ParseLineTest(BaseCase):
    def test_invalid_lines(self):
        for line in ("", "   ", "not json", "[1,2]", '{"a":1} trailing', "null"):
            if line == '{"a":1} trailing':
                self.assertIsNone(L.parse_line(line))
            elif line == "null":
                self.assertIsNone(L.parse_line(line))
            else:
                self.assertIsNone(L.parse_line(line), line)

    def test_normalize_record(self):
        rec = L.parse_line(
            json.dumps(
                {
                    "time": "1700000000",
                    "host": "h.com",
                    "ip": 123,
                    "method": "get",
                    "uri": "u" * 600,
                    "query": "q" * 600,
                    "status": 999,
                    "action": "block",
                    "score": "5",
                    "sensitivity": 9,
                    "ua": "a" * 300,
                    "referer": "b" * 300,
                    "snippet": "s" * 600,
                    "body_len": -5,
                    "hits": [
                        {"module": "sqli", "rule": "r%d" % i, "name": "n", "score": 1, "tier": 9}
                        for i in range(25)
                    ],
                }
            )
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["time"], 1700000000)
        self.assertEqual(rec["site"], "h.com")  # site 缺失回退 host
        self.assertEqual(rec["host"], "h.com")
        self.assertEqual(rec["ip"], "123")
        self.assertEqual(len(rec["uri"]), 512)
        self.assertEqual(len(rec["query"]), 512)
        self.assertEqual(len(rec["ua"]), 256)
        self.assertEqual(len(rec["referer"]), 256)
        self.assertEqual(len(rec["snippet"]), 512)
        self.assertEqual(rec["status"], 599)
        self.assertEqual(rec["sensitivity"], 3)
        self.assertEqual(rec["body_len"], 0)
        self.assertEqual(len(rec["hits"]), 20)
        self.assertEqual(rec["hits"][0]["tier"], 3)

    def test_hits_missing(self):
        rec = L.parse_line(json.dumps({"time": 1, "hits": "bad"}))
        self.assertEqual(rec["hits"], [])
        rec2 = L.parse_line(json.dumps({"time": 1, "hits": [{"module": "xss"}, "junk", None]}))
        self.assertEqual(len(rec2["hits"]), 1)


class QueryLogsTest(BaseCase):
    def setUp(self):
        super().setUp()
        write_lines(P.WAF_LOG, make_waf_records())

    def test_pagination_and_order(self):
        res = L.query_logs({"p": 1, "rows": 2})
        self.assertEqual(res["total"], 4)
        self.assertEqual(res["page"], 1)
        self.assertEqual(res["rows"], 2)
        self.assertEqual(len(res["list"]), 2)
        self.assertEqual([r["time"] for r in res["list"]], [400, 300])  # 最新在前
        page2 = L.query_logs({"p": 2, "rows": 2})
        self.assertEqual([r["time"] for r in page2["list"]], [200, 100])
        page3 = L.query_logs({"p": 3, "rows": 2})
        self.assertEqual(page3["list"], [])
        self.assertEqual(page3["total"], 4)
        self.assertFalse(res["limited"])

    def test_filters(self):
        self.assertEqual(L.query_logs({"site": "a.com"})["total"], 3)
        self.assertEqual(L.query_logs({"site": "A.COM"})["total"], 3)
        self.assertEqual(L.query_logs({"site": "b.com"})["total"], 1)
        self.assertEqual(L.query_logs({"ip": "1.1.1.1"})["total"], 2)
        self.assertEqual(L.query_logs({"ip": "1.1.1.1", "site": "a.com"})["total"], 2)
        self.assertEqual(L.query_logs({"action": "block"})["total"], 1)
        self.assertEqual(L.query_logs({"log_action": "block"})["total"], 1)
        self.assertEqual(L.query_logs({"action": "cc"})["total"], 1)
        self.assertEqual(L.query_logs({"type": "sqli"})["total"], 1)
        self.assertEqual(L.query_logs({"type": "xss"})["total"], 1)
        self.assertEqual(L.query_logs({"type": "cc"})["total"], 1)  # action=cc -> module cc
        self.assertEqual(L.query_logs({"type": "blacklist"})["total"], 1)  # action=blacklist
        self.assertEqual(L.query_logs({"type": "unknown"})["total"], 0)
        self.assertEqual(L.query_logs({"keyword": "sql"})["total"], 1)
        self.assertEqual(L.query_logs({"keyword": "crs-941100"})["total"], 1)
        self.assertEqual(L.query_logs({"keyword": "nikto"})["total"], 1)
        self.assertEqual(L.query_logs({"keyword": "nothing-here"})["total"], 0)

    def test_types_aggregation(self):
        res = L.query_logs({"p": 1, "rows": 200})
        got = dict((t["module"], t["count"]) for t in res["types"])
        # action=cc / blacklist 按 action 归入对应模块（真机口径）
        self.assertEqual(got, {"sqli": 1, "xss": 1, "cc": 1, "blacklist": 1})
        names = dict((t["module"], t["name"]) for t in res["types"])
        self.assertEqual(names["sqli"], "SQL 注入")
        self.assertEqual(names["cc"], "CC 攻击")
        self.assertEqual(names["blacklist"], "黑名单")
        self.assertTrue(all("_module" not in r for r in res["list"]))

    def test_empty_log(self):
        os.remove(P.WAF_LOG)
        res = L.query_logs({})
        self.assertEqual(res["total"], 0)
        self.assertEqual(res["list"], [])
        self.assertEqual(res["types"], [])

    def test_limited_window(self):
        write_lines(P.WAF_LOG, make_waf_records() * 275)  # 1100 条
        res = L.query_logs({"p": 1, "rows": 1})
        self.assertTrue(res["limited"])
        self.assertEqual(res["total"], 1020)  # window = 1*1*20 + 1000


class StatTrendTest(BaseCase):
    def setUp(self):
        super().setUp()
        write_lines(P.WAF_LOG, make_waf_records())
        self.today = U.date_str()
        self.yesterday = U.date_str(U.now() - 86400)
        write_lines(
            os.path.join(P.LOG_DIR, "waf-%s.log" % self.yesterday.replace("-", "")),
            make_waf_records()[:2],
        )

    def test_stat_for_date(self):
        st = L.stat_for_date(self.today)
        self.assertEqual(st["total"], 4)
        self.assertEqual(st["blocks"], 3)  # 非 allow：block + cc + blacklist
        self.assertEqual(st["allowed"], 1)  # action=allow
        self.assertEqual(st["cc"], 1)
        got = dict((t["module"], t["count"]) for t in st["types"])
        self.assertEqual(got, {"sqli": 1, "xss": 1, "cc": 1, "blacklist": 1})
        sites = dict((s["site"], s["count"]) for s in st["sites"])
        self.assertEqual(sites, {"a.com": 3, "b.com": 1})
        ips = dict((i["ip"], i["count"]) for i in st["ips"])
        self.assertEqual(ips["1.1.1.1"], 2)
        # 站点过滤
        b = L.stat_for_date(self.today, "b.com")
        self.assertEqual(b["total"], 1)
        self.assertEqual(b["blocks"], 1)
        self.assertEqual(b["allowed"], 0)
        # 指定历史日期（block + cc 两条，均非 allow）
        old = L.stat_for_date(self.yesterday)
        self.assertEqual(old["total"], 2)
        self.assertEqual(old["blocks"], 2)
        self.assertEqual(old["allowed"], 0)

    def test_trend(self):
        tr = L.trend(2)
        self.assertEqual(len(tr), 2)
        self.assertEqual(tr[0]["date"], self.yesterday)
        self.assertEqual(tr[1]["date"], self.today)
        self.assertEqual(tr[0]["blocks"], 2)  # block + cc（非 allow）
        self.assertEqual(tr[0]["cc"], 1)
        self.assertEqual(tr[1]["blocks"], 3)  # 排除 action=allow 的那条
        self.assertEqual(tr[1]["cc"], 1)
        self.assertEqual(len(L.trend(7)), 7)

    def test_available_days_recent_and_tops(self):
        days = L.available_days()
        self.assertIn(self.today, days)
        self.assertIn(self.yesterday, days)
        rec = L.recent(2)
        self.assertEqual([r["time"] for r in rec], [400, 300])
        uris = [t["uri"] for t in L.top_urls(self.today, 3)]
        self.assertEqual(len(uris), 3)
        self.assertIn("/x.php", uris)  # 每个 uri 各 1 次，稳定排序保留首次出现顺序
        ips = L.top_ips(self.today, 10, lambda ip: {"country": {"names": {"zh-CN": "中国"}}})
        self.assertTrue(all(i["area"] == "中国" for i in ips))

    def test_site_hit_counts(self):
        counts, last = L.site_hit_counts(self.today)
        # 只统计非 allow：a.com = block + blacklist，b.com = cc
        self.assertEqual(counts["a.com"], 2)
        self.assertEqual(counts["b.com"], 1)
        self.assertNotIn("", counts)
        # last_hit 仍是任意命中（含 allow）
        self.assertEqual(last["a.com"], 400)
        self.assertEqual(last["b.com"], 200)


class BlockListTest(BaseCase):
    """封锁记录状态推导（CONTRACT §5）。

    block.log / unban.log 走 logs._tail_raw + parse_block_record/parse_unban_record，
    与 WAF 日志（§4）的 normalize_record 分离，避免 expire/reason 被裁剪。
    """

    def setUp(self):
        super().setUp()
        now = U.now()
        self.now = now
        write_lines(
            P.BLOCK_LOG,
            [
                {"time": now - 100, "ip": "1.1.1.1", "site": "a.com", "reason": "cc",
                 "expire": now + 3600, "block_time": 300},
                {"time": now - 200, "ip": "2.2.2.2", "site": "a.com", "reason": "attack",
                 "expire": now - 50, "block_time": 300},
                {"time": now - 300, "ip": "3.3.3.3", "site": "b.com", "reason": "attack",
                 "expire": now + 3600, "block_time": 86400},
            ],
        )
        write_lines(P.UNBAN_LOG, [{"time": now - 150, "ip": "3.3.3.3", "site": "b.com"}])

    def _states(self, res):
        return dict(((i["ip"], i["site"]), i["state"]) for i in res["list"])

    def test_current(self):
        res = L.block_list({"status": "current"})
        self.assertEqual(res["status"], "current")
        self.assertEqual(res["window"], 5000)
        self.assertEqual(res["total"], 1)
        item = res["list"][0]
        self.assertEqual(item["state"], "blocked")
        self.assertEqual(item["ip"], "1.1.1.1")
        self.assertEqual(item["reason"], "cc")
        self.assertEqual(item["unban_time"], 0)
        self.assertEqual(item["area"], "")

    def test_history(self):
        res = L.block_list({"status": "history"})
        self.assertEqual(res["total"], 2)
        states = self._states(res)
        self.assertEqual(states[("2.2.2.2", "a.com")], "expired")
        self.assertEqual(states[("3.3.3.3", "b.com")], "unbanned")
        unbanned = [i for i in res["list"] if i["state"] == "unbanned"][0]
        self.assertEqual(unbanned["unban_time"], self.now - 150)

    def test_all_and_site_filter_and_pagination(self):
        res = L.block_list({"status": "all"})
        self.assertEqual(res["total"], 3)
        states = self._states(res)
        self.assertEqual(states[("1.1.1.1", "a.com")], "blocked")
        self.assertEqual(states[("2.2.2.2", "a.com")], "expired")
        self.assertEqual(states[("3.3.3.3", "b.com")], "unbanned")
        self.assertEqual([i["ip"] for i in res["list"]], ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual(L.block_list({"site": "a.com", "status": "all"})["total"], 2)
        self.assertEqual(L.block_list({"site": "b.com", "status": "all"})["total"], 1)
        page2 = L.block_list({"status": "all", "p": 2, "rows": 1})
        self.assertEqual(page2["total"], 3)
        self.assertEqual(len(page2["list"]), 1)
        self.assertEqual(page2["list"][0]["ip"], "2.2.2.2")
        # 非法 status 回退 current
        self.assertEqual(L.block_list({"status": "bogus"})["status"], "current")

    def test_newer_block_overrides_older(self):
        now = self.now
        write_lines(
            P.BLOCK_LOG,
            [
                {"time": now - 900, "ip": "5.5.5.5", "site": "a.com", "expire": now - 800, "block_time": 60},
                {"time": now - 10, "ip": "5.5.5.5", "site": "a.com", "expire": now + 300, "block_time": 60},
            ],
        )
        res = L.block_list({"status": "current"})
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["list"][0]["time"], now - 10)

    def test_empty(self):
        for p in (P.BLOCK_LOG, P.UNBAN_LOG):
            if os.path.isfile(p):
                os.remove(p)
        res = L.block_list({})
        self.assertEqual(res["total"], 0)
        self.assertEqual(res["list"], [])

    def test_unban(self):
        L.unban("9.9.9.9", "a.com")
        recs = read_lines_json(P.UNBAN_LOG)
        self.assertEqual(recs[-1]["ip"], "9.9.9.9")
        self.assertEqual(recs[-1]["site"], "a.com")
        self.assertEqual(recs[-1]["reason"], "manual")
        self.assertGreater(recs[-1]["time"], 0)
        with self.assertRaises(ValueError):
            L.unban("not-an-ip")
        with self.assertRaises(ValueError):
            L.unban("")

    def test_unban_all(self):
        self.assertEqual(L.block_list({"status": "current"})["total"], 1)
        count = L.unban_all("")
        self.assertEqual(count, 1)
        self.assertEqual(L.block_list({"status": "current"})["total"], 0)
        self.assertEqual(len(read_lines_json(P.UNBAN_LOG)), 2)

    def test_area_lookup(self):
        def lookup(ip):
            return {"country": {"names": {"zh-CN": "美国", "en": "US"}}, "city": {"names": {"zh-CN": "加州"}}}

        res = L.block_list({"status": "all"}, lookup)
        self.assertEqual(res["list"][0]["area"], "美国-US-加州")


# ---------------------------------------------------------------------------
# 8) 面板系统防火墙
# ---------------------------------------------------------------------------
class PanelFirewallTest(BaseCase):
    class FakeM(object):
        def __init__(self, rows):
            self.rows = rows

        def select(self):
            return [dict(row) for row in self.rows]

    class FakePublic(object):
        def __init__(self, rows):
            self.rows = rows

        def M(self, name):
            return PanelFirewallTest.FakeM(self.rows)

    class FakeModule(object):
        calls = []

        class firewalls(object):
            def GetList(self):
                PanelFirewallTest.FakeModule.calls.append("GetList")

            def DelDropAddress(self, get):
                PanelFirewallTest.FakeModule.calls.append((get.id, get.port))
                return {"status": True}

    def setUp(self):
        super().setUp()
        self.rows = [
            {"id": 1, "port": "1.2.3.4", "ps": "手动", "addtime": "2026-11-19"},
            {"id": 2, "port": "80", "ps": "", "addtime": ""},
            {"id": 3, "port": "39000-40000", "ps": "", "addtime": ""},
            {"id": 4, "port": "5.6.7.0/24", "ps": "", "addtime": ""},
            {"id": 5, "port": "1.2.3.4", "ps": "重复", "addtime": ""},
        ]
        type(self).FakeModule.calls = []

    def test_list_filters_ports_and_duplicates(self):
        result = F.PanelFirewall(self.FakePublic(self.rows)).list_blocked()
        self.assertTrue(result["available"])
        self.assertEqual(result["source"], "panel-firewall")
        self.assertEqual([x["ip"] for x in result["list"]], ["1.2.3.4", "5.6.7.0/24"])

    def test_list_sync_calls_panel_firewalls(self):
        with mock.patch.object(F, "_load_firewalls", return_value=self.FakeModule):
            result = F.PanelFirewall(self.FakePublic(self.rows)).list_blocked(sync=True)
        self.assertTrue(result["available"])
        self.assertEqual(self.FakeModule.calls, ["GetList"])

    def test_unban_calls_panel_del_drop_address(self):
        with mock.patch.object(F, "_load_firewalls", return_value=self.FakeModule):
            result = F.PanelFirewall(self.FakePublic(self.rows)).unban("1.2.3.4")
        self.assertTrue(result["ok"])
        self.assertEqual(self.FakeModule.calls, [(1, "1.2.3.4")])

    def test_unban_missing_ip_does_not_call_panel(self):
        with mock.patch.object(F, "_load_firewalls", return_value=self.FakeModule):
            result = F.PanelFirewall(self.FakePublic(self.rows)).unban("9.9.9.9")
        self.assertFalse(result["ok"])
        self.assertEqual(self.FakeModule.calls, [])

    def test_unavailable_without_public(self):
        with mock.patch.object(F, "_default_public", return_value=None):
            result = F.PanelFirewall().list_blocked()
        self.assertFalse(result["available"])
        self.assertEqual(result["list"], [])

    def test_unban_rejects_invalid_ip_without_panel(self):
        with mock.patch.object(F, "_load_firewalls") as fake:
            result = F.PanelFirewall(self.FakePublic(self.rows)).unban("not-an-ip")
        self.assertFalse(result["ok"])
        fake.assert_not_called()


# ---------------------------------------------------------------------------
# 9) sites.sync（fake db）
# ---------------------------------------------------------------------------
class SitesSyncTest(BaseCase):
    def test_sync_rebuilds_hosts_and_fills_sites(self):
        C.save_sites({"www.example.com": C.clean_site({"open": False})})
        res = S.sync(make_sites_db())
        self.assertEqual(res["sites"], 2)
        self.assertEqual(res["added"], 1)
        hosts = C.load_hosts()
        self.assertEqual(hosts["www.example.com"], "www.example.com")
        self.assertEqual(hosts["api.example.com"], "www.example.com")
        self.assertEqual(hosts["shop.example.com"], "www.example.com")  # 端口被剥离
        self.assertEqual(hosts["m.example.com"], "m.example.com")
        self.assertEqual(len(hosts), 4)
        self.assertEqual(res["hosts"], 4)
        sites = C.load_sites()
        self.assertEqual(set(sites.keys()), {"www.example.com", "m.example.com"})
        self.assertIs(sites["www.example.com"]["open"], False)  # 已有配置保留
        self.assertIs(sites["m.example.com"]["open"], True)  # 新站点默认开启

    def test_sync_wildcard_registers_apex(self):
        db = FakeDB(
            {
                "sites": [{"id": 9, "name": "www.ca.com", "path": "/www/wwwroot/c", "status": 1}],
                "domain": [{"pid": 9, "name": "*.ca.com", "port": 80}],
            }
        )
        S.sync(db)
        hosts = C.load_hosts()
        self.assertEqual(hosts["*.ca.com"], "www.ca.com")
        self.assertEqual(hosts["ca.com"], "www.ca.com")
        self.assertEqual(hosts["www.ca.com"], "www.ca.com")

    def test_sync_write_false_does_not_touch_files(self):
        res = S.sync(make_sites_db(), write=False)
        self.assertEqual(res["sites"], 2)
        self.assertFalse(os.path.isfile(P.HOSTS_CONFIG))
        self.assertFalse(os.path.isfile(P.SITE_CONFIG))

    def test_fetch_fallback_when_field_unsupported(self):
        sites = S.list_sites(make_sites_db(raise_on_field=True))
        self.assertEqual([s["site_name"] for s in sites], ["m.example.com", "www.example.com"])
        self.assertIn("www.example.com", sites[1]["domains"])

    def test_list_sites_and_lookup(self):
        sites = S.list_sites(make_sites_db())
        self.assertEqual([s["site_name"] for s in sites], ["m.example.com", "www.example.com"])
        self.assertEqual(sites[1]["domains"][0], "www.example.com")
        self.assertEqual(S.site_names(make_sites_db()), ["m.example.com", "www.example.com"])
        self.assertEqual(S.site_by_name(make_sites_db(), "www.example.com")["path"], "/www/wwwroot/a")
        self.assertIsNone(S.site_by_name(make_sites_db(), ""))
        self.assertIsNone(S.site_by_name(make_sites_db(), "nope.com"))

    def test_ensure_site_raises(self):
        db = make_sites_db()
        self.assertEqual(S.ensure_site(db, "www.example.com"), "www.example.com")
        with self.assertRaises(ValueError):
            S.ensure_site(db, "nope.com")

    def test_db_failure_returns_empty(self):
        class BadDB(object):
            def __call__(self, table):
                raise RuntimeError("db down")

        self.assertEqual(S.list_sites(BadDB()), [])
        self.assertEqual(S.sync(BadDB(), write=False)["sites"], 0)


# ---------------------------------------------------------------------------
# 9) rules：index.json 优先 / 扫描兜底 / 过滤与排除
# ---------------------------------------------------------------------------
class RulesIndexTest(BaseCase):
    def _write_data_index(self):
        return write_json(
            P.RULES_INDEX,
            {
                "crs_version": "4.9.9",
                "generated_at": 111,
                "skipped": [{"id": "crs-920999", "reason": "unsupported ctl"}],
                "rules": [
                    {"id": "crs-942100", "module": "sqli", "name": "SQLi", "tier": 1, "score": 5, "src": "crs"},
                    {"id": "ce-sqli-001", "module": "sqli", "name": "UNION", "tier": 2, "score": 5, "src": "ce"},
                    {"id": "crs-941100", "module": "xss", "name": "XSS", "tier": 3, "score": 4, "src": "crs"},
                ],
            },
        )

    def test_data_index_preferred(self):
        self._write_data_index()
        idx = R.load_index()
        self.assertEqual(idx["crs_version"], "4.9.9")
        self.assertEqual(len(idx["rules"]), 3)
        self.assertNotIn("_fallback", idx)
        info = R.version_info()
        self.assertEqual(info["crs_version"], "4.9.9")
        self.assertEqual(info["generated_at"], 111)
        self.assertFalse(info["fallback_scan"])

    def test_missing_index_falls_back_to_scan(self):
        write_text = (
            'return {\n'
            '  meta = {module="sqli", source="ce", version="test"},\n'
            '  rules = {\n'
            '    { id = "ce-sqli-001", module = "sqli", tier = 1, score = 5, '
            'name = "UNION SELECT 联合查询", chain = {} },\n'
            '    { id = "crs-999999", module = "xss", tier = 2, score = 4, '
            'name = "XSS test", chain = {} },\n'
            '  },\n'
            '}\n'
        )
        write_lines(os.path.join(DATA_DIR, "lua", "rules", "base.lua"), [write_text])
        with mock.patch.object(R, "_index_paths", return_value=[]):
            idx = R.load_index()
            self.assertTrue(idx.get("_fallback"))
            self.assertEqual(idx["rules"], [])
            info = R.version_info()
            self.assertTrue(info["fallback_scan"])
            rules = R.all_rules()
        by_id = dict((r["id"], r) for r in rules)
        self.assertIn("ce-sqli-001", by_id)
        self.assertIn("crs-999999", by_id)
        self.assertEqual(by_id["ce-sqli-001"]["module"], "sqli")
        self.assertEqual(by_id["ce-sqli-001"]["name"], "UNION SELECT 联合查询")
        self.assertEqual(by_id["ce-sqli-001"]["src"], "ce")
        self.assertEqual(by_id["crs-999999"]["src"], "crs")
        self.assertEqual(by_id["crs-999999"]["tier"], 2)

    def test_scan_lua_rules_direct(self):
        root = os.path.join(_TMP_ROOT, "scan_root")
        write_lines(
            os.path.join(root, "sub", "x.lua"),
            ['return { rules = { { id = "ce-xss-007", module = "xss", tier = 3, score = 3, name = "X" } } }'],
        )
        # 被排除的文件
        write_lines(os.path.join(root, "ac.lua"), ['{ id = "should-skip" }'])
        found = R._scan_lua_rules(root)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["id"], "ce-xss-007")
        self.assertEqual(found[0]["tier"], 3)
        self.assertEqual(R._scan_lua_rules(os.path.join(root, "nope")), [])

    def test_get_rules_filters_and_enabled(self):
        self._write_data_index()
        res = R.get_rules({})
        self.assertEqual(res["total"], 3)
        self.assertEqual(res["crs_version"], "4.9.9")
        self.assertEqual(res["skipped"], [{"id": "crs-920999", "reason": "unsupported ctl"}])
        self.assertEqual(
            [r["id"] for r in res["list"]],
            ["ce-sqli-001", "crs-942100", "crs-941100"],  # 排序键 (module, src, id)
        )
        enabled = dict((r["id"], r["enabled"]) for r in res["list"])
        self.assertIs(enabled["crs-942100"], True)  # tier1 <= sensitivity2
        self.assertIs(enabled["ce-sqli-001"], True)  # tier2
        self.assertIs(enabled["crs-941100"], False)  # tier3 > sensitivity2
        self.assertEqual(R.get_rules({"module": "sqli"})["total"], 2)
        self.assertEqual(R.get_rules({"source": "crs"})["total"], 2)
        self.assertEqual(R.get_rules({"keyword": "942100"})["total"], 1)
        page2 = R.get_rules({"rows": 1, "p": 2})
        self.assertEqual(page2["total"], 3)
        self.assertEqual(len(page2["list"]), 1)
        self.assertEqual(page2["list"][0]["id"], "crs-942100")

    def test_get_rules_tier_follows_sensitivity(self):
        self._write_data_index()
        C.save_global({"sensitivity": 1})
        res = R.get_rules({})
        enabled = dict((r["id"], r["enabled"]) for r in res["list"])
        self.assertIs(enabled["crs-942100"], True)  # tier1
        self.assertIs(enabled["ce-sqli-001"], False)  # tier2 > 1
        C.save_global({"sensitivity": 3})
        enabled = dict((r["id"], r["enabled"]) for r in R.get_rules({})["list"])
        self.assertIs(enabled["crs-941100"], True)

    def test_custom_rules_merged_and_excluded(self):
        self._write_data_index()
        write_json(
            P.CUSTOM_RULES,
            {"rules": [{"id": "custom-1", "name": "拦截 sqlmap", "value": "sqlmap",
                        "operator": "contains", "field": "ua", "action": "block"}]},
        )
        rules = R.all_rules()
        custom = [r for r in rules if r["src"] == "custom"]
        self.assertEqual(len(custom), 1)
        self.assertEqual(custom[0]["module"], "custom")
        self.assertIn("custom-1", [r["id"] for r in R.get_rules({"source": "custom"})["list"]])
        # 排除后 enabled=False
        R.set_rule_exclude("global", "", "crs", ["crs-942100"])
        res = R.get_rules({})
        enabled = dict((r["id"], r["enabled"]) for r in res["list"])
        self.assertIs(enabled["crs-942100"], False)
        self.assertEqual(U.read_json(P.GLOBAL_CONFIG)["rule_exclude"]["crs"], ["crs-942100"])
        self.assertGreater(ST.get_apply_time(), 0)

    def test_set_rule_exclude_validation(self):
        with self.assertRaises(ValueError):
            R.set_rule_exclude("global", "", "bad", [])
        with self.assertRaises(ValueError):
            R.set_rule_exclude("global", "", "crs", "not-a-list")
        with self.assertRaises(ValueError):
            R.set_rule_exclude("site", "", "crs", [])
        with self.assertRaises(ValueError):
            R.set_rule_exclude("site", "nope.com", "crs", [])
        write_sites = {"a.com": C.clean_site({})}
        C.save_sites(write_sites)
        res = R.set_rule_exclude("site", "a.com", "ce", ["ce-1", "ce-1", ""])
        self.assertEqual(res["count"], 1)
        self.assertEqual(C.load_sites()["a.com"]["rule_exclude"]["ce"], ["ce-1"])

    def test_modules_meta(self):
        self._write_data_index()
        meta = R.modules_meta()
        self.assertEqual(set(meta.keys()), set(C.MODULE_KEYS))
        self.assertEqual(meta["sqli"]["total"], 2)
        self.assertEqual(meta["xss"]["total"], 1)
        self.assertIs(meta["xss"]["enabled"], 0)
        for key in meta:
            self.assertIn("open", meta[key])
            self.assertIn("tier", meta[key])


# ---------------------------------------------------------------------------
# 10) engine：无 nginx 环境下的 status / check_env 容错
# ---------------------------------------------------------------------------
class EngineStatusTest(BaseCase):
    def test_status_without_nginx(self):
        st = E.status()
        self.assertIsInstance(st, dict)
        for key in (
            "version", "ready", "enabled", "observe", "sensitivity", "nginx",
            "dirs", "lua_files", "rules", "config_apply_at", "last_reload",
            "errors", "perf",
        ):
            self.assertIn(key, st, key)
        self.assertEqual(st["version"], P.VERSION)
        self.assertIs(st["ready"], False)
        self.assertIs(st["enabled"], True)
        self.assertIs(st["observe"], False)
        self.assertEqual(st["sensitivity"], 2)
        self.assertIsInstance(st["nginx"], dict)
        for key in ("bin", "exists", "lua", "conf_path", "conf_exists", "conf_ok", "conf_hash_ok"):
            self.assertIn(key, st["nginx"], key)
        self.assertIs(st["nginx"]["exists"], False)
        self.assertIs(st["nginx"]["lua"], False)
        self.assertIs(st["nginx"]["conf_exists"], False)
        self.assertIsInstance(st["dirs"], dict)
        for key in ("data", "lua", "rule", "logs", "data_dir_data"):
            self.assertIsInstance(st["dirs"][key], bool)
        self.assertIsInstance(st["dirs"]["writable"], bool)
        self.assertIsInstance(st["lua_files"], int)
        self.assertIsInstance(st["rules"], dict)
        for key in ("crs_version", "total", "by_src", "skipped", "skipped_count", "generated_at", "index_ok"):
            self.assertIn(key, st["rules"], key)
        self.assertEqual(set(st["rules"]["by_src"].keys()), {"crs", "ce", "custom"})
        self.assertIsInstance(st["errors"], list)
        self.assertIsInstance(st["perf"], dict)
        for key in ("requests", "hits", "avg_ms"):
            self.assertIn(key, st["perf"], key)

    def test_check_env_without_nginx(self):
        res = E.check_env()
        self.assertIsInstance(res, dict)
        self.assertIn("items", res)
        self.assertIn("repairable", res)
        items = res["items"]
        self.assertIsInstance(items, list)
        self.assertGreater(len(items), 0)
        names = []
        for item in items:
            self.assertIsInstance(item, dict)
            self.assertIn("name", item)
            self.assertIn("ok", item)
            self.assertIn("detail", item)
            self.assertIsInstance(item["name"], str)
            self.assertIsInstance(item["ok"], bool)
            self.assertIsInstance(item["detail"], str)
            self.assertIn("repairable", item)
            self.assertIsInstance(item["repairable"], bool)
            names.append(item["name"])
        for required in (
            "Nginx 可执行文件",
            "Nginx Lua 模块",
            "Nginx 配置文件",
            "全局配置可解析",
            "数据目录",
            "运行期 Lua 目录",
            "日志目录",
            "数据目录可写",
            "规则索引",
            "nginx -t 通过",
        ):
            self.assertIn(required, names)
        self.assertIsInstance(res["repairable"], bool)
        self.assertEqual(res["repairable"], res["needs_repair"])
        self.assertIn("manual_required", res)
        self.assertIn("all_ok", res)
        self.assertIsInstance(res["all_ok"], bool)
        self.assertIsInstance(res["manual_required"], bool)
        by_name = dict((i["name"], i) for i in items)
        self.assertIs(by_name["Nginx 可执行文件"]["ok"], False)
        self.assertIs(by_name["Nginx Lua 模块"]["ok"], False)

    def test_conf_write_status_and_hash(self):
        E.write_conf()
        st = E.conf_status()
        self.assertTrue(st["exists"])
        self.assertTrue(st["hash_ok"])
        self.assertEqual(E.read_conf(), P.CONF_TEXT)
        # 篡改后哈希不一致
        U.write_text(P.CONF_PATH, "# broken\n")
        st2 = E.conf_status()
        self.assertTrue(st2["exists"])
        self.assertFalse(st2["hash_ok"])
        E.remove_conf()
        self.assertFalse(E.conf_status()["exists"])

    def test_dirs_status_probe(self):
        S.default_data_files()
        dirs = E.dirs_status()
        self.assertIs(dirs["writable"], True)
        self.assertIs(dirs["data"], True)
        self.assertFalse(os.path.isfile(os.path.join(DATA_DIR, "data", ".write_probe")))

    def test_read_perf_and_block_page(self):
        self.assertEqual(E.read_perf()["requests"], 0)
        write_json(P.PERF_FILE, {"requests": 4, "hits": 2, "total_ms": 8, "updated_at": 5, "errors": 1})
        perf = E.read_perf()
        self.assertEqual(perf["requests"], 4)
        self.assertEqual(perf["hits"], 2)
        self.assertEqual(perf["avg_ms"], 2.0)
        self.assertEqual(perf["errors"], 1)
        res = E.save_block_page('<h1>blocked</h1><script>x</script>', True)
        self.assertTrue(res["saved"])
        self.assertTrue(res["removed"])
        self.assertNotIn("<script", E.read_block_page().lower())
        self.assertIs(C.load_global()["block"]["use_custom"], True)


# ---------------------------------------------------------------------------
# 11) btwaf_ce_main 只读接口（public=None）
# ---------------------------------------------------------------------------
class ControllerReadOnlyTest(BaseCase):
    def setUp(self):
        super().setUp()
        if MAIN.public is not None:
            self.skipTest("面板 public 可用，跳过 public=None 场景")
        self.ctrl = MAIN.btwaf_ce_main()
        self.assertIsNone(self.ctrl.public)

    def _envelope(self, res):
        self.assertIsInstance(res, dict)
        self.assertIn("status", res)
        self.assertIn("msg", res)
        self.assertIn("data", res)
        self.assertIsInstance(res["status"], bool)
        return res

    def test_get_engine_status(self):
        res = self._envelope(self.ctrl.get_engine_status(None))
        self.assertIs(res["status"], True)
        data = res["data"]
        self.assertEqual(data["version"], P.VERSION)
        self.assertIn("nginx", data)
        self.assertIn("rules", data)
        self.assertIn("perf", data)
        self.assertIsInstance(data["perf"]["requests"], int)

    def test_get_overview(self):
        res = self._envelope(self.ctrl.get_overview(None))
        self.assertIs(res["status"], True)
        data = res["data"]
        self.assertEqual(data["date"], U.date_str())
        for key in ("stats", "trend", "types", "top_ips", "top_urls", "recent"):
            self.assertIn(key, data, key)
        for key in ("blocks", "allowed", "cc_blocks", "attack_ips", "sites_total", "sites_open", "requests"):
            self.assertIn(key, data["stats"], key)
        self.assertEqual(len(data["trend"]), 7)
        self.assertIsInstance(data["types"], list)
        self.assertIsInstance(data["top_ips"], list)
        self.assertIsInstance(data["top_urls"], list)
        self.assertIsInstance(data["recent"], list)
        # 显式日期
        res2 = self._envelope(self.ctrl.get_overview({"date": "2000-01-01"}))
        self.assertIs(res2["status"], True)
        self.assertEqual(res2["data"]["date"], "2000-01-01")
        # 非法日期 -> status=false
        res3 = self._envelope(self.ctrl.get_overview({"date": "2026/01/01"}))
        self.assertIs(res3["status"], False)
        self.assertIn("日期", res3["msg"])

    def test_get_sites_requires_db(self):
        res = self._envelope(self.ctrl.get_sites(None))
        self.assertIs(res["status"], False)
        self.assertIn("数据库", res["msg"])
        self.assertIsNone(res["data"])

    def test_get_rules(self):
        res = self._envelope(self.ctrl.get_rules(None))
        self.assertIs(res["status"], True)
        data = res["data"]
        for key in ("list", "total", "page", "rows", "skipped", "crs_version"):
            self.assertIn(key, data, key)
        self.assertIsInstance(data["list"], list)
        self.assertIsInstance(data["total"], int)
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["rows"], 50)
        # 过滤参数（dict 形式）
        res2 = self._envelope(self.ctrl.get_rules({"module": "sqli", "p": "1", "rows": "5"}))
        self.assertIs(res2["status"], True)
        self.assertLessEqual(res2["data"]["rows"], 50)

    def test_get_lists(self):
        res = self._envelope(self.ctrl.get_lists(None))
        self.assertIs(res["status"], True)
        lists = res["data"]["lists"]
        self.assertEqual(
            set(lists.keys()),
            {"ip_black", "ip_white", "url_black", "url_white", "ua_black", "ua_white", "param_white"},
        )
        self.assertEqual(res["data"]["scope"], "global")
        # 站点作用域缺 site_name -> status=false
        res2 = self._envelope(self.ctrl.get_lists({"scope": "site"}))
        self.assertIs(res2["status"], False)

    def test_get_block_list(self):
        res = self._envelope(self.ctrl.get_block_list(None))
        self.assertIs(res["status"], True)
        data = res["data"]
        for key in ("list", "total", "page", "rows", "status", "window"):
            self.assertIn(key, data, key)
        self.assertEqual(data["status"], "current")
        self.assertEqual(data["window"], 5000)
        self.assertEqual(data["total"], 0)
        res2 = self._envelope(self.ctrl.get_block_list({"status": "all", "p": "1", "rows": "10"}))
        self.assertIs(res2["status"], True)
        self.assertEqual(res2["data"]["status"], "all")

    def test_get_custom_rules(self):
        res = self._envelope(self.ctrl.get_custom_rules(None))
        self.assertIs(res["status"], True)
        data = res["data"]
        for key in ("list", "total", "page", "rows"):
            self.assertIn(key, data, key)
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["list"], [])

    def test_write_methods_guarded_without_public(self):
        # unban_ip 参数非法 -> status=false，不抛异常
        res = self._envelope(self.ctrl.unban_ip({"ip": "not-an-ip"}))
        self.assertIs(res["status"], False)
        # 缺少 id
        res2 = self._envelope(self.ctrl.del_custom_rule(None))
        self.assertIs(res2["status"], False)
        self.assertIn("ID", res2["msg"])
        # sync_sites 依赖面板 DB
        res3 = self._envelope(self.ctrl.sync_sites(None))
        self.assertIs(res3["status"], False)

    def test_check_env_and_index(self):
        res = self._envelope(self.ctrl.check_env(None))
        self.assertIs(res["status"], True)
        self.assertIn("items", res["data"])
        self.assertIsInstance(res["data"]["repairable"], bool)
        idx = self._envelope(self.ctrl.index(None))
        self.assertIs(idx["status"], True)
        self.assertEqual(idx["data"]["version"], P.VERSION)

    def test_preview_block_page(self):
        # QA-3：API.md 约定返回 intercepted（实现同时保留 removed）
        res = self._envelope(self.ctrl.preview_block_page({"html": "<script>x</script><p>hi</p>"}))
        self.assertIs(res["status"], True)
        data = res["data"]
        self.assertIn("html", data)
        self.assertIn("intercepted", data)
        self.assertIn("removed", data)
        self.assertEqual(data["intercepted"], data["removed"])
        self.assertTrue(data["intercepted"])
        self.assertNotIn("<script", data["html"].lower())
        # save_block_page 落盘 + 配置生效
        saved = self._envelope(self.ctrl.save_block_page({"html": "<h1>blocked</h1>"}))
        self.assertIs(saved["status"], True)
        self.assertTrue(os.path.isfile(P.BLOCK_PAGE))
        self.assertIn("blocked", E.read_block_page())


# ---------------------------------------------------------------------------
# 11) P0：范围、响应码、面板 CDN、操作日志筛选
# ---------------------------------------------------------------------------
class FirewallControllerTest(BaseCase):
    class FakeClient(object):
        def __init__(self, ips):
            self.ips = list(ips)
            self.unbanned = []

        def list_blocked(self, sync=None):
            return {
                "available": True,
                "source": "test",
                "list": [{"ip": ip, "ps": "", "addtime": ""} for ip in self.ips],
                "total": len(self.ips),
                "error": "",
            }

        def unban(self, ip):
            self.unbanned.append(ip)
            return {"ok": True, "error": ""}

        def unban_many(self, ips):
            for ip in ips:
                self.unbanned.append(ip)
            return {"unbanned": len(ips), "errors": []}

    def setUp(self):
        super().setUp()
        if MAIN.public is not None:
            self.skipTest("面板 public 可用，跳过 public=None 场景")
        self.ctrl = MAIN.btwaf_ce_main()
        now = U.now()
        write_lines(
            P.BLOCK_LOG,
            [
                {"time": now - 10, "ip": "1.1.1.1", "site": "a.com", "expire": now + 300, "block_time": 60},
                {"time": now - 20, "ip": "2.2.2.2", "site": "b.com", "expire": now + 300, "block_time": 60},
            ],
        )

    def _envelope(self, res):
        self.assertIsInstance(res, dict)
        self.assertIn("status", res)
        self.assertIn("data", res)
        return res

    def test_block_list_marks_system_ips(self):
        fake = self.FakeClient(["1.1.1.1"])
        with mock.patch.object(F, "DEFAULT_CLIENT", fake):
            data = self._envelope(self.ctrl.get_block_list(None))["data"]
        self.assertEqual(data["system"]["sync_count"], 1)
        tagged = [item for item in data["list"] if item["system_blocked"]]
        self.assertEqual([item["ip"] for item in tagged], ["1.1.1.1"])

    def test_system_firewall_endpoint(self):
        fake = self.FakeClient(["1.1.1.1"])
        with mock.patch.object(F, "DEFAULT_CLIENT", fake):
            data = self._envelope(self.ctrl.get_system_firewall(None))["data"]
        self.assertTrue(data["available"])
        self.assertEqual(data["list"][0]["ip"], "1.1.1.1")

    def test_unban_sync_system(self):
        fake = self.FakeClient(["1.1.1.1"])
        with mock.patch.object(F, "DEFAULT_CLIENT", fake):
            data = self._envelope(self.ctrl.unban_ip({"ip": "1.1.1.1", "sync_system": "1"}))["data"]
        self.assertEqual(data["system_unbanned"], 1)
        self.assertEqual(fake.unbanned, ["1.1.1.1"])

    def test_unban_without_sync_does_not_touch_system(self):
        fake = self.FakeClient(["1.1.1.1"])
        with mock.patch.object(F, "DEFAULT_CLIENT", fake):
            data = self._envelope(self.ctrl.unban_ip({"ip": "1.1.1.1"}))["data"]
        self.assertEqual(data["system_unbanned"], 0)
        self.assertEqual(fake.unbanned, [])

    def test_unban_all_sync_only_intersection(self):
        fake = self.FakeClient(["1.1.1.1"])
        with mock.patch.object(F, "DEFAULT_CLIENT", fake):
            data = self._envelope(self.ctrl.unban_all({"sync_system": "1"}))["data"]
        self.assertEqual(data["unbanned"], 2)
        self.assertEqual(data["system_unbanned"], 1)
        self.assertEqual(fake.unbanned, ["1.1.1.1"])

    def test_unban_system_ip_and_all(self):
        fake = self.FakeClient(["1.1.1.1", "2.2.2.2"])
        with mock.patch.object(F, "DEFAULT_CLIENT", fake):
            one = self._envelope(self.ctrl.unban_system_ip({"ip": "1.1.1.1"}))["data"]
            all_res = self._envelope(self.ctrl.unban_system_all(None))["data"]
        self.assertEqual(one["unbanned"], 1)
        self.assertEqual(all_res["unbanned"], 2)


class P0RangeAndStatusTest(BaseCase):
    def test_ip_range_validation_and_lists(self):
        self.assertTrue(U.valid_ip_range("1.2.3.4-1.2.3.10"))
        self.assertTrue(U.valid_ip_range(" 1.2.3.4 - 1.2.3.4 "))
        self.assertFalse(U.valid_ip_range("1.2.3.10-1.2.3.4"))
        self.assertFalse(U.valid_ip_range("1.2.3.4-::1"))
        self.assertFalse(U.valid_ip_range("1.2.3.4"))
        self.assertEqual(C.clean_lists({"ip_black": ["1.2.3.4-1.2.3.10", "bad", "10.0.0.0/8"]})["ip_black"],
                         ["1.2.3.4-1.2.3.10", "10.0.0.0/8"])
        self.assertEqual(C.clean_trusted(["1.2.3.4-1.2.3.10", "bad"]), ["1.2.3.4-1.2.3.10"])

    def test_site_block_and_rule_status_merge(self):
        site = C.clean_site({"block": {"status": 404}, "rule_status": {"crs-1": 403}})
        self.assertEqual(site["block"], {"status": 404})
        self.assertEqual(site["rule_status"], {"crs-1": 403})
        g = C.clean_global({"block": {"status": 403}, "rule_status": {"crs-1": 404, "x": 200}})[0]
        eff = C.effective_site(g, site)
        self.assertEqual(eff["block"]["status"], 404)
        self.assertEqual(eff["rule_status"], {"crs-1": 403})
        self.assertEqual(C.clean_site({"block": {"status": 0}})["block"]["status"], 0)

    def test_rule_status_api(self):
        rule_id = R.all_rules()[0]["id"]
        R.set_rule_status("global", "", rule_id, 404)
        self.assertEqual(C.load_global()["rule_status"][rule_id], 404)
        rows = R.get_rules({"scope": "global", "keyword": rule_id})["list"]
        target = [r for r in rows if r["id"] == rule_id]
        self.assertTrue(target)
        self.assertEqual(target[0]["status_override"], 404)
        R.set_rule_status("global", "", rule_id, 0)
        self.assertNotIn(rule_id, C.load_global()["rule_status"])


class P0PanelCdnTest(BaseCase):
    def set_realip(self, path, header="X-Forwarded-For", trusted="0.0.0.0/0"):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("set_real_ip_from %s;\nreal_ip_header %s;\nreal_ip_recursive on;\n" % (trusted, header))

    def test_panel_cdn_global_and_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            global_file = os.path.join(tmp, "real_cdn_ip.conf")
            ext_dir = os.path.join(tmp, "extension")
            with mock.patch.object(N, "PANEL_CDN_GLOBAL", global_file), \
                    mock.patch.object(N, "PANEL_CDN_EXT_DIR", ext_dir):
                self.assertFalse(N.panel_cdn_status()["open"])
                self.set_realip(global_file)
                g = N.panel_cdn_status("example.com")
                self.assertTrue(g["open"])
                self.assertEqual(g["scope"], "global")
                self.assertEqual(g["header"], "X-Forwarded-For")
                self.set_realip(os.path.join(ext_dir, "example.com", "proxy_real_ip.conf"), "CF-Connecting-IP")
                s = N.panel_cdn_status("example.com")
                self.assertEqual(s["scope"], "site")
                self.assertEqual(s["header"], "CF-Connecting-IP")
                self.assertFalse(N.panel_cdn_status("../bad")["site"])


class P0OperationLogTest(BaseCase):
    def test_get_logs_filters(self):
        ctrl = MAIN.btwaf_ce_main()
        os.makedirs(os.path.dirname(P.PLUGIN_LOG), exist_ok=True)
        with open(P.PLUGIN_LOG, "w", encoding="utf-8") as f:
            f.write("2026-01-02 10:00:00  更新全局配置\n")
            f.write("2026-01-03 10:00:00  更新规则响应码\n")
        d = ctrl.get_logs({"date": "2026-01-03"})
        d = d.get("data", d)
        self.assertEqual(d["total"], 1)
        self.assertIn("规则响应码", d["list"][0]["content"])
        d = ctrl.get_logs({"keyword": "全局配置"})
        d = d.get("data", d)
        self.assertEqual(d["total"], 1)


class GeoConfigTest(BaseCase):
    def test_geo_defaults_and_validation(self):
        cfg = C.clean_global({})[0]
        self.assertEqual(cfg["geo"], {
            "open": False, "mode": "allow", "regions": ["CN"],
            "unknown": "allow", "status": 403,
        })
        cfg, warnings = C.clean_global({"geo": {
            "open": True, "mode": "bad", "regions": ["US"], "unknown": "bad", "status": 200,
        }})
        self.assertEqual(cfg["geo"]["mode"], "allow")
        self.assertEqual(cfg["geo"]["unknown"], "allow")
        self.assertEqual(cfg["geo"]["status"], 403)
        self.assertEqual(cfg["geo"]["regions"], ["CN"])
        self.assertTrue(warnings)

    def test_site_geo_inherit_and_override(self):
        site = C.clean_site({"geo": {
            "open": True, "mode": "block", "regions": ["CN"], "unknown": "block", "status": 404,
        }})
        self.assertEqual(site["geo"], {
            "open": True, "mode": "block", "regions": ["CN"],
            "unknown": "block", "status": 404,
        })
        global_cfg = C.clean_global({"geo": {
            "open": True, "mode": "allow", "regions": ["CN"], "unknown": "allow", "status": 403,
        }})[0]
        inherited = C.clean_site({"geo": {"open": None}})
        effective = C.effective_site(global_cfg, inherited)
        self.assertEqual(effective["geo"]["open"], True)
        self.assertEqual(effective["geo"]["mode"], "allow")
        self.assertEqual(effective["geo"]["status"], 403)
        disabled = C.effective_site(global_cfg, C.clean_site({"geo": {"open": False}}))
        self.assertEqual(disabled["geo"]["open"], False)

    def test_geo_data_status_and_log_fields(self):
        status = G.status()
        self.assertTrue(status["available"])
        self.assertEqual(status["source"], "DB-IP Lite Country")
        self.assertGreater(status["records"], 1000)
        rec = L.parse_line(json.dumps({
            "time": 1, "ip": "8.8.8.8", "site": "a", "action": "geo",
            "status": 403, "country": "OTHER", "geo_source": "builtin-cn",
            "reason": "仅允许中国大陆访问",
        }, ensure_ascii=False))
        self.assertEqual(rec["country"], "OTHER")
        self.assertEqual(rec["geo_source"], "builtin-cn")
        self.assertEqual(rec["reason"], "仅允许中国大陆访问")


class BlockPageDefaultsTest(BaseCase):
    def test_default_block_page_is_file_backed(self):
        page = E.default_block_page()
        self.assertIn("请求被拦截", page)
        self.assertIn("宝塔WAF社区版", page)
        self.assertIn("提供安全防护", page)
        self.assertIn("https://github.com/makotowu/btwaf-ce", page)
        self.assertNotIn("<script", page.lower())
        self.assertEqual(C.load_global()["block"]["page"], "")
        self.assertEqual(E.status()["default_block_page"], page)
        clean, removed = U.sanitize_block_page(page)
        self.assertEqual(removed, [])
        self.assertEqual(clean, page)

    def test_default_block_page_is_seeded_into_data_dir(self):
        S.default_data_files()
        self.assertTrue(os.path.isfile(P.default_block_page()))
        self.assertIn("github.com/makotowu/btwaf-ce",
                      U.read_text(P.default_block_page(), ""))


# ---------------------------------------------------------------------------
# 12) 汇总入口
# ---------------------------------------------------------------------------
def main():
    print("btwaf_ce 后端单元测试")
    print("  DATA_DIR = %s" % DATA_DIR)
    print("  LOG_DIR  = %s" % LOG_DIR)
    print("  NGINX_BIN(不存在) = %s" % NGINX_BIN)
    print("  Python = %s" % sys.version.split()[0])
    print("-" * 70)
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    total = result.testsRun
    bad = len(result.failures) + len(result.errors)
    skipped = len(result.skipped)
    print("=" * 70)
    print(
        "汇总：共 %d 项，通过 %d，失败/错误 %d，跳过 %d"
        % (total, total - bad - skipped, bad, skipped)
    )
    if result.failures:
        print("失败用例：")
        for case, _tb in result.failures:
            print("  - %s" % case)
    if result.errors:
        print("错误用例：")
        for case, _tb in result.errors:
            print("  - %s" % case)
    print("=" * 70)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
