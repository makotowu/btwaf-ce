# coding: utf-8
"""路径与常量。"""
import hashlib
import os

from .nginx import resolve_paths, resolve_vhost_dir

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 宝塔运行期目录固定；隔离测试通过 mock 这些常量替换路径。
DATA_DIR = "/www/server/btwaf_ce"
LOG_DIR = "/www/wwwlogs/btwaf_ce"
NGINX_BIN, NGINX_CONF, NGINX_INIT = resolve_paths()
VHOST_DIR = resolve_vhost_dir()
CONF_PATH = os.path.join(VHOST_DIR, "btwaf_ce.conf")

GLOBAL_CONFIG = os.path.join(DATA_DIR, "config.json")
SITE_CONFIG = os.path.join(DATA_DIR, "site.json")
HOSTS_CONFIG = os.path.join(DATA_DIR, "hosts.json")
CUSTOM_RULES = os.path.join(DATA_DIR, "rule", "custom.json")
STATE_FILE = os.path.join(DATA_DIR, "data", "state.json")
BLOCK_LOG = os.path.join(DATA_DIR, "data", "block.log")
UNBAN_LOG = os.path.join(DATA_DIR, "data", "unban.log")
PERF_FILE = os.path.join(DATA_DIR, "data", "perf.json")
BLOCK_PAGE = os.path.join(DATA_DIR, "data", "blockpage.html")
PLUGIN_LOG = os.path.join(DATA_DIR, "logs", "plugin.log")
WAF_LOG = os.path.join(LOG_DIR, "waf.log")

PLUGIN_LUA = os.path.join(PLUGIN_DIR, "lua")
PLUGIN_DEFAULTS = os.path.join(PLUGIN_DIR, "defaults")
RUNTIME_LUA_DIR = os.path.join(DATA_DIR, "lua")
RULES_INDEX = os.path.join(RUNTIME_LUA_DIR, "rules", "index.json")

VERSION = "0.1.0"


def _lua_quote(value):
    return '"' + value.replace("\\", "/").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n") + '"'


def write_runtime_paths():
    """由入口读取路径表，避免占用宿主的 init_by_lua / lua_package_path。"""
    from . import util

    text = "return { data_dir = %s, log_dir = %s, lua_dir = %s }\n" % (
        _lua_quote(DATA_DIR), _lua_quote(LOG_DIR), _lua_quote(RUNTIME_LUA_DIR),
    )
    util.atomic_write(os.path.join(RUNTIME_LUA_DIR, "runtime_paths.lua"), text, 0o644)


def _conf_text():
    lua_dir = RUNTIME_LUA_DIR.replace("\\", "/").rstrip("/")
    return """# 宝塔WAF社区版（btwaf_ce 插件自动生成，请勿手工修改；插件诊断页会自动校验并恢复）
lua_shared_dict btwaf_ce_cfg 16m;
lua_shared_dict btwaf_ce_cc 16m;
lua_shared_dict btwaf_ce_block 8m;
init_worker_by_lua_file %s;
access_by_lua_file %s;
""" % (_lua_quote(lua_dir + "/init.lua"), _lua_quote(lua_dir + "/access.lua"))


CONF_TEXT = _conf_text()


def conf_hash():
    """模板哈希，用于诊断 conf 是否被改动。"""
    norm = "\n".join([ln.strip() for ln in CONF_TEXT.strip().splitlines()])
    return hashlib.md5(norm.encode("utf-8")).hexdigest()


def runtime_lua_dir():
    return RUNTIME_LUA_DIR


def runtime_rule_dir():
    return os.path.join(DATA_DIR, "rule")


def geo_dir():
    return os.path.join(DATA_DIR, "geo")


def default_block_page():
    return os.path.join(DATA_DIR, "defaults", "blockpage.html")


def default_file(name):
    return os.path.join(PLUGIN_DEFAULTS, name)
