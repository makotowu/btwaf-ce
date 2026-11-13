# coding: utf-8
"""路径与常量。"""
import hashlib
import os

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 运行期目录（可用环境变量覆盖，便于本地测试）
DATA_DIR = os.environ.get("BTWAF_CE_DATA_DIR", "/www/server/btwaf_ce")
LOG_DIR = os.environ.get("BTWAF_CE_LOG_DIR", "/www/wwwlogs/btwaf_ce")
NGINX_BIN = os.environ.get("BTWAF_CE_NGINX_BIN", "/www/server/nginx/sbin/nginx")
NGINX_CONF = os.environ.get("BTWAF_CE_NGINX_CONF", "/www/server/nginx/conf/nginx.conf")
NGINX_INIT = os.environ.get("BTWAF_CE_NGINX_INIT", "/etc/init.d/nginx")
VHOST_DIR = os.environ.get("BTWAF_CE_VHOST_DIR", "/www/server/panel/vhost/nginx")
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
RULES_INDEX = os.path.join(DATA_DIR, "lua", "rules", "index.json")

VERSION = "0.1.0"

CONF_TEXT = """# 宝塔WAF社区版（btwaf_ce 插件自动生成，请勿手工修改；插件诊断页会自动校验并恢复）
lua_shared_dict btwaf_ce_cfg 16m;
lua_shared_dict btwaf_ce_cc 16m;
lua_shared_dict btwaf_ce_block 8m;
init_worker_by_lua_file /www/server/btwaf_ce/lua/init.lua;
access_by_lua_file /www/server/btwaf_ce/lua/access.lua;
"""


def conf_hash():
    """模板哈希，用于诊断 conf 是否被改动。"""
    norm = "\n".join([ln.strip() for ln in CONF_TEXT.strip().splitlines()])
    return hashlib.md5(norm.encode("utf-8")).hexdigest()


def runtime_lua_dir():
    return os.path.join(DATA_DIR, "lua")


def runtime_rule_dir():
    return os.path.join(DATA_DIR, "rule")


def default_file(name):
    return os.path.join(PLUGIN_DEFAULTS, name)
