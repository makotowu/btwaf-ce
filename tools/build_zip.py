# coding: utf-8
"""打包插件：python tools/build_zip.py [--version 0.1.0]

产物：dist/btwaf_ce-<version>.zip（内容位于 zip 根目录，面板"导入插件"可直接安装）
排除：测试、构建工具、缓存、面板 CSS 副本（如存在）、日志、dist 自身。
"""
import argparse
import json
import os
import subprocess
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = ROOT
DIST = os.path.join(ROOT, "dist")

EXCLUDE_DIRS = {
    "__pycache__",
    ".git",
    ".claude",
    "node_modules",
    "tests",
    "tools",
    "dist",
    ".idea",
    ".vscode",
}
EXCLUDE_FILES = {
    ".DS_Store",
    "Thumbs.db",
    "panel.css",  # 面板 style.css 副本仅用于本地预览，不随包分发
}
EXCLUDE_SUFFIX = (".pyc", ".pyo", ".log", ".tmp", ".bak")


def should_skip(rel_path, name):
    parts = rel_path.replace("\\", "/").split("/")
    for p in parts[:-1]:
        if p in EXCLUDE_DIRS:
            return True
    if name in EXCLUDE_FILES:
        return True
    if name.endswith(EXCLUDE_SUFFIX):
        return True
    return False


def collect(plugin_dir):
    items = []
    for dirpath, dirnames, filenames in os.walk(plugin_dir):
        dirnames[:] = sorted([d for d in dirnames if d not in EXCLUDE_DIRS])
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, plugin_dir)
            if should_skip(rel, name):
                continue
            items.append((full, rel.replace("\\", "/")))
    return items


def asset_version():
    """Return the short commit hash embedded into release static assets."""
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
        if not commit:
            return "dev"
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip())
        return commit + ("-dirty" if dirty else "")
    except Exception:
        return "dev"


def refresh_geo():
    """Fetch the latest DB-IP Lite monthly snapshot before packaging."""
    script = os.path.join(ROOT, "tools", "build_geoip.py")
    if not os.path.isfile(script):
        print("缺少 tools/build_geoip.py，无法刷新地区数据", file=sys.stderr)
        return False
    try:
        subprocess.check_call([sys.executable, script, "--refresh", "--strict"])
    except Exception as exc:
        print("地区数据刷新失败：%s" % exc, file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--out", default="")
    parser.add_argument(
        "--no-geo-refresh",
        action="store_true",
        help="use the committed geo data without downloading (local/offline only)",
    )
    args = parser.parse_args()

    asset = asset_version()
    if not args.no_geo_refresh:
        if not refresh_geo():
            return 1
    else:
        print("警告：--no-geo-refresh 使用仓库基线地区数据，非最新数据", file=sys.stderr)

    items = collect(PLUGIN)
    if not os.path.isfile(os.path.join(PLUGIN, "info.json")):
        print("缺少 info.json，无法打包", file=sys.stderr)
        return 1
    os.makedirs(DIST, exist_ok=True)
    out = args.out or os.path.join(DIST, "btwaf_ce-%s.zip" % args.version)

    items = collect(PLUGIN)
    # 必备文件检查
    required = ["info.json", "install.sh", "btwaf_ce_main.py", "index.html",
                "lua/geo/cn.ranges", "lua/geo/meta.json"]
    rels = set(rel for _full, rel in items)
    missing = [r for r in required if r not in rels]
    if missing:
        print("缺少必需文件：%s" % ", ".join(missing), file=sys.stderr)
        return 1

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for full, rel in items:
            if rel == "static/version.json":
                try:
                    with open(full, "r", encoding="utf-8") as handle:
                        version_data = json.load(handle)
                except Exception:
                    version_data = {}
                version_data["asset"] = asset
                zf.writestr(rel, json.dumps(version_data, ensure_ascii=False, indent=2) + "\n")
            else:
                zf.write(full, rel)

    size = os.path.getsize(out)
    print("打包完成：%s" % out)
    print("asset：%s" % asset)
    print("文件数：%d，大小：%.2f MB，时间：%s" % (len(items), size / 1024.0 / 1024.0, time.strftime("%Y-%m-%d %H:%M:%S")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
