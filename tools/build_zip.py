# coding: utf-8
"""打包插件：python tools/build_zip.py [--version 0.1.0]

产物：dist/btwaf_ce-<version>.zip（内容位于 zip 根目录，面板"导入插件"可直接安装）
排除：测试、构建工具、缓存、面板 CSS 副本（如存在）、日志、dist 自身。
"""
import argparse
import os
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = ROOT
DIST = os.path.join(ROOT, "dist")

EXCLUDE_DIRS = {
    "__pycache__",
    ".git",
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    if not os.path.isfile(os.path.join(PLUGIN, "info.json")):
        print("缺少 info.json，无法打包", file=sys.stderr)
        return 1
    os.makedirs(DIST, exist_ok=True)
    out = args.out or os.path.join(DIST, "btwaf_ce-%s.zip" % args.version)

    items = collect(PLUGIN)
    # 必备文件检查
    required = ["info.json", "install.sh", "btwaf_ce_main.py", "index.html"]
    rels = set(rel for _full, rel in items)
    missing = [r for r in required if r not in rels]
    if missing:
        print("缺少必需文件：%s" % ", ".join(missing), file=sys.stderr)
        return 1

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for full, rel in items:
            zf.write(full, rel)

    size = os.path.getsize(out)
    print("打包完成：%s" % out)
    print("文件数：%d，大小：%.2f MB，时间：%s" % (len(items), size / 1024.0 / 1024.0, time.strftime("%Y-%m-%d %H:%M:%S")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
