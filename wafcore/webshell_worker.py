# coding: utf-8
"""独立 Webshell 扫描 worker，避免占用面板请求生命周期。"""
import os
import sys

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from wafcore import webshell  # noqa: E402


def main():
    if len(sys.argv) < 2:
        return 1
    webshell.run_scan(sys.argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
