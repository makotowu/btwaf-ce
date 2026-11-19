#!/usr/bin/env python
# coding: utf-8
"""Webshell 扫描模块单元测试（不依赖真实 YARA）。"""
import os
import shutil
import sys
import tempfile
import unittest

from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from wafcore import paths, webshell  # noqa: E402


class WebshellCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="btwaf_ce_webshell_")
        self.site = os.path.join(self.root, "site")
        os.makedirs(self.site)
        self.patch = mock.patch.multiple(
            paths,
            WEBSHELL_DIR=os.path.join(self.root, "job"),
            WEBSHELL_JOB=os.path.join(self.root, "job", "job.json"),
            WEBSHELL_LIST=os.path.join(self.root, "job", "files.txt"),
            WEBSHELL_LOG=os.path.join(self.root, "job", "worker.log"),
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_collect_files_filters_extensions_and_size(self):
        with open(os.path.join(self.site, "a.php"), "w", encoding="utf-8") as f:
            f.write("<?php echo 1;")
        with open(os.path.join(self.site, "b.phtml"), "w", encoding="utf-8") as f:
            f.write("<?php echo 2;")
        with open(os.path.join(self.site, "skip.js"), "w", encoding="utf-8") as f:
            f.write("x")
        with open(os.path.join(self.site, "large.php"), "wb") as f:
            f.write(b"x" * (webshell.MAX_FILE_SIZE + 1))
        files = webshell.collect_files(self.site)
        names = sorted(os.path.basename(p) for p in files)
        self.assertEqual(names, ["a.php", "b.phtml"])

    def test_parse_output_and_relative_path(self):
        target = os.path.join(self.site, "uploads", "x.php")
        text = "webshell_php_eval_request %s\nother_rule %s\n" % (target, target)
        result = webshell.parse_output(text, self.site)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["file"], os.path.join("uploads", "x.php"))
        self.assertEqual(result[0]["rule"], "webshell_php_eval_request")
        self.assertEqual(webshell.parse_output("error: bad rule\n", self.site), [])

    def test_rules_available(self):
        info = webshell.rules_info()
        self.assertTrue(info["available"])
        self.assertGreater(info["count"], 0)

    def test_stale_job_marked_failed(self):
        webshell.save_job({"id": "x", "status": "running", "pid": 99999999})
        job = webshell.load_job()
        self.assertEqual(job["status"], "failed")
        self.assertIn("进程", job["error"])

    def test_start_scan_spawns_worker(self):
        with mock.patch.object(webshell, "engine_info", return_value={"installed": True, "version": "4.2.3", "path": "yara"}), \
                mock.patch.object(webshell, "rules_info", return_value={"available": True, "count": 1}), \
                mock.patch.object(webshell.S, "site_by_name", return_value={"site_name": "example.com", "path": self.site}), \
                mock.patch.object(webshell.subprocess, "Popen") as popen:
            popen.return_value.pid = 12345
            job = webshell.start_scan(None, "example.com")
        self.assertEqual(job["status"], "running")
        self.assertEqual(job["pid"], 12345)
        self.assertTrue(os.path.isdir(paths.WEBSHELL_DIR))

    def test_run_scan_done(self):
        sample = os.path.join(self.site, "x.php")
        with open(sample, "w", encoding="utf-8") as f:
            # 测试只验证扫描状态与输出解析，不落盘真实 Webshell 样本。
            f.write("<?php echo 'scanner-fixture';")
        webshell.save_job({"id": "job-1", "status": "running", "site_name": "example.com",
                           "path": self.site, "pid": 0, "started": 0, "results": []})
        fake = mock.Mock()
        fake.returncode = 0
        fake.communicate.return_value = (("webshell_php_eval_request %s\n" % sample).encode(), b"")
        with mock.patch.object(webshell, "engine_path", return_value="yara"), \
                mock.patch.object(webshell, "_rules_path", return_value=os.path.join(_PLUGIN_DIR, "defaults", "webshell", "rules.yar")), \
                mock.patch.object(webshell.subprocess, "Popen", return_value=fake):
            webshell.run_scan("job-1")
        job = webshell.load_job()
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["matched"], 1)
        self.assertEqual(job["results"][0]["file"], "x.php")

    def test_cancel_running_job(self):
        webshell.save_job({"id": "x", "status": "running", "pid": 0, "results": []})
        job = webshell.cancel_scan()
        self.assertEqual(job["status"], "cancelled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
