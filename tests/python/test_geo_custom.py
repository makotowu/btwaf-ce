#!/usr/bin/env python
# coding: utf-8
"""中国 IP 段自定义覆盖层测试。"""
import json
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

from wafcore import geo as G  # noqa: E402
from wafcore import geo_custom, paths  # noqa: E402


class GeoCustomCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="btwaf_ce_geo_custom_")
        self.base = os.path.join(self.root, "cn.ranges")
        with open(self.base, "w", encoding="utf-8") as f:
            f.write("1.2.3.0 1.2.3.255\n114.114.114.0 114.114.114.255\n")
        self.meta = os.path.join(self.root, "meta.json")
        with open(self.meta, "w", encoding="utf-8") as f:
            json.dump({"source": "fixture", "source_release": "2026-11", "records": 2}, f)
        self.custom = os.path.join(self.root, "geo_custom.json")
        self.patch_paths = mock.patch.multiple(paths, GEO_CUSTOM=self.custom)
        self.patch_paths.start()
        self.addCleanup(self.patch_paths.stop)
        self.patch_data = mock.patch.object(G, "data_path", return_value=self.base)
        self.patch_data.start()
        self.addCleanup(self.patch_data.stop)
        self.patch_meta = mock.patch.object(G, "meta", return_value={"source": "fixture", "source_release": "2026-11", "records": 2})
        self.patch_meta.start()
        self.addCleanup(self.patch_meta.stop)
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_merge_and_subtract(self):
        merged = geo_custom.merge_ranges([[1, 5], [3, 8], [20, 30]])
        self.assertEqual(merged, [[1, 8], [20, 30]])
        out = geo_custom.subtract_ranges([[1, 10]], [[3, 4], [8, 20]])
        self.assertEqual(out, [[1, 2], [5, 7]])

    def test_status_empty_custom(self):
        data = geo_custom.status()
        self.assertEqual(data["builtin"]["records"], 2)
        self.assertEqual(data["effective"], 2)
        self.assertEqual(data["include"], [])
        self.assertEqual(data["exclude"], [])

    def test_save_include_and_exclude(self):
        data = geo_custom.save(
            [{"start": "1.2.4.0", "end": "1.2.4.255"}],
            [{"start": "1.2.3.128", "end": "1.2.3.255"}],
        )
        self.assertEqual(len(data["include"]), 1)
        self.assertEqual(len(data["exclude"]), 1)
        self.assertEqual(data["effective"], 3)
        with open(self.custom, "r", encoding="utf-8") as f:
            stored = json.load(f)
        self.assertEqual(stored["include"][0]["start"], "1.2.4.0")

    def test_invalid_range_rejected(self):
        with self.assertRaises(ValueError):
            geo_custom.save([{"start": "1.2.3.4", "end": "1.2.3.1"}], [])
        with self.assertRaises(ValueError):
            geo_custom.save([{"start": "bad", "end": "1.2.3.1"}], [])

    def test_duplicate_and_merge(self):
        data = geo_custom.save(
            [{"start": "1.2.3.0", "end": "1.2.3.255"}, {"start": "1.2.3.0", "end": "1.2.3.255"}],
            [],
        )
        self.assertEqual(len(data["include"]), 1)

    def test_malformed_custom_status_reports_error(self):
        with open(self.custom, "w", encoding="utf-8") as f:
            f.write("{bad json")
        data = geo_custom.status()
        self.assertTrue(data["error"])
        self.assertEqual(data["effective"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
