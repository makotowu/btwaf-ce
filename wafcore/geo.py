# coding: utf-8
"""GeoIP status helpers for the bundled China range data.

The runtime Lua module owns lookups. Python only reports metadata/diagnostics
and never downloads or parses the range file during a request.
"""
import os

from . import paths, util


def _candidates():
    return (
        paths.geo_dir(),
        os.path.join(paths.PLUGIN_LUA, "geo"),
    )


def data_dir():
    for directory in _candidates():
        if os.path.isfile(os.path.join(directory, "cn.ranges")):
            return directory
    return _candidates()[0]


def data_path():
    return os.path.join(data_dir(), "cn.ranges")


def meta_path():
    return os.path.join(data_dir(), "meta.json")


def meta():
    data = util.read_json(meta_path(), {})
    if not isinstance(data, dict):
        return {}
    return data


def status():
    data = meta()
    return {
        "available": os.path.isfile(data_path()) and bool(data),
        "path": data_path(),
        "source": data.get("source") or "",
        "license": data.get("license") or "",
        "source_release": data.get("source_release") or "",
        "generated_at": data.get("generated_at") or "",
        "records": util.safe_int(data.get("records"), 0),
        "source_records": util.safe_int(data.get("source_records"), 0),
    }
