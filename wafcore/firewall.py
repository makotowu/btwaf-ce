# coding: utf-8
"""Read/unban the panel system firewall block list.

The data source is the panel firewall table, optionally synchronized through
the panel ``firewalls`` module. This module never executes iptables,
firewall-cmd, or shell commands itself.
"""
import importlib
from types import SimpleNamespace

from . import util

PANEL_CLASS_PATH = "/www/server/panel/class"


def _default_public():
    try:
        import public  # type: ignore
        return public
    except Exception:
        return None


def _load_firewalls():
    try:
        return importlib.import_module("firewalls")
    except Exception:
        return None


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _norm_row(row):
    """Return a normalized system-firewall IP row, or None.

    The panel stores manually blocked IPs in ``port``. Port entries and port
    ranges are not IPs and must not be shown as blocked addresses.
    """
    if not isinstance(row, dict):
        return None
    ip = str(row.get("port") or "").strip()
    if not ip or not util.valid_ip_or_cidr_range(ip):
        return None
    return {
        "id": _as_int(row.get("id")),
        "ip": ip,
        "ps": str(row.get("ps") or ""),
        "addtime": str(row.get("addtime") or ""),
        "can_unban": True,
    }


class PanelFirewall(object):
    def __init__(self, public_obj=None, sync_on_list=False):
        self.public = public_obj
        self.sync_on_list = sync_on_list
        self.last_error = ""

    def _public(self):
        return self.public if self.public is not None else _default_public()

    def _sync(self, public_obj):
        module = _load_firewalls()
        if module is None:
            raise RuntimeError("面板防火墙模块不可用")
        module.firewalls().GetList()
        return public_obj

    def _rows(self, sync=False):
        public_obj = self._public()
        if public_obj is None:
            raise RuntimeError("面板 public 不可用")
        if sync:
            try:
                self._sync(public_obj)
            except Exception as exc:
                self.last_error = util.truncate(str(exc), 200)
        return public_obj.M("firewall").select()

    def list_blocked(self, sync=None):
        if sync is None:
            sync = self.sync_on_list
        self.last_error = ""
        try:
            rows = self._rows(sync=bool(sync))
        except Exception as exc:
            self.last_error = util.truncate(str(exc), 200)
            return {
                "available": False,
                "source": "",
                "list": [],
                "total": 0,
                "error": self.last_error,
            }
        items = []
        seen = set()
        for row in rows or []:
            item = _norm_row(row)
            if item is None or item["ip"] in seen:
                continue
            seen.add(item["ip"])
            items.append(item)
        items.sort(key=lambda item: item["id"])
        return {
            "available": True,
            "source": "panel-firewall",
            "list": items,
            "total": len(items),
            "error": self.last_error,
        }

    def _find(self, ip):
        public_obj = self._public()
        if public_obj is None:
            raise RuntimeError("面板 public 不可用")
        for row in public_obj.M("firewall").select() or []:
            item = _norm_row(row)
            if item is not None and item["ip"] == ip:
                return row
        return None

    def unban(self, ip):
        ip = (ip or "").strip()
        if not util.valid_ip_or_cidr_range(ip):
            return {"ok": False, "error": "IP 格式错误"}
        try:
            row = self._find(ip)
        except Exception as exc:
            return {"ok": False, "error": util.truncate(str(exc), 200)}
        if not row:
            return {"ok": False, "error": "面板防火墙中未找到该 IP"}
        rid = _as_int(row.get("id"))
        if not rid:
            return {"ok": False, "error": "面板防火墙记录缺少 ID"}
        module = _load_firewalls()
        if module is None:
            return {"ok": False, "error": "面板防火墙模块不可用"}
        try:
            result = module.firewalls().DelDropAddress(
                SimpleNamespace(id=rid, port=ip)
            )
        except Exception as exc:
            return {"ok": False, "error": util.truncate(str(exc), 200)}
        if isinstance(result, dict) and result.get("status") is False:
            return {"ok": False, "error": str(result.get("msg") or result.get("message") or "解封失败")}
        return {"ok": True, "error": ""}

    def unban_many(self, ips):
        success = 0
        errors = []
        for ip in ips or []:
            result = self.unban(ip)
            if result.get("ok"):
                success += 1
            elif result.get("error"):
                errors.append("%s: %s" % (ip, result["error"]))
        return {"unbanned": success, "errors": errors}


DEFAULT_CLIENT = PanelFirewall()


def client(public_obj=None):
    if public_obj is not None:
        return PanelFirewall(public_obj)
    return DEFAULT_CLIENT


def status():
    return DEFAULT_CLIENT.list_blocked()
