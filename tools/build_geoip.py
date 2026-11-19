#!/usr/bin/env python
# coding: utf-8
"""Build the bundled China IPv4 range list from DB-IP Lite Country.

The plugin never downloads geo data at runtime. This tool is run by
tools/build_zip.py before packaging, so a release always contains the latest
available monthly DB-IP Lite snapshot at build time.

Usage:
    python tools/build_geoip.py --refresh --strict
    python tools/build_geoip.py --input dbip-country-lite-2026-11.csv.gz --out lua/geo
"""
import argparse
import csv
import datetime
import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(ROOT, "lua", "geo")
DOWNLOAD_URL = "https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz"
SOURCE_NAME = "DB-IP Lite Country"
LICENSE = "CC BY 4.0"
LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
MAX_DOWNLOAD = 120 * 1024 * 1024
MAX_AGE_DAYS = 45


def _months():
    now = datetime.datetime.now(datetime.timezone.utc)
    year, month = now.year, now.month
    out = []
    for _ in range(3):
        out.append("%04d-%02d" % (year, month))
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return out


def _release_age_days(release):
    try:
        year, month = [int(x) for x in release.split("-")]
    except (TypeError, ValueError):
        return 99999
    first = datetime.datetime(year, month, 1, tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((now - first).total_seconds() // 86400))


def _download_once(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "btwaf-ce-build/1.0 (+https://github.com/makotowu/btwaf-ce)",
        "Accept": "application/gzip,application/octet-stream,*/*",
    })
    with urllib.request.urlopen(request, timeout=90) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise IOError("HTTP %s" % status)
        chunks = []
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise IOError("download exceeds %d bytes" % MAX_DOWNLOAD)
            chunks.append(chunk)
    return b"".join(chunks)


def download(url):
    last = None
    for attempt in range(3):
        try:
            return _download_once(url)
        except urllib.error.HTTPError as exc:
            # Missing current-month file should fall through to the previous month.
            if exc.code in (403, 404):
                raise
            last = exc
        except Exception as exc:
            last = exc
        if attempt < 2:
            time.sleep(2 * (attempt + 1))
    raise last


def _ipv4(text):
    try:
        value = str(text).strip()
        parts = [int(x) for x in value.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return None


def parse_csv(blob, region):
    """Return (merged ranges, source record count, total CN rows)."""
    try:
        raw = gzip.decompress(blob)
    except OSError as exc:
        raise ValueError("not a valid gzip file: %s" % exc)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    reader = csv.reader(io.StringIO(text))
    ranges = []
    source_records = 0
    cn_rows = 0
    for row in reader:
        if not row:
            continue
        if len(row) < 3:
            continue
        start = _ipv4(row[0])
        end = _ipv4(row[1])
        country = (row[2] or "").strip().upper()
        if start is None or end is None:
            # Header or malformed row; count only valid data rows.
            continue
        source_records += 1
        if country != region:
            continue
        if start > end:
            continue
        cn_rows += 1
        ranges.append((start, end))
    if source_records < 100000:
        raise ValueError("source has too few records: %d" % source_records)
    if not ranges:
        raise ValueError("no %s ranges found" % region)
    ranges.sort()
    merged = []
    for start, end in ranges:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        elif end > merged[-1][1]:
            merged[-1][1] = end
    return merged, source_records, cn_rows


def _fmt(value):
    return "%d.%d.%d.%d" % (
        (value >> 24) & 255,
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255,
    )


def write_outputs(out_dir, ranges, meta):
    os.makedirs(out_dir, exist_ok=True)
    lines = ["# China IPv4 ranges, generated from DB-IP Lite Country"]
    lines.append("# source=%s release=%s" % (meta["source"], meta["source_release"]))
    lines.append("# license=%s" % meta["license"])
    for start, end in ranges:
        lines.append("%s %s" % (_fmt(start), _fmt(end)))
    data = "\n".join(lines) + "\n"
    meta_text = json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    for name, content in (("cn.ranges", data), ("meta.json", meta_text)):
        fd, tmp = tempfile.mkstemp(prefix=".%s." % name, dir=out_dir, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            os.replace(tmp, os.path.join(out_dir, name))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def build(input_path=None, out_dir=DEFAULT_OUT, region="CN", max_age_days=MAX_AGE_DAYS,
          strict=True):
    blob = None
    release = None
    source_url = ""
    if input_path:
        with open(input_path, "rb") as handle:
            blob = handle.read()
        base = os.path.basename(input_path)
        release = ""
        for token in base.replace(".", "-").split("-"):
            if len(token) == 4 and token.isdigit():
                year = token
                continue
            if len(token) == 2 and token.isdigit() and "year" in locals():
                release = "%s-%s" % (year, token)
                break
        if not release:
            release = _months()[0]
    else:
        for month in _months():
            url = DOWNLOAD_URL % month
            try:
                blob = download(url)
                release = month
                source_url = url
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 404):
                    continue
                raise
    if blob is None:
        raise RuntimeError("no DB-IP Lite release available")
    if max_age_days and _release_age_days(release) > max_age_days:
        raise RuntimeError(
            "DB-IP Lite release %s is older than %d days" % (release, max_age_days)
        )
    ranges, source_records, cn_rows = parse_csv(blob, region)
    meta = {
        "source": SOURCE_NAME,
        "license": LICENSE,
        "license_url": LICENSE_URL,
        "source_url": source_url,
        "source_release": release,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z"),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "records": len(ranges),
        "source_records": source_records,
        "source_region_rows": cn_rows,
        "region": region,
        "format": "ipv4-start-end",
    }
    write_outputs(out_dir, ranges, meta)
    return meta


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="download latest DB-IP release")
    parser.add_argument("--input", default="", help="use an existing .csv.gz file")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--region", default="CN")
    parser.add_argument("--max-age-days", type=int, default=MAX_AGE_DAYS)
    parser.add_argument("--strict", action="store_true", help="fail on stale/failed data")
    parser.add_argument("--no-strict", action="store_false", dest="strict")
    parser.set_defaults(strict=True)
    args = parser.parse_args(argv)
    if not args.input and not args.refresh:
        parser.error("either --refresh or --input is required")
    try:
        meta = build(
            input_path=args.input or None,
            out_dir=args.out,
            region=args.region,
            max_age_days=args.max_age_days,
            strict=args.strict,
        )
    except Exception as exc:
        print("build_geoip: %s" % exc, file=sys.stderr)
        return 1
    print(
        "build_geoip: %s %s, %d ranges (source records: %d, sha256: %s)"
        % (meta["source"], meta["source_release"], meta["records"],
           meta["source_records"], meta["sha256"][:16])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
