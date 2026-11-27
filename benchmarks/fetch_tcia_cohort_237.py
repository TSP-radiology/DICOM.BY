#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open NCI TCIA Pseudo-PHI-DICOM-Data 237-Object Cohort Fetcher (MIT License).

Downloads the exact 26 series (237 clinical DICOM objects across 8 vendors and 6 modalities)
directly from the US National Cancer Institute's public NBIA REST API:
  https://services.cancerimagingarchive.net/nbia-api/services/v1/getImage?SeriesInstanceUID=...
  Dataset DOI: https://doi.org/10.7937/s17z-r072 (CC BY 4.0)

Verifies every extracted file's SHA-256 against `tcia_cohort_237_manifest.json` so any
independent auditor or CI runner reproduces the exact byte-identical clinical cohort
without redistributing TCIA images inside the software repository.
"""
import argparse
import hashlib
import io
import json
import struct
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

NBIA_GET_IMAGE_URL = "https://services.cancerimagingarchive.net/nbia-api/services/v1/getImage?SeriesInstanceUID="


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def extract_sop_instance_uid_part10(buf: bytes) -> str:
    """Extracts (0002,0003) MediaStorageSOPInstanceUID from DICOM Part 10 File Meta using stdlib only."""
    if len(buf) < 132 or buf[128:132] != b"DICM":
        return ""
    long_vrs = {b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"SQ", b"SV", b"UC", b"UN", b"UR", b"UT", b"UV"}
    p = 132
    end = len(buf)
    while p + 8 <= end:
        g, e = struct.unpack_from("<HH", buf, p)
        if g != 0x0002:
            break
        vr = buf[p + 4 : p + 6]
        if vr in long_vrs:
            if p + 12 > end:
                break
            ln = struct.unpack_from("<I", buf, p + 8)[0]
            hdr = 12
        else:
            ln = struct.unpack_from("<H", buf, p + 6)[0]
            hdr = 8
        val = buf[p + hdr : min(end, p + hdr + ln)]
        if (g, e) == (0x0002, 0x0003):
            return val.decode("ascii", errors="ignore").strip(" \t\r\n\x00")
        p += hdr + ln
    return ""


def fetch_series_zip(series_uid: str, wanted_by_sha: Dict[str, dict], wanted_by_sop: Dict[str, dict], out_dir: Path) -> Tuple[str, int]:
    # Skip network call if all requested files in this series are already verified on disk
    all_items = list(wanted_by_sha.values())
    if all(
        (out_dir / it["rel_path"]).is_file() and sha256_bytes((out_dir / it["rel_path"]).read_bytes()) == it["input_sha256"]
        for it in all_items
    ):
        return series_uid, len(all_items)

    url = NBIA_GET_IMAGE_URL + series_uid
    raw_zip = b""
    last_err = None
    for attempt in range(1, 5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DICOMBY-Repro-Audit/0.9.3"})
            with urllib.request.urlopen(req, timeout=180) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                raw_zip = resp.read()
                break
        except Exception as exc:
            last_err = exc
            time.sleep(2.0 * attempt)
    if not raw_zip:
        raise RuntimeError(f"Failed downloading NBIA series {series_uid}: {last_err}")

    matched = 0
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        for zinfo in zf.infolist():
            if zinfo.is_dir() or not zinfo.filename.lower().endswith(".dcm"):
                continue
            dcm_bytes = zf.read(zinfo.filename)
            digest = sha256_bytes(dcm_bytes)
            entry = wanted_by_sha.get(digest)
            if entry is None:
                sop_uid = extract_sop_instance_uid_part10(dcm_bytes)
                entry = wanted_by_sop.get(sop_uid)
                if entry is not None and digest != entry["input_sha256"]:
                    raise RuntimeError(
                        f"SHA-256 mismatch for SOPInstanceUID={sop_uid}: got {digest}, expected {entry['input_sha256']}"
                    )
            if entry is not None:
                dst = out_dir / entry["rel_path"]
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(dcm_bytes)
                matched += 1

    if matched != len(all_items):
        raise RuntimeError(f"Series {series_uid}: matched {matched}/{len(all_items)} expected slices")
    return series_uid, matched


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch & verify the 237-object NCI TCIA Pseudo-PHI cohort")
    ap.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parent / "tcia_cohort_237_manifest.json")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory for verified clinical DICOMs")
    ap.add_argument("--workers", type=int, default=6, help="Concurrent NBIA series downloads")
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    items: List[dict] = manifest["objects"]

    by_series_sha: Dict[str, Dict[str, dict]] = {}
    by_series_sop: Dict[str, Dict[str, dict]] = {}
    for it in items:
        suid = it["series_instance_uid"]
        by_series_sha.setdefault(suid, {})[it["input_sha256"].lower()] = it
        by_series_sop.setdefault(suid, {})[it["sop_instance_uid"]] = it

    args.out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Fetching {len(items)} clinical DICOMs across {len(by_series_sha)} series from NCI TCIA NBIA API...", flush=True)
    t0 = time.perf_counter()
    total_ok = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {
            ex.submit(fetch_series_zip, suid, by_series_sha[suid], by_series_sop[suid], args.out_dir): suid
            for suid in sorted(by_series_sha.keys())
        }
        for idx, fut in enumerate(as_completed(futs), 1):
            suid, cnt = fut.result()
            total_ok += cnt
            if idx % 5 == 0 or idx == len(futs):
                print(f"  [{idx}/{len(futs)} series] verified {total_ok}/{len(items)} objects", flush=True)

    elapsed = time.perf_counter() - t0
    if total_ok != len(items):
        print(f"FAIL: verified {total_ok}/{len(items)} objects", file=sys.stderr)
        return 1
    print(f"OK: all {total_ok}/{len(items)} NCI TCIA clinical DICOMs fetched and SHA-256 verified in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
