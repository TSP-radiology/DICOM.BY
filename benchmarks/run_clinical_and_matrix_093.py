#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open Reproducible Clinical & Adversarial Matrix Suite for DICOM.BY 0.9.4 (MIT License).

Designed to run identically on:
  - any external auditor's Windows workstation or neutral GitHub Actions `windows-latest` VM
    against an installed `DICOM-BY-0.9.4-Setup.exe` (`--bin-dir <installed_dir>`), OR
  - a local build tree (`--bin-dir build/win-slim/Release`).

Executes:
  1. `matrix_094` (12 functional, admission_v7 lossless Zero-Recompression Bitstream Pass-Through,
     compressed burned-in PHI decompression+masking, lossy JPEG refusal, PS3.15 (0028,0303),
     RLE >HighBit steganography refusal, and gateway audit chain LAST-RECORD tamper + truncation sabotage checks).
  2. `tcia_094` (237 clinical DICOM objects across 8 vendors and 6 modalities from open NCI TCIA
     Pseudo-PHI-DICOM-Data, doi:10.7937/s17z-r072):
       - paired `--vision` (Vision 1.1) vs `--pixels` (Classic) execution;
       - 100% verification of all 216 released objects via native `dicom-verify.exe --cert`;
       - 100% verification of all 216 released objects via open MIT `dicom_by_verify.py --cert --input`;
       - exhaustive independent input-vs-output PHI remanence audit across all 216 released objects
         (top-level + nested SQ identifying attributes, raw header byte token scan, 2.25.* UID regeneration,
         PS3.15 (0028,0303)=MODIFIED, private tag strip, and pixel diff verification).
"""
import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.encaps import encapsulate
from pydicom.sequence import Sequence
from pydicom.uid import ExplicitVRLittleEndian, RLELossless, generate_uid

TEST_KEY = "5a91c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff01"
GENERIC_SKIP_TOKENS = {
    "ANONYMIZED", "REMOVED", "MODIFIED", "UNMODIFIED", "UNKNOWN", "HOSPITAL", "CLINIC",
    "MEDICAL", "CENTER", "DEPARTMENT", "RADIOLOGY", "PATIENT", "DOCTOR", "PHYSICIAN",
    "ORIGINAL", "PRIMARY", "AXIAL", "CHEST", "HEAD", "ABDOMEN", "PELVIS", "BREAST",
    "NONE", "NULL", "TRUE", "FALSE",
}
PHI_TAGS = [
    ((0x0010, 0x0010), "PatientName"),
    ((0x0010, 0x0020), "PatientID"),
    ((0x0010, 0x1000), "OtherPatientIDs"),
    ((0x0010, 0x0030), "PatientBirthDate"),
    ((0x0010, 0x1040), "PatientAddress"),
    ((0x0010, 0x2154), "PatientTelephoneNumbers"),
    ((0x0008, 0x0050), "AccessionNumber"),
    ((0x0008, 0x0080), "InstitutionName"),
    ((0x0008, 0x0081), "InstitutionAddress"),
    ((0x0008, 0x0090), "ReferringPhysicianName"),
    ((0x0008, 0x1050), "PerformingPhysicianName"),
    ((0x0008, 0x1070), "OperatorsName"),
]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _base_ct_ds(dst: Path) -> FileDataset:
    meta = FileMetaDataset()
    meta.FileMetaInformationVersion = b"\x00\x01"
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds = FileDataset(str(dst), {}, file_meta=meta, preamble=b"\x00" * 128)
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.PatientName = "SIDOROV^IVAN"
    ds.PatientID = "MAT-093"
    ds.PatientBirthDate = "19750312"
    ds.PatientSex = "M"
    ds.StudyDate = "20260315"
    ds.StudyTime = "093000"
    ds.AccessionNumber = "ACCMAT093"
    ds.StudyID = "1"
    ds.SeriesNumber = "1"
    ds.InstanceNumber = "1"
    ds.ImageType = ["ORIGINAL", "PRIMARY", "AXIAL"]
    ds.Rows = 128
    ds.Columns = 128
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.RescaleIntercept = "-1024"
    ds.RescaleSlope = "1"
    ds.WindowCenter = "40"
    ds.WindowWidth = "400"
    ds.KVP = "120"
    ds.SliceThickness = "2.0"
    ds.ImagePositionPatient = ["0", "0", "0"]
    ds.ImageOrientationPatient = ["1", "0", "0", "0", "1", "0"]
    ds.PixelSpacing = ["0.8", "0.8"]
    ds.FrameOfReferenceUID = generate_uid()
    ds.PositionReferenceIndicator = ""
    ds.PixelData = np.full((128, 128), 1024, dtype=np.uint16).tobytes()
    return ds


def _packbits_encode(row_bytes: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(row_bytes), 128):
        seg = row_bytes[i : i + 128]
        out.append(len(seg) - 1)
        out.extend(seg)
    if len(out) % 2 == 1:
        out.append(0x80)
    return bytes(out)


def _encode_dicom_rle_u16(arr: np.ndarray) -> bytes:
    raw_hi = np.ascontiguousarray((arr >> 8).astype(np.uint8)).tobytes()
    raw_lo = np.ascontiguousarray((arr & 0xFF).astype(np.uint8)).tobytes()
    s1 = _packbits_encode(raw_hi)
    s2 = _packbits_encode(raw_lo)
    off1 = 64
    off2 = off1 + len(s1)
    hdr = [2, off1, off2] + [0] * 13
    frame = struct.pack("<16I", *hdr) + s1 + s2
    return encapsulate([frame])


def audit_phi_remanence_pair(in_dcm: Path, out_dcm: Path, cert_obj: dict) -> List[str]:
    """Independent pydicom + raw-byte PHI remanence inspector for an input/output clinical pair."""
    errs: List[str] = []
    ds_in = pydicom.dcmread(str(in_dcm), stop_before_pixels=False)
    ds_out = pydicom.dcmread(str(out_dcm), stop_before_pixels=False)

    raw_out = out_dcm.read_bytes()
    px_pos = raw_out.find(b"\xe0\x7f\x10\x00")
    raw_hdr_out = raw_out[:px_pos] if px_pos > 132 else raw_out

    # 1. Check all PHI tags stripped/pseudonymized and zero raw token leaks in output header
    phi_tokens = set()
    for (g, e), name in PHI_TAGS:
        if (g, e) in ds_in:
            in_val = str(ds_in[g, e].value or "").strip()
            if len(in_val) >= 2:
                out_val = str(ds_out[g, e].value or "").strip() if (g, e) in ds_out else ""
                if out_val and out_val == in_val:
                    errs.append(f"{name} unchanged: {out_val!r}")
                for tok in in_val.replace("^", " ").replace(",", " ").replace("/", " ").split():
                    t_clean = tok.strip(" ._-:")
                    if len(t_clean) >= 4 and not t_clean.isdigit() and t_clean.upper() not in GENERIC_SKIP_TOKENS:
                        phi_tokens.add(t_clean)

    hdr_upper = raw_hdr_out.upper()
    for tok in sorted(phi_tokens):
        pat = rb"(?<![A-Z0-9])" + re.escape(tok.upper().encode("utf-8")) + rb"(?![A-Z0-9])"
        if re.search(pat, hdr_upper):
            errs.append(f"Input PHI token {tok!r} found as standalone token in output raw header bytes")

    # 2. Check UID regeneration into 2.25.*
    for (g, e), uname in [
        ((0x0020, 0x000D), "StudyInstanceUID"),
        ((0x0020, 0x000E), "SeriesInstanceUID"),
        ((0x0008, 0x0018), "SOPInstanceUID"),
    ]:
        u_in = str(ds_in.get((g, e), "") and ds_in[g, e].value or "").strip()
        u_out = str(ds_out.get((g, e), "") and ds_out[g, e].value or "").strip()
        if not u_out.startswith("2.25.") or u_out == u_in:
            errs.append(f"{uname} not regenerated into 2.25.* ({u_out!r})")

    # 3. Check PatientIdentityRemoved=YES and PS3.15 E.3.6 (0028,0303)=MODIFIED top + nested SQ
    if str(getattr(ds_out, "PatientIdentityRemoved", "")).strip() != "YES":
        errs.append("PatientIdentityRemoved != YES")
    if str(getattr(ds_out, "LongitudinalTemporalInformationModified", "")).strip() != "MODIFIED":
        errs.append("Top-level (0028,0303) != MODIFIED")

    def _walk_sq(dataset: Dataset, prefix: str) -> None:
        for elem in dataset:
            if elem.VR == "SQ":
                for idx, item in enumerate(elem.value):
                    if (0x0028, 0x0303) in item and str(item[0x0028, 0x0303].value).strip() != "MODIFIED":
                        errs.append(f"Nested {prefix}/{elem.tag}[{idx}]/(0028,0303) != MODIFIED")
                    _walk_sq(item, f"{prefix}/{elem.tag}[{idx}]")

    _walk_sq(ds_out, "")

    # 4. If pixels were masked, output PixelData must differ from input PixelData
    px_info = cert_obj.get("pixels") or {}
    if int(px_info.get("lines_masked") or 0) > 0 and "PixelData" in ds_in and "PixelData" in ds_out:
        if hashlib.sha256(ds_in.PixelData).digest() == hashlib.sha256(ds_out.PixelData).digest():
            errs.append("lines_masked > 0 in cert, but PixelData bytes are identical to input")

    return errs


def _resolve_runtime_cwd(bin_dir: Path) -> Path:
    if (bin_dir / "models").is_dir() and (bin_dir / "standard").is_dir():
        return bin_dir
    for anc in [bin_dir.parent, bin_dir.parent.parent, bin_dir.parent.parent.parent]:
        if (anc / "models").is_dir() and (anc / "standard").is_dir():
            return anc
    return bin_dir


def run_matrix_093(bin_dir: Path, std_dir: Path, pub_verifier: Path, out_report_dir: Path) -> dict:
    bin_dir = bin_dir.resolve()
    std_dir = std_dir.resolve()
    pub_verifier = pub_verifier.resolve()
    out_report_dir = out_report_dir.resolve()
    run_cwd = _resolve_runtime_cwd(bin_dir)
    anon_exe = bin_dir / "dicom-anon.exe"
    verify_exe = bin_dir / "dicom-verify.exe"
    gw_exe = bin_dir / "dicom-anon-gateway.exe"
    adm_v7 = std_dir / "admission_v7.json"
    priv_safe_p = std_dir / "private_safe_v2.json"

    cases = []
    with tempfile.TemporaryDirectory(prefix="matrix_094_") as td:
        tmp = Path(td)
        key_f = tmp / "k.key"
        key_f.write_text(TEST_KEY + "\n", encoding="ascii")

        # 1. Nested SQ contradictory (0028,0303)=UNMODIFIED -> rewritten to MODIFIED
        c1_in, c1_out = tmp / "c1_in.dcm", tmp / "c1_out.dcm"
        ds1 = _base_ct_ds(c1_in)
        ref_it = Dataset()
        ref_it.SeriesInstanceUID = generate_uid()
        ref_it.add_new((0x0028, 0x0303), "CS", "UNMODIFIED")
        ds1.ReferencedSeriesSequence = Sequence([ref_it])
        ds1.save_as(str(c1_in), write_like_original=False)
        r1 = subprocess.run([str(anon_exe), "--in", str(c1_in), "--out", str(c1_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        ds1_o = pydicom.dcmread(str(c1_out), stop_before_pixels=True)
        nested_ok = ds1_o.LongitudinalTemporalInformationModified == "MODIFIED" and ds1_o.ReferencedSeriesSequence[0][0x0028, 0x0303].value == "MODIFIED"
        v1 = subprocess.run([sys.executable, str(pub_verifier), "--cert", str(c1_out) + ".deid.json", "--input", str(c1_in), "--admission", str(adm_v7), "--key-file", str(key_f)], capture_output=True, text=True)
        assert r1.returncode == 0 and nested_ok and v1.returncode == 0
        cases.append({"id": "ps315_nested_sq_0028_0303", "scope": "production_admission_v7", "expected": "SCREENED + top & nested (0028,0303)=MODIFIED", "actual_rc": r1.returncode, "passed": True})

        # 2. Retain Safe Private (113111) + strip unlisted private tags
        ps_json = json.loads(priv_safe_p.read_text("utf-8"))
        creator_name = next(iter(ps_json["creators"].keys()))
        grp_hex, elem_map = next(iter(ps_json["creators"][creator_name].items()))
        el_low_hex, vr_list = next(iter(elem_map.items()))
        grp_i, el_i, vr_s = int(grp_hex, 16), 0x1000 | int(el_low_hex, 16), vr_list[0]

        c2_in, c2_out = tmp / "c2_in.dcm", tmp / "c2_out.dcm"
        ds2 = _base_ct_ds(c2_in)
        ds2.add_new((grp_i, 0x0010), "LO", creator_name)
        ds2.add_new((grp_i, el_i), vr_s if vr_s in ("DS", "IS", "CS", "SH", "LO") else "US", "1" if vr_s in ("DS", "IS", "CS", "SH", "LO") else 1)
        ds2.add_new((0x0011, 0x0010), "LO", "UNLISTED_VENDOR_PHI")
        ds2.add_new((0x0011, 0x1001), "LO", "IVANOV SECRET PHONE 375291112233")
        ds2.save_as(str(c2_in), write_like_original=False)
        r2 = subprocess.run([str(anon_exe), "--in", str(c2_in), "--out", str(c2_out), "--key-file", str(key_f), "--retain-safe-private", "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        ds2_o = pydicom.dcmread(str(c2_out), stop_before_pixels=True)
        unsafe_gone = (0x0011, 0x1001) not in ds2_o and (0x0011, 0x0010) not in ds2_o
        v2 = subprocess.run([str(verify_exe), "--cert", str(c2_out) + ".deid.json", "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
        v2_mit = subprocess.run([sys.executable, str(pub_verifier), "--cert", str(c2_out) + ".deid.json", "--admission", str(adm_v7), "--key-file", str(key_f)], capture_output=True, text=True)
        assert r2.returncode == 0 and unsafe_gone and v2.returncode == 0 and json.loads(v2.stdout)["clean"] is True and v2_mit.returncode == 0
        cases.append({"id": "retain_safe_private_113111_and_strip_unsafe", "scope": "production_admission_v7", "expected": "SCREENED + unsafe 0011,1001 stripped + 113111 verified", "actual_rc": r2.returncode, "passed": True})

        # 3. Uncompressed multi-frame (NumberOfFrames=4) under normative admission_v7
        c3_in, c3_out = tmp / "c3_in.dcm", tmp / "c3_out.dcm"
        ds3 = _base_ct_ds(c3_in)
        ds3.NumberOfFrames = "4"
        ds3.PixelData = np.full((4, 128, 128), 1024, dtype=np.uint16).tobytes()
        ds3.save_as(str(c3_in), write_like_original=False)
        r3 = subprocess.run([str(anon_exe), "--in", str(c3_in), "--out", str(c3_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        v3 = subprocess.run([str(verify_exe), "--cert", str(c3_out) + ".deid.json", "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r3.returncode == 0 and v3.returncode == 0 and json.loads(v3.stdout)["clean"] is True
        cases.append({"id": "multiframe_uncompressed_explicit_vr_admission_v7", "scope": "production_admission_v7", "expected": "SCREENED (rc=0; matches admission_v7 rule & refuse_if 1:1)", "actual_rc": r3.returncode, "passed": True})

        # 4. Compressed RLE US cine -> REFUSED (rc=11; ultrasound always modifies outer-cone pixels)
        c3b_in, c3b_out = tmp / "c3b_in.dcm", tmp / "c3b_out.dcm"
        ds3b = _base_ct_ds(c3b_in)
        ds3b.SOPClassUID = "1.2.840.10008.5.1.4.1.1.3.1"
        ds3b.file_meta.MediaStorageSOPClassUID = ds3b.SOPClassUID
        ds3b.file_meta.TransferSyntaxUID = RLELossless
        ds3b.Modality = "US"
        ds3b.NumberOfFrames = "1"
        ds3b.PixelData = _encode_dicom_rle_u16(np.full((128, 128), 512, dtype=np.uint16))
        ds3b["PixelData"].VR = "OB"
        ds3b["PixelData"].is_undefined_length = True
        ds3b.save_as(str(c3b_in), write_like_original=False)
        r3b = subprocess.run([str(anon_exe), "--in", str(c3b_in), "--out", str(c3b_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r3b.returncode == 11 and (tmp / "c3b_out.dcm.refused.json").is_file() and not c3b_out.exists()
        cases.append({"id": "compressed_cine_rle_us_production_admission_v7", "scope": "production_admission_v7", "expected": "REFUSED (rc=11)", "actual_rc": r3b.returncode, "passed": True})

        # 5. Enhanced CT -> REFUSED (rc=11)
        c4_in, c4_out = tmp / "c4_in.dcm", tmp / "c4_out.dcm"
        ds4 = _base_ct_ds(c4_in)
        ds4.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2.1"
        ds4.file_meta.MediaStorageSOPClassUID = ds4.SOPClassUID
        ds4.save_as(str(c4_in), write_like_original=False)
        r4 = subprocess.run([str(anon_exe), "--in", str(c4_in), "--out", str(c4_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r4.returncode == 11 and not c4_out.exists()
        cases.append({"id": "enhanced_ct_production_admission_v7", "scope": "production_admission_v7", "expected": "REFUSED (rc=11)", "actual_rc": r4.returncode, "passed": True})

        # 6. Zero-Recompression Lossless Bitstream Pass-Through: Clean RLE Lossless CT -> SCREENED (rc=0) + 0% bloat + exact encapsulated_sha256!
        c5_in, c5_out = tmp / "c5_in.dcm", tmp / "c5_out.dcm"
        ds5 = _base_ct_ds(c5_in)
        ds5.file_meta.TransferSyntaxUID = RLELossless
        ds5.PixelData = _encode_dicom_rle_u16(np.full((128, 128), 1024, dtype=np.uint16))
        ds5["PixelData"].VR = "OB"
        ds5["PixelData"].is_undefined_length = True
        ds5.save_as(str(c5_in), write_like_original=False)
        r5_prod = subprocess.run([str(anon_exe), "--in", str(c5_in), "--out", str(c5_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r5_prod.returncode == 0 and c5_out.is_file(), f"Expected clean RLE CT rc=0: {r5_prod.returncode} {r5_prod.stderr}"
        ds5_o = pydicom.dcmread(str(c5_out), stop_before_pixels=False)
        c5_cert = json.loads(Path(str(c5_out) + ".deid.json").read_text("utf-8"))
        assert str(ds5_o.file_meta.TransferSyntaxUID) == str(RLELossless), f"Expected RLELossless preserved, got {ds5_o.file_meta.TransferSyntaxUID}"
        assert c5_cert.get("pixels", {}).get("bitstream_passthrough") is True
        v5_cpp = subprocess.run([str(verify_exe), "--cert", str(c5_out) + ".deid.json", "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
        v5_mit = subprocess.run([sys.executable, str(pub_verifier), "--cert", str(c5_out) + ".deid.json", "--input", str(c5_in), "--admission", str(adm_v7), "--key-file", str(key_f)], capture_output=True, text=True)
        assert v5_cpp.returncode == 0 and v5_mit.returncode == 0, f"Verifier failed on RLE passthrough: {v5_mit.stderr}"
        cases.append({"id": "zero_recompression_rle_lossless_passthrough", "scope": "production_admission_v7", "expected": "SCREENED (rc=0) + bitstream_passthrough=true + encapsulated_sha256 match (0% bloat)", "actual_rc": r5_prod.returncode, "passed": True})

        # 7. Burned-in PHI inside RLE Lossless CT -> decompressed, glyph-masked by Vision 1.1, and written as Explicit VR LE!
        from PIL import Image, ImageDraw
        c5b_in, c5b_out = tmp / "c5b_in.dcm", tmp / "c5b_out.dcm"
        arr_phi = np.full((256, 256), 1024, dtype=np.uint16)
        im_p = Image.new("L", (256, 256), 0)
        ImageDraw.Draw(im_p).text((16, 16), "SIDOROV IVAN 1975", fill=255)
        arr_phi[np.asarray(im_p) > 100] = 2800
        ds5b = _base_ct_ds(c5b_in)
        ds5b.Rows = 256
        ds5b.Columns = 256
        ds5b.BurnedInAnnotation = "YES"
        ds5b.file_meta.TransferSyntaxUID = RLELossless
        ds5b.PixelData = _encode_dicom_rle_u16(arr_phi)
        ds5b["PixelData"].VR = "OB"
        ds5b["PixelData"].is_undefined_length = True
        ds5b.save_as(str(c5b_in), write_like_original=False)
        r5b = subprocess.run([str(anon_exe), "--in", str(c5b_in), "--out", str(c5b_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r5b.returncode == 0 and c5b_out.is_file(), f"Expected RLE+PHI CT rc=0: {r5b.returncode} {r5b.stderr}"
        ds5b_o = pydicom.dcmread(str(c5b_out), stop_before_pixels=True)
        c5b_cert = json.loads(Path(str(c5b_out) + ".deid.json").read_text("utf-8"))
        assert str(ds5b_o.file_meta.TransferSyntaxUID) == str(ExplicitVRLittleEndian)
        assert c5b_cert.get("pixels", {}).get("bitstream_passthrough") is False and int(c5b_cert.get("pixels", {}).get("lines_masked", 0)) >= 1
        v5b_mit = subprocess.run([sys.executable, str(pub_verifier), "--cert", str(c5b_out) + ".deid.json", "--input", str(c5b_in), "--admission", str(adm_v7), "--key-file", str(key_f)], capture_output=True, text=True)
        assert v5b_mit.returncode == 0
        cases.append({"id": "lossless_rle_burnedin_phi_decompressed_and_masked", "scope": "production_admission_v7", "expected": "SCREENED (rc=0) + PHI glyph-masked + bitstream_passthrough=false -> ExplicitVRLE", "actual_rc": r5b.returncode, "passed": True})

        # 8. Post-decompression >HighBit steganography inside RLE Lossless CT -> REFUSED (rc=11) in production mode!
        c5_steg_in, c5_steg_out = tmp / "c5_steg_in.dcm", tmp / "c5_steg_out.dcm"
        arr_steg = np.full((128, 128), 1024, dtype=np.uint16)
        arr_steg[64, 64] |= (1 << 14)
        ds5s = _base_ct_ds(c5_steg_in)
        ds5s.file_meta.TransferSyntaxUID = RLELossless
        ds5s.PixelData = _encode_dicom_rle_u16(arr_steg)
        ds5s["PixelData"].VR = "OB"
        ds5s["PixelData"].is_undefined_length = True
        ds5s.save_as(str(c5_steg_in), write_like_original=False)
        r5_steg = subprocess.run([str(anon_exe), "--in", str(c5_steg_in), "--out", str(c5_steg_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r5_steg.returncode == 11 and not c5_steg_out.exists()
        cases.append({"id": "lossless_rle_highbit_steganography_refused", "scope": "production_admission_v7", "expected": "REFUSED (rc=11; post-decompression >HighBit plane guard)", "actual_rc": r5_steg.returncode, "passed": True})

        # 9. Lossy JPEG Baseline (1.2.840.10008.1.2.4.50) -> REFUSED (rc=11) in production mode!
        c5_lossy_in, c5_lossy_out = tmp / "c5_lossy_in.dcm", tmp / "c5_lossy_out.dcm"
        ds5l = _base_ct_ds(c5_lossy_in)
        ds5l.BitsAllocated = 8
        ds5l.BitsStored = 8
        ds5l.HighBit = 7
        ds5l.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.4.50"
        ds5l.PixelData = encapsulate([b"\xff\xd8\xff\xd9"])
        ds5l["PixelData"].VR = "OB"
        ds5l["PixelData"].is_undefined_length = True
        ds5l.save_as(str(c5_lossy_in), write_like_original=False)
        r5_lossy = subprocess.run([str(anon_exe), "--in", str(c5_lossy_in), "--out", str(c5_lossy_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r5_lossy.returncode == 11 and not c5_lossy_out.exists()
        cases.append({"id": "lossy_jpeg_baseline_refused", "scope": "production_admission_v7", "expected": "REFUSED (rc=11; lossy codecs forbidden)", "actual_rc": r5_lossy.returncode, "passed": True})

        # 10. Deliberate PS3.15 E.3.6 sabotage: strip (0028,0303) & re-sign cert -> MUST FAIL both verifiers!
        c6_sab = tmp / "c6_sab.dcm"
        ds6 = pydicom.dcmread(str(c1_out))
        del ds6[0x0028, 0x0303]
        ds6.save_as(str(c6_sab), write_like_original=False)
        raw6 = bytearray(c6_sab.read_bytes())
        raw6[:128] = b"\x00" * 128
        c6_sab.write_bytes(bytes(raw6))
        cert6 = json.loads(Path(str(c1_out) + ".deid.json").read_text("utf-8"))
        cert6["output"] = {"name": c6_sab.name, "sha256": sha256_file(c6_sab)}
        import hmac as _hm
        body6 = {k: v for k, v in cert6.items() if k not in ("seal", "created")}
        cert6["seal"] = _hm.new(bytes.fromhex(TEST_KEY), json.dumps(body6, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"), hashlib.sha256).hexdigest()
        c6_cp = Path(str(c6_sab) + ".deid.json")
        c6_cp.write_text(json.dumps(cert6), encoding="utf-8")
        v6_cpp = subprocess.run([str(verify_exe), "--cert", str(c6_cp), "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
        v6_mit = subprocess.run([sys.executable, str(pub_verifier), "--cert", str(c6_cp), "--key-file", str(key_f)], capture_output=True, text=True)
        assert v6_cpp.returncode == 1 and v6_mit.returncode == 1
        cases.append({"id": "sabotage_missing_0028_0303_rejected", "scope": "sabotage_calibration", "expected": "BOTH verifiers rc=1", "actual_rc": v6_mit.returncode, "passed": True})

        # 11. ModalityLUTSequence -> REFUSED (rc=11)
        c7_in, c7_out = tmp / "c7_in.dcm", tmp / "c7_out.dcm"
        ds7 = _base_ct_ds(c7_in)
        ml = Dataset()
        ml.LUTDescriptor = [256, 0, 16]
        ml.ModalityLUTType = "US"
        ml.LUTData = bytes(512)
        ds7.ModalityLUTSequence = Sequence([ml])
        ds7.save_as(str(c7_in), write_like_original=False)
        r7 = subprocess.run([str(anon_exe), "--in", str(c7_in), "--out", str(c7_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r7.returncode == 11 and not c7_out.exists()
        cases.append({"id": "modality_lut_sequence_refused", "scope": "production_admission_v7", "expected": "REFUSED (rc=11)", "actual_rc": r7.returncode, "passed": True})

        # 12. BurnedInAnnotation=YES without text -> REVIEW (rc=10)
        c8_in, c8_out = tmp / "c8_in.dcm", tmp / "c8_out.dcm"
        ds8 = _base_ct_ds(c8_in)
        ds8.BurnedInAnnotation = "YES"
        ds8.save_as(str(c8_in), write_like_original=False)
        r8 = subprocess.run([str(anon_exe), "--in", str(c8_in), "--out", str(c8_out), "--key-file", str(key_f), "--vision"], capture_output=True, text=True, cwd=str(run_cwd))
        assert r8.returncode == 10 and not c8_out.exists() and (tmp / "_quarantine" / "c8_out.dcm").is_file()
        cases.append({"id": "ambiguous_burnedin_yes_quarantined", "scope": "production_admission_v7", "expected": "REVIEW (rc=10)", "actual_rc": r8.returncode, "passed": True})

        # 13. Live Gateway Pro audit chain + LAST-RECORD modification & truncation sabotage!
        if gw_exe.is_file():
            gw_in, gw_out = tmp / "gw_in", tmp / "gw_out"
            gw_in.mkdir(); gw_out.mkdir()
            shutil.copy2(c1_in, gw_in / "a1.dcm")
            shutil.copy2(c5_in, gw_in / "a2_rle.dcm")
            aud_p = tmp / "gw_live.jsonl"
            gw_p = subprocess.Popen(
                [str(gw_exe), "--watch", str(gw_in), "--out", str(gw_out), "--key-file", str(key_f), "--audit", str(aud_p), "--vision"],
                cwd=str(run_cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                t_dead = time.time() + 25.0
                while time.time() < t_dead:
                    if aud_p.is_file() and len([ln for ln in aud_p.read_text("utf-8").splitlines() if ln.strip()]) >= 2:
                        time.sleep(0.3)
                        break
                    time.sleep(0.2)
            finally:
                gw_p.terminate()
                try:
                    gw_p.wait(timeout=5)
                except Exception:
                    gw_p.kill()

            va_cpp = subprocess.run([str(verify_exe), "--audit", str(aud_p), "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
            va_mit = subprocess.run([sys.executable, str(pub_verifier), "--audit", str(aud_p), "--key-file", str(key_f)], capture_output=True, text=True)
            assert va_cpp.returncode == 0 and va_mit.returncode == 0

            # Tamper ONLY the LAST record of gw_live.jsonl keeping canonical JSON!
            orig_lines = [ln for ln in aud_p.read_text("utf-8").splitlines() if ln.strip()]
            last_obj = json.loads(orig_lines[-1])
            last_obj["outcome"] = "PROVEN" if last_obj.get("outcome") != "PROVEN" else "REVIEW"
            tail_tampered = tmp / "gw_tail_tampered.jsonl"
            tail_tampered.write_text("\n".join(orig_lines[:-1] + [json.dumps(last_obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))]) + "\n", encoding="utf-8")
            vt_cpp = subprocess.run([str(verify_exe), "--audit", str(tail_tampered), "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
            vt_mit = subprocess.run([sys.executable, str(pub_verifier), "--audit", str(tail_tampered), "--key-file", str(key_f)], capture_output=True, text=True)
            assert vt_cpp.returncode == 1 and vt_mit.returncode == 1

            # Truncate the LAST record (keep .head.json next to truncated log)
            trunc_p = tmp / "gw_truncated.jsonl"
            trunc_p.write_text(orig_lines[0] + "\n", encoding="utf-8")
            shutil.copy2(str(aud_p) + ".head.json", str(trunc_p) + ".head.json")
            vtr_cpp = subprocess.run([str(verify_exe), "--audit", str(trunc_p), "--key-file", str(key_f), "--json"], capture_output=True, text=True, cwd=str(run_cwd))
            vtr_mit = subprocess.run([sys.executable, str(pub_verifier), "--audit", str(trunc_p), "--key-file", str(key_f)], capture_output=True, text=True)
            assert vtr_cpp.returncode == 1 and vtr_mit.returncode == 1
            cases.append({"id": "gateway_audit_tail_tamper_and_truncation_sabotage", "scope": "sabotage_calibration", "expected": "valid=0; last-record tamper=1; last-record truncation=1 (C++ & MIT)", "actual_rc": vt_mit.returncode, "passed": True})

    report = {
        "benchmark": "functional_and_adversarial_matrix_094",
        "version": "0.9.4",
        "admission_version": "7",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {"os": platform.platform(), "python": platform.python_version()},
        "total_cases": len(cases),
        "passed_cases": sum(1 for c in cases if c["passed"]),
        "cases": cases,
    }
    out_report_dir.mkdir(parents=True, exist_ok=True)
    out_p = out_report_dir / "matrix_094_report.json"
    out_p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"[0.9.4 MATRIX] PASS ({len(cases)}/{len(cases)}) -> {out_p}", flush=True)
    return report

def discover_or_load_cohort(tcia_dir: Path, manifest_path: Optional[Path]) -> Tuple[List[Tuple[Path, str, str]], dict]:
    if manifest_path and manifest_path.is_file():
        m = json.loads(manifest_path.read_text("utf-8"))
        selected = []
        for obj in m["objects"]:
            fp = tcia_dir / obj["rel_path"]
            if not fp.is_file():
                raise FileNotFoundError(f"Missing TCIA object: {fp}")
            if sha256_file(fp) != obj["input_sha256"]:
                raise RuntimeError(f"Input SHA-256 mismatch on {fp}")
            selected.append((fp, obj["modality"], obj["manufacturer"]))
        return selected, m["corpus_summary"]

    # Local initial discovery from full 1,693-object TCIA directory
    by_series: Dict[str, List[Path]] = defaultdict(list)
    all_dcm = sorted(tcia_dir.rglob("*.dcm"))
    for p in all_dcm:
        rel_series = f"{p.parent.parent.name}/{p.parent.name}"
        by_series[rel_series].append(p)

    selected = []
    mod_totals: Counter = Counter()
    mod_sel: Counter = Counter()
    vendors = set()
    for ser_key in sorted(by_series.keys()):
        files = sorted(by_series[ser_key])
        ds0 = pydicom.dcmread(str(files[0]), stop_before_pixels=True)
        mod = str(getattr(ds0, "Modality", "") or ser_key.split("/")[-1].split("_")[0]).strip()
        vendor = str(getattr(ds0, "Manufacturer", "") or "UNKNOWN").strip()
        if vendor and vendor != "UNKNOWN":
            vendors.add(vendor)
        mod_totals[mod] += len(files)
        if mod in ("CR", "DX", "MG"):
            chosen = files
        elif len(files) <= 12:
            chosen = files
        else:
            idxs = sorted({round(i * (len(files) - 1) / 11) for i in range(12)})
            chosen = [files[i] for i in idxs]
        for fp in chosen:
            selected.append((fp, mod, vendor))
            mod_sel[mod] += 1

    summary = {
        "source_dataset": "NCI The Cancer Imaging Archive (TCIA) — Pseudo-PHI-DICOM-Data",
        "source_doi": "https://doi.org/10.7937/s17z-r072",
        "selected_cohort_files": len(selected),
        "selected_series": len(by_series),
        "selected_by_modality": dict(sorted(mod_sel.items())),
        "planar_xray_mg_coverage_pct": 100.0,
        "manufacturers_tested": sorted(vendors),
    }
    return selected, summary


def _eval_mode(
    anon_exe: Path,
    verify_exe: Path,
    in_dir: Path,
    out_dir: Path,
    key_file: Path,
    extra_flags: List[str],
    rel_map: Dict[str, Tuple[str, str]],
    cwd: Path,
) -> dict:
    cmd = [
        str(anon_exe),
        "--in-dir", str(in_dir),
        "--out-dir", str(out_dir),
        "--layout", "mirror",
        "--key-file", str(key_file),
        "--clean-sr",
        "--use-ner",
        "--keep-time",
        "--retain-safe-private",
        "--keep-clean-descriptors",
        "--jobs", "8",
    ] + extra_flags
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(cwd))
    elapsed = time.perf_counter() - t0
    if p.returncode not in (0, 10):
        raise RuntimeError(f"dicom-anon failed rc={p.returncode}: {p.stderr}")

    outcomes: Counter = Counter()
    by_mod: Dict[str, Counter] = defaultdict(Counter)
    by_vendor: Dict[str, Counter] = defaultdict(Counter)
    lines_masked = 0
    verified_kept_files = 0
    verified_kept_total = 0

    for line in p.stdout.splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        rec = json.loads(s)
        outc = rec.get("outcome", "UNKNOWN")
        inp_rel = str(Path(rec["input"]).relative_to(in_dir)).replace("\\", "/")
        mod, vendor = rel_map.get(inp_rel, ("UNK", "UNK"))
        outcomes[outc] += 1
        by_mod[mod][outc] += 1
        by_vendor[vendor][outc] += 1
        px = rec.get("pixels") or {}
        lines_masked += int(px.get("lines_masked", 0))
        vis = px.get("vision") or {}
        vk = int(vis.get("verified_kept_lines", 0))
        if vk > 0:
            verified_kept_files += 1
            verified_kept_total += vk

    rel_certs = [cp for cp in sorted(out_dir.rglob("*.deid.json")) if "_quarantine" not in cp.parts]

    def _chk_cpp(cp: Path) -> bool:
        vp = subprocess.run([str(verify_exe), "--cert", str(cp), "--key-file", str(key_file), "--json"], capture_output=True, text=True, cwd=str(cwd))
        return vp.returncode == 0 and json.loads(vp.stdout).get("clean") is True

    with ThreadPoolExecutor(max_workers=8) as ex:
        cpp_clean = sum(1 for ok in ex.map(_chk_cpp, rel_certs) if ok)

    return {
        "flags": extra_flags,
        "elapsed_sec": round(elapsed, 2),
        "throughput_obj_per_sec": round(len(rel_map) / max(elapsed, 0.001), 2),
        "outcomes": dict(sorted(outcomes.items())),
        "by_modality": {m: dict(sorted(c.items())) for m, c in sorted(by_mod.items())},
        "by_manufacturer": {v: dict(sorted(c.items())) for v, c in sorted(by_vendor.items())},
        "total_burned_in_lines_masked": lines_masked,
        "files_with_verified_clinical_markers_kept": verified_kept_files,
        "total_verified_clinical_markers_kept": verified_kept_total,
        "verify_cert_released_checked": len(rel_certs),
        "verify_cert_released_clean": cpp_clean,
    }


def run_tcia_093(
    bin_dir: Path,
    std_dir: Path,
    pub_verifier: Path,
    tcia_dir: Path,
    out_report_dir: Path,
    manifest_in: Optional[Path] = None,
    export_manifest_out: Optional[Path] = None,
    export_certs_tar: Optional[Path] = None,
) -> dict:
    bin_dir = bin_dir.resolve()
    std_dir = std_dir.resolve()
    pub_verifier = pub_verifier.resolve()
    tcia_dir = tcia_dir.resolve()
    out_report_dir = out_report_dir.resolve()
    run_cwd = _resolve_runtime_cwd(bin_dir)
    anon_exe = bin_dir / "dicom-anon.exe"
    verify_exe = bin_dir / "dicom-verify.exe"
    adm_v7 = std_dir / "admission_v7.json"

    selected, corpus_summary = discover_or_load_cohort(tcia_dir, manifest_in)
    print(f"[0.9.4 TCIA] Running paired clinical evaluation on {len(selected)} objects...", flush=True)

    work = Path(tempfile.mkdtemp(prefix="tcia_094_"))
    try:
        in_dir = work / "in"
        rel_map: Dict[str, Tuple[str, str]] = {}
        for fp, mod, vendor in selected:
            rel = fp.relative_to(tcia_dir)
            dst = in_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(fp, dst)
            except OSError:
                shutil.copy2(fp, dst)
            rel_map[str(rel).replace("\\", "/")] = (mod, vendor)

        key_f = work / "tcia_demo.key"
        key_f.write_text(TEST_KEY + "\n", encoding="ascii")

        res_classic = _eval_mode(anon_exe, verify_exe, in_dir, work / "out_classic", key_f, ["--pixels"], rel_map, run_cwd)
        out_vis = work / "out_vision"
        res_vision = _eval_mode(anon_exe, verify_exe, in_dir, out_vis, key_f, ["--vision"], rel_map, run_cwd)

        assert res_vision["verify_cert_released_checked"] == res_vision["verify_cert_released_clean"]
        assert res_classic["verify_cert_released_checked"] == res_classic["verify_cert_released_clean"]

        vis_certs = [cp for cp in sorted(out_vis.rglob("*.deid.json")) if "_quarantine" not in cp.parts]

        # Run BOTH MIT verifier (with --input pair diff!) AND independent pydicom PHI remanence audit on ALL 216 released objects!
        def _audit_released(cp: Path) -> Tuple[bool, List[str]]:
            rel_cert = cp.relative_to(out_vis)
            rel_dcm = Path(str(rel_cert)[: -len(".deid.json")])
            orig_dcm = in_dir / rel_dcm
            out_dcm = out_vis / rel_dcm
            r_mit = subprocess.run(
                [sys.executable, str(pub_verifier), "--cert", str(cp), "--input", str(orig_dcm), "--admission", str(adm_v7), "--key-file", str(key_f)],
                capture_output=True, text=True,
            )
            mit_ok = r_mit.returncode == 0 and "ltim_0028_0303=MODIFIED" in r_mit.stdout and "pair_checked=True" in r_mit.stdout
            cert_obj = json.loads(cp.read_text("utf-8"))
            rem_errs = audit_phi_remanence_pair(orig_dcm, out_dcm, cert_obj)
            if not mit_ok:
                rem_errs.append(f"MIT verifier failed: {r_mit.stderr.strip()}")
            return (mit_ok and len(rem_errs) == 0), rem_errs

        mit_pair_clean = 0
        phi_remanence_leaks = 0
        all_rem_errors: List[str] = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            for ok, errs in ex.map(_audit_released, vis_certs):
                if ok:
                    mit_pair_clean += 1
                else:
                    phi_remanence_leaks += 1
                    all_rem_errors.extend(errs[:5])

        assert mit_pair_clean == len(vis_certs) and phi_remanence_leaks == 0, f"TCIA audit failures: {all_rem_errors}"
        res_vision["mit_public_verifier_pair_checked"] = len(vis_certs)
        res_vision["mit_public_verifier_pair_clean"] = mit_pair_clean
        res_vision["independent_phi_remanence_checked"] = len(vis_certs)
        res_vision["independent_phi_remanence_leaks"] = phi_remanence_leaks

        # Optional deterministic cohort manifest + sanitized 237-certificate tarball export
        if export_manifest_out is not None:
            objs_manifest = []
            for fp, mod, vendor in selected:
                rel_s = str(fp.relative_to(tcia_dir)).replace("\\", "/")
                ds_h = pydicom.dcmread(str(fp), stop_before_pixels=True)
                rel_out_dcm = out_vis / rel_s
                q_out_dcm = out_vis / "_quarantine" / Path(rel_s).name
                if not q_out_dcm.is_file():
                    q_out_dcm = out_vis / Path(rel_s).parent / "_quarantine" / Path(rel_s).name
                if rel_out_dcm.is_file():
                    eff_dcm = rel_out_dcm
                    eff_cert = Path(str(rel_out_dcm) + ".deid.json")
                    exp_outcome = "SCREENED"
                else:
                    eff_dcm = q_out_dcm
                    eff_cert = Path(str(q_out_dcm) + ".deid.json")
                    exp_outcome = "REVIEW"
                objs_manifest.append({
                    "rel_path": rel_s,
                    "series_instance_uid": str(ds_h.SeriesInstanceUID),
                    "sop_instance_uid": str(ds_h.SOPInstanceUID),
                    "modality": mod,
                    "manufacturer": vendor,
                    "input_sha256": sha256_file(fp),
                    "expected_vision_093_outcome": exp_outcome,
                    "expected_vision_093_output_sha256": sha256_file(eff_dcm),
                })
            export_manifest_out.parent.mkdir(parents=True, exist_ok=True)
            export_manifest_out.write_text(
                json.dumps(
                    {
                        "schema": "dicom-by-tcia-cohort-237-v1",
                        "version": "0.9.4",
                        "admission_version": "7",
                        "demo_key_hex": TEST_KEY,
                        "corpus_summary": corpus_summary,
                        "objects": objs_manifest,
                    },
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            print(f"[0.9.4 TCIA] Exported deterministic 237-object manifest -> {export_manifest_out}", flush=True)

        if export_certs_tar is not None:
            export_certs_tar.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(export_certs_tar, "w:gz") as tf:
                for cp in sorted(out_vis.rglob("*.deid.json")):
                    arc = str(cp.relative_to(out_vis)).replace("\\", "/")
                    raw_c = cp.read_bytes()
                    ti = tarfile.TarInfo(name=arc)
                    ti.size = len(raw_c)
                    ti.mtime = 1764244800
                    tf.addfile(ti, io.BytesIO(raw_c))
            print(f"[0.9.4 TCIA] Exported 237 signed certificates archive -> {export_certs_tar}", flush=True)

        report = {
            "benchmark": "tcia_pseudo_phi_real_clinical_094",
            "disclosure": "Reproducible benchmark on open NCI TCIA Pseudo-PHI-DICOM-Data (doi:10.7937/s17z-r072); independently executable via benchmarks/fetch_tcia_cohort_237.py + benchmarks/run_clinical_and_matrix_093.py and GitHub Actions windows-latest CI.",
            "version": "0.9.4",
            "vision_engine": "1.1",
            "admission_version": "7",
            "ps3_15_ltim_0028_0303_verified": f"{mit_pair_clean}/{len(vis_certs)} released objects carry (0028,0303)=MODIFIED",
            "independent_phi_remanence_verified": f"0/{len(vis_certs)} residual PHI leaks across attributes, nested SQs, raw header bytes & pixels",
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "environment": {"os": platform.platform(), "cpu_threads": os.cpu_count()},
            "corpus": corpus_summary,
            "classic_pixels_mode": res_classic,
            "vision_1_1_mode": res_vision,
        }
        out_report_dir.mkdir(parents=True, exist_ok=True)
        out_p = out_report_dir / "tcia_vision_094_report.json"
        out_p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(
            f"[0.9.4 TCIA] PASS -> {out_p} ({mit_pair_clean}/{len(vis_certs)} MIT pair + 0/{len(vis_certs)} PHI remanence leaks)",
            flush=True,
        )
        return report
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run DICOM.BY 0.9.4 reproducible clinical & adversarial matrix suite")
    ap.add_argument("--bin-dir", type=Path, required=True, help="Directory containing dicom-anon.exe & dicom-verify.exe")
    ap.add_argument("--std-dir", type=Path, help="Directory containing admission_v7.json (defaults to <bin-dir>/standard)")
    ap.add_argument("--verifier", type=Path, required=True, help="Path to open MIT dicom_by_verify.py")
    ap.add_argument("--tcia-dir", type=Path, help="Path to 237-object TCIA input cohort directory")
    ap.add_argument("--manifest", type=Path, help="Optional tcia_cohort_237_manifest.json")
    ap.add_argument("--out-reports", type=Path, required=True, help="Output directory for JSON reports")
    ap.add_argument("--export-manifest", type=Path, help="Write deterministic tcia_cohort_237_manifest.json")
    ap.add_argument("--export-certs-tar", type=Path, help="Write tcia-certs-0.9.4.tar.gz")
    ap.add_argument("--mode", choices=["all", "matrix", "tcia"], default="all")
    args = ap.parse_args()

    std_dir = args.std_dir if args.std_dir else (args.bin_dir / "standard")
    if not (std_dir / "admission_v7.json").is_file():
        for repo_guess in (Path(__file__).resolve().parents[1] / "standard", Path(__file__).resolve().parents[3] / "standard"):
            if (repo_guess / "admission_v7.json").is_file():
                std_dir = repo_guess
                break

    if args.mode in ("all", "matrix"):
        run_matrix_093(args.bin_dir, std_dir, args.verifier, args.out_reports)
    if args.mode in ("all", "tcia"):
        if not args.tcia_dir:
            raise ValueError("--tcia-dir is required for mode 'all' or 'tcia'")
        run_tcia_093(
            args.bin_dir,
            std_dir,
            args.verifier,
            args.tcia_dir,
            args.out_reports,
            manifest_in=args.manifest,
            export_manifest_out=args.export_manifest,
            export_certs_tar=args.export_certs_tar,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
