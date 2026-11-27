"""Модульные и саботажные проверки для независимого верификатора DICOM.BY 0.9.2."""
import base64
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import dicom_by_verify as v


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def sign_cert(cert: dict, key: bytes) -> dict:
    out = dict(cert)
    out.pop("seal", None)
    body = {k: val for k, val in out.items() if k != "created"}
    out["seal"] = hmac.new(key, v.canonical_json_bytes(body), hashlib.sha256).hexdigest()
    return out


def _pad_dicom_str(s: str, vr: bytes) -> bytes:
    raw = s.encode("utf-8")
    if len(raw) % 2 == 1:
        raw += b"\x00" if vr == b"UI" else b" "
    return raw


def _elem_explicit(g: int, e: int, vr: bytes, val: bytes) -> bytes:
    if len(val) % 2 == 1:
        val += b"\x00"
    if vr in v.LONG_LEN_VRS:
        return struct.pack("<HH2sHI", g, e, vr, 0, len(val)) + val
    return struct.pack("<HH2sH", g, e, vr, len(val)) + val


def _sq_item(elems: bytes) -> bytes:
    return struct.pack("<HHI", 0xFFFE, 0xE000, len(elems)) + elems


def build_minimal_part10(
    *,
    sop_inst: str = "2.25.9999999999999999999991",
    study_uid: str = "2.25.8888888888888888888881",
    series_uid: str = "2.25.7777777777777777777771",
    patient_name: str = "PS-TESTPSEUDO123456",
    patient_id: str = "PS-TESTPSEUDO123456",
    birth_date: str = "",
    study_date: str = "20251201",
    accession: str = "",
    pir: str = "YES",
    codes: Tuple[str, ...] = ("113100", "113101", "113107"),
    ltim: str | None = "MODIFIED",
    nested_ltim: str | None = None,
    include_pixels: bool = True,
    add_private_tag: bool = False,
    preamble_byte: int = 0,
) -> bytes:
    preamble = bytes([preamble_byte]) * 128 + b"DICM"
    meta_body = (
        _elem_explicit(0x0002, 0x0001, b"OB", b"\x00\x01")
        + _elem_explicit(0x0002, 0x0002, b"UI", _pad_dicom_str("1.2.840.10008.5.1.4.1.1.2", b"UI"))
        + _elem_explicit(0x0002, 0x0003, b"UI", _pad_dicom_str(sop_inst, b"UI"))
        + _elem_explicit(0x0002, 0x0010, b"UI", _pad_dicom_str("1.2.840.10008.1.2.1", b"UI"))
    )
    meta = _elem_explicit(0x0002, 0x0000, b"UL", struct.pack("<I", len(meta_body))) + meta_body

    ds_parts: List[bytes] = [
        _elem_explicit(0x0008, 0x0016, b"UI", _pad_dicom_str("1.2.840.10008.5.1.4.1.1.2", b"UI")),
        _elem_explicit(0x0008, 0x0018, b"UI", _pad_dicom_str(sop_inst, b"UI")),
        _elem_explicit(0x0008, 0x0020, b"DA", _pad_dicom_str(study_date, b"DA")),
        _elem_explicit(0x0008, 0x0050, b"SH", _pad_dicom_str(accession, b"SH")),
    ]
    if add_private_tag:
        ds_parts.append(_elem_explicit(0x0009, 0x0010, b"LO", _pad_dicom_str("ACME_PRIV", b"LO")))
        ds_parts.append(_elem_explicit(0x0009, 0x1001, b"LO", _pad_dicom_str("SECRET", b"LO")))

    ds_parts.extend([
        _elem_explicit(0x0010, 0x0010, b"PN", _pad_dicom_str(patient_name, b"PN")),
        _elem_explicit(0x0010, 0x0020, b"LO", _pad_dicom_str(patient_id, b"LO")),
        _elem_explicit(0x0010, 0x0030, b"DA", _pad_dicom_str(birth_date, b"DA")),
        _elem_explicit(0x0012, 0x0062, b"CS", _pad_dicom_str(pir, b"CS")),
    ])

    sq_items = b"".join(
        _sq_item(
            _elem_explicit(0x0008, 0x0100, b"SH", _pad_dicom_str(c, b"SH"))
            + _elem_explicit(0x0008, 0x0102, b"SH", _pad_dicom_str("DCM", b"SH"))
        )
        for c in codes
    )
    ds_parts.append(_elem_explicit(0x0012, 0x0064, b"SQ", sq_items))
    ds_parts.extend([
        _elem_explicit(0x0020, 0x000D, b"UI", _pad_dicom_str(study_uid, b"UI")),
        _elem_explicit(0x0020, 0x000E, b"UI", _pad_dicom_str(series_uid, b"UI")),
    ])
    if ltim is not None:
        ds_parts.append(_elem_explicit(0x0028, 0x0303, b"CS", _pad_dicom_str(ltim, b"CS")))
    if nested_ltim is not None:
        sub_item = _sq_item(_elem_explicit(0x0028, 0x0303, b"CS", _pad_dicom_str(nested_ltim, b"CS")))
        ds_parts.append(_elem_explicit(0x0008, 0x1115, b"SQ", sub_item))
    if include_pixels:
        ds_parts.append(_elem_explicit(0x7FE0, 0x0010, b"OW", b"\x10\x04" * 16))
    return preamble + meta + b"".join(ds_parts)


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        key = b"\x22" * 32
        key_file = tmp / "anon.key"
        key_file.write_text("# Demo key\n" + key.hex() + "\r\n", encoding="ascii")
        assert v.load_key_file_bytes(key_file) == key, "hex key file must decode to 32 raw bytes"

        raw_key_file = tmp / "raw.key"
        raw_key_file.write_bytes(key)
        assert v.load_key_file_bytes(raw_key_file) == key, "32-byte raw binary key must be supported"

        dpapi_file = tmp / "clinic.dpapi"
        dpapi_file.write_bytes(b"DCMDPAP1\x01\x02\x03\x04")
        try:
            v.load_key_file_bytes(dpapi_file)
            raise AssertionError("DPAPI key must be rejected with clear ValueError")
        except ValueError:
            pass

        valid_dcm_bytes = build_minimal_part10()
        dcm = tmp / "sample.dcm"
        dcm.write_bytes(valid_dcm_bytes)

        base_cert_fields = {
            "cert_version": "1.0",
            "outcome": "SCREENED",
            "publication": "released",
            "pixel_check": "checked_found_masked",
            "outcome_reasons": [],
            "admission": {"admitted": True, "allowlist": {"version": "5", "sha256": "02a2e6fe" + "0" * 56}},
            "output": {"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)},
            "pixels": {
                "review_required": False,
                "ignored_words": 0,
                "lines_masked": 1,
                "masked_lines": [{"box": [0, 0, 10, 10], "reason": "не из белого списка"}],
            },
            "created": "2026-11-27T10:00:00+00:00",
        }
        cert = sign_cert(base_cert_fields, key)
        cp = tmp / "sample.dcm.deid.json"
        cp.write_text(json.dumps(cert), encoding="utf-8")

        assert v.verify_cert(cp, key) == 0, "valid Part-10 DICOM + PS3.15 (0028,0303)=MODIFIED must pass"

        # Проверка парной сверки (--input vs --cert)
        in_dcm = tmp / "in_sample.dcm"
        in_dcm.write_bytes(
            build_minimal_part10(
                sop_inst="1.2.826.0.1.3680043.2.1125.1",
                study_uid="1.2.826.0.1.3680043.2.1125.2",
                series_uid="1.2.826.0.1.3680043.2.1125.3",
                patient_name="IVANOV^SERGEI",
                patient_id="PID-778899",
                birth_date="19780514",
                study_date="20260410",
                accession="ACC-9911",
                pir="NO",
            )
        )
        assert v.verify_cert(cp, key, input_dcm_path=in_dcm) == 0, "clean before/after pair must pass"

        # Саботаж пары: входное ФИО осталось в выходном заголовке
        leaked_dcm = build_minimal_part10(patient_name="IVANOV^SERGEI")
        dcm.write_bytes(leaked_dcm)
        cp.write_text(json.dumps(sign_cert(dict(base_cert_fields, output={"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)}), key)), encoding="utf-8")
        assert v.verify_cert(cp, key, input_dcm_path=in_dcm) == 1, "leaked input PatientName must fail pair check"

        # Саботаж PS3.15 E.3.6: заявлен код 113107, но отсутствует (0028,0303)=MODIFIED
        missing_ltim_bytes = build_minimal_part10(ltim=None)
        dcm.write_bytes(missing_ltim_bytes)
        cp.write_text(json.dumps(sign_cert(dict(base_cert_fields, output={"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)}), key)), encoding="utf-8")
        assert v.verify_cert(cp, key) == 1, "missing (0028,0303) with code 113107 must fail!"

        # Саботаж вложенного SQ: противоречивый (0028,0303)=UNMODIFIED внутри последовательности
        bad_nested_ltim = build_minimal_part10(ltim="MODIFIED", nested_ltim="UNMODIFIED")
        dcm.write_bytes(bad_nested_ltim)
        cp.write_text(json.dumps(sign_cert(dict(base_cert_fields, output={"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)}), key)), encoding="utf-8")
        assert v.verify_cert(cp, key) == 1, "contradictory nested (0028,0303) must fail!"

        # Саботаж приватного тега без 113111
        priv_bytes = build_minimal_part10(add_private_tag=True)
        dcm.write_bytes(priv_bytes)
        cp.write_text(json.dumps(sign_cert(dict(base_cert_fields, output={"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)}), key)), encoding="utf-8")
        assert v.verify_cert(cp, key) == 1, "private tag without 113111 must fail!"

        # Саботаж ненулевой 128-байтовой преамбулы
        bad_pre = build_minimal_part10(preamble_byte=0x41)
        dcm.write_bytes(bad_pre)
        cp.write_text(json.dumps(sign_cert(dict(base_cert_fields, output={"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)}), key)), encoding="utf-8")
        assert v.verify_cert(cp, key) == 1, "non-zero 128-byte preamble must fail!"

        # Восстанавливаем эталонный DICOM и базовые саботажи
        dcm.write_bytes(valid_dcm_bytes)
        cp.write_text(json.dumps(cert), encoding="utf-8")
        assert v.verify_cert(cp, None) == 1, "missing key without --allow-unsealed must fail"
        dcm.write_bytes(valid_dcm_bytes[:-1] + b"\xff")
        assert v.verify_cert(cp, key) == 1, "tampered output DICOM must fail"
        dcm.unlink()
        assert v.verify_cert(cp, key) == 1, "deleted output DICOM must fail"
        dcm.write_bytes(valid_dcm_bytes)
        assert v.verify_cert(cp, b"\x33" * 32) == 1, "wrong HMAC key must fail"

        cert_rev = sign_cert(dict(cert, outcome="REVIEW", publication="quarantine"), key)
        cp_rev = tmp / "rev.dcm.deid.json"
        cp_rev.write_text(json.dumps(cert_rev), encoding="utf-8")
        assert v.verify_cert(cp_rev, key) == 1, "REVIEW outcome must not pass as clean release"

        cert_txt = sign_cert(
            dict(cert, pixels={"review_required": False, "ignored_words": 0, "masked_lines": [{"text": "", "box": [0, 0, 10, 10]}]}),
            key,
        )
        cp.write_text(json.dumps(cert_txt), encoding="utf-8")
        assert v.verify_cert(cp, key) == 1, "masked_lines containing 'text' key must fail"
        cp.write_text(json.dumps(cert), encoding="utf-8")

        qdir = tmp / "_quarantine"
        qdir.mkdir()
        qdcm = qdir / "sample.dcm"
        qdcm.write_bytes(valid_dcm_bytes)
        qcp = qdir / "sample.dcm.deid.json"
        qcp.write_text(json.dumps(cert), encoding="utf-8")
        assert v.verify_cert(qcp, key) == 1, "SCREENED cert inside _quarantine must fail"

        ref_cert = sign_cert({
            "cert_version": "1.0",
            "outcome": "REFUSED",
            "outcome_reasons": ["ModalityLUTSequence не допускается"],
            "output": None,
            "created": "2026-11-27T10:00:00+00:00",
        }, key)
        ref_p = tmp / "bad.dcm.refused.json"
        ref_p.write_text(json.dumps(ref_cert), encoding="utf-8")
        assert v.verify_cert(ref_p, key, expect_refused=False) == 1, "REFUSED must fail closed without --expect-refused"
        assert v.verify_cert(ref_p, key, expect_refused=True) == 0, "valid REFUSED cert must pass with --expect-refused"

        old_seal = "a" * 64
        cur_cert = sign_cert(dict(
            cert,
            pixel_check="curator_approved",
            prev=old_seal,
            quarantine_origin={"outcome": "REVIEW", "seal": old_seal},
            curator_review={
                "curator_id": "dr_ivanov",
                "curator_hmac": v.text_hmac_hex16(key, "curator", "dr_ivanov"),
                "reason": "проверено визуально",
                "approved_at": "2026-11-27T11:00:00+00:00",
                "prev_quarantine_seal": old_seal,
            },
        ), key)
        cp.write_text(json.dumps(cur_cert), encoding="utf-8")
        assert v.verify_cert(cp, key) == 0, "valid curator_approved cert must pass"
        bad_cur = dict(cur_cert)
        bad_cur["curator_review"] = dict(cur_cert["curator_review"], curator_hmac="0" * 16)
        bad_cur = sign_cert(bad_cur, key)
        cp.write_text(json.dumps(bad_cur), encoding="utf-8")
        assert v.verify_cert(cp, key) == 1, "forged curator_hmac must fail"

        # Хеш-цепь аудита (формат Gateway Pro: prev + seal + канонический JSON)
        r1 = {"event": "sr_cleaned", "outcome": "SCREENED", "prev": "", "seal": "b" * 64, "ts": "2026-11-27T10:00:00Z"}
        l1 = v.canonical_json_str(r1)
        r2 = {"event": "sr_cleaned", "outcome": "PROVEN", "prev": v.audit_zero_chain_hex(l1.encode("utf-8")), "seal": "c" * 64, "ts": "2026-11-27T10:00:01Z"}
        l2 = v.canonical_json_str(r2)
        ap = tmp / "gw.jsonl"
        ap.write_text(l1 + "\n" + l2 + "\n", encoding="utf-8")
        assert v.verify_audit(ap) == 0, "valid gateway audit chain must pass"
        r2_bad = dict(r2, outcome="REVIEW")
        r3 = {"event": "next", "prev": v.audit_zero_chain_hex(l2.encode("utf-8")), "ts": "2026-11-27T10:00:02Z"}
        ap.write_text(l1 + "\n" + v.canonical_json_str(r2_bad) + "\n" + v.canonical_json_str(r3) + "\n", encoding="utf-8")
        assert v.verify_audit(ap) == 1, "tampered audit entry must break chain"
        ap_empty = tmp / "empty.jsonl"
        ap_empty.write_text("", encoding="utf-8")
        assert v.verify_audit(ap_empty) == 1, "empty audit log must fail closed"

        # Подписанный Ed25519 манифест, Evidence Registry, все политики и SBOM
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("44" * 32))
        pub_hex = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        man = {
            "version": "0.9.2",
            "published_at": "2026-11-27",
            "installer_url": "https://dicom.by/downloads/DICOM-BY-0.9.2-Setup.exe",
            "installer_sha256": "ab" * 32,
            "installer_size": 51480000,
        }
        msg = f"dicom-by-update-v1|{man['version']}|{man['published_at']}|{man['installer_url']}|{man['installer_sha256']}|{man['installer_size']}".encode("utf-8")
        man["signature_ed25519"] = b64u(priv.sign(msg))
        mp = tmp / "windows-x64.json"
        mp.write_text(json.dumps(man), encoding="utf-8")
        assert v.verify_manifest(mp, pub_hex) == 0, "signed manifest must pass"

        pol_dir = tmp / "standard"
        pol_dir.mkdir()
        adm_body = {"version": "5", "combos": []}
        adm_canon_sha = hashlib.sha256(v.canonical_json_bytes(adm_body)).hexdigest()
        adm_full = dict(adm_body, sha256=adm_canon_sha)
        adm = pol_dir / "admission_v5.json"
        adm.write_text(json.dumps(adm_full, indent=2) + "\n", encoding="utf-8")
        adm_sha = v.sha256_file_hex(adm)

        sbom_p = tmp / "sbom-0.9.2.cdx.json"
        sbom_p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5"}), encoding="utf-8")
        sbom_sha = v.sha256_file_hex(sbom_p)

        ev = {
            "schema_version": "2.1",
            "update_signing_pubkey_ed25519": pub_hex,
            "editions": {"desktop_community": {"version": "0.9.2"}},
            "core": {
                "admission_canonical_rules_sha256": adm_canon_sha,
                "standards_sha256": {"admission_v5.json": adm_sha},
            },
            "supply_chain": {"sbom_cyclonedx_sha256": sbom_sha},
        }
        ev["signature_ed25519"] = b64u(priv.sign(v.canonical_json_bytes(ev)))
        ep = tmp / "RELEASE_MANIFEST.json"
        ep.write_text(json.dumps(ev), encoding="utf-8")
        assert v.verify_evidence(ep, adm, pol_dir, sbom_p, pub_hex) == 0, "signed evidence + policies + sbom must pass"

        # Комбинированный вызов --manifest + --evidence обязан проверять ОБЕ подписи
        ev_tampered = dict(ev, editions={"desktop_community": {"version": "9.9.9"}})
        ep.write_text(json.dumps(ev_tampered), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(Path(v.__file__).resolve()), "--manifest", str(mp), "--evidence", str(ep), "--admission", str(adm), "--pub-hex", pub_hex],
            capture_output=True, text=True,
        )
        assert proc.returncode == 1, "combined --manifest + tampered --evidence must fail!"

        ep.write_text(json.dumps(ev), encoding="utf-8")
        man_tampered = dict(man, installer_size=12345)
        mp.write_text(json.dumps(man_tampered), encoding="utf-8")
        proc2 = subprocess.run(
            [sys.executable, str(Path(v.__file__).resolve()), "--manifest", str(mp), "--evidence", str(ep), "--admission", str(adm), "--pub-hex", pub_hex],
            capture_output=True, text=True,
        )
        assert proc2.returncode == 1, "combined tampered --manifest + valid --evidence must fail!"

    print("ИТОГ test_verify: PASS")


if __name__ == "__main__":
    main()
