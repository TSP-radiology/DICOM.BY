"""Модульные и саботажные проверки для независимого верификатора DICOM.BY."""
import base64
import hashlib
import hmac
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import dicom_by_verify as v


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        key = b"\x22" * 32
        dcm = tmp / "sample.dcm"
        dcm.write_bytes(b"DICM_FAKE_PAYLOAD")
        cert = {
            "cert_version": "1",
            "outcome": "SCREENED",
            "outcome_reasons": [],
            "output": {"name": "sample.dcm", "sha256": v.sha256_file_hex(dcm)},
            "created": "2026-11-25T10:00:00+00:00",
        }
        cert["seal"] = hmac.new(key, v.canonical_json_bytes({k: cert[k] for k in cert if k != "created"}), hashlib.sha256).hexdigest()
        cp = tmp / "sample.dcm.deid.json"
        cp.write_text(json.dumps(cert), encoding="utf-8")

        assert v.verify_cert(cp, key) == 0, "valid cert must pass"
        # Саботаж 1: порча 1 байта DICOM
        dcm.write_bytes(b"DICM_FAKE_PAYLOAX")
        assert v.verify_cert(cp, key) == 1, "tampered output DICOM must fail"
        dcm.write_bytes(b"DICM_FAKE_PAYLOAD")
        # Саботаж 2: неверный ключ
        assert v.verify_cert(cp, b"\x33" * 32) == 1, "wrong HMAC key must fail"

        # Хеш-цепь аудита
        r1 = {"prev_hash": "0" * 64, "event": "START"}
        r1["entry_hash"] = hashlib.sha256(v.canonical_json_bytes(r1)).hexdigest()
        r2 = {"prev_hash": r1["entry_hash"], "event": "RELEASED"}
        r2["entry_hash"] = hashlib.sha256(v.canonical_json_bytes(r2)).hexdigest()
        ap = tmp / "gw.jsonl"
        ap.write_text(json.dumps(r1) + "\n" + json.dumps(r2) + "\n", encoding="utf-8")
        assert v.verify_audit(ap) == 0, "valid audit chain must pass"
        r2["event"] = "TAMPERED"
        ap.write_text(json.dumps(r1) + "\n" + json.dumps(r2) + "\n", encoding="utf-8")
        assert v.verify_audit(ap) == 1, "tampered audit entry must fail"

        # Подписанный Ed25519 манифест и Evidence Registry
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("44" * 32))
        pub_hex = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        man = {
            "version": "0.4.3",
            "published_at": "2026-11-25",
            "installer_url": "https://dicom.by/downloads/DICOM-BY-0.4.3-Setup.exe",
            "installer_sha256": "ab" * 32,
            "installer_size": 123456,
        }
        msg = f"dicom-by-update-v1|{man['version']}|{man['published_at']}|{man['installer_url']}|{man['installer_sha256']}|{man['installer_size']}".encode("utf-8")
        man["signature_ed25519"] = b64u(priv.sign(msg))
        mp = tmp / "windows-x64.json"
        mp.write_text(json.dumps(man), encoding="utf-8")
        assert v.verify_manifest(mp, pub_hex) == 0, "signed manifest must pass"
        man["installer_size"] = 123457
        mp.write_text(json.dumps(man), encoding="utf-8")
        assert v.verify_manifest(mp, pub_hex) == 1, "tampered manifest size must fail"

        adm = tmp / "admission_v5.json"
        adm.write_bytes(b"{}")
        adm_sha = v.sha256_file_hex(adm)
        ev = {
            "schema_version": "2.0",
            "update_signing_pubkey_ed25519": pub_hex,
            "editions": {"desktop_community": {"version": "0.4.3"}},
            "core": {"standards_sha256": {"admission_v5.json": adm_sha}},
        }
        ev["signature_ed25519"] = b64u(priv.sign(v.canonical_json_bytes(ev)))
        ep = tmp / "RELEASE_MANIFEST.json"
        ep.write_text(json.dumps(ev), encoding="utf-8")
        assert v.verify_evidence(ep, adm, pub_hex) == 0, "signed evidence registry must pass"
        ev["editions"]["desktop_community"]["version"] = "9.9.9"
        ep.write_text(json.dumps(ev), encoding="utf-8")
        assert v.verify_evidence(ep, adm, pub_hex) == 1, "tampered evidence registry must fail"

    print("ИТОГ test_verify: PASS")


if __name__ == "__main__":
    main()
