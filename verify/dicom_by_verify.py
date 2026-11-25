#!/usr/bin/env python3
"""Независимый открытый верификатор DICOM.BY (лицензия MIT).

Позволяет медицинской организации или аудитору независимо от бинарников DICOM.BY проверять:
  1. Сертификаты обработки (.deid.json / .refused.json) по HMAC-SHA-256 и хэш выходного DICOM;
  2. Журнал шлюза Gateway Pro (.jsonl) по криптографической хеш-цепи SHA-256;
  3. Подпись Ed25519 манифеста обновлений (windows-x64.json);
  4. Подпись Ed25519 паспорта доказательств (RELEASE_MANIFEST.json) и SHA-256 матрицы admission_v5.json.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UPDATE_ED25519_PUB_HEX = "e3e4a53f46c919f587460c6522c00c9e53299f1c564619d997ccb6d21b8b45c7"
VALID_OUTCOMES = {"PROVEN", "SCREENED", "REVIEW", "REFUSED"}


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_file_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def verify_cert(cert_path: Path, key_bytes: Optional[bytes]) -> int:
    cert = json.loads(cert_path.read_text(encoding="utf-8"))
    outcome = cert.get("outcome")
    if outcome not in VALID_OUTCOMES:
        print(f"FAIL: недопустимый outcome={outcome!r} в {cert_path}", file=sys.stderr)
        return 1

    # Проверка SHA-256 выходного DICOM-файла, если он лежит рядом с .deid.json
    if outcome != "REFUSED" and isinstance(cert.get("output"), dict):
        out_sha = (cert["output"].get("sha256") or "").lower()
        cand_name = cert["output"].get("name") or ""
        out_file = cert_path.with_name(cand_name) if cand_name else Path(str(cert_path).removesuffix(".deid.json"))
        if out_file.exists() and out_sha:
            actual = sha256_file_hex(out_file)
            if not hmac.compare_digest(actual, out_sha):
                print(f"FAIL: SHA-256 выходного файла {out_file.name} не сходится (actual={actual}, cert={out_sha})",
                      file=sys.stderr)
                return 1

    if key_bytes is not None:
        expected_seal = (cert.get("seal") or "").lower()
        body = {k: v for k, v in cert.items() if k not in ("seal", "created")}
        computed = hmac.new(key_bytes, canonical_json_bytes(body), hashlib.sha256).hexdigest().lower()
        if not hmac.compare_digest(expected_seal, computed):
            print(f"FAIL: подпись HMAC-SHA-256 (seal) в {cert_path.name} не верна", file=sys.stderr)
            return 1

    print(f"OK cert={cert_path.name} outcome={outcome} seal_checked={key_bytes is not None}")
    return 0


def verify_audit(audit_path: Path) -> int:
    prev = "0" * 64
    count = 0
    for lineno, raw in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        rec = json.loads(line)
        rec_prev = (rec.get("prev_hash") or "").lower()
        rec_hash = (rec.get("entry_hash") or "").lower()
        if rec_prev != prev:
            print(f"FAIL: разрыв prev_hash в строке {lineno}", file=sys.stderr)
            return 1
        body = {k: v for k, v in rec.items() if k != "entry_hash"}
        computed = hashlib.sha256(canonical_json_bytes(body)).hexdigest().lower()
        if not hmac.compare_digest(rec_hash, computed):
            print(f"FAIL: искажён entry_hash в строке {lineno}", file=sys.stderr)
            return 1
        prev = rec_hash
        count += 1
    print(f"OK audit={audit_path.name} entries={count}")
    return 0


def verify_manifest(manifest_path: Path, pub_hex: str) -> int:
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    sig_s = obj.get("signature_ed25519") or ""
    if not sig_s:
        print("FAIL: отсутствует signature_ed25519 в манифесте обновлений", file=sys.stderr)
        return 1
    msg = "|".join([
        "dicom-by-update-v1",
        str(obj["version"]),
        str(obj["published_at"]),
        str(obj["installer_url"]),
        str(obj["installer_sha256"]).lower(),
        str(int(obj["installer_size"])),
    ]).encode("utf-8")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(b64url_decode(sig_s), msg)
    except InvalidSignature:
        print("FAIL: подпись Ed25519 манифеста обновлений недействительна", file=sys.stderr)
        return 1
    print(f"OK manifest={manifest_path.name} version={obj['version']}")
    return 0


def verify_evidence(evidence_path: Path, admission_path: Optional[Path], pub_hex: str) -> int:
    obj = json.loads(evidence_path.read_text(encoding="utf-8"))
    sig_s = obj.get("signature_ed25519") or ""
    if not sig_s:
        print("FAIL: отсутствует signature_ed25519 в RELEASE_MANIFEST.json", file=sys.stderr)
        return 1
    body = {k: v for k, v in obj.items() if k not in ("signing_key_id", "signature_ed25519")}
    embed_pub = (obj.get("update_signing_pubkey_ed25519") or "").strip().lower()
    if embed_pub and embed_pub != pub_hex.lower():
        print("FAIL: встроенный публичный ключ в RELEASE_MANIFEST.json не совпадает с доверенным", file=sys.stderr)
        return 1
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(b64url_decode(sig_s), canonical_json_bytes(body))
    except InvalidSignature:
        print("FAIL: подпись Ed25519 паспорта доказательств недействительна", file=sys.stderr)
        return 1

    if admission_path is not None:
        exp_sha = (obj.get("core", {}).get("standards_sha256", {}).get("admission_v5.json") or "").lower()
        act_sha = sha256_file_hex(admission_path)
        if not exp_sha or not hmac.compare_digest(exp_sha, act_sha):
            print(f"FAIL: SHA-256 admission_v5.json не совпадает (expected={exp_sha}, actual={act_sha})",
                  file=sys.stderr)
            return 1

    ver = obj.get("editions", {}).get("desktop_community", {}).get("version", "?")
    print(f"OK evidence={evidence_path.name} schema={obj.get('schema_version')} desktop={ver}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Независимый открытый верификатор DICOM.BY (MIT)")
    p.add_argument("--cert", type=Path)
    p.add_argument("--key-hex", default="")
    p.add_argument("--key-file", type=Path)
    p.add_argument("--audit", type=Path)
    p.add_argument("--manifest", type=Path)
    p.add_argument("--evidence", type=Path)
    p.add_argument("--admission", type=Path)
    p.add_argument("--pub-hex", default=UPDATE_ED25519_PUB_HEX)
    args = p.parse_args()

    key_bytes = None
    if args.key_hex:
        key_bytes = bytes.fromhex(args.key_hex.strip())
    elif args.key_file:
        key_bytes = args.key_file.read_bytes()

    if args.cert:
        return verify_cert(args.cert, key_bytes)
    if args.audit:
        return verify_audit(args.audit)
    if args.manifest:
        return verify_manifest(args.manifest, args.pub_hex)
    if args.evidence:
        return verify_evidence(args.evidence, args.admission, args.pub_hex)

    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
