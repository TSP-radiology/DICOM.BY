#!/usr/bin/env python3
"""Независимый открытый верификатор DICOM.BY (версия 0.9.4, лицензия MIT).

Зависимости: стандартная библиотека Python 3.9+ и пакет `cryptography` (для Ed25519).
Не требует установленного pydicom, DCMTK или закрытых бинарников DICOM.BY.

Проверяет:
  1. Сертификаты выпуска (.deid.json) и записи об отказе (.refused.json):
     - печать учреждения HMAC-SHA-256 (seal) — принимает 64-символьный hex-ключ или 32-байтовый бинарный ключ;
     - побайтовый SHA-256 выходного DICOM-файла и контрактные инварианты исходов PROVEN/SCREENED/REVIEW/REFUSED;
     - бинарную структуру DICOM Part 10 (нулевая 128-байтовая преамбула + DICM, совпадение SOPInstanceUID в
       File Meta (0002,0003) и наборе данных (0008,0018), PatientIdentityRemoved (0012,0062) = YES,
       отсутствие неразрешённых приватных тегов, контроль SHA-256 инкапсулированных сжатых фрагментов при
       Zero-Recompression Bitstream Pass-Through и строгое выполнение DICOM PS3.15 E.3.6:
       при коде 113107 обязателен LongitudinalTemporalInformationModified (0028,0303) = MODIFIED на верхнем
       уровне и во всех вложенных последовательностях SQ);
     - при передаче --input <in.dcm>: независимую парную сверку удаления входных PHI (ФИО, ID, дата рождения,
       AccessionNumber), сдвига дат, перегенерации UID в корень 2.25.* и побайтового совпадения сжатых фрагментов;
  2. Журнал шлюза Gateway Pro (.jsonl) по непрерывной криптографической цепи (prev + entry_hmac + .head.json);
  3. Подпись Ed25519 манифеста обновлений (--manifest / --update-manifest);
  4. Подпись Ed25519 паспорта релиза (--evidence), оба SHA-256 таблицы admission_v7.json (--admission),
     SHA-256 всех политик PS3.15 (--policies-dir), нормативных документов (--docs-dir) и CycloneDX SBOM (--sbom).
     При комбинированном вызове выполняются ВСЕ переданные проверки с агрегацией кода возврата.
"""
import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UPDATE_ED25519_PUB_HEX = "e3e4a53f46c919f587460c6522c00c9e53299f1c564619d997ccb6d21b8b45c7"
VALID_OUTCOMES = {"PROVEN", "SCREENED", "REVIEW", "REFUSED"}
RELEASABLE_OUTCOMES = {"PROVEN", "SCREENED"}
SCREENED_PIXEL_CHECKS = {
    "checked_not_found",
    "checked_found_masked",
    "checked_found_verified",
    "curator_approved",
}
LONG_LEN_VRS = {b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"SQ", b"SV", b"UC", b"UN", b"UR", b"UT", b"UV"}
IMPLICIT_KNOWN_SQ_TAGS = {
    (0x0008, 0x1110),
    (0x0008, 0x1115),
    (0x0008, 0x1140),
    (0x0012, 0x0064),
    (0x0028, 0x3000),
    (0x0028, 0x3010),
    (0x0040, 0x0275),
    (0x0040, 0xA043),
    (0x0040, 0xA730),
    (0x5200, 0x9229),
    (0x5200, 0x9230),
}


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def canonical_json_str(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def canonical_json_bytes(obj: dict) -> bytes:
    return canonical_json_str(obj).encode("utf-8")


def sha256_file_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def text_hmac_hex16(key_bytes: bytes, domain: str, value: str) -> str:
    msg = f"dicom-anonymizer|{domain}|{value}".encode("utf-8")
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest().lower()[:16]


def is_hex64(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())


def load_key_file_bytes(key_path: Path) -> bytes:
    raw = key_path.read_bytes()
    if raw.startswith(b"DCMDPAP1"):
        raise ValueError(
            f"Файл ключа {key_path.name} защищён контейнером Windows DPAPI (DCMDPAP1). "
            "Используйте нативный dicom-verify.exe --key-dpapi на рабочей станции Windows "
            "или передайте hex-ключ через --key-hex / текстовый .key."
        )
    if not raw:
        raise ValueError(f"Файл ключа пуст: {key_path}")
    try:
        text = raw.decode("utf-8-sig", errors="strict")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            cleaned = "".join(ch for ch in stripped if ch not in " \t\r\n")
            if cleaned.lower().startswith("0x"):
                cleaned = cleaned[2:]
            if len(cleaned) >= 32 and len(cleaned) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
                return bytes.fromhex(cleaned)
    except UnicodeDecodeError:
        pass
    # Поддержка сырого бинарного ключа (16, 24 или 32 байта), если файл не является ASCII-hex строкой
    if len(raw) in (16, 24, 32):
        return raw
    raise ValueError(
        f"Некорректный формат ключа в {key_path.name}: ожидается 64-символьная hex-строка (>=32 hex) "
        f"или сырой бинарный ключ 16/24/32 байта (получено {len(raw)} байт)."
    )


class DicomInspection:
    def __init__(self) -> None:
        self.meta_tags: Dict[Tuple[int, int], bytes] = {}
        self.top_tags: Dict[Tuple[int, int], bytes] = {}
        self.all_values: List[Tuple[str, Tuple[int, int], bytes]] = []
        self.deid_codes: Set[str] = set()
        self.private_tags: List[str] = []
        self.nested_ltim: List[Tuple[str, str]] = []
        self.has_pixel_data: bool = False
        self.encapsulated_pixel_sha256: str = ""
        self.header_end_offset: int = 0


def _decode_str(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip(" \t\r\n\x00")


def _skip_undefined_value(buf: bytes, pos: int, end: int) -> int:
    """Пропускает неопределённую длину (0xFFFFFFFF) вплоть до Sequence Delimitation Item (FFFE,E0DD)."""
    depth = 1
    p = pos
    while p + 8 <= end and depth > 0:
        g, e, ln = struct.unpack_from("<HHI", buf, p)
        p += 8
        if g == 0xFFFE and e == 0xE0DD:
            depth -= 1
            continue
        if g == 0xFFFE and e == 0xE00D:
            continue
        if g == 0xFFFE and e == 0xE000:
            if ln != 0xFFFFFFFF:
                p = min(end, p + ln)
            continue
        if ln == 0xFFFFFFFF:
            depth += 1
        else:
            p = min(end, p + ln)
    return p


def _parse_dataset_region(
    buf: bytes,
    start: int,
    end: int,
    implicit_vr: bool,
    path_prefix: str,
    depth: int,
    in_dmcs: bool,
    out: DicomInspection,
) -> int:
    if depth > 32:
        raise ValueError("Превышена максимальная глубина вложенности SQ (> 32)")
    p = start
    while p + 8 <= end:
        g, e = struct.unpack_from("<HH", buf, p)
        if g == 0xFFFE:
            if e in (0xE00D, 0xE0DD):
                return p + 8
            if e == 0xE000:
                ln = struct.unpack_from("<I", buf, p + 4)[0]
                p += 8
                if ln != 0xFFFFFFFF:
                    p = min(end, p + ln)
                continue
        if depth == 0 and (g, e) == (0x7FE0, 0x0010):
            out.has_pixel_data = True
            if out.header_end_offset == 0:
                out.header_end_offset = p
            if not implicit_vr and p + 12 <= end:
                px_ln = struct.unpack_from("<I", buf, p + 8)[0]
                if px_ln == 0xFFFFFFFF:
                    h_enc = hashlib.sha256()
                    ip = p + 12
                    saw_delim = False
                    while ip + 8 <= end:
                        ig, ie, iln = struct.unpack_from("<HHI", buf, ip)
                        ip += 8
                        if ig == 0xFFFE and ie == 0xE0DD:
                            saw_delim = True
                            break
                        if ig == 0xFFFE and ie == 0xE000 and iln != 0xFFFFFFFF and ip + iln <= end:
                            if iln > 0:
                                h_enc.update(buf[ip : ip + iln])
                            ip += iln
                        else:
                            break
                    if saw_delim:
                        out.encapsulated_pixel_sha256 = h_enc.hexdigest().lower()
            return end

        tag_label = f"({g:04X},{e:04X})"
        cur_path = f"{path_prefix}/{tag_label}" if path_prefix else tag_label

        if g > 0x0008 and (g % 2 == 1):
            out.private_tags.append(cur_path)

        if implicit_vr:
            ln = struct.unpack_from("<I", buf, p + 4)[0]
            hdr = 8
            peek_item = (
                ln != 0xFFFFFFFF
                and ln >= 8
                and p + 8 + 8 <= end
                and buf[p + 8 : p + 12] == b"\xfe\xff\x00\xe0"
                and (
                    struct.unpack_from("<I", buf, p + 12)[0] == 0xFFFFFFFF
                    or 8 + struct.unpack_from("<I", buf, p + 12)[0] <= ln
                )
            )
            is_sq = (ln == 0xFFFFFFFF) or ((g, e) in IMPLICIT_KNOWN_SQ_TAGS) or peek_item
        else:
            vr = buf[p + 4 : p + 6]
            if vr in LONG_LEN_VRS:
                if p + 12 > end:
                    break
                ln = struct.unpack_from("<I", buf, p + 8)[0]
                hdr = 12
            else:
                ln = struct.unpack_from("<H", buf, p + 6)[0]
                hdr = 8
            is_sq = vr == b"SQ"

        val_start = p + hdr
        if is_sq:
            is_this_dmcs = in_dmcs or (depth == 0 and (g, e) == (0x0012, 0x0064))
            if ln == 0xFFFFFFFF:
                ip = val_start
                idx = 0
                while ip + 8 <= end:
                    ig, ie, iln = struct.unpack_from("<HHI", buf, ip)
                    ip += 8
                    if ig == 0xFFFE and ie == 0xE0DD:
                        break
                    if ig == 0xFFFE and ie == 0xE000:
                        if iln == 0xFFFFFFFF:
                            ip = _parse_dataset_region(
                                buf, ip, end, implicit_vr, f"{cur_path}[{idx}]", depth + 1, is_this_dmcs, out
                            )
                        else:
                            item_end = min(end, ip + iln)
                            _parse_dataset_region(
                                buf, ip, item_end, implicit_vr, f"{cur_path}[{idx}]", depth + 1, is_this_dmcs, out
                            )
                            ip = item_end
                        idx += 1
                    else:
                        break
                p = ip
            else:
                sq_end = min(end, val_start + ln)
                ip = val_start
                idx = 0
                while ip + 8 <= sq_end:
                    ig, ie, iln = struct.unpack_from("<HHI", buf, ip)
                    ip += 8
                    if ig == 0xFFFE and ie == 0xE000:
                        if iln == 0xFFFFFFFF:
                            ip = _parse_dataset_region(
                                buf, ip, sq_end, implicit_vr, f"{cur_path}[{idx}]", depth + 1, is_this_dmcs, out
                            )
                        else:
                            item_end = min(sq_end, ip + iln)
                            _parse_dataset_region(
                                buf, ip, item_end, implicit_vr, f"{cur_path}[{idx}]", depth + 1, is_this_dmcs, out
                            )
                            ip = item_end
                        idx += 1
                    else:
                        break
                p = sq_end
            continue

        if ln == 0xFFFFFFFF:
            p = _skip_undefined_value(buf, val_start, end)
            continue

        val_end = min(end, val_start + ln)
        val_bytes = buf[val_start:val_end]
        if depth == 0:
            out.top_tags[(g, e)] = val_bytes
        else:
            if (g, e) == (0x0028, 0x0303):
                out.nested_ltim.append((cur_path, _decode_str(val_bytes).upper()))
            if in_dmcs and (g, e) == (0x0008, 0x0100):
                out.deid_codes.add(_decode_str(val_bytes))
        out.all_values.append((cur_path, (g, e), val_bytes))
        p = val_end

    if depth == 0 and out.header_end_offset == 0:
        out.header_end_offset = end
    return p


def inspect_dicom_part10(dcm_path: Path) -> DicomInspection:
    buf = dcm_path.read_bytes()
    if len(buf) < 132 or buf[128:132] != b"DICM":
        raise ValueError(f"{dcm_path.name}: отсутствует сигнатура DICM по смещению 128")
    if buf[:128] != b"\x00" * 128:
        raise ValueError(f"{dcm_path.name}: 128-байтовая преамбула не обнулена")

    info = DicomInspection()
    p = 132
    end = len(buf)
    while p + 8 <= end:
        g, e = struct.unpack_from("<HH", buf, p)
        if g != 0x0002:
            break
        vr = buf[p + 4 : p + 6]
        if vr in LONG_LEN_VRS:
            if p + 12 > end:
                raise ValueError(f"{dcm_path.name}: обрезан заголовок File Meta")
            ln = struct.unpack_from("<I", buf, p + 8)[0]
            hdr = 12
        else:
            ln = struct.unpack_from("<H", buf, p + 6)[0]
            hdr = 8
        val_end = min(end, p + hdr + ln)
        info.meta_tags[(g, e)] = buf[p + hdr : val_end]
        p = val_end

    ts_uid = _decode_str(info.meta_tags.get((0x0002, 0x0010), b""))
    if not ts_uid:
        raise ValueError(f"{dcm_path.name}: отсутствует (0002,0010) TransferSyntaxUID в File Meta")
    implicit_vr = ts_uid == "1.2.840.10008.1.2"
    _parse_dataset_region(buf, p, end, implicit_vr, "", 0, False, info)
    return info


def verify_dicom_binary_invariants(dcm_path: Path, outcome: str) -> Tuple[Optional[DicomInspection], int]:
    try:
        info = inspect_dicom_part10(dcm_path)
    except ValueError as exc:
        print(f"FAIL: нарушение структуры DICOM Part 10 ({exc})", file=sys.stderr)
        return None, 1

    meta_sop_inst = _decode_str(info.meta_tags.get((0x0002, 0x0003), b""))
    ds_sop_inst = _decode_str(info.top_tags.get((0x0008, 0x0018), b""))
    if not meta_sop_inst or meta_sop_inst != ds_sop_inst:
        print(
            f"FAIL: несовпадение SOPInstanceUID между File Meta ({meta_sop_inst!r}) и Dataset ({ds_sop_inst!r})",
            file=sys.stderr,
        )
        return None, 1

    pir = _decode_str(info.top_tags.get((0x0012, 0x0062), b"")).upper()
    want_pir = "YES" if outcome in RELEASABLE_OUTCOMES else "NO"
    if pir != want_pir:
        print(
            f"FAIL: PatientIdentityRemoved (0012,0062) = {pir!r}, ожидается {want_pir!r} для outcome={outcome}",
            file=sys.stderr,
        )
        return None, 1

    if outcome == "PROVEN" and info.has_pixel_data:
        print("FAIL: outcome=PROVEN недопустим для файла, содержащего PixelData (7FE0,0010)", file=sys.stderr)
        return None, 1

    if "113100" not in info.deid_codes:
        print("FAIL: в (0012,0064) DeidentificationMethodCodeSequence отсутствует базовый код 113100", file=sys.stderr)
        return None, 1

    if "113111" not in info.deid_codes and info.private_tags:
        print(
            f"FAIL: обнаружены приватные теги без опции 113111 (Retain Safe Private): {info.private_tags[:5]}",
            file=sys.stderr,
        )
        return None, 1

    # DICOM PS3.15 E.1 / E.3.6 / E.3.7: проверка обязательного LongitudinalTemporalInformationModified (0028,0303)
    want_ltim = (
        "UNMODIFIED"
        if "113106" in info.deid_codes
        else ("MODIFIED" if "113107" in info.deid_codes else "REMOVED")
    )
    got_ltim = _decode_str(info.top_tags.get((0x0028, 0x0303), b"")).upper()
    if got_ltim != want_ltim:
        print(
            f"FAIL: несоответствие DICOM PS3.15 E.3.6 в {dcm_path.name}: "
            f"LongitudinalTemporalInformationModified (0028,0303) = {got_ltim!r}, ожидается {want_ltim!r}",
            file=sys.stderr,
        )
        return None, 1
    for npath, nval in info.nested_ltim:
        if nval != want_ltim:
            print(
                f"FAIL: вложенный {npath} = {nval!r} противоречит ожидаемому {want_ltim!r}",
                file=sys.stderr,
            )
            return None, 1

    return info, 0


def verify_pair_diff(in_path: Path, out_path: Path, out_info: DicomInspection) -> int:
    if not in_path.is_file():
        print(f"FAIL: входной DICOM-файл для парной сверки не найден: {in_path}", file=sys.stderr)
        return 1
    try:
        in_buf = in_path.read_bytes()
        in_info = inspect_dicom_part10(in_path)
    except ValueError as exc:
        print(f"FAIL: не удалось разобрать входной DICOM {in_path.name}: {exc}", file=sys.stderr)
        return 1

    out_raw_hdr = out_path.read_bytes()[: out_info.header_end_offset]
    sensitive_tags = [
        ((0x0010, 0x0010), "PatientName"),
        ((0x0010, 0x0020), "PatientID"),
        ((0x0010, 0x0030), "PatientBirthDate"),
        ((0x0008, 0x0050), "AccessionNumber"),
    ]
    for tag, tname in sensitive_tags:
        in_val = _decode_str(in_info.top_tags.get(tag, b""))
        if len(in_val) < 3:
            continue
        out_val = _decode_str(out_info.top_tags.get(tag, b""))
        if out_val == in_val:
            print(f"FAIL: парная сверка: атрибут {tname} не обезличен ({out_val!r})", file=sys.stderr)
            return 1
        # Проверяем отсутствие токенов ФИО/ID входа в сырых байтах заголовка выхода
        tokens = [tok for tok in in_val.replace("^", " ").split() if len(tok) >= 4]
        for tok in tokens:
            if tok.encode("utf-8") in out_raw_hdr:
                print(
                    f"FAIL: парная сверка: токен входного PHI {tok!r} ({tname}) обнаружен в заголовке {out_path.name}",
                    file=sys.stderr,
                )
                return 1

    if "113107" in out_info.deid_codes:
        in_sd = _decode_str(in_info.top_tags.get((0x0008, 0x0020), b""))
        out_sd = _decode_str(out_info.top_tags.get((0x0008, 0x0020), b""))
        if len(in_sd) == 8 and in_sd.isdigit():
            if not (len(out_sd) == 8 and out_sd.isdigit()):
                print(f"FAIL: парная сверка: некорректный формат сдвинутой StudyDate ({out_sd!r})", file=sys.stderr)
                return 1

    if "113110" not in out_info.deid_codes:
        for uid_tag, uname in [((0x0020, 0x000D), "StudyInstanceUID"), ((0x0020, 0x000E), "SeriesInstanceUID"), ((0x0008, 0x0018), "SOPInstanceUID")]:
            in_u = _decode_str(in_info.top_tags.get(uid_tag, b""))
            out_u = _decode_str(out_info.top_tags.get(uid_tag, b""))
            if in_u and (out_u == in_u or not out_u.startswith("2.25.")):
                print(f"FAIL: парная сверка: {uname} не перегенерирован в 2.25.* ({out_u!r})", file=sys.stderr)
                return 1

    _ = in_buf
    return 0


def verify_cert(
    cert_path: Path,
    key_bytes: Optional[bytes],
    allow_unsealed: bool = False,
    expect_refused: bool = False,
    admission_path: Optional[Path] = None,
    input_dcm_path: Optional[Path] = None,
) -> int:
    name_s = str(cert_path)
    is_refusal_file = name_s.endswith(".refused.json")
    is_deid_file = name_s.endswith(".deid.json")
    if not (is_refusal_file or is_deid_file):
        print(f"FAIL: ожидается файл *.deid.json или *.refused.json ({cert_path.name})", file=sys.stderr)
        return 1

    base_path = Path(name_s[: -len(".refused.json")] if is_refusal_file else name_s[: -len(".deid.json")])
    cert = json.loads(cert_path.read_text(encoding="utf-8"))
    outcome = cert.get("outcome")
    if outcome not in VALID_OUTCOMES:
        print(f"FAIL: недопустимый outcome={outcome!r} в {cert_path.name}", file=sys.stderr)
        return 1

    if key_bytes is None:
        if not allow_unsealed:
            print("FAIL: печать учреждения (seal) не проверена — не задан --key-hex или --key-file", file=sys.stderr)
            return 1
    else:
        if len(key_bytes) < 16:
            print(f"FAIL: длина ключа меньше 16 байт ({len(key_bytes)})", file=sys.stderr)
            return 1
        expected_seal = (cert.get("seal") or "").lower()
        body = {k: v for k, v in cert.items() if k not in ("seal", "created")}
        computed = hmac.new(key_bytes, canonical_json_bytes(body), hashlib.sha256).hexdigest().lower()
        if not expected_seal or not hmac.compare_digest(expected_seal, computed):
            print(f"FAIL: подпись HMAC-SHA-256 (seal) в {cert_path.name} не верна", file=sys.stderr)
            return 1

    # Записи об отказе (REFUSED)
    if is_refusal_file or outcome == "REFUSED":
        if not (is_refusal_file and outcome == "REFUSED"):
            print(f"FAIL: несоответствие суффикса сертификата и outcome={outcome!r}", file=sys.stderr)
            return 1
        if cert.get("output") is not None:
            print("FAIL: запись об отказе (.refused.json) содержит ненулевой блок output", file=sys.stderr)
            return 1
        q_file = base_path.parent / "_quarantine" / base_path.name
        if base_path.exists() or q_file.exists():
            print("FAIL: при outcome=REFUSED выходной или карантинный DICOM-файл существует на диске", file=sys.stderr)
            return 1
        if expect_refused:
            print(f"OK refusal_cert={cert_path.name} outcome=REFUSED seal_checked={key_bytes is not None}")
            return 0
        print(f"FAIL: сертификат фиксирует отказ обработки (outcome=REFUSED) в {cert_path.name}", file=sys.stderr)
        return 1

    if expect_refused:
        print(f"FAIL: ожидался сертификат отказа (REFUSED), но получен outcome={outcome!r}", file=sys.stderr)
        return 1

    if outcome not in RELEASABLE_OUTCOMES:
        print(f"FAIL: объект не выпущен наружу (outcome={outcome!r} требует проверки человеком)", file=sys.stderr)
        return 1

    if base_path.parent.name == "_quarantine":
        print(f"FAIL: выпущенный объект {base_path.name} находится внутри каталога _quarantine", file=sys.stderr)
        return 1

    out_info = cert.get("output")
    if not isinstance(out_info, dict):
        print(f"FAIL: отсутствует объект output в {cert_path.name}", file=sys.stderr)
        return 1
    out_sha = (out_info.get("sha256") or "").lower()
    cand_name = out_info.get("name") or ""
    if not is_hex64(out_sha):
        print(f"FAIL: отсутствует корректный output.sha256 в {cert_path.name}", file=sys.stderr)
        return 1
    if cand_name and cand_name != base_path.name:
        print(f"FAIL: output.name={cand_name!r} не совпадает с ожидаемым файлом {base_path.name!r}", file=sys.stderr)
        return 1
    if not base_path.is_file():
        print(f"FAIL: выходной DICOM-файл не найден рядом с сертификатом: {base_path.name}", file=sys.stderr)
        return 1

    actual = sha256_file_hex(base_path)
    if not hmac.compare_digest(actual, out_sha):
        print(
            f"FAIL: SHA-256 выходного файла {base_path.name} не сходится (actual={actual}, cert={out_sha})",
            file=sys.stderr,
        )
        return 1

    pub = cert.get("publication")
    if pub != "released":
        print(
            f"FAIL: недопустимый статус publication={pub!r} для выпущенного объекта (ожидается 'released')",
            file=sys.stderr,
        )
        return 1

    adm = cert.get("admission")
    if not isinstance(adm, dict) or adm.get("admitted") is not True:
        print("FAIL: блок admission отсутствует или admission.admitted != true у выпущенного объекта", file=sys.stderr)
        return 1

    if admission_path is not None:
        if not admission_path.is_file():
            print(f"FAIL: файл политики допуска не найден: {admission_path}", file=sys.stderr)
            return 1
        adm_obj = json.loads(admission_path.read_text(encoding="utf-8"))
        want_rules_sha = str(adm_obj.get("sha256") or "").lower()
        cert_rules_sha = str((adm.get("allowlist") or {}).get("sha256") or "").lower()
        if want_rules_sha and cert_rules_sha and not hmac.compare_digest(want_rules_sha, cert_rules_sha):
            print(
                f"FAIL: хэш правил admission в сертификате ({cert_rules_sha}) не совпадает с {admission_path.name} ({want_rules_sha})",
                file=sys.stderr,
            )
            return 1

    pc = cert.get("pixel_check")
    if outcome == "PROVEN":
        if pc != "no_pixels":
            print(f"FAIL: outcome=PROVEN допустим только при pixel_check='no_pixels' (получено {pc!r})", file=sys.stderr)
            return 1
    else:
        if pc not in SCREENED_PIXEL_CHECKS:
            print(f"FAIL: недопустимый pixel_check={pc!r} для outcome=SCREENED", file=sys.stderr)
            return 1

    px = cert.get("pixels") if isinstance(cert.get("pixels"), dict) else {}
    if pc == "checked_found_verified":
        kept_ann = px.get("kept_annotations")
        if px.get("vision_verified_kept") is not True or not isinstance(kept_ann, list) or len(kept_ann) == 0:
            print("FAIL: pixel_check=checked_found_verified без vision_verified_kept и kept_annotations", file=sys.stderr)
            return 1

    if pc == "curator_approved":
        cr = cert.get("curator_review")
        qo = cert.get("quarantine_origin")
        if not isinstance(cr, dict) or not isinstance(qo, dict):
            print("FAIL: pixel_check=curator_approved без блоков curator_review и quarantine_origin", file=sys.stderr)
            return 1
        cur_id = (cr.get("curator_id") or "").strip()
        cur_hmac = (cr.get("curator_hmac") or "").strip().lower()
        reason = (cr.get("reason") or "").strip()
        app_at = (cr.get("approved_at") or "").strip()
        prev_q = (cr.get("prev_quarantine_seal") or "").strip().lower()
        cert_prev = (cert.get("prev") or "").strip().lower()
        if not (cur_id and cur_hmac and reason and app_at and is_hex64(prev_q) and prev_q == cert_prev and qo.get("outcome") == "REVIEW"):
            print("FAIL: нарушена структура или связность цепи curator_review / quarantine_origin", file=sys.stderr)
            return 1
        if key_bytes is not None:
            want_chmac = text_hmac_hex16(key_bytes, "curator", cur_id)
            if not hmac.compare_digest(cur_hmac, want_chmac):
                print("FAIL: curator_hmac не подтверждён ключом учреждения", file=sys.stderr)
                return 1

    if px.get("review_required") is True or int(px.get("ignored_words") or 0) != 0:
        print("FAIL: блок pixels требует карантина (review_required / ignored_words)", file=sys.stderr)
        return 1
    if px.get("phi_in_pixels") is True and int(px.get("lines_masked") or 0) == 0:
        print("FAIL: phi_in_pixels=true при lines_masked=0", file=sys.stderr)
        return 1
    for ml in px.get("masked_lines") or []:
        if isinstance(ml, dict) and "text" in ml:
            print("FAIL: сертификат выданного объекта содержит поле text в pixels.masked_lines", file=sys.stderr)
            return 1

    # Бинарная инспекция выходного DICOM Part 10 (включая PS3.15 E.3.6 (0028,0303) = MODIFIED)
    dcm_info, rc_bin = verify_dicom_binary_invariants(base_path, outcome)
    if rc_bin != 0 or dcm_info is None:
        return 1

    # 0.9.4 Zero-Recompression Bitstream Pass-Through инвариант
    if px.get("bitstream_passthrough") is True:
        if int(px.get("lines_masked") or 0) != 0:
            print("FAIL: bitstream_passthrough=true недопустим при lines_masked > 0", file=sys.stderr)
            return 1
        cert_enc_sha = str(px.get("encapsulated_sha256") or "").lower()
        if not is_hex64(cert_enc_sha) or not dcm_info.encapsulated_pixel_sha256 or not hmac.compare_digest(cert_enc_sha, dcm_info.encapsulated_pixel_sha256):
            print(
                f"FAIL: encapsulated_sha256 в сертификате ({cert_enc_sha}) не совпадает со сжатыми фрагментами файла ({dcm_info.encapsulated_pixel_sha256})",
                file=sys.stderr,
            )
            return 1

    pair_checked = False
    if input_dcm_path is not None:
        if verify_pair_diff(input_dcm_path, base_path, dcm_info) != 0:
            return 1
        if px.get("bitstream_passthrough") is True:
            in_info = inspect_dicom_part10(input_dcm_path)
            if not in_info.encapsulated_pixel_sha256 or not hmac.compare_digest(in_info.encapsulated_pixel_sha256, dcm_info.encapsulated_pixel_sha256):
                print("FAIL: парная сверка Zero-Recompression: сжатые фрагменты входа и выхода не совпадают побайтово", file=sys.stderr)
                return 1
        pair_checked = True

    ltim_s = _decode_str(dcm_info.top_tags.get((0x0028, 0x0303), b"")).upper()
    extra = f" pair_checked={pair_checked}" if pair_checked else ""
    print(
        f"OK cert={cert_path.name} outcome={outcome} pixel_check={pc} "
        f"ltim_0028_0303={ltim_s} seal_checked={key_bytes is not None}{extra}"
    )
    return 0


def audit_zero_chain_hex(raw_line_utf8: bytes) -> str:
    return hmac.new(b"\x00", raw_line_utf8, hashlib.sha256).hexdigest().lower()


def audit_entry_hmac_hex(key_bytes: bytes, body_without_mac: dict) -> str:
    msg = b"dicom-anonymizer|gateway-audit-v2|" + canonical_json_bytes(body_without_mac)
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest().lower()


def audit_head_hmac_hex(key_bytes: bytes, entries: int, head_sha256: str) -> str:
    msg = f"dicom-anonymizer|gateway-audit-head-v2|{entries}|{head_sha256.lower()}".encode("utf-8")
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest().lower()


def verify_audit(
    audit_path: Path,
    key_bytes: Optional[bytes] = None,
    allow_unsealed: bool = False,
    expect_head_sha256: str = "",
    head_file_path: Optional[Path] = None,
) -> int:
    prev = ""
    count = 0
    for lineno, raw in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.rstrip("\r")
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"FAIL: повреждённый JSON в строке {lineno}: {exc}", file=sys.stderr)
            return 1
        if not isinstance(rec, dict) or "prev" not in rec or not isinstance(rec["prev"], str):
            print(f"FAIL: отсутствует строковое поле prev в строке {lineno}", file=sys.stderr)
            return 1
        if canonical_json_str(rec) != line:
            print(f"FAIL: нарушена каноническая запись JSON в строке {lineno}", file=sys.stderr)
            return 1
        if not hmac.compare_digest(rec["prev"], prev):
            print(f"FAIL: разрыв цепи prev в строке {lineno}", file=sys.stderr)
            return 1
        if "seal" in rec and rec["seal"] is not None:
            seal_v = str(rec["seal"])
            if seal_v and not is_hex64(seal_v):
                print(f"FAIL: некорректный формат поля seal в строке {lineno}", file=sys.stderr)
                return 1
        if key_bytes is not None:
            got_emac = str(rec.get("entry_hmac") or "").lower()
            if not is_hex64(got_emac):
                print(f"FAIL: отсутствует корректный entry_hmac в строке {lineno}", file=sys.stderr)
                return 1
            body = {k: v for k, v in rec.items() if k != "entry_hmac"}
            want_emac = audit_entry_hmac_hex(key_bytes, body)
            if not hmac.compare_digest(got_emac, want_emac):
                print(f"FAIL: недействительный entry_hmac в строке {lineno} (запись изменена)", file=sys.stderr)
                return 1
        prev = audit_zero_chain_hex(line.encode("utf-8"))
        count += 1

    if count == 0:
        print(f"FAIL: журнал аудита пуст ({audit_path.name})", file=sys.stderr)
        return 1

    anchored = False
    exp_head = expect_head_sha256.strip().lower()
    if exp_head:
        if not is_hex64(exp_head) or not hmac.compare_digest(prev, exp_head):
            print(
                f"FAIL: head_sha256 последней записи ({prev}) не совпадает с закреплённой вершиной ({exp_head})",
                file=sys.stderr,
            )
            return 1
        anchored = True

    cand_head = head_file_path if head_file_path is not None else Path(str(audit_path) + ".head.json")
    if cand_head.is_file():
        try:
            hobj = json.loads(cand_head.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL: повреждён файл вершины журнала {cand_head.name}: {exc}", file=sys.stderr)
            return 1
        h_entries = int(hobj.get("entries", -1))
        h_sha = str(hobj.get("head_sha256") or "").lower()
        if h_entries != count:
            print(
                f"FAIL: число записей журнала ({count}) не совпадает с {cand_head.name} ({h_entries}) — журнал усечён или дописан",
                file=sys.stderr,
            )
            return 1
        if not is_hex64(h_sha) or not hmac.compare_digest(h_sha, prev):
            print(
                f"FAIL: head_sha256 последней записи ({prev}) не совпадает с {cand_head.name} ({h_sha}) — хвост журнала изменён",
                file=sys.stderr,
            )
            return 1
        if key_bytes is not None:
            got_hmac = str(hobj.get("head_hmac") or "").lower()
            want_hmac = audit_head_hmac_hex(key_bytes, count, prev)
            if not is_hex64(got_hmac) or not hmac.compare_digest(got_hmac, want_hmac):
                print(f"FAIL: недействительный head_hmac в {cand_head.name}", file=sys.stderr)
                return 1
        anchored = True

    if key_bytes is not None:
        anchored = True

    if not anchored and not allow_unsealed:
        print(
            "FAIL: хвост журнала аудита не закреплён (передайте --key-file / --key-hex, --audit-head, "
            "--evidence с sample_audit_head_sha256 или файл .head.json; для только структурной проверки укажите --allow-unsealed)",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK audit={audit_path.name} entries={count} head_sha256={prev[:16]}... "
        f"hmac_checked={key_bytes is not None} head_anchored={anchored}"
    )
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


def verify_evidence(
    evidence_path: Path,
    admission_path: Optional[Path],
    policies_dir: Optional[Path],
    sbom_path: Optional[Path],
    pub_hex: str,
    docs_dir: Optional[Path] = None,
) -> int:
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

    std_shas = obj.get("core", {}).get("standards_sha256", {})
    if admission_path is not None:
        exp_sha = (
            std_shas.get(admission_path.name)
            or std_shas.get("admission_v7.json")
            or std_shas.get("admission_v6.json")
            or std_shas.get("admission_v5.json")
            or ""
        ).lower()
        act_sha = sha256_file_hex(admission_path)
        if not exp_sha or not hmac.compare_digest(exp_sha, act_sha):
            print(
                f"FAIL: побайтовый SHA-256 файла {admission_path.name} не совпадает (expected={exp_sha}, actual={act_sha})",
                file=sys.stderr,
            )
            return 1
        adm_obj = json.loads(admission_path.read_text(encoding="utf-8"))
        if isinstance(adm_obj, dict) and "sha256" in adm_obj:
            adm_body = {k: v for k, v in adm_obj.items() if k != "sha256"}
            canon_rules_sha = hashlib.sha256(canonical_json_bytes(adm_body)).hexdigest().lower()
            declared_rules_sha = str(adm_obj.get("sha256") or "").lower()
            if not hmac.compare_digest(canon_rules_sha, declared_rules_sha):
                print(
                    f"FAIL: канонический SHA-256 правил внутри {admission_path.name} нарушен ({canon_rules_sha} != {declared_rules_sha})",
                    file=sys.stderr,
                )
                return 1
            man_rules_sha = (obj.get("core", {}).get("admission_canonical_rules_sha256") or "").lower()
            if man_rules_sha and admission_path.name == f"admission_v{obj.get('core', {}).get('admission_version', '7')}.json":
                if not hmac.compare_digest(man_rules_sha, canon_rules_sha):
                    print(
                        f"FAIL: admission_canonical_rules_sha256 в RELEASE_MANIFEST.json не совпадает с правилами ({man_rules_sha} != {canon_rules_sha})",
                        file=sys.stderr,
                    )
                    return 1

    if policies_dir is not None:
        for fname, exp_s in std_shas.items():
            fp = policies_dir / fname
            if not fp.is_file():
                print(f"FAIL: отсутствует файл политики {fp}", file=sys.stderr)
                return 1
            act_s = sha256_file_hex(fp)
            if not hmac.compare_digest(act_s, str(exp_s).lower()):
                print(f"FAIL: SHA-256 файла политики {fname} не совпадает ({act_s} != {exp_s})", file=sys.stderr)
                return 1

    if docs_dir is not None:
        sc = obj.get("supply_chain") or {}
        for doc_name, sc_key in [
            ("DICOM_CONFORMANCE_STATEMENT.md", "conformance_statement_sha256"),
            ("KEY_LIFECYCLE_AND_PROVENANCE.md", "key_lifecycle_doc_sha256"),
            ("GATES.md", "gates_doc_sha256"),
        ]:
            exp_d = str(sc.get(sc_key) or "").lower()
            if not exp_d:
                continue
            dp = docs_dir / doc_name
            if not dp.is_file():
                print(f"FAIL: отсутствует нормативный документ {dp}", file=sys.stderr)
                return 1
            act_d = sha256_file_hex(dp)
            if not hmac.compare_digest(act_d, exp_d):
                print(f"FAIL: SHA-256 нормативного документа {doc_name} не совпадает ({act_d} != {exp_d})", file=sys.stderr)
                return 1

    if sbom_path is not None:
        exp_sbom = str((obj.get("supply_chain") or {}).get("sbom_cyclonedx_sha256") or "").lower()
        act_sbom = sha256_file_hex(sbom_path)
        if not exp_sbom or not hmac.compare_digest(exp_sbom, act_sbom):
            print(f"FAIL: SHA-256 SBOM ({act_sbom}) не совпадает с RELEASE_MANIFEST.json ({exp_sbom})", file=sys.stderr)
            return 1

    ver = obj.get("editions", {}).get("desktop_community", {}).get("version", "?")
    print(f"OK evidence={evidence_path.name} schema={obj.get('schema_version')} desktop={ver}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Независимый открытый верификатор DICOM.BY (MIT)")
    p.add_argument("--cert", type=Path, help="Путь к сертификату *.deid.json или *.refused.json")
    p.add_argument("--refusal-cert", type=Path, help="Синоним --cert <file> --expect-refused")
    p.add_argument("--input", type=Path, dest="input_dcm", help="Опциональный входной DICOM для парной сверки обезличивания")
    p.add_argument("--key-hex", default="", help="Ключ учреждения в виде hex-строки (>=32 hex символов)")
    p.add_argument("--key-file", type=Path, help="Путь к файлу ключа (64-символьный hex или 32-байтовый ключ)")
    p.add_argument("--allow-unsealed", action="store_true", help="Проверить хэши и структуру без проверки HMAC-печати")
    p.add_argument("--expect-refused", action="store_true", help="Ожидать валидную подписанную запись об отказе (.refused.json)")
    p.add_argument("--audit", type=Path, help="Путь к журналу аудита шлюза (*.jsonl)")
    p.add_argument("--audit-head", default="", help="Ожидаемый SHA-256 вершины (последней записи) журнала аудита")
    p.add_argument("--audit-head-file", type=Path, help="Путь к файлу вершины журнала (*.jsonl.head.json)")
    p.add_argument("--manifest", "--update-manifest", dest="manifest", type=Path, help="Путь к windows-x64.json")
    p.add_argument("--evidence", type=Path, help="Путь к паспорту релиза RELEASE_MANIFEST.json / release-manifest.json")
    p.add_argument("--admission", type=Path, help="Путь к admission_v7.json (или v6/v5) для сверки обоих хэшей")
    p.add_argument("--policies-dir", type=Path, help="Каталог standard/ для сверки всех опубликованных политик PS3.15")
    p.add_argument("--docs-dir", type=Path, help="Каталог docs/ для сверки DICOM_CONFORMANCE_STATEMENT.md и KEY_LIFECYCLE_AND_PROVENANCE.md")
    p.add_argument("--sbom", type=Path, help="Путь к CycloneDX SBOM (*.cdx.json) для сверки SHA-256")
    p.add_argument("--pub-hex", default=UPDATE_ED25519_PUB_HEX, help="Публичный ключ Ed25519 (hex)")
    args = p.parse_args()

    key_bytes = None
    try:
        if args.key_hex:
            cleaned_hex = args.key_hex.strip()
            if cleaned_hex.lower().startswith("0x"):
                cleaned_hex = cleaned_hex[2:]
            key_bytes = bytes.fromhex(cleaned_hex)
            if len(key_bytes) < 16:
                raise ValueError(f"Ключ --key-hex короче 16 байт ({len(key_bytes)} байт)")
        elif args.key_file:
            key_bytes = load_key_file_bytes(args.key_file)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    ran_any = False
    rc_out = 0

    if args.cert:
        ran_any = True
        rc = verify_cert(
            args.cert,
            key_bytes,
            allow_unsealed=args.allow_unsealed,
            expect_refused=args.expect_refused,
            admission_path=args.admission,
            input_dcm_path=args.input_dcm,
        )
        rc_out = max(rc_out, rc)

    if args.refusal_cert:
        ran_any = True
        rc = verify_cert(
            args.refusal_cert,
            key_bytes,
            allow_unsealed=args.allow_unsealed,
            expect_refused=True,
            admission_path=args.admission,
        )
        rc_out = max(rc_out, rc)

    if args.audit:
        ran_any = True
        eff_head = args.audit_head.strip()
        if not eff_head and args.evidence and args.evidence.is_file():
            try:
                ev_o = json.loads(args.evidence.read_text(encoding="utf-8"))
                eff_head = str((ev_o.get("supply_chain") or {}).get("sample_audit_head_sha256") or "")
            except Exception:
                eff_head = ""
        rc_out = max(
            rc_out,
            verify_audit(
                args.audit,
                key_bytes=key_bytes,
                allow_unsealed=args.allow_unsealed,
                expect_head_sha256=eff_head,
                head_file_path=args.audit_head_file,
            ),
        )

    if args.manifest:
        ran_any = True
        rc_out = max(rc_out, verify_manifest(args.manifest, args.pub_hex))

    if args.evidence:
        ran_any = True
        rc_out = max(
            rc_out,
            verify_evidence(args.evidence, args.admission, args.policies_dir, args.sbom, args.pub_hex, docs_dir=args.docs_dir),
        )

    if ran_any:
        return rc_out

    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
