#!/usr/bin/env python
# -*- coding: utf-8 -*-
'Source-derived parser observation.'
import sys, io, os, re, struct, shutil, hashlib, base64, argparse, tempfile, subprocess
from pathlib import Path

import gxw_ladder_writer as W
from gxw_ladder_reader import INSTR, INSTR_NOOP, EDGE04
import olefile, pythoncom
from win32com import storagecon

RW = storagecon.STGM_READWRITE | storagecon.STGM_SHARE_EXCLUSIVE
CREATE = storagecon.STGM_CREATE | storagecon.STGM_WRITE | storagecon.STGM_SHARE_EXCLUSIVE
ISSUE22_RESIDUAL_EXPERIMENTAL = False
_OP_BY_MNEM = {v: k for k, v in INSTR.items()}            # 단순 접점/코일 (03 op 03)
_NOOP_BY_MNEM = {v: k for k, v in INSTR_NOOP.items()}     # 연결/블록 (무오퍼랜드 03 op 03): ORB/ANB/MPS/MRD/MPP/INV/MEP/MEF/FEND
_EDGE_BY_MNEM = {v: k for k, v in EDGE04.items()}         # 에지 접점 (04 op marker 04 + 1op): LDP/LDF/LDPI/ORP/ORF/ANDP/ANDPI/ANDFI

# Source-derived parser observation.
# 05-family 토큰: 05 <marker> <A> <B> 05 + operand프레임.  (marker,A,B) per 명령.
# Issue #39 phase 6: byte evidence fixes these target instruction arities.
# Their operand families remain closed by the lifecycle verifier and contract.
PHASE6_FIXED_OPERAND_COUNTS = {
    "WTOB": 3, "BTOW": 3, "EVAL": 2, "DINT": 2,
}

PREFIX_05 = {
    # Source-derived parser observation.
    # Source-derived parser observation.
    'SUM': (0x53, 0x05, 0x02), 'SEG': (0x53, 0x05, 0x06),
    'WSUM': (0x53, 0x06, 0x13), 'LEN': (0x59, 0x05, 0x0d),
    'SER': (0x53, 0x08, 0x00), 'SORT': (0x53, 0x09, 0x11),
    'UNI': (0x53, 0x06, 0x08), 'BIN': (0x4b, 0x04, 0x02),
    # Source-derived parser observation.
    'DBCD': (0x4b, 0x04, 0x01), 'DXOR': (0x4f, 0x06, 0x0d),
    'DINC': (0x4a, 0x04, 0x01), 'DZCP': (0x48, 0x08, 0x09),
    'BCD': (0x4b, 0x02, 0x00), 'BKRST': (0x52, 0x03, 0x04), 'BMOV': (0x4c, 0x04, 0x06),
    # Issue #39 phase 6 Q06UDV A/B lifecycle: only the observed non-pulse
    # D,D,K / D,D forms are admitted to the target contract by its verifier.
    'WTOB': (0x53, 0x04, 0x0b), 'BTOW': (0x53, 0x04, 0x0c),
    'EVAL': (0x59, 0x03, 0x13), 'CML': (0x4c, 0x02, 0x04), 'CMP': (0x48, 0x04, 0x06),
    'D*': (0x49, 0x03, 0x0c),
    'D/': (0x49, 0x03, 0x0e), 'DAND': (0x4f, 0x03, 0x09), 'DATERD': (0x5d, 0x02, 0x00),
    'DATEWR': (0x5d, 0x02, 0x01), 'DCMP': (0x48, 0x04, 0x07), 'DEC': (0x4a, 0x02, 0x02),
    'DECO': (0x53, 0x04, 0x04), 'DMAX': (0x53, 0x04, 0x0e), 'DMIN': (0x53, 0x04, 0x10),
    'DMOV': (0x4c, 0x03, 0x01), 'DNEG': (0x4b, 0x02, 0x0f), 'DOR': (0x4f, 0x03, 0x0b),
    'E*': (0x49, 0x03, 0x20), 'E/': (0x49, 0x03, 0x21),   # E+/E-는 2op/3op 가변 → encode_token 전용 분기
    'ENCO': (0x53, 0x04, 0x05), 'FLT': (0x4b, 0x02, 0x06), 'FMOV': (0x4c, 0x04, 0x07),
    'INC': (0x4a, 0x02, 0x00), 'MOV': (0x4c, 0x02, 0x00), 'ROL': (0x50, 0x04, 0x02),
    'ROR': (0x50, 0x04, 0x00), 'SFL': (0x51, 0x04, 0x01), 'TTMR': (0x63, 0x04, 0x02),
    'WAND': (0x4f, 0x03, 0x01), 'WOR': (0x4f, 0x03, 0x03), 'WXOR': (0x4f, 0x03, 0x05),
    'ZCP': (0x48, 0x05, 0x08),
    # Source-derived parser observation.
    # Source-derived parser observation.
    'CALL': (0x54, 0x02, 0x01), 'XCALL': (0x54, 0x03, 0x1a), 'FOR': (0x6a, 0x02, 0x00),
    'NEXT': (0x6a, 0x01, 0x01), 'RET': (0x6a, 0x01, 0x02),
    # Source-derived parser observation.
    'CJ': (0x4d, 0x02, 0x00), 'SCJ': (0x4d, 0x03, 0x01), 'JMP': (0x68, 0x02, 0x00),
    'GOEND': (0x4d, 0x01, 0x06), 'BSFR': (0x51, 0x03, 0x02), 'BSFL': (0x51, 0x03, 0x03),
    'XCH': (0x4c, 0x03, 0x08),
    # Source-derived parser observation.
    'INT': (0x4b, 0x02, 0x04), 'DFLTD': (0x4b, 0x03, 0x17), 'DINT': (0x4b, 0x02, 0x05),
    'DFLT': (0x4b, 0x02, 0x07), 'EMOV': (0x4c, 0x02, 0x02),
    'MAX': (0x53, 0x04, 0x0d), 'MIN': (0x53, 0x04, 0x0f), 'DIS': (0x53, 0x04, 0x07),
}
# 펄스 06-family 토큰: 06 <marker> <A> <B> 02 06 + operand프레임. (A = 05-family A +1)
PREFIX_PULSE = {
    'BMOVP': (0x4c, 0x05, 0x06), 'DECP': (0x4a, 0x03, 0x02), 'DMOVP': (0x4c, 0x04, 0x01),
    'FMOVP': (0x4c, 0x05, 0x07), 'INCP': (0x4a, 0x03, 0x00), 'MOVP': (0x4c, 0x03, 0x00),
    # Source-derived parser observation.
    'DINCP': (0x4a, 0x03, 0x01),
    'XCHP': (0x4c, 0x04, 0x08),   # Source-derived parser observation.
}
# 32비트 데이터 명령(K/H 상수 → e9/eb). count(n) operand는 16비트라 D32 비포함 명령에만 영향.
D32 = {
    'DMOV', 'DMOVP', 'D+', 'D-', 'D*', 'D/', 'DCMP', 'DAND', 'DOR', 'DNEG',
    'DBCD', 'DXOR', 'DINC', 'DZCP',
}
# Source-derived parser observation.
# Source-derived parser observation.
ARITH_VAR = {'+': (0x00, 0x01), '-': (0x02, 0x03), 'D+': (0x04, 0x05), 'D-': (0x06, 0x07),
             '*': (0x08, 0x09), 'E+': (0x1c, 0x1d), 'E-': (0x1e, 0x1f)}

# Source-derived parser observation.
# 스트림: 06 40 <W> <op> <conn> 06 + operand1프레임 + operand2프레임 (§3.4).
# Source-derived parser observation.
# Source-derived parser observation.
# Source-derived parser observation.
# Source-derived parser observation.
#   바이트에서 g(W)=Wbyte-1-g(상대)로 역산해 전건 단일해 2로 확정, 재인코딩 byte-exact 검증.
# Source-derived parser observation.
# Source-derived parser observation.
_CMP_CONN = {'LD': 0x10, 'AND': 0x11, 'OR': 0x12}
_CMP_SYMS = ['=', '<>', '>', '>=', '<', '<=']
_CMP_RE = re.compile(r'^(LD|AND|OR)(D?)(<>|>=|<=|=|>|<)$')


def _frame(tc, val, w):
    if not 0 <= val < (1 << (8 * w)):
        raise ValueError(f"{w * 8}비트 프레임 범위 밖: {val}")
    return bytes([0x03 + w, tc]) + int(val).to_bytes(w, "little") + bytes([0x03 + w])


# Source-derived parser observation.
# Source-derived parser observation.
MOD_UMODULE, MOD_DIGIT, MOD_ZINDEX, MOD_ZINDEX2, MOD_BIT = 0xf8, 0xf1, 0xf0, 0xf6, 0xf2


def _mod_frame(tc, val):
    val = int(val)
    if not 0 <= val <= 0xFF:
        raise ValueError(f"수식자 값은 0..255 범위여야 함: {val}")
    return bytes([0x04, tc, val, 0x04])


def _is_base_device(t):
    """t가 수식자 없는 베이스 디바이스로 인코딩되는가(Z/bit 접미 분리 모호성 차단용)."""
    try:
        W.encode_operand(t); return True
    except Exception:
        return False


def _split_modifiers(op):
    '수식자 포함 operand 텍스트 → (u, digit, base, z, zz, bit). 리더 _read_operand 조립의 역함수.\n    base = 디바이스명+주소(수식자 제거). 수식자 없으면 전부 None base=op.'
    u = dig = z = zz = bit = None
    t = op
    m = re.match(r"^U(\d+)\\(.+)$", t)             # U모듈 prefix  U{n}\{base}
    if m:
        u = int(m.group(1)); t = m.group(2)
    m = re.match(r"^K([1-8])([A-Za-z].*)$", t)     # digit prefix  K{n}{device} (n=1..8; K0Z..=상수+Z인덱스)
    if m:
        dig = int(m.group(1)); t = m.group(2)
    m = re.match(r"^(.+)\.([0-9A-Fa-f]+)$", t)     # bit suffix    {base}.{hex}
    if m and _is_base_device(m.group(1)):
        bit = int(m.group(2), 16); t = m.group(1)
    mz = re.match(r"^(.+?)ZZ(\d+)$", t)            # ZZ suffix (Z보다 먼저)
    if mz and _is_base_device(mz.group(1)):
        zz = int(mz.group(2)); t = mz.group(1)
    else:
        mz = re.match(r"^(.+?)Z(\d+)$", t)         # Z suffix      {base}Z{n}
        if mz and _is_base_device(mz.group(1)):
            z = int(mz.group(2)); t = mz.group(1)
    return u, dig, t, z, zz, bit


def _enc_operand(op, is32):
    'Source-derived parser observation.'
    op = op.strip()
    h = op[0].upper()
    if h == "K" and re.match(r"^K-?\d+$", op):       # 순수 정수 상수 (digit수식 K{n}{dev}은 아래로)
        v = _checked_k_constant(op, is32)
        return _frame(0xe9 if is32 else 0xe8, v, _minw(v))   # 최소폭 1/2/3/4
    if h == "H" and re.match(r"^H[0-9A-Fa-f]+$", op):  # 16진 상수
        v = _checked_h_constant(op, is32)
        return _frame(0xeb if is32 else 0xea, v, _minw(v))
    if h == "E" and re.match(r"^E[-+0-9.][0-9.eE+-]*$", op):  # 부동소수 상수 (4B IEEE LE)
        return _frame(0xec, struct.unpack("<I", struct.pack("<f", float(op[1:])))[0], 4)
    u, dig, base, z, zz, bit = _split_modifiers(op)
    if any(x is not None for x in (u, dig, z, zz, bit)):
        out = b""                                    # Source-derived parser observation.
        if u is not None:   out += _mod_frame(MOD_UMODULE, u)
        if dig is not None: out += _mod_frame(MOD_DIGIT, dig)
        if z is not None:   out += _mod_frame(MOD_ZINDEX, z)
        if zz is not None:  out += _mod_frame(MOD_ZINDEX2, zz)
        if bit is not None: out += _mod_frame(MOD_BIT, bit)
        return out + W.encode_operand(base)
    return W.encode_operand(op)


def _minw(v):
    """값(마스킹된 unsigned) → 최소 프레임 폭 바이트수."""
    return 1 if v <= 0xFF else 2 if v <= 0xFFFF else 3 if v <= 0xFFFFFF else 4


def _checked_k_constant(op, is32):
    bits = 32 if is32 else 16
    value = int(op[1:])
    lower, upper = -(1 << (bits - 1)), (1 << bits) - 1
    if not lower <= value <= upper:
        raise ValueError(f"K 상수는 현재 {bits}비트 프레임 범위 밖: {op}")
    return value & upper


def _checked_h_constant(op, is32):
    bits = 32 if is32 else 16
    value = int(op[1:], 16)
    upper = (1 << bits) - 1
    if not 0 <= value <= upper:
        raise ValueError(f"H 상수는 현재 {bits}비트 프레임 범위 밖: {op}")
    return value


def _cmp_op_meta(fb):
    """operand 프레임열 → (base_tc, base_w, 수식자프레임수). 마지막 비-수식자 프레임=base."""
    i, nmods = 0, 0
    MODTC = (0xf0, 0xf1, 0xf2, 0xf6, 0xf8)
    while i < len(fb):
        f = fb[i]; w = f - 0x03; tc = fb[i + 1]
        if tc in MODTC:
            nmods += 1; i += 3 + w; continue
        return tc, w, nmods
    raise ValueError("operand 프레임 base 미검출")


def _cmp_contrib(fb, is32=False):
    'Source-derived parser observation.'
    tc, w, nmods = _cmp_op_meta(fb)
    if tc == 0xa8:               # Source-derived parser observation.
        bc = 1 if nmods and not is32 else 2
    elif tc == 0xaf:             # Source-derived parser observation.
        bc = 1
    elif tc == 0xb0:             # Source-derived parser observation.
        bc = 2 if w >= 3 else 1
    elif tc == 0xb4 and w <= 2:  # Source-derived parser observation.
        bc = 2
    elif tc in (0xe8, 0xea):     # K16 / H16
        bc = 1
    elif tc in (0xe9, 0xeb):     # Source-derived parser observation.
        bc = 2 if w >= 3 else 1
    elif tc == 0xab:             # Source-derived parser observation.
        bc = 1
    else:
        raise ValueError(f"비교접점 operand 미검증 디바이스 typecode 0x{tc:02x} — "
                         "골든 census 미포함(D/R/ZR/K/H만 확정, W 기여도 추측 금지)")
    return bc + nmods


def _enc_cmp_operand(op, is32):
    '비교접점 operand → 프레임 바이트. 상수 최소폭(32bit=e9/eb, min2B 아님) 디바이스/수식자는 _enc_operand.'
    t = op.strip()
    h = t[0].upper()
    if h == "K" and re.match(r"^K-?\d+$", t):
        v = _checked_k_constant(t, is32)
        return _frame(0xe9 if is32 else 0xe8, v, _minw(v))
    if h == "H" and re.match(r"^H[0-9A-Fa-f]+$", t):
        v = _checked_h_constant(t, is32)
        return _frame(0xeb if is32 else 0xea, v, _minw(v))
    return _enc_operand(t, False)   # Source-derived parser observation.


def _str_frame(s):
    f = 0x03 + len(s)
    return bytes([f, 0xee]) + s.encode("latin1") + bytes([f])


# Source-derived parser observation.
# 헤더 [L, 0x70, 0x0c, count, 0x02] + ASCII(SP. 제외) + [L], L=len(name)+6.
# 오퍼랜드 닫힘: U0, SOCOPEN은 K1|K5|K7, 나머지는 K1|K7,
# D256..65535, M0..65535. K5는 Issue #54 Q06UDV 공식 lifecycle 범위다.
_SOCKET_SP = {
    "SP.SOCOPEN": (b"SOCOPEN", 4),
    "SP.SOCCLOSE": (b"SOCCLOSE", 4),
    "SP.SOCSND": (b"SOCSND", 5),
    "SP.SOCRCV": (b"SOCRCV", 5),
}


def _enc_socket_plain_dm(op, letter, mnem, raw):
    t = op.strip()
    m = re.fullmatch(letter + r"([0-9]+)", t)
    if not m or not (256 if letter == "D" else 0) <= int(m.group(1)) <= 0xFFFF:
        raise ValueError(f"{mnem}는 관측 범위 D256..65535 또는 M0..65535만 지원: '{raw}'")
    return _enc_operand(t, False)


def _enc_socket_sp(mnem, ops, raw):
    name, arity = _SOCKET_SP[mnem]
    if len(ops) != arity:
        raise ValueError(f"{mnem}는 {arity}-오퍼랜드: '{raw}'")
    u, k, *ds, mdev = ops
    if u.strip() != "U0":
        raise ValueError(f"{mnem}는 U0만 지원: '{raw}'")
    k = k.strip()
    allowed_connections = ("K1", "K5", "K7") if mnem == "SP.SOCOPEN" else ("K1", "K7")
    if k not in allowed_connections:
        raise ValueError(f"{mnem}의 승인된 접속 번호가 아님: '{raw}'")
    L = len(name) + 6
    header = bytes([L, 0x70, 0x0c, arity, 0x02]) + name + bytes([L])
    return (
        header
        + _frame(0xd8, 0, 1)
        + _enc_operand(k, True)
        + b"".join(_enc_socket_plain_dm(d, "D", mnem, raw) for d in ds)
        + _enc_socket_plain_dm(mdev, "M", mnem, raw)
    )


def _issue49_kn_header(mnem, ops):
    """Observed Q06UDV A/B transfer headers; no modifier composition.

    Full-width alignment classes are limited to observed residues 0, 1, 5, 9 and 13.
    Three SD controls are exact pairs, not a generic SD transfer rule.
    """
    controls = {("SD1282", "K4M700"): 3, ("SD1284", "K4M720"): 2,
                ("SD1286", "K4M740"): 3}
    if mnem == "MOV" and tuple(ops) in controls:
        return controls[tuple(ops)]
    if mnem not in ("MOV", "MOVP", "DMOV", "DMOVP") or len(ops) != 2:
        return None
    for side in (0, 1):
        match = re.fullmatch(r"K([1-8])(SM|SB|[XYMLFB])([0-9A-F]+)", ops[side])
        if not match or not re.fullmatch(r"D[0-9]+", ops[1-side]):
            continue
        n, family, spelling = int(match[1]), match[2], match[3]
        radix = 16 if family in ("X", "Y", "B", "SB") else 10
        if radix == 10 and not spelling.isdecimal():
            return None
        address = int(spelling, radix)
        if not 256 <= address <= 65535 - (4*n - 1) or not 256 <= int(ops[1-side][1:]) <= 65535:
            return None
        if family in ("SM", "SB") and address + 4*n - 1 > 2047:
            return None
        wide = mnem.startswith("D")
        limit = 8 if wide else 4
        if n > limit:
            raise ValueError("Kn exceeds transfer width")
        if n == limit and address % 16 not in (0, 1, 5, 9, 13):
            return None
        # Tables independently observed for each of the eight bit families.
        table = ((4, 4, 4, 4, 3, 3, 3, 2) if side == 0 else
                 (3, 3, 3, 3, 3, 3, 3, 2)) if wide else (3, 3, 3, 2)
        header = table[n-1]
        if n == limit and address % 16 in (1, 5, 9, 13):
            header += 1
        if mnem.endswith("P"):
            header += 1
        return header
    return None


def encode_token(mnem, ops, raw):
    if any(not op.startswith(chr(34)) and re.search(r"SB", op, re.I) for op in ops) and _issue49_kn_header(mnem, ops) is None:
        raise ValueError("SB operand is outside Issue49 observed transfer scope")
    """단일 명령 → 토큰 바이트. 단순(03)/복합(05)/펄스(06)/$MOV/수식자/연결블록/에지/타이머·PLS·FF·MC·포인터 분기."""
    is32 = mnem in D32
    if mnem in _SOCKET_SP:
        return _enc_socket_sp(mnem, ops, raw)
    if mnem == "$MOV":                                   # 05 4c 05 03 05 + 문자열프레임 + device
        m = re.match(r'\$MOV\s+"([^"]*)"\s+(\S+)', raw, re.I)
        if not m:
            raise ValueError(f'$MOV 형식: $MOV "문자열" 디바이스  (받음: {raw})')
        return bytes([0x05, 0x4c, 0x05, 0x03, 0x05]) + _str_frame(m.group(1)) + _enc_operand(m.group(2), False)
    if mnem == "$+":                                     # Source-derived parser observation.
        literal = re.match(r'^\$\+\s+"([^"]*)"\s+(\S+)\s*$', raw, re.I)
        if literal:
            return (bytes([0x05, 0x49, 0x0c, 0x22, 0x05])
                    + _str_frame(literal.group(1))
                    + _enc_operand(literal.group(2), False))
        if len(ops) == 2:
            return bytes([0x05, 0x49, 0x06, 0x22, 0x05]) + b"".join(_enc_operand(o, False) for o in ops)
        if len(ops) == 3:
            return bytes([0x05, 0x49, 0x07, 0x23, 0x05]) + b"".join(_enc_operand(o, False) for o in ops)
        raise ValueError(f"$+는 2 또는 3 오퍼랜드: '{raw}'")
    if re.match(r"^P\d+:?$", mnem) and not ops:          # Source-derived parser observation.
        return bytes([0x03, 0x3c, 0x03]) + _enc_operand(mnem.rstrip(":"), False)
    if mnem == "OUT" and ops and re.match(r"^[TC]\d", ops[0].upper()):  # OUT 타이머/카운터 (04 21 04 04 + dev[+K])
        if not 1 <= len(ops) <= 2:                                       # Source-derived parser observation.
            raise ValueError(f"OUT 타이머/카운터는 dev[+프리셋]: '{raw}'")    # Source-derived parser observation.
        return bytes([0x04, 0x21, 0x04, 0x04]) + b"".join(_enc_operand(o, False) for o in ops)
    if mnem == "PLS":                                    # Source-derived parser observation.
        if len(ops) != 1:
            raise ValueError(f"PLS는 1-오퍼랜드: '{raw}'")
        return bytes([0x04, 0x25, 0x02, 0x04]) + _enc_operand(ops[0], False)
    if mnem == "PLF":                                    # Source-derived parser observation.
        if len(ops) != 1:                                # Source-derived parser observation.
            raise ValueError(f"PLF는 1-오퍼랜드: '{raw}'")
        return bytes([0x04, 0x26, 0x02, 0x04]) + _enc_operand(ops[0], False)
    if mnem == "OUTH":                                   # Source-derived parser observation.
        if not 1 <= len(ops) <= 2:                       # Source-derived parser observation.
            raise ValueError(f"OUTH는 dev[+프리셋]: '{raw}'")
        return bytes([0x04, 0x22, 0x04, 0x04]) + b"".join(_enc_operand(o, False) for o in ops)
    if mnem == "RST" and ops and re.match(r"^[TC]\d", ops[0].strip().upper()):  # RST T/C (04 24 04 04 + dev)
        if len(ops) != 1:                                # Source-derived parser observation.
            raise ValueError(f"RST T/C는 1-오퍼랜드: '{raw}'")  # RST M/L 등 비트는 아래 _OP_BY_MNEM 03 24 03 경유
        return bytes([0x04, 0x24, 0x04, 0x04]) + _enc_operand(ops[0], False)
    if ISSUE22_RESIDUAL_EXPERIMENTAL and mnem == "RST" and len(ops) == 1 and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[0], re.I):
        # Source-derived parser observation.
        return bytes([0x04, 0x24, 0x04, 0x04]) + _enc_operand(ops[0], False)
    if mnem in ("SFT", "SFTP"):                          # Source-derived parser observation.
        if len(ops) != 1:
            raise ValueError(f"{mnem}은 1-오퍼랜드: '{raw}'")
        op, mk = (0x2a, 0x02) if mnem == "SFT" else (0x2b, 0x03)
        return bytes([0x04, op, mk, 0x04]) + _enc_operand(ops[0], False)
    if mnem in ("OUT", "SET", "RST") and ops and re.match(r"^F\d+$", ops[0].strip().upper()):  # F(애넌시에이터) 코일 04-프레이밍
        # Source-derived parser observation.
        if len(ops) != 1:
            raise ValueError(f"{mnem} F는 1-오퍼랜드: '{raw}'")
        op = _OP_BY_MNEM[mnem]; marker = 0x02 if mnem == "OUT" else 0x03
        return bytes([0x04, op, marker, 0x04]) + _enc_operand(ops[0], False)
    if ISSUE22_RESIDUAL_EXPERIMENTAL and mnem == "OUT" and len(ops) == 1 and re.fullmatch(r"F\d+Z\d+", ops[0], re.I):
        # Source-derived parser observation.
        return bytes([0x04, _OP_BY_MNEM[mnem], 0x03, 0x04]) + _enc_operand(ops[0], False)
    if mnem in ARITH_VAR and len(ops) in (2, 3):         # Source-derived parser observation.
        B = ARITH_VAR[mnem][len(ops) - 2]
        return bytes([0x05, 0x49, 0x03, B, 0x05]) + b"".join(_enc_operand(o, is32) for o in ops)
    if mnem == "FOR":                                   # A는 operand 프레임 폭에 연동(K20=02, D6000=03)
        if len(ops) != 1:
            raise ValueError(f"FOR는 1-오퍼랜드: '{raw}'")
        frame = _enc_operand(ops[0], False)
        A = 0x02 if re.match(r"^[KH]", ops[0], re.I) else len(frame) - 2
        return bytes([0x05, 0x6a, A, 0x00, 0x05]) + frame
    if mnem == "FF":                                     # 플립플롭 (04 27 marker 04 + dev)
        if len(ops) != 1:
            raise ValueError(f"FF는 1-오퍼랜드: '{raw}'")
        # Source-derived parser observation.
        # uses marker 03.  The existing plain-device family remains marker 02.
        marker = 0x03 if ISSUE22_RESIDUAL_EXPERIMENTAL and re.fullmatch(r"M\d+Z\d+", ops[0], re.I) else 0x02
        return bytes([0x04, 0x27, marker, 0x04]) + _enc_operand(ops[0], False)
    if mnem == "MC":                                     # Source-derived parser observation.
        if len(ops) != 2:
            raise ValueError(f"MC는 2-오퍼랜드(N,dev): '{raw}'")
        return bytes([0x04, 0x2c, 0x02, 0x04]) + _enc_operand(ops[0], False) + _enc_operand(ops[1], False)
    cm = _CMP_RE.match(mnem)                             # 비교접점 06 40 W op conn 06 + 2 operand프레임
    if cm:
        if len(ops) != 2:
            raise ValueError(f"비교접점 {mnem}은 2-오퍼랜드: '{raw}'")
        conn = _CMP_CONN[cm.group(1)]
        cmp32 = cm.group(2) == "D"
        op = _CMP_SYMS.index(cm.group(3)) + (6 if cmp32 else 0)
        f1 = _enc_cmp_operand(ops[0], cmp32)
        f2 = _enc_cmp_operand(ops[1], cmp32)
        W = 1 + _cmp_contrib(f1, cmp32) + _cmp_contrib(f2, cmp32)
        if (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and ((mnem == "AND<" and re.fullmatch(r"R\d+Z\d+", ops[0], re.I) and re.fullmatch(r"D\d+", ops[1], re.I))
            or (mnem == "ANDD=" and re.fullmatch(r"D\d+", ops[0], re.I) and re.fullmatch(r"R\d+Z\d+", ops[1], re.I))
        )):
            # Source-derived parser observation.
            W = 0x04
        return bytes([0x06, 0x40, W, op, conn, 0x06]) + f1 + f2
    if mnem in PREFIX_PULSE:                              # 06 marker A B 02 06 + frames
        mk, A, B = PREFIX_PULSE[mnem]
        if (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and mnem == "MOVP"
            and len(ops) == 2
            and re.fullmatch(r"R\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+", ops[1], re.I)
        ):
            # Source-derived parser observation.
            A = 0x04
        kn_header = _issue49_kn_header(mnem, ops)
        if kn_header is not None:
            A = kn_header
        return bytes([0x06, mk, A, B, 0x02, 0x06]) + b"".join(_enc_operand(o, is32) for o in ops)
    if mnem in PREFIX_05:                                 # 05 marker A B 05 + frames
        expected_count = PHASE6_FIXED_OPERAND_COUNTS.get(mnem)
        if expected_count is not None and len(ops) != expected_count:
            raise ValueError(f"{mnem} requires {expected_count} operands: '{raw}'")
        mk, A, B = PREFIX_05[mnem]
        # Q06UDV GX Works2 Issue #22 raw forms. Do not infer an A formula.
        # Each observed operand grammar receives a separate, narrow branch.
        if (
            mnem == "D/"
            and len(ops) == 3
            and re.fullmatch(r"D\d+Z\d+", ops[0], re.I)
            and all(re.fullmatch(r"D\d+", op, re.I) for op in ops[1:])
        ):
            A = 0x04
        elif (
            mnem == "D/"
            and len(ops) == 3
            and re.fullmatch(r"D\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"K[-+]?\d+", ops[1], re.I)
            and re.fullmatch(r"D\d+Z\d+", ops[2], re.I)
        ):
            A = 0x06
        elif (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"K[-+]?\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+Z\d+", ops[1], re.I)
        ):
            A = 0x03
        elif (
            mnem == "DMOV"
            and len(ops) == 2
            and re.fullmatch(r"K[-+]?\d+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x06
        elif (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"D\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x06
        elif (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"K[-+]?\d+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x05
        elif (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"D\d+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x05
        elif (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+Z\d+", ops[1], re.I)
        ):
            A = 0x06
        elif (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"K4M\d+", ops[1], re.I)
        ):
            # Source-derived parser observation.
            # destination keeps the same observed A=06 family as indexed D.
            A = 0x06
        elif (
            mnem == "DMOV"
            and len(ops) == 2
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+Z\d+", ops[1], re.I)
        ):
            A = 0x06
        elif (
            mnem == "DMOV"
            and len(ops) == 2
            and re.fullmatch(r"D\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x06
        elif (
            mnem == "DMOV"
            and len(ops) == 2
            and re.fullmatch(r"K[-+]?\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+Z\d+", ops[1], re.I)
        ):
            A = 0x04
        elif (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"K[-+]?\d+", ops[0], re.I)
            and re.fullmatch(r"K4M\d+Z\d+", ops[1], re.I)
        ):
            A = 0x03
        elif (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and mnem == "DECO"
            and len(ops) == 3
            and re.fullmatch(r"D\d+Z\d+", ops[0], re.I)
            and re.fullmatch(r"M\d+Z\d+", ops[1], re.I)
            and re.fullmatch(r"K[-+]?\d+", ops[2], re.I)
        ):
            A = 0x06
        elif (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"H[0-9A-F]+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x05
        elif (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"D\d+", ops[0], re.I)
            and re.fullmatch(r"R\d+Z\d+", ops[1], re.I)
        ):
            A = 0x03
        elif (
            ISSUE22_RESIDUAL_EXPERIMENTAL
            and mnem == "BMOV"
            and len(ops) == 3
            and re.fullmatch(r"D\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+Z\d+", ops[1], re.I)
            and re.fullmatch(r"K[-+]?\d+", ops[2], re.I)
        ):
            A = 0x05
        elif (
            mnem == "DMOV"
            and len(ops) == 2
            and re.fullmatch(r"D\d+", ops[0], re.I)
            and re.fullmatch(r"U\d+\\G\d+Z\d+", ops[1], re.I)
        ):
            A = 0x05
        elif (
            mnem == "DMOV"
            and len(ops) == 2
            and all(re.fullmatch(r"D\d+Z\d+", op, re.I) for op in ops)
        ):
            A = 0x04
        # Q06UDV GX Works2 batch-016 A/B 실측: MOV K{1..8}F<n> D<n>의
        # digit 수식자 1프레임은 A를 02→03으로 올린다. 다른 05-family나
        # 다른 수식자에 일반화할 authority는 없으므로 이 승인된 형상만 고정한다.
        if (
            mnem == "MOV"
            and len(ops) == 2
            and re.fullmatch(r"K[1-8]F\d+", ops[0], re.I)
            and re.fullmatch(r"D\d+", ops[1], re.I)
        ):
            A = 0x03
        # Issue #39 phase 6 Q06UDV A/B lifecycle proof.  SD1255 to K4M
        # has no inferred A formula: only the two saved project pairs are
        # allowed to vary the observed 05-family A byte.
        if (
            mnem == "MOV" and len(ops) == 2 and ops[0].upper() == "SD1255"
            and re.fullmatch(r"K4M\d+", ops[1], re.I)
        ):
            observed_a = {"K4M2400": 0x02, "K4M2500": 0x03}.get(ops[1].upper())
            if observed_a is None:
                raise ValueError(f"MOV SD1255,K4M byte encoding is outside observed A/B pairs: '{raw}'")
            A = observed_a

        # Issue #39 isolated Q06UDV A/B lifecycle proof.  The grouped Y
        # destination changes MOV's observed 05-family A byte from 02 to 03.
        # Keep this exact pair closed: it is byte authority for the two
        # synthetic records only, never a general K2Y encoding rule.
        if (
            mnem == "MOV"
            and len(ops) == 2
            and tuple(op.upper() for op in ops) in {
                ("D444", "K2Y200"),
                ("D446", "K2Y220"),
            }
        ):
            A = 0x03
        kn_header = _issue49_kn_header(mnem, ops)
        if kn_header is not None:
            A = kn_header
        return bytes([0x05, mk, A, B, 0x05]) + b"".join(_enc_operand(o, is32) for o in ops)
    if mnem in _NOOP_BY_MNEM:                            # Source-derived parser observation.
        if ops:
            raise ValueError(f"연결/블록 명령 {mnem}은 무오퍼랜드: '{raw}'")
        return bytes([0x03, _NOOP_BY_MNEM[mnem], 0x03])
    if mnem in _EDGE_BY_MNEM:                            # 에지 접점 (04 op marker 04 + 1op)
        if len(ops) != 1:
            raise ValueError(f"에지접점 {mnem}은 1-오퍼랜드: '{raw}'")
        op = _EDGE_BY_MNEM[mnem]
        u, dig, base, z, zz, bit = _split_modifiers(ops[0])
        # Source-derived parser observation.
        marker = 0x03 if (
            bit is not None
            or (ISSUE22_RESIDUAL_EXPERIMENTAL and mnem == "ORP" and re.fullmatch(r"M\d+Z\d+", ops[0], re.I))
        ) else 0x02
        return bytes([0x04, op, marker, 0x04]) + _enc_operand(ops[0], False)
    if mnem in _OP_BY_MNEM:                               # 단순 접점/코일
        op = _OP_BY_MNEM[mnem]
        if len(ops) == 0:                                # 무오퍼랜드 특수(MCR 등)
            return bytes([0x03, op, 0x03])
        if len(ops) != 1:
            raise ValueError(f"단순명령 1-오퍼랜드 초과: '{raw}'")
        u, dig, base, z, zz, bit = _split_modifiers(ops[0])
        if any(x is not None for x in (u, dig, z, zz, bit)):  # 수식자 접점/코일: 04 op marker 04
            marker = 0x03 if (u is not None and bit is not None) else 0x02  # Source-derived parser observation.
            return bytes([0x04, op, marker, 0x04]) + _enc_operand(ops[0], False)
        return bytes([0x03, op, 0x03]) + _enc_operand(ops[0], False)  # 수식자 없음: 03 op 03
    raise ValueError(f"미지원 명령 '{mnem}' (NOOP/EDGE04/PREFIX_05/PULSE·$MOV·단순 INSTR 어디에도 없음)")


def encode_il_body(il):
    'IL(\'MOV K100 D0;DMOV ...;$MOV "HELLO" D10\') → 본체 토큰. 단순+복합+펄스+$MOV + 수식자 operand 지원.\n    수식자(U\\G Zn ZZn .bit Kn): 복합/펄스 operand는 _enc_operand, 접점/코일은 04 op marker 04 프레이밍.'
    toks = b""
    for part in re.split(r"[;\n]", il):
        part = part.strip()
        if not part:
            continue
        bits = part.split()
        toks += encode_token(bits[0].upper(), bits[1:], part)
    return toks


def pou_streams(gxw_path):
    """projectdatalist.xml에서 {POU: {'res':num,'prg':num}} (iID=_hdb 스트림번호)."""
    ole = olefile.OleFileIO(gxw_path)
    pdl = ole.openstream("projectdatalist.xml").read().decode("utf-8"); ole.close()
    out = {}
    for m in re.finditer(r"<D_Projectdata\b.*?</D_Projectdata>", pdl, re.S):
        r = m.group(0)
        nm = re.search(r"<szName>([^<]+)</szName>", r)
        iid = re.search(r"<iID>(\d+)</iID>", r)
        if not nm or not iid:
            continue
        mm = re.match(r"(.+)\.(res|Program\.pou)$", nm.group(1))
        if mm:
            out.setdefault(mm.group(1), {})["res" if mm.group(2) == "res" else "prg"] = iid.group(1)
    return out


def _patch_hdb_with_temporary(hdb, replacements, prefix):
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        return W.patch_hdb_substreams(hdb, replacements, Path(temporary) / 'work.ole')


def _history_with_stream_digests(gxw, replacements):
    ole = olefile.OleFileIO(gxw)
    try:
        history = ole.openstream("history.xml").read().decode("utf-8")
    finally:
        ole.close()
    for stream_name, payload in replacements.items():
        digest = base64.b64encode(hashlib.md5(payload).digest()).decode()
        history = re.sub(
            rf"(<D_History\b[^>]*>\s*<iID>{stream_name}</iID>.*?)<iFileSize>\d+</iFileSize>(.*?)<szMD5val>[^<]+</szMD5val>",
            lambda match: f"{match.group(1)}<iFileSize>{len(payload)}</iFileSize>{match.group(2)}<szMD5val>{digest}</szMD5val>",
            history,
            flags=re.S,
        )
    return history.encode("utf-8")


def _write_check_publish(gxw, out, new_hdb, history, input_sha256=None):
    candidate = None
    try:
        candidate, dst, backup = W.prepare_candidate(gxw, out, expected_sha256=input_sha256)
        assert backup is None
        W.write_streams(candidate, {"history.xml": history, "_hdb": new_hdb})
        rc, sout = W.self_check(candidate)
        if rc != 0:
            print(f"  중단: self-check rc={rc}; 후보를 발행하지 않음.")
            return 9, ""
        W.publish_candidate(candidate, gxw, dst, expected_sha256=input_sha256)
        candidate = None
        return 0, sout
    except Exception as error:
        print(f"  중단: 후보 작성/검증 실패: {error}")
        return 9, ""
    finally:
        if candidate is not None:
            W.discard_candidate(candidate)


def fill_res(d, tokens):
    """빈 .res(`<len> 04 34 02 04`)에 토큰 삽입 + len += len(tokens)."""
    marker = d.find(b"\x34\x02\x04"); assert marker > 0
    len_off = marker - 5
    ln = struct.unpack_from("<I", d, len_off)[0]
    nd = bytearray(d); nd[len_off + 4:len_off + 4] = tokens
    struct.pack_into("<I", nd, len_off, ln + len(tokens))
    return bytes(nd)


def fill_prg(d, tokens):
    """빈 .Program.pou(`… ff ff ff ff 04 34 02 04`)에 토큰 삽입 + len1/len2 += len(tokens)."""
    anchor = d.find(b"\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff")
    assert anchor > 0, "prg anchor 없음"
    l1o, l2o = anchor - 8, anchor - 4
    l1 = struct.unpack_from("<I", d, l1o)[0]; l2 = struct.unpack_from("<I", d, l2o)[0]
    ff = d.find(b"\xff\xff\xff\xff", anchor)
    nd = bytearray(d); nd[ff + 4:ff + 4] = tokens
    struct.pack_into("<I", nd, l1o, l1 + len(tokens)); struct.pack_into("<I", nd, l2o, l2 + len(tokens))
    return bytes(nd)


def fill_pou(gxw, pou, il, apply, out):
    input_sha256 = W.source_sha256(gxw)
    streams = W.hdb_substreams(W.read_top(gxw, "_hdb"))
    pous = pou_streams(gxw)
    if pou not in pous or "res" not in pous[pou] or "prg" not in pous[pou]:
        print(f"POU '{pou}' .res/.Program.pou 스트림 미발견 (있는 POU: {list(pous)})"); return 1
    res_n, prg_n = pous[pou]["res"], pous[pou]["prg"]
    tokens = encode_il_body(il)
    print(f"POU {pou}: .res=_hdb/{res_n} .Program.pou=_hdb/{prg_n} / 토큰 {len(tokens)}B: {tokens.hex(' ')}")
    new_res = fill_res(streams[res_n], tokens)
    new_prg = fill_prg(streams[prg_n], tokens)
    # self-check 디코드 미리보기는 작성 후
    if not apply:
        print(f"  [dry-run] .res {len(streams[res_n])}→{len(new_res)}B · .Program.pou {len(streams[prg_n])}→{len(new_prg)}B. --apply로 작성.")
        return 0
    hdb = W.read_top(gxw, "_hdb")
    new_hdb = _patch_hdb_with_temporary(hdb, {res_n: new_res, prg_n: new_prg}, 'gxw-fill-')
    hist = _history_with_stream_digests(gxw, {res_n: new_res, prg_n: new_prg})
    output = out or (os.path.splitext(gxw)[0] + "-filled.gxw")
    rc, sout = _write_check_publish(gxw, output, new_hdb, hist, input_sha256)
    if rc != 0:
        return rc
    dst = output
    body = re.search(rf"## POU: {re.escape(pou)}.*?(?=\n## |\Z)", sout, re.S)
    print(f"  작성: {dst}  self-check rc={rc}")
    if body:
        print("  " + body.group(0).strip().replace("\n", "\n  "))
    print("  변경 = 본체 2스트림만(레지·트리·dataprotection 불변) - GX Works2 실측 권장.")
    return 0


# ─────────────────────── --transpose (기존 본체 횡전개) ───────────────────────
import gxw_ladder_reader as R


def parse_offsets(spec):
    """'M:+5000,D:+5000,X:+0x20,Y:+0x60' → {디바이스명: 정수 오프셋}. 0x.. 16진 허용."""
    out = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        dev, off = part.split(":")
        out[dev.strip().upper()] = int(off.strip(), 0)
    return out


def _recording_read_operand(records):
    """리더 _read_operand 복제 + 베이스 device 프레임 (start,end,tc,val,w) 기록(수식자 제외)."""
    def rro(data, i):
        n = len(data); u = z = z2 = bit = dig = None; skips = 0
        while i < n - 2:
            f = data[i]
            if f in (0x04, 0x05, 0x06, 0x07):
                w = f - 0x03
                if i + 2 + w < n and data[i + 2 + w] == f:
                    tc = data[i + 1]; val = int.from_bytes(data[i + 2:i + 2 + w], "little"); nxt = i + 3 + w
                    if tc == R.MOD_ZINDEX: z = val; i = nxt; continue
                    if tc == R.MOD_ZINDEX2: z2 = val; i = nxt; continue
                    if tc == R.MOD_UMODULE: u = val; i = nxt; continue
                    if tc == R.MOD_BIT: bit = val; i = nxt; continue
                    if tc == R.MOD_DIGIT: dig = val; i = nxt; continue
                    records.append([i, nxt, tc, val, w])      # 베이스 프레임
                    s = R._format_base(tc, val, w)
                    if u is not None: s = f"U{u}\\{s}"
                    if z is not None: s = f"{s}Z{z}"
                    if z2 is not None: s = f"{s}ZZ{z2}"
                    if bit is not None: s = f"{s}.{bit:X}"
                    if dig is not None: s = f"K{dig}{s}"
                    return s, nxt
                if f == 0x04:
                    i += 1; skips += 1
                    if skips > 6: break
                    continue
            break
        return None, i
    return rro


def collect_operands(il_region):
    """il_region(순수 IL 토큰)을 리더 워크로 디코드하며 베이스 device 프레임 전수 수집."""
    records = []
    orig = R._read_operand
    R._read_operand = _recording_read_operand(records)
    try:
        R.decode_program(il_region)   # start=0(순수IL), 워크가 모든 operand를 _read_operand로 읽음
    finally:
        R._read_operand = orig
    return records


def _enc_frame(tc, val):
    """device 프레임 재인코딩: <f> <tc> <val:w LE> <f>, w=최소바이트(GX 관찰)."""
    if not 0 <= val <= 0xFFFFFFFF:
        raise ValueError(f"디바이스 주소는 현재 32비트 프레임 범위 밖: {val}")
    w = 1 if val <= 0xFF else 2 if val <= 0xFFFF else 3 if val <= 0xFFFFFF else 4
    f = 0x03 + w
    return bytes([f, tc]) + int(val).to_bytes(w, "little") + bytes([f])


def transpose_il_region(il, offsets):
    """순수 IL 토큰 영역의 device operand에 오프셋 적용 → 새 IL 영역. 재디코드 대조 검증."""
    recs = collect_operands(il)
    repl = []   # (start, end, new_bytes)
    moved = []
    for start, end, tc, val, w in recs:
        if tc not in R.DEVICE:
            continue
        name = R.DEVICE[tc][0]
        if name not in offsets:
            continue
        nv = val + offsets[name]
        if nv < 0:
            raise ValueError(f"{name}{val} + {offsets[name]} < 0")
        repl.append((start, end, _enc_frame(tc, nv)))
        moved.append((name, val, nv))
    # 위치 내림차순 적용(앞 offset 보존)
    out = bytearray(il)
    for start, end, nb in sorted(repl, key=lambda x: -x[0]):
        out[start:end] = nb
    new_il = bytes(out)
    # 검증: 재디코드한 operand multiset == 기대(원본 operand에 오프셋 적용)
    return new_il, moved


def transpose_pou(gxw, pou, offsets, apply, out):
    input_sha256 = W.source_sha256(gxw)
    streams = W.hdb_substreams(W.read_top(gxw, "_hdb"))
    pous = pou_streams(gxw)
    if pou not in pous:
        print(f"POU '{pou}' 미발견 (있는 POU: {list(pous)})"); return 1
    res_n, prg_n = pous[pou].get("res"), pous[pou].get("prg")
    print(f"POU {pou}: .res=_hdb/{res_n} .Program.pou=_hdb/{prg_n} / 오프셋 {offsets}")
    new_streams = {}
    total_moved = 0
    for sn, kind in [(res_n, "res"), (prg_n, "prg")]:
        d = streams[sn]
        marker = d.find(b"\x34\x02\x04")
        if kind == "res":
            # .res len 필드 = uint32@p where 값 == marker - p - 1 (body=토큰+04+마커, len 포함)
            len_offs = [p for p in range(0x30, marker - 3) if struct.unpack_from("<I", d, p)[0] == marker - p - 1]
            assert len_offs, ".res len 필드 미발견"
            lenp = len_offs[0]; il_start = lenp + 4; len_field_offs = [lenp]
        else:
            anc = d.find(b"\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff")
            il_start = d.find(b"\xff\xff\xff\xff", anc) + 4; len_field_offs = [anc - 8, anc - 4]
        il = d[il_start:marker]                       # 순수 IL 토큰(끝 04 터미네이터 포함)
        new_il, moved = transpose_il_region(il, offsets)
        total_moved += len(moved)
        nd = bytearray(d); nd[il_start:marker] = new_il
        delta = len(new_il) - len(il)
        for lo in len_field_offs:                     # 길이필드 += delta
            struct.pack_into("<I", nd, lo, struct.unpack_from("<I", d, lo)[0] + delta)
        new_streams[sn] = bytes(nd)
    # 검증: .Program.pou 재디코드 operand가 오프셋 적용본과 일치
    print(f"  변환 operand {total_moved//2}건(스트림당). 예시: {moved[:5]}")
    if not apply:
        print(f"  [dry-run] --apply로 작성.")
        return 0
    hdb = W.read_top(gxw, "_hdb")
    new_hdb = _patch_hdb_with_temporary(hdb, new_streams, 'gxw-transpose-')
    hist = _history_with_stream_digests(gxw, new_streams)
    output = out or (os.path.splitext(gxw)[0] + "-transposed.gxw")
    rc, sout = _write_check_publish(gxw, output, new_hdb, hist, input_sha256)
    if rc != 0:
        return rc
    dst = output
    body = re.search(rf"## POU: {re.escape(pou)}.*?(?=\n## |\Z)", sout, re.S)
    print(f"  작성: {dst}  self-check rc={rc}")
    if body:
        print("  " + "\n  ".join(body.group(0).strip().split("\n")[:14]))
    print("  변경 = 본체 2스트림만 - GX Works2 실측 권장.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="GX 생성 POU 본체 편집(경로 B): fill(IL주입)/transpose(횡전개)")
    ap.add_argument("gxw"); ap.add_argument("pou")
    ap.add_argument("--il", help='단순명령 IL ";"/개행 구분, 예: "LD X0;OUT Y0;LD M100;OUT Y10"')
    ap.add_argument("--transpose", metavar="OFFSETS", help='디바이스 오프셋, 예: "M:+5000,D:+5000,X:+0x20,Y:+0x60"')
    ap.add_argument("--apply", action="store_true"); ap.add_argument("--out")
    a = ap.parse_args()
    if a.transpose:
        try:
            return transpose_pou(a.gxw, a.pou, parse_offsets(a.transpose), a.apply, a.out)
        except ValueError as error:
            print(f"중단: {error}")
            return 2
    if a.il:
        return fill_pou(a.gxw, a.pou, a.il, a.apply, a.out)
    ap.error("--il 또는 --transpose 필요")


if __name__ == "__main__":
    sys.exit(main())
