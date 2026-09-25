#!/usr/bin/env python
# -*- coding: utf-8 -*-
'\ngxw_ladder_reader.py - GX Works2 .gxw 래더(POU) → 사람이 읽는 IL 텍스트 덤프\n\nCSV export 대체 PoC 리더. `_hdb/12`(POU 본체, 비암호화 바이너리 토큰)를 직접 디코드한다.\n암호 해독 불필요 - 평문 토큰 파싱.\n\n요소 문법(관찰):\n  03 TT 03 04 DD AA          단순 IL 요소: 명령 TT, 디바이스 코드 DD, 주소 AA\n  0e ee <텍스트> 0e 04 a8 PP  라인 스테이트먼트(rung 주석), PP=위치(줄마다 +0x14)\n  05 00 00 00 <UTF-16LE>      POU 이름\n  04 34 02 04 …               섹션 구분자\n\nopcode/디바이스 사전은 1차(샘플 차분 기반). 미확인 토큰은 raw로 표기.\n완전화: T/C/D/응용명령 다중접점(AND/OR) 샘플로 사전 확장(README §5).\n\n사용:\n  python gxw_ladder_reader.py <project.gxw>               # 텍스트: 전 POU IL + 디바이스 코멘트\n  python gxw_ladder_reader.py <project.gxw> --csv <dir>   # GX Works2 IL CSV: POU별 <dir>/<POU>.csv + COMMENT.csv\n  python gxw_ladder_reader.py <project.gxw> --csv         # (dir 없으면) MAIN을 stdout으로\nGX CSV는 원본 포맷(UTF-16 탭 전필드인용 프리앰블 연속행 END)을 재현 - Step No.는 GX가 import 시 재계산.\n'
import sys, os, re, struct, tempfile
from pathlib import Path
import gxw_bounded_ole as bounded_ole

# Source-derived parser observation.
INSTR = {
    0x00: "LD", 0x01: "LDI", 0x06: "OR", 0x07: "ORI", 0x0c: "AND", 0x0d: "ANI",
    0x20: "OUT", 0x23: "SET", 0x24: "RST",
    0x30: "MCR",   # Source-derived parser observation.
}
# 연결명령(03 TT 03, 피연산자 없음)
INSTR_NOOP = {
    0x19: "ANB", 0x14: "INV", 0x1a: "MPS", 0x1b: "MRD", 0x1c: "MPP",
    0x12: "MEP", 0x13: "MEF", 0x18: "ORB", 0x33: "FEND",
}
# Source-derived parser observation.
DEVICE = {
    0x9c: ("X", 16), 0x9d: ("Y", 16), 0x90: ("M", 10),
    0xc2: ("T", 10), 0xc5: ("C", 10), 0xa8: ("D", 10), 0xaf: ("R", 10),
    0x91: ("SM", 10),   # 특수릴레이 (2바이트 주소, test-1 SM400)
    0x92: ("L", 10),    # 래치릴레이
    0x93: ("F", 10),    # Source-derived parser observation.
    0xa1: ("SB", 16),   # Issue49 Q06UDV A/B: 48 Kn operands per variant
    0xa0: ("B", 16),    # Source-derived parser observation.
    0xb0: ("ZR", 10),   # 파일레지스터(연속 ZR, 3바이트 주소까지)
    0xb4: ("W", 16),    # Source-derived parser observation.
    0xcc: ("Z", 10),    # 인덱스 레지스터
    0xd2: ("N", 10),    # 네스팅 (MC/MCR)
    0xab: ("G", 10),    # Source-derived parser observation.
    0xd0: ("P", 10),    # Source-derived parser observation.
    0xa9: ("SD", 10),   # 특수 데이터레지스터
    0xaa: ("FD", 10),   # Source-derived parser observation.
}
# 오퍼랜드 수식자(modifier) typecode: 베이스 앞에 누적 → 조립
MOD_ZINDEX = 0xf0       # Z 인덱스 수식 → {base}Z{n}
MOD_UMODULE = 0xf8      # U 모듈번호 → U{n}\{base}
MOD_BIT = 0xf2          # 비트 지정 → {base}.{bit:X}
MOD_ZINDEX2 = 0xf6      # ZR 인덱스 수식(GX 표시 ZZ) → {base}ZZ{n}
MOD_DIGIT = 0xf1        # 디지트 지정(KnXXX, n니블 비트 묶음) → K{n}{base}, UTG 250820

# 전송패밀리(05 4c <A> <B>): A=오퍼랜드 프레이밍, B=명령 → (니모닉, 오퍼랜드 수)
XFER_B = {0x00: ("MOV", 2), 0x01: ("DMOV", 2), 0x06: ("BMOV", 3), 0x07: ("FMOV", 3)}
# The Issue #39 peripheral Note A fixture adds the raw flag 01.  Existing
# Note frames use the legacy length relation ``flag == ceil(L/2)``.  The raw
# flag alone is not a PLC-wide subtype specification: the 07 observation is
# also the legacy value for its fixed nine-byte sample text.
ISSUE39_NOTE_TYPE = {0x01: "s", 0x07: "i"}
# Source-derived parser observation.
ARITH_B = {b: ["+", "-", "D+", "D-", "*"][b // 2] for b in range(10)}
ARITH_B.update({0x1d: "E+", 0x20: "E*", 0x21: "E/"})   # 관찰된 부동소수만(추측 미포함)
# Source-derived parser observation.
PXFER_B = {0x00: "MOVP", 0x01: "DMOVP", 0x06: "BMOVP", 0x07: "FMOVP", 0x08: "XCHP"}
# 펄스 INC(06 4a <A> <B> <x> 06): B→ INCP/DINCP
PINC_B = {0x00: "INCP", 0x01: "DINCP"}
# 04 <op> <02|03> 04 특수명령(수식자 아님): op → (니모닉, 오퍼랜드 수). LDP는 EDGE04로 통합(02/03 비트버전 포함).
# Source-derived parser observation.
SPECIAL04 = {0x27: ("FF", 1), 0x2c: ("MC", 2), 0x2a: ("SFT", 1), 0x2b: ("SFTP", 1)}
# 05 <marker> <A> <B> 응용명령 디스패치: (marker, B) → (니모닉, 오퍼랜드 수)
DISPATCH_05 = {
    # Source-derived parser observation.
    (0x53, 0x02): ("SUM", 2), (0x53, 0x06): ("SEG", 2),
    (0x53, 0x00): ("SER", 4), (0x53, 0x11): ("SORT", 5),
    (0x53, 0x08): ("UNI", 3), (0x4b, 0x02): ("BIN", 2),
    # Source-derived parser observation.
    (0x4b, 0x01): ("DBCD", 2), (0x4f, 0x0d): ("DXOR", 3),
    (0x4a, 0x01): ("DINC", 1), (0x48, 0x09): ("DZCP", 4),
    (0x53, 0x04): ("DECO", 3), (0x53, 0x10): ("DMIN", 3), (0x53, 0x0e): ("DMAX", 3),
    # Issue #39 phase 6 Q06UDV A/B lifecycle: these fixed operand counts
    # close the generic APPLY scanner before it can consume a following token.
    (0x53, 0x0b): ("WTOB", 3), (0x53, 0x0c): ("BTOW", 3),
    (0x59, 0x11): ("DVAL", 3), (0x59, 0x13): ("EVAL", 2), (0x4b, 0x05): ("DINT", 2),
    (0x63, 0x02): ("TTMR", 2), (0x6a, 0x00): ("FOR", 1),
    (0x4b, 0x00): ("BCD", 2), (0x4b, 0x0f): ("DNEG", 1),
    (0x6a, 0x01): ("NEXT", 0),
    (0x54, 0x01): ("CALL", 1), (0x54, 0x1a): ("XCALL", 1),
    (0x4b, 0x06): ("FLT", 2), (0x5d, 0x00): ("DATERD", 1), (0x5d, 0x01): ("DATEWR", 1),
    (0x51, 0x01): ("SFL", 2), (0x51, 0x02): ("BSFR", 2), (0x51, 0x03): ("BSFL", 2),
    (0x4d, 0x01): ("SCJ", 1),   # Source-derived parser observation.
    (0x4b, 0x04): ("INT", 2), (0x4b, 0x17): ("DFLTD", 2),   # Source-derived parser observation.
    (0x53, 0x0d): ("MAX", 3), (0x53, 0x0f): ("MIN", 3), (0x53, 0x07): ("DIS", 3),  # Source-derived parser observation.
    (0x49, 0x1c): ("E+", 2), (0x49, 0x1e): ("E-", 2),      # Source-derived parser observation.
    # Source-derived parser observation.
    # 문자열 리터럴을 첫 operand로 갖는 B=22는 decode_program의 전용 분기에서 먼저 처리한다.
    (0x49, 0x22): ("$+", 2), (0x49, 0x23): ("$+", 3),
}
# 미등록 05 응용명령: (marker,B) 미확정군은 generic 폴백이 <i:05:marker:B>로 노출(안전).
# Source-derived parser observation.
# Source-derived parser observation.
# Source-derived parser observation.
APPLY_MAP = {
    (0x05, 0x5a, 0x00): "SIN", (0x05, 0x5a, 0x01): "COS", (0x05, 0x5a, 0x04): "ACOS",
    (0x05, 0x5a, 0x06): "RAD", (0x05, 0x5a, 0x07): "DEG",
    (0x05, 0x59, 0x0d): "LEN", (0x05, 0x59, 0x14): "ASC",
    (0x05, 0x59, 0x15): "HEX", (0x05, 0x59, 0x18): "MIDR", (0x05, 0x59, 0x1a): "INSTR",
    (0x05, 0x59, 0x25): "STRDEL",
    (0x05, 0x4b, 0x07): "DFLT",
    (0x05, 0x50, 0x00): "ROR", (0x05, 0x50, 0x03): "RCL", (0x05, 0x51, 0x00): "SFR",
    (0x05, 0x49, 0x0a): "/", (0x05, 0x49, 0x1f): "E-", (0x05, 0x49, 0x22): "$+",
    (0x05, 0x53, 0x13): "WSUM", (0x05, 0x63, 0x24): "SCL",
    (0x05, 0x6a, 0x02): "RET", (0x05, 0x54, 0x00): "BREAK",
    (0x05, 0x54, 0x1b): "XCALL", (0x05, 0x54, 0x1c): "XCALL",
    (0x05, 0x52, 0x04): "BKRST",
    (0x05, 0x4c, 0x02): "EMOV", (0x05, 0x4c, 0x08): "XCH", (0x05, 0x4c, 0x0b): "SWAP",
    (0x06, 0x4f, 0x04): "WXORP", (0x06, 0x4f, 0x0c): "DXORP", (0x06, 0x4a, 0x02): "DECP",
    # Source-derived parser observation.
    (0x05, 0x48, 0x06): "CMP", (0x05, 0x48, 0x07): "DCMP", (0x05, 0x48, 0x08): "ZCP",
    (0x05, 0x49, 0x0c): "D*", (0x05, 0x49, 0x0e): "D/",
    (0x05, 0x4c, 0x04): "CML", (0x05, 0x50, 0x02): "ROL", (0x05, 0x53, 0x05): "ENCO",
    (0x05, 0x4f, 0x01): "WAND", (0x05, 0x4f, 0x03): "WOR", (0x05, 0x4f, 0x05): "WXOR",
    (0x05, 0x4f, 0x09): "DAND", (0x05, 0x4f, 0x0b): "DOR",
    (0x05, 0x4a, 0x00): "INC", (0x05, 0x4a, 0x02): "DEC",
    # Source-derived parser observation.
    (0x05, 0x4d, 0x00): "CJ", (0x05, 0x4d, 0x06): "GOEND", (0x05, 0x68, 0x00): "JMP",
    # Source-derived parser observation.
    (0x06, 0x51, 0x01): "SFLP", (0x06, 0x52, 0x04): "BKRSTP",
}
# Source-derived parser observation.
EDGE04 = {0x02: "LDP", 0x03: "LDF", 0x04: "LDPI", 0x08: "ORP", 0x09: "ORF",
          0x0e: "ANDP", 0x0f: "ANDF", 0x15: "ANDPI", 0x16: "ANDFI"}
# Source-derived parser observation.
COMM_PFX = {0x71: "ZP.", 0x72: "GP."}

# 비교명령(06 40 [W] op conn 06): conn→연결, op→연산자(op%6, op>=6이면 D접두)
CMP_CONN = {0x10: "LD", 0x11: "AND", 0x12: "OR"}
CMP_SYM = ["=", "<>", ">", ">=", "<", "<="]


def cmp_mnemonic(op, conn):
    c = CMP_CONN.get(conn)
    if c is None or op > 0x0b:
        return f"<cmp:{op:02x}{conn:02x}>"
    return f"{c}{'D' if op >= 6 else ''}{CMP_SYM[op % 6]}"


def load_all_substreams(arg):
    """arg(.gxw 또는 추출디렉토리)에서 _hdb 전 서브스트림 {번호:bytes} 반환."""
    out = {}
    if os.path.isdir(arg):
        sd = os.path.join(arg, "_hdb_sub")
        if os.path.isdir(sd):
            names = os.listdir(sd)
            if len(names) > bounded_ole.MAX_STREAMS:
                raise ValueError("extracted stream count exceeds the budget")
            total = 0
            for f in names:
                path = os.path.join(sd, f)
                if os.path.islink(path) or not os.path.isfile(path):
                    raise ValueError("extracted stream must be a regular file")
                size = os.path.getsize(path)
                total += size
                if size > bounded_ole.MAX_STREAM_BYTES or total > bounded_ole.MAX_TOTAL_BYTES:
                    raise ValueError("extracted stream byte budget exceeded")
                with open(path, "rb") as handle:
                    body = handle.read(size + 1)
                if len(body) != size:
                    raise ValueError("extracted stream size changed during read")
                out[f.split("__")[-1]] = body
        return out
    with open(arg, "rb") as handle:
        head = handle.read(8)
    if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":  # OLE = .gxw
        ole = bounded_ole.open_file(arg)
        try:
            hdb = bounded_ole.stream(ole, "_hdb")
        finally:
            ole.close()
        sub = bounded_ole.open_nested(hdb)
        try:
            return bounded_ole.all_streams(sub)
        finally:
            sub.close()
    # 단일 _hdb__NN 파일
    with open(arg, "rb") as handle:
        size = os.path.getsize(arg)
        if size > bounded_ole.MAX_STREAM_BYTES:
            raise ValueError("single stream exceeds the byte budget")
        out["12"] = handle.read(size + 1)
        if len(out["12"]) != size:
            raise ValueError("single stream size changed during read")
    return out


POU_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{1,31}$")


def is_valid_pou_name(name):
    """GX Works POU name candidate. Allows numeric/hyphen names such as 100-MZ."""
    return bool(POU_NAME_RE.match(name))


def find_pou_name(b):
    """POU 본체 끝의 <uint32 len><name UTF-16><00 00>에서 POU명 추출."""
    nm = None
    for m in re.finditer(rb"([\x02-\x20])\x00\x00\x00((?:[\x20-\x7e]\x00){1,32})\x00\x00", b):
        cand = m.group(2).decode("utf-16le")
        if m.group(1)[0] == len(cand) + 1 and is_valid_pou_name(cand):
            nm = cand
    return nm


# ── 디바이스 코멘트 디렉토리 RE (100 클론 전진분 역흡수) ─────────────────────────
# Source-derived parser observation.
# Source-derived parser observation.
# Source-derived parser observation.
# Source-derived parser observation.
# Source-derived parser observation.
# 2파일 교차 확정: `d0 00 <addr:2 LE><00 00><count:4 LE>` 1차 포맷 그대로 재사용,
# Source-derived parser observation.
CMT_DIR_DEVICE = {
    0x9c: ("X", 16), 0x9d: ("Y", 16), 0x90: ("M", 10), 0x92: ("L", 10),
    0xa1: ("SB", 16),   # Issue49 Q06UDV A/B: 48 Kn operands per variant
    0xa0: ("B", 16), 0xa8: ("D", 10), 0xb0: ("ZR", 10), 0xb4: ("W", 16),
    0xc2: ("T", 10), 0xc5: ("C", 10), 0x91: ("SM", 10), 0xa9: ("SD", 10),
    0xd0: ("P", 10),
}


def _cmt_hex(a):
    "GX Works2 코멘트 표기 16진 - A-F 시작 주소에 leading 0(0xA→'0A' 0xA0→'0A0' 0x10→'10')."
    h = format(a, "X")
    return "0" + h if h[0] in "ABCDEF" else h


def comment_directory(data):
    '1차 range-run 디렉토리(전체화): <code:1><00><addr:2 LE><00 00><count:4 LE> (10B).\n    100 전진분 흡수 - typecode 12종 전부 addr 0..0xFFFF count 1..65535(구 X/Y/M/T/C 트리비얼\n    한정 폐기). best-stream이 최장 코멘트블록 기준이라 가짜 디렉토리에 속지 않는다.'
    devs = []
    i, end = 0, len(data) - 10
    while i <= end:
        c = data[i]
        info = CMT_DIR_DEVICE.get(c)
        if info and data[i + 1] == 0 and data[i + 4] == 0 and data[i + 5] == 0:
            addr = struct.unpack_from("<H", data, i + 2)[0]
            cnt = struct.unpack_from("<I", data, i + 6)[0]
            if 0 <= addr <= 0xFFFF and 1 <= cnt <= 65535:
                nm, radix = info
                for k in range(cnt):
                    a = addr + k
                    devs.append(f"{nm}{_cmt_hex(a)}" if radix == 16 else f"{nm}{a}")
                i += 10
                continue
        i += 1
    return devs


def high_addr_directory(data):
    '2차 고주소 디렉토리(파일레지스터 등): <addr:4 LE><count:4 LE><typecode×2> (10B).\n    판별자 = typecode 2회 반복(D=a8 a8 ZR=b0 b0). 1차(1B code+2B addr)와 구분.\n    + 청크끝 마커 보정(작업67 phase2): 정상 code×2 엔트리 직후 <…><code8><00>(직전타입 code 누설\n    + addr=직전+stride count동일) 마커를 직전 타입 1개로 흡수(스캔 커서는 정상엔트리 다음=i+10).'
    devs = []
    i, end = 0, len(data) - 10
    s_code = s_addr = s_prev = -1
    while i <= end:
        c1, c2 = data[i + 8], data[i + 9]
        info = CMT_DIR_DEVICE.get(c1) if c1 == c2 else None
        if info:
            addr = struct.unpack_from("<I", data, i)[0]
            cnt = struct.unpack_from("<I", data, i + 4)[0]
            if 0 <= addr <= 0xFFFFFF and 1 <= cnt <= 65535:
                nm, radix = info
                for k in range(cnt):
                    a = addr + k
                    devs.append(f"{nm}{_cmt_hex(a)}" if radix == 16 else f"{nm}{a}")
                s_prev = s_addr if c1 == s_code else -1
                s_code, s_addr = c1, addr
                m = i + 10
                if s_prev >= 0 and m + 9 < len(data):
                    stride = s_addr - s_prev
                    m_addr = struct.unpack_from("<I", data, m)[0]
                    m_cnt = struct.unpack_from("<I", data, m + 4)[0]
                    if (data[m + 9] == 0 and data[m + 8] in CMT_DIR_DEVICE
                            and m_addr == s_addr + stride and m_cnt == cnt):
                        devs.append(f"{nm}{_cmt_hex(m_addr)}" if radix == 16 else f"{nm}{m_addr}")
                i += 10
                continue
        i += 1
    return devs


def ug_directory(data):
    '3차 U\\G(지능형모듈 버퍼) 디렉토리: `ab f8 <addr:2 LE><module:2 LE><count:4 LE>` (10B).\n    ab=G 디바이스 코드 f8=U-모듈 수식자(MOD_UMODULE 동일 상수). addr **십진** 전개 module 16진\n    패딩 → `U{module}\\G{addr+k}`. 100 작업63 q1 RE(precision 100% / recall ~96%, 비트지정 제외).'
    devs = []
    i, end = 0, len(data) - 10
    while i <= end:
        if data[i] == 0xab and data[i + 1] == 0xf8:
            addr = struct.unpack_from("<H", data, i + 2)[0]
            module = struct.unpack_from("<H", data, i + 4)[0]
            cnt = struct.unpack_from("<I", data, i + 6)[0]
            if 1 <= cnt <= 65535:
                for k in range(cnt):
                    devs.append(f"U{_cmt_hex(module)}\\G{addr + k}")
                i += 10
                continue
        i += 1
    return devs


def ug_bit_directory(data):
    'Source-derived parser observation.'
    out = []
    i, end = 0, len(data) - 10
    while i <= end:
        addr = struct.unpack_from("<I", data, i)[0]
        cnt = struct.unpack_from("<H", data, i + 4)[0]
        firstbit = struct.unpack_from("<H", data, i + 6)[0]
        if 0 <= addr <= 0xFFFF and 1 <= cnt <= 16 and 0 <= firstbit <= 15:
            pos, bit, entries, ok = i + 8, firstbit, [], True
            for k in range(cnt):
                if k > 0:
                    if pos + 2 > len(data):
                        ok = False; break
                    bit = struct.unpack_from("<H", data, pos)[0]
                    if not (0 <= bit <= 15):
                        ok = False; break
                    pos += 2
                if pos + 2 > len(data):
                    ok = False; break
                ln = struct.unpack_from("<H", data, pos)[0]
                if not (2 <= ln <= 64):
                    ok = False; break
                tlen = (ln - 1) * 2
                te = pos + 2 + tlen
                if te + 2 > len(data) or data[te] != 0 or data[te + 1] != 0:
                    ok = False; break
                try:
                    text = data[pos + 2:te].decode("utf-16le")
                except Exception:
                    ok = False; break
                if not text:
                    ok = False; break
                entries.append((bit, text))
                pos = te + 2
            if (ok and len(entries) == cnt
                    and all(entries[k][0] < entries[k + 1][0] for k in range(len(entries) - 1))):
                for bit, text in entries:
                    out.append((f"U2\\G{addr}.{bit:X}", text))
                i = pos
                continue
        i += 1
    return out


def unified_directory(data):
    '1 2 3차 디렉토리를 offset순 단일 스캔으로 통합 전개(통합 = 깨끗한 12-run 타입 시퀀스\n    M,L,SM,T,D,SD,ZR,Y,X,U\\G,W,B). 매 위치 i마다 (1) 3차 ab f8 → (2) 1차 range-run →\n    (3) 2차 고주소+마커보정 순으로 시도. N==M 무영향(ab f8 0건이면 1차와 동일).'
    devs = []
    i, end = 0, len(data) - 10
    s_code = s_addr = s_prev = -1
    while i <= end:
        # (1) 3차 U\G
        if data[i] == 0xab and data[i + 1] == 0xf8:
            addr = struct.unpack_from("<H", data, i + 2)[0]
            module = struct.unpack_from("<H", data, i + 4)[0]
            cnt = struct.unpack_from("<I", data, i + 6)[0]
            if 1 <= cnt <= 65535:
                for k in range(cnt):
                    devs.append(f"U{_cmt_hex(module)}\\G{addr + k}")
                s_code = s_addr = s_prev = -1
                i += 10
                continue
        # (2) 1차 range-run
        c = data[i]
        info1 = CMT_DIR_DEVICE.get(c)
        if info1 and data[i + 1] == 0 and data[i + 4] == 0 and data[i + 5] == 0:
            addr = struct.unpack_from("<H", data, i + 2)[0]
            cnt = struct.unpack_from("<I", data, i + 6)[0]
            if 0 <= addr <= 0xFFFF and 1 <= cnt <= 65535:
                nm, radix = info1
                for k in range(cnt):
                    a = addr + k
                    devs.append(f"{nm}{_cmt_hex(a)}" if radix == 16 else f"{nm}{a}")
                s_code = s_addr = s_prev = -1
                i += 10
                continue
        # (3) 2차 고주소 + 청크끝 마커 보정
        c1, c2 = data[i + 8], data[i + 9]
        info3 = CMT_DIR_DEVICE.get(c1) if c1 == c2 else None
        if info3:
            addr = struct.unpack_from("<I", data, i)[0]
            cnt = struct.unpack_from("<I", data, i + 4)[0]
            if 0 <= addr <= 0xFFFFFF and 1 <= cnt <= 65535:
                nm, radix = info3
                for k in range(cnt):
                    a = addr + k
                    devs.append(f"{nm}{_cmt_hex(a)}" if radix == 16 else f"{nm}{a}")
                s_prev = s_addr if c1 == s_code else -1
                s_code, s_addr = c1, addr
                m = i + 10
                if s_prev >= 0 and m + 9 < len(data):
                    stride = s_addr - s_prev
                    m_addr = struct.unpack_from("<I", data, m)[0]
                    m_cnt = struct.unpack_from("<I", data, m + 4)[0]
                    if (data[m + 9] == 0 and data[m + 8] in CMT_DIR_DEVICE
                            and m_addr == s_addr + stride and m_cnt == cnt):
                        devs.append(f"{nm}{_cmt_hex(m_addr)}" if radix == 16 else f"{nm}{m_addr}")
                i += 10
                continue
        i += 1
    return devs


# Source-derived parser observation.
# Source-derived parser observation.
# W 구간 직전에 끼어들어 N!=M 폴백 바인딩을 +2 시프트시킨다(구조적 구분 신호 없음
# Source-derived parser observation.
# 모듈 모델명 표기(대문자+숫자, 공백 없음, 3~12자)로 후보를 걸러 코멘트 풀에서
# Source-derived parser observation.
# Source-derived parser observation.
_MODULE_LABEL_RE = re.compile(r"^[A-Z][A-Z0-9]{2,11}$")


def _comment_candidates(data):
    '길이접두 UTF-16LE 코멘트 후보 [(off, text, next_off)]. next_off = off + 2*len + 8 (연쇄).\n    텍스트=영문/한글/혼용 사용자 코멘트 전체(CJK 필터 폐기 - 100 §4).\n    모듈 구성 라벨(_MODULE_LABEL_RE)은 후보 목록에서 제외 - 스캔 커서(i)는 정상\n    진행하되 out에 append하지 않아, 해당 위치에서 체인이 자연 분리된다(off==prev\n    연쇄조건 불일치).'
    out, i, end = [], 0, len(data) - 4
    while i <= end:
        ln = struct.unpack_from("<I", data, i)[0]
        if 2 <= ln <= 64:
            text_len = (ln - 1) * 2
            te = i + 4 + text_len
            if te + 2 <= len(data) and data[te] == 0 and data[te + 1] == 0:
                try:
                    raw = data[i + 4:i + 4 + text_len].decode("utf-16le")
                except Exception:
                    raw = None
                if (raw is not None and any(ch.isalpha() for ch in raw)
                        and all(ch in "\t\n" or ord(ch) >= 0x20 for ch in raw)):
                    if not _MODULE_LABEL_RE.match(raw):
                        out.append((i, raw, te + 2 + 4))
                    i += 4 + ln * 2
                    continue
        i += 2
    return out


def longest_comment_block(data):
    """코멘트 풀 최장 연쇄 블록(off==prev.next_off 연쇄, 싱글톤 노이즈 배제)."""
    cands = _comment_candidates(data)
    if not cands:
        return []
    best_s = best_l = cur_s = 0
    prev = -1
    for j in range(len(cands)):
        if prev != -1 and cands[j][0] != prev:
            if j - cur_s > best_l:
                best_l, best_s = j - cur_s, cur_s
            cur_s = j
        prev = cands[j][2]
    if len(cands) - cur_s > best_l:
        best_l, best_s = len(cands) - cur_s, cur_s
    return [cands[k][1] for k in range(best_s, best_s + best_l)]


def comment_chains(data):
    '코멘트 풀 연쇄 블록별 분리(>=30 필터, 30 미만은 디렉토리영역 노이즈) - N!=M 양방향 매칭용.'
    cands = _comment_candidates(data)
    if not cands:
        return []
    out, cs, prev = [], 0, -1
    for j in range(len(cands)):
        if prev != -1 and cands[j][0] != prev:
            ch = [cands[k][1] for k in range(cs, j)]
            if len(ch) >= 30:
                out.append(ch)
            cs = j
        prev = cands[j][2]
    tail = [cands[k][1] for k in range(cs, len(cands))]
    if len(tail) >= 30:
        out.append(tail)
    return out


def _is_ug(dev):
    return "\\" in dev


def _is_system(dev):
    return dev.startswith("SM") or dev.startswith("SD")


def bind_bidirectional(unified, chains):
    'Source-derived parser observation.'
    bound = [""] * len(unified)
    if not chains:
        return bound
    if sum(len(c) for c in chains) == len(unified):
        pos = 0
        for ch in chains:
            for k, cm in enumerate(ch):
                bound[pos + k] = cm
            pos += len(ch)
        return bound
    first, last = chains[0], chains[-1]
    n = len(unified)
    i = 0
    while i < min(len(first), n) and not _is_ug(unified[i]):
        bound[i] = first[i]
        i += 1
    j, saw = 0, False
    while j < min(len(last), n) and (n - 1 - j) >= i:
        ug = _is_ug(unified[n - 1 - j])
        if ug and saw:
            break
        if not ug:
            saw = True
        bound[n - 1 - j] = last[len(last) - 1 - j]
        j += 1
    return bound


def device_comment_pairs(streams):
    '전 서브스트림에서 (device, comment) user 쌍 - best-stream(최장 코멘트블록) 선택 +\n    N==M 단조 zip(SM/SD 드롭) / N!=M 통합 디렉토리 재등록 + 양방향 부분복구.\n    100 GxwCommentExtractor.extract() 포팅. 4차 비트지정 U\\G(`ug_bit_directory`)는\n    위치기반 zip과 독립적(자기서술적 addr+text)이라 별도 스캔 후 합산한다.\n    반환 (pairs, warning).'
    best_c, best_d, best_b = [], [], None
    for num, b in streams.items():
        d = comment_directory(b)
        if not d:
            continue
        c = longest_comment_block(b)
        if len(c) > len(best_c):
            best_c, best_d, best_b = c, d, b
    if len(best_c) < 2 or not best_d or best_b is None:
        return [], "NoCommentStream"
    bit_pairs = ug_bit_directory(best_b)
    if len(best_d) == len(best_c):                       # N==M 청정 바인딩
        pairs = [(dev, cm) for dev, cm in zip(best_d, best_c) if not _is_system(dev)]
        return pairs + bit_pairs, None
    uni = unified_directory(best_b)                      # N!=M 폴백
    bound = bind_bidirectional(uni, comment_chains(best_b))
    pairs = [(dev, cm) for dev, cm in zip(uni, bound) if not _is_system(dev)]
    return pairs + bit_pairs, ("CountMismatch", len(uni), len(best_c))


def device_comment_map(streams):
    '디바이스↔코멘트 dict(코멘트 채워진 쌍만 - IL 덤프 COMMENT.csv용).\n    인자 = load_all_substreams 결과 dict. (하위호환: 단일 스트림 bytes도 수용.)'
    if not isinstance(streams, dict):
        streams = {"0": streams}
    pairs, _ = device_comment_pairs(streams)
    return {d: c for d, c in pairs if c}


def decode_device(dd, aa):
    if dd in DEVICE and dd != 0xa1:
        nm, radix = DEVICE[dd]
        return f"{nm}{_cmt_hex(aa)}" if radix == 16 else f"{nm}{aa}"
    return f"<dev:{dd:02x}.{aa:02x}>"


def decode_il(data):
    '단순 IL 요소(03 TT 03 04 DD AA)만 - 회귀 비교/POU 탐지용 경량 디코드.'
    il = []
    for m in re.finditer(rb"\x03(.)\x03\x04(.)(.)", data):
        tt, dd, aa = m.group(1)[0], m.group(2)[0], m.group(3)[0]
        instr = INSTR.get(tt, f"<i:{tt:02x}>")
        il.append((m.start(), instr, decode_device(dd, aa)))
    return il


_OPERAND_TC = set(DEVICE) | {0xe8, 0xe9, 0xea, 0xeb, 0xec, MOD_ZINDEX, MOD_UMODULE, MOD_BIT, MOD_ZINDEX2, MOD_DIGIT}


def _is_operand_frame(data, p, n):
    """data[p]가 유효 오퍼랜드 프레임 오프너(<f><tc><val><f>, tc=디바이스/상수/수식자)인지."""
    f = data[p]
    if f in (0x04, 0x05, 0x06, 0x07):
        w = f - 0x03
        if p + 2 + w < n and data[p + 2 + w] == f:
            return data[p + 1] in _OPERAND_TC
    return False


def _scan_to_operand(data, i, n, window=6):
    """i부터 다음 오퍼랜드 프레임 위치 반환. opcode 경계(다음 명령) 만나면 -1(오퍼랜드 끝)."""
    p = i
    for _ in range(window):
        if p >= n - 2:
            return -1
        if _is_operand_frame(data, p, n):
            return p
        if ((data[p] == 0x03 and p + 2 < n and data[p + 2] == 0x03)          # 03 TT 03
                or (data[p] == 0x05 and p + 1 < n and 0x40 <= data[p + 1] <= 0x7f)  # Source-derived parser observation.
                or (data[p] == 0x06 and p + 1 < n and data[p + 1] == 0x40)    # 비교
                or (data[p] == 0x04 and p + 2 < n and data[p + 1] in INSTR and data[p + 2] == 0x02)  # 수식자 접점
                or data[p] in (0x21, 0x25)):                                  # Source-derived parser observation.
            return -1
        p += 1
    return -1


def _format_base(tc, val, w):
    '베이스 오퍼랜드(수식자 제외) → 텍스트. K/H 상수 디바이스.'
    if tc == 0xe8:                                   # K 16비트 (w>=2면 부호)
        if w >= 2 and val >= 0x8000:
            val -= 0x10000
        return f"K{val}"
    if tc == 0xe9:                                   # K 32비트 (부호)
        if val >= 0x80000000:
            val -= 0x100000000
        return f"K{val}"
    if tc in (0xea, 0xeb):                           # Source-derived parser observation.
        return f"H{val:X}"
    if tc == 0xec:                                   # E 부동소수 상수 (4바이트 IEEE LE)
        fv = struct.unpack("<f", int(val).to_bytes(4, "little"))[0]
        return f"E{fv:g}"
    if tc in DEVICE and tc != 0xa1:
        nm, radix = DEVICE[tc]
        return f"{nm}{_cmt_hex(val)}" if radix == 16 else f"{nm}{val}"
    return f"<dev:{tc:02x}>{val}"


def _read_operand(data, i):
    """프레임-폭 오퍼랜드: <f> <tc> <val:(f-3)B LE> <f>. f=0x04→1B … 0x07→4B (open==close 자기검증).
    선행 수식자(f0=Z인덱스/f8=U모듈/f2=비트)를 누적해 베이스에 조립: U{u}\\{base}Z{z}.{bit}.
    유효 프레임 아니면 04 분리자 건너뛰고 재시도. 반환 (텍스트, 다음위치) 또는 (None, i)."""
    n = len(data)
    u_num = z_idx = z_idx2 = bit = digit = None
    skips = 0
    while i < n - 2:
        f = data[i]
        if f in (0x04, 0x05, 0x06, 0x07):
            w = f - 0x03
            if i + 2 + w < n and data[i + 2 + w] == f:
                tc = data[i + 1]
                val = int.from_bytes(data[i + 2:i + 2 + w], "little")
                nxt = i + 3 + w
                if tc == MOD_ZINDEX:                  # Z 인덱스 수식 (베이스 앞)
                    z_idx = val; i = nxt; continue
                if tc == MOD_ZINDEX2:                 # ZR 인덱스 수식 (GX 표시 ZZ)
                    z_idx2 = val; i = nxt; continue
                if tc == MOD_UMODULE:                 # U 모듈번호 (베이스 앞)
                    u_num = val; i = nxt; continue
                if tc == MOD_BIT:                     # 비트 지정 (베이스 앞)
                    bit = val; i = nxt; continue
                if tc == MOD_DIGIT:                   # 디지트 지정 KnXXX (베이스 앞)
                    digit = val; i = nxt; continue
                if tc == 0xa1 and (w != 2 or digit not in range(1, 9)
                        or not 256 <= val or val + 4 * digit - 1 > 2047
                        or any(mod is not None for mod in (u_num, z_idx, z_idx2, bit))):
                    return f"<dev:{tc:02x}>{val}", nxt
                s = f"SB{_cmt_hex(val)}" if tc == 0xa1 else _format_base(tc, val, w)          # 베이스 도달 → 조립
                if u_num is not None:
                    s = f"U{u_num}\\{s}"
                if z_idx is not None:
                    s = f"{s}Z{z_idx}"
                if z_idx2 is not None:
                    s = f"{s}ZZ{z_idx2}"
                if bit is not None:
                    s = f"{s}.{bit:X}"
                if digit is not None:
                    s = f"K{digit}{s}"
                return s, nxt
            if f == 0x04:                            # 유효프레임 아닌 04 = 분리자
                i += 1
                skips += 1
                if skips > 6:
                    break
                continue
        break
    return None, i


def _decode_socket_command(data, offset):
    """Decode only the Issue #46 observed 70-family shapes, atomically.

    This is binary observation, not CSV lifecycle authority.  Do not extend
    the global device grammar for the local d8 unit operand.  Return a row
    and exclusive end, or None when this is not a 70-family candidate.
    """
    n = len(data)
    if offset + 1 >= n or data[offset + 1] != 0x70:
        return None
    length = data[offset]
    if not 8 <= length <= 31:
        return None
    end = min(offset + length, n)
    unknown = (("<i:70:socket>", ""), end)
    if offset + length > n or data[end - 1] != length:
        # The claimed length is untrusted until its closer matches.  Advancing
        # by it could swallow the next intact instruction after a torn frame.
        return (("<i:70:socket>", ""), offset + 2)
    name = data[offset + 5:end - 1]
    shapes = {b"SOCOPEN": (13, 4), b"SOCCLOSE": (13, 4),
              b"SOCSND": (14, 5), b"SOCRCV": (14, 5)}
    shape = shapes.get(name)
    if shape is None:
        return unknown
    header = data[offset + 2:offset + 5]
    fresh = header == bytes((12, shape[1], 2))
    if not fresh and header != bytes((*shape, 2)):
        return unknown
    # Official synthetic A/B: H12, D two bytes, M one or two bytes.
    # Preserve the attachment H13/H14 layouts, whose M is always two bytes.
    types = [(0xd8, 1), (0xe9, 1)] + [(0xa8, 2)] * (shape[1] - 3) + [(0x90, 0 if fresh else 2)]
    values, cursor = [], end
    for tc, width in types:
        if width == 0:
            if cursor >= n or data[cursor] not in (4, 5):
                return (("<i:70:socket>", ""), cursor)
            width = data[cursor] - 3
        size = width + 3
        if (cursor + size > n or data[cursor:cursor + 2] != bytes((size, tc))
                or data[cursor + size - 1] != size):
            return (("<i:70:socket>", ""), cursor)
        values.append(int.from_bytes(data[cursor + 2:cursor + 2 + width], "little"))
        cursor += size
    if values[0] != 0:
        return (("<i:70:socket>", ""), cursor)
    if cursor < n and (_is_operand_frame(data, cursor, n)
                       or data[cursor:cursor + 2] == b"\x04\xd8"):
        return (("<i:70:socket>", ""), cursor)
    operands = ["U0", "K" + str(values[1])]
    operands += ["D" + str(value) for value in values[2:-1]]
    operands.append("M" + str(values[-1]))
    return (("SP." + name.decode("ascii"), " ".join(operands)), cursor)


def decode_program(data):
    'POU 본체 sec0를 IL 순서대로 디코드 - 접점/코일/연결/응용/타이머 카운터/MOV.'
    # Source-derived parser observation.
    # 단순명령뿐 아니라 비교접점이 첫 rung인 프로젝트도 시작 후보로 인정한다.
    start = 0
    for k in range(len(data) - 5):
        socket = _decode_socket_command(data, k)
        if socket is not None and socket[0][0].startswith("SP.SOC"):
            start = k
            break
        if (data[k] == 0x05 and data[k + 4] == 0x05
                and ((data[k + 1], data[k + 3]) in DISPATCH_05
                     or (0x05, data[k + 1], data[k + 3]) in APPLY_MAP)):
            start = k
            break
        if (k + 6 < len(data) and data[k:k + 2] == b"\x06\x40"
                and data[k + 4] in CMP_CONN and data[k + 5] == 0x06
                and _is_operand_frame(data, k + 6, len(data))):
            start = k
            break
        if (data[k] == 0x03 and data[k + 2] == 0x03 and data[k + 1] in INSTR
                and data[k + 3] in (0x04, 0x05) and data[k + 4] in DEVICE):
            start = k
            break
        # 수식자 접점/코일이 첫 명령인 경우도 실제 명령 시작점이다.
        # batch-020 Q06UDV GX Works2 export: 04 00 02 04 + 04 f0 0c 04 + M4100.
        if (k + 5 < len(data) and data[k] == 0x04 and data[k + 1] in INSTR
                and data[k + 2] in (0x02, 0x03) and data[k + 3] == 0x04
                and data[k + 4] == 0x04
                and data[k + 5] in (MOD_BIT, MOD_ZINDEX, MOD_UMODULE, MOD_ZINDEX2)):
            start = k
            break
        # 첫 라인 스테이트먼트도 시작점 후보 (<L> 80 <H=ceil(L/2)> <text> <L>, 첫 LS=[Title])
        if data[k + 1] == 0x80 and 5 <= data[k] and data[k + 2] == (data[k] + 1) // 2 and data[k + 3] == 0x5b:
            L = data[k]
            if (k + 3 + (L - 4) < len(data) and data[k + 3 + (L - 4)] == L
                    and all(0x20 <= c <= 0xff for c in data[k + 3:k + 3 + (L - 4)])):
                start = k
                break
    data = data[start:]
    out, i, n = [], 0, len(data)
    while i < n - 2:
        b = data[i]
        socket = _decode_socket_command(data, i)
        if socket is not None:
            row, i = socket
            out.append(row)
            continue
        # 라인 스테이트먼트(rung 주석): <L=len+4> 80 <H=ceil(L/2)> <텍스트 (L-4)자> <L>
        # 닫기 바이트(=L) + 80 마커가 false match 차단. 텍스트는 cp1252(em dash 0x97 등).
        # Source-derived parser observation.
        if (i + 3 < n and data[i + 1] == 0x80
                and data[i + 2] == (data[i] + 1) // 2):
            L = data[i]
            tl = L - 4
            if 5 <= L and 1 <= tl and i + 3 + tl < n and data[i + 3 + tl] == L:
                txt = data[i + 3:i + 3 + tl]
                if all(0x20 <= c <= 0xff for c in txt):
                    out.append(("__STMT__", txt.decode("cp1252", errors="replace")))
                    i += 3 + tl + 1
                    continue
        # Note frame accepts the established length relation and the isolated
        # Issue #39 peripheral raw-01 frame.  Do not infer a general subtype
        # grammar from either raw byte here.
        if (i + 3 < n and data[i + 1] == 0x82
                and (data[i + 2] == (data[i] + 1) // 2 or data[i + 2] == 0x01)):
            L = data[i]
            tl = L - 4
            if 5 <= L and 1 <= tl and i + 3 + tl < n and data[i + 3 + tl] == L:
                txt = data[i + 3:i + 3 + tl]
                if all(0x20 <= c <= 0xff for c in txt):
                    out.append(("__NOTE__", txt.decode("cp1252", errors="replace")))
                    i += 3 + tl + 1
                    continue
        # 통신/지능형 명령 <L> <71|72> <3B> <ASCII (L-6)자> <L> + 오퍼랜드 (ZP.BUFSND/GP.OUTPUT/G.INPUT 등)
        if (0x08 <= b <= 0x1f and i + 1 < n and data[i + 1] in COMM_PFX
                and i + b - 1 < n and data[i + b - 1] == b):
            nl = b - 6
            nm = data[i + 5:i + 5 + nl]
            if nl > 0 and all(0x20 <= c <= 0x7f for c in nm):
                pre = "G." if (data[i + 1] == 0x72 and data[i + 4] == 0x0a) else COMM_PFX[data[i + 1]]
                i += b
                ops = []
                while len(ops) < 6:
                    p = _scan_to_operand(data, i, n)
                    if p < 0:
                        break
                    o, i = _read_operand(data, p)
                    ops.append(o or "")
                out.append((pre + nm.decode("ascii"), " ".join(ops).strip()))
                continue
        # Source-derived parser observation.
        if (b == 0x04 and i + 3 < n and data[i + 1] in EDGE04
                and data[i + 2] in (0x02, 0x03) and data[i + 3] == 0x04):
            mnem = EDGE04[data[i + 1]]
            i += 4
            dev, i = _read_operand(data, i)
            out.append((mnem, dev or ""))
            continue
        # Source-derived parser observation.
        if (b == 0x04 and i + 3 < n and data[i + 1] in SPECIAL04
                and data[i + 2] in (0x02, 0x03, 0x04) and data[i + 3] == 0x04):
            mnem, nops = SPECIAL04[data[i + 1]]
            i += 4
            ops = []
            while len(ops) < nops:
                p = _scan_to_operand(data, i, n)
                if p < 0:
                    break
                o, i = _read_operand(data, p)
                ops.append(o or "")
            out.append((mnem, " ".join(ops).strip()))
            continue
        # 수식자 접점/코일: 04 <op> <marker> 04 + 04 <f2|f0|f8|f6> <v> 04 <base>
        # Source-derived parser observation.
        if (b == 0x04 and i + 5 < n and data[i + 1] in INSTR and data[i + 2] in (0x02, 0x03)
                and data[i + 3] == 0x04 and data[i + 4] == 0x04
                and data[i + 5] in (MOD_BIT, MOD_ZINDEX, MOD_UMODULE, MOD_ZINDEX2)):
            op = data[i + 1]; i += 4
            dev, i = _read_operand(data, i)
            out.append((INSTR[op], dev or ""))
            continue
        # Source-derived parser observation.
        # Source-derived parser observation.
        if (b == 0x04 and i + 5 < n and data[i + 1] in INSTR and data[i + 2] in (0x02, 0x03)
                and data[i + 3] == 0x04 and data[i + 4] == 0x04
                and data[i + 5] in DEVICE):
            op = data[i + 1]; i += 4
            dev, i = _read_operand(data, i)
            out.append((INSTR[op], dev or ""))
            continue
        # OUT 타이머/카운터 full-token: 04 21 <04|05> 04 + T/C + 프리셋(K/D/ZR 등).
        if (b == 0x04 and i + 3 < n and data[i + 1] == 0x21
                and data[i + 2] in (0x04, 0x05) and data[i + 3] == 0x04):
            i += 4
            dev, i = _read_operand(data, i)
            k, j = _read_operand(data, i)
            if k:
                out.append(("OUT", f"{dev} {k}")); i = j
            else:
                out.append(("OUT", dev or ""))
            continue
        # 대상 명령 04 <op> <02|04> 04 + 디바이스 [+ K]:
        # Source-derived parser observation.
        if (b == 0x04 and i + 3 < n and data[i + 1] in (0x22, 0x24)
                and data[i + 2] in ((0x04,) if data[i + 1] == 0x22 else (0x02, 0x04))
                and data[i + 3] == 0x04):
            mnem = "OUTH" if data[i + 1] == 0x22 else "RST"
            i += 4
            dev, i = _read_operand(data, i)
            if mnem == "OUTH":
                k, j = _read_operand(data, i)
                if k and k.startswith("K"):
                    out.append((mnem, f"{dev} {k}")); i = j
                    continue
            out.append((mnem, dev or ""))
            continue
        if b == 0x04:
            i += 1; continue
        if b == 0x03 and data[i + 2] == 0x03:          # 03 TT 03
            tt = data[i + 1]; i += 3
            if tt in INSTR_NOOP:                         # 연결명령(피연산자 없음)
                out.append((INSTR_NOOP[tt], "")); continue
            if tt == 0x3c:                               # Source-derived parser observation.
                dev, j = _read_operand(data, i)
                out.append((dev or "<ptr>", "")); i = j if dev else i
                continue
            dev, j = _read_operand(data, i)
            instr = INSTR.get(tt, f"<i:{tt:02x}>")
            if dev:
                out.append((instr, dev)); i = j
            elif instr.startswith("<i:"):                # 미확인 명령은 노출(사전확장 신호)
                out.append((instr, ""))
            # else: 오퍼랜드 필수 접점/코일인데 비었으면 응용명령 바이트 파편 = 생략
            continue
        if b == 0x21 and i + 1 < n and data[i + 1] == 0x04:  # OUT 타이머/카운터(21 04 04 …, + K프리셋)
            # 마커 `21 04 04`(선행 0x04는 line 663서 소비)를 통째 건너뛰어 디바이스 프레임에 직접 도달.
            # i+=1만 하면 잔여 0x04 두 개가 디바이스 번호 저바이트 0x04와 만나 유령 1바이트 프레임
            # `04 05 c2 04`를 만들어 OUT T/C를 통째 silent 오디코드(예: T6148=0x1804 → <dev:05>194). TS-011.
            i += 3 if (i + 2 < n and data[i + 2] == 0x04) else 1
            dev, i = _read_operand(data, i)
            # 프리셋은 K상수뿐 아니라 ZR/D 등 간접지정 디바이스도 가능(OUT T140 ZR349). dev 직후
            # 첫 오퍼랜드 프레임은 프리셋(다음 rung은 03 명령이라 _read_operand가 None 반환 → 미흡수).
            k, j = _read_operand(data, i)
            if k:
                out.append(("OUT", f"{dev} {k}")); i = j
            else:
                out.append(("OUT", dev or ""))
            continue
        if b == 0x25 and i + 1 < n and data[i + 1] == 0x02:  # PLS (25 02 04 …)
            i += 2
            dev, i = _read_operand(data, i)
            out.append(("PLS", dev or "")); continue
        if b == 0x26 and i + 1 < n and data[i + 1] == 0x02:  # Source-derived parser observation.
            # Source-derived parser observation.
            # Source-derived parser observation.
            dev, j = _read_operand(data, i + 2)
            if dev:
                out.append(("PLF", dev)); i = j; continue
            # dev 없음 → 폴스루(generic i+=1)
        if b == 0x05 and data[i + 1] == 0x4c:           # MOV / DMOV / $MOV(문자열)
            # $MOV: 05 4c <A> <0a|03> + 문자열 <f> ee <text> <f> (f=0x03+길이, 프레임-폭) + 디바이스
            # Source-derived parser observation.
            if i + 3 < n and (data[i + 2] == 0x0a or data[i + 3] == 0x03):
                sm = re.search(rb"(.)\xee([\x20-\x7e]*?)\1", data[i:i + 96], re.DOTALL)
                if sm and sm.start() <= 6:
                    text = sm.group(2).decode("latin1"); j = i + sm.end()
                    d, i = _read_operand(data, j)
                    out.append(("$MOV", f'"{text}" {d or ""}'.strip()))
                    continue
            # Source-derived parser observation.
            # Source-derived parser observation.
            if i + 3 < n and data[i + 3] in XFER_B and 0x02 <= data[i + 2] <= 0x09:
                mnem, nops = XFER_B[data[i + 3]]
                i += 4
                ops = []
                for _ in range(nops):
                    p = i
                    while p < n - 4 and not _is_operand_frame(data, p, n):
                        p += 1
                        if p - i > 12:
                            p = i
                            break
                    o, i = _read_operand(data, p)
                    ops.append(o or "")
                out.append((mnem, " ".join(ops).strip()))
                continue
            # Source-derived parser observation.
        if (b == 0x05 and i + 4 < n and data[i + 1] == 0x49
                and data[i + 3] == 0x22 and data[i + 4] == 0x05):       # $+ 문자열 리터럴 + destination
            # batch-003 A/B 실측: 05 49 0c 22 05 + <f> ee <ASCII> <f> + device.
            # 일반 operand scanner는 문자열 프레임을 건너뛰므로 여기서 리터럴을 보존한다.
            sm = re.match(rb"(.)\xee([\x20-\x7e]*?)\1", data[i + 5:i + 101], re.DOTALL)
            if sm:
                text = sm.group(2).decode("latin1")
                j = i + 5 + sm.end()
                dest, j = _read_operand(data, j)
                if dest:
                    out.append(("$+", f'"{text}" {dest}'))
                    i = j
                    continue
        if b == 0x05 and i + 3 < n and (data[i + 1], data[i + 3]) in DISPATCH_05:  # 05 응용명령 디스패치
            mnem, nops = DISPATCH_05[(data[i + 1], data[i + 3])]
            i += 4
            ops = []
            for _ in range(nops):
                p = _scan_to_operand(data, i, n)
                if p < 0:
                    break
                o, i = _read_operand(data, p)
                ops.append(o or "")
            out.append((mnem, " ".join(ops).strip()))
            continue
        # Source-derived parser observation.
        # Source-derived parser observation.
        if (b == 0x05 and data[i + 1] == 0x49 and i + 3 < n              # 산술 05 49 <A> <B>
                and data[i + 3] in ARITH_B and 0x02 <= data[i + 2] <= 0x07):
            mnem = ARITH_B[data[i + 3]]
            i += 4
            ops = []
            while len(ops) < 3:                                          # Source-derived parser observation.
                p = _scan_to_operand(data, i, n)
                if p < 0:
                    break
                o, i = _read_operand(data, p)
                ops.append(o or "")
            out.append((mnem, " ".join(ops).strip()))
            continue
        if (b == 0x06 and data[i + 1] == 0x4a and i + 5 < n             # 펄스 INC 06 4a <A> <B> <x> 06
                and data[i + 5] == 0x06 and data[i + 3] in PINC_B):
            mnem = PINC_B[data[i + 3]]
            i += 6
            p = _scan_to_operand(data, i, n)
            if p >= 0:
                o, i = _read_operand(data, p)
                out.append((mnem, o or ""))
            else:
                out.append((mnem, ""))
            continue
        if b == 0x06 and data[i + 1] == 0x40:           # 비교접점 06 40 [W] op conn 06 + 2오퍼랜드
            # 닫는 06 = conn(10/11/12) 직후 (op바이트 0x06[D=]에서 조기종료 방지)
            j = i + 2
            k = j + 1
            while k < n and k - j < 4 and not (data[k] == 0x06 and data[k - 1] in (0x10, 0x11, 0x12)):
                k += 1
            if k < n and data[k] == 0x06 and data[k - 1] in (0x10, 0x11, 0x12):
                mnem = cmp_mnemonic(data[k - 2], data[k - 1])
                i = k + 1
                o1, i = _read_operand(data, i)
                o2, i = _read_operand(data, i)
                out.append((mnem, f"{o1 or ''} {o2 or ''}".strip()))
                continue
            i += 1
            continue
        if (b == 0x06 and data[i + 1] == 0x4c and i + 5 < n            # 펄스 전송 06 4c <A> <B> <x> 06
                and data[i + 5] == 0x06 and data[i + 3] in PXFER_B):   # inner 고정3B (B=data[i+3])
            B = data[i + 3]
            mnem = PXFER_B[B]
            nops = 3 if B in (0x06, 0x07) else 2
            i += 6
            ops = []
            for _ in range(nops):
                p = _scan_to_operand(data, i, n)
                if p < 0:
                    break
                o, i = _read_operand(data, p)
                ops.append(o or "")
            out.append((mnem, " ".join(ops).strip()))
            continue
        # Source-derived parser observation.
        # Source-derived parser observation.
        if b in (0x05, 0x06) and i + 3 < n and 0x40 <= data[i + 1] <= 0x7f:
            tag = APPLY_MAP.get((b, data[i + 1], data[i + 3]),
                                f"<i:{b:02x}:{data[i + 1]:02x}:{data[i + 3]:02x}>")
            i += 4
            ops = []
            while len(ops) < 6:
                p = _scan_to_operand(data, i, n)
                if p < 0:
                    break
                o, i = _read_operand(data, p)
                ops.append(o or "")
            out.append((tag, " ".join(ops).strip()))
            continue
        i += 1
    # Source-derived parser observation.
    if data and data[-1] == 0x04 and (not out or out[-1][0] not in ("END", "FEND")):
        out.append(("END", ""))
    return out


def line_statements(data):
    out = []
    for m in re.finditer(rb"\x0e\xee([\x20-\x7e]{1,64}?)\x0e\x04\xa8(.)", data):
        out.append((m.group(1).decode("latin1"), m.group(2)[0]))
    return out


def constants(data):
    """K 상수 토큰: e8 VV (예: e8 0a=K10, e8 64=K100)."""
    return [v[0] for v in re.findall(rb"\xe8(.)", data)]


def parse_pou_registry(streams):
    '권위 POU 레지스트리(번호 MAIN 무관): ff ff ff ff 헤더 + count(off8) + POU명(UTF-16).\n    유효 POU명이 최다인 ff ff ff ff 스트림을 채택 - 현장 무-MAIN 프로젝트(POU=기능명 M000 U001…) 대응(100 동치).\n    count(off8)는 보조 참조(현장 관찰: 유효명 +1 = 루트/삭제 슬롯 - 엄격 검증 불가). 반환 (stream_num, count, [names]) 또는 None.'
    best = None
    for num, b in streams.items():
        if not b.startswith(b"\xff\xff\xff\xff"):
            continue
        names = [m.decode("utf-16le") for m in re.findall(rb"((?:[\x20-\x7e]\x00){2,})", b)]
        pou = [n for n in names if is_valid_pou_name(n)]
        # Source-derived parser observation.
        seen, ordered = set(), []
        for n in pou:
            if n not in seen:
                seen.add(n); ordered.append(n)
        if not ordered:                              # 유효 POU명 0 = 레지스트리 아님
            continue
        cnt = struct.unpack_from("<I", b, 8)[0] if len(b) >= 12 else len(ordered)
        if best is None or len(ordered) > len(best[2]):
            best = (num, cnt, ordered)
    return best


def is_pou_body(b, registry_names=None):
    """POU 본체 판정(번호 무관): 섹션마커(34 02 04) + trailing POU명.
    registry_names 주어지면 그 이름만 인정(오탐 차단)."""
    if b"\x34\x02\x04" not in b:
        return False
    nm = find_pou_name(b)
    if nm is None:
        return False
    return (registry_names is None) or (nm in registry_names)


def pou_rows(b, cmap=None):
    'POU 본체 sec0 → [(instr, operand, comment)] 구조화 행 + 미확인 토큰. 텍스트 CSV 공용.'
    cmap = cmap or {}
    sec0 = re.split(rb"\x34\x02\x04", b)[0]
    rows, unk_i, unk_d = [], set(), set()
    for instr, dev in decode_program(sec0):
        first = dev.split()[0] if dev else ""
        rows.append((instr, dev, cmap.get(first, "")))
        if instr.startswith("<i:"):
            unk_i.add(instr)
        # 라인 스테이트먼트/노트는 자유 텍스트다. 비교 기호(`<`)를 미확인
        # 디바이스 표식으로 오인하지 않고, 실제 명령 피연산자의 표식만 집계한다.
        if instr not in ("__STMT__", "__NOTE__") and "<" in dev:
            unk_d.add(dev)
    return rows, unk_i, unk_d


def typed_note_records(b, cmap=None):
    """Return observed Note records with raw subtype and preceding instruction.

    This is deliberately a verification view, not a new CSV projection model.
    ``pou_rows`` remains the public three-field compatibility API.  The helper
    refuses an unpaired raw/text stream so a caller cannot silently promote a
    Note when the reader lost an attachment or subtype.
    """
    sec0 = re.split(rb"\x34\x02\x04", b, maxsplit=1)[0]
    raw_notes = []
    i, n = 0, len(sec0)
    while i + 3 < n:
        length = sec0[i]
        subtype_byte = sec0[i + 2]
        if (
            sec0[i + 1] == 0x82
            and (subtype_byte == (length + 1) // 2 or subtype_byte == 0x01)
        ):
            text_length = length - 4
            end = i + 3 + text_length
            if 5 <= length and 1 <= text_length and end < n and sec0[end] == length:
                text = sec0[i + 3:end]
                if all(0x20 <= byte <= 0xff for byte in text):
                    # Only the two equal-text Issue #39 A/B frames prove the
                    # s/i mapping. Legacy Note frames remain readable but
                    # untyped, so callers cannot silently change their CSV
                    # Note column representation.
                    subtype = (
                        ISSUE39_NOTE_TYPE.get(subtype_byte)
                        if length == 13 and text == b"SAME TEXT"
                        else None
                    )
                    raw_notes.append({
                        "text": text.decode("cp1252", errors="replace"),
                        "raw_type": f"0x{subtype_byte:02x}",
                        "subtype": subtype,
                        "offset": i,
                    })
                    i = end + 1
                    continue
        i += 1

    rows, _, _ = pou_rows(b, cmap)
    note_indexes = [index for index, row in enumerate(rows) if row[0] == "__NOTE__"]
    if len(raw_notes) != len(note_indexes):
        raise ValueError(
            "typed Note frame count does not match decoded Note row count: "
            f"raw={len(raw_notes)} rows={len(note_indexes)}"
        )
    result = []
    for raw, index in zip(raw_notes, note_indexes):
        if rows[index][1] != raw["text"]:
            raise ValueError("typed Note frame text does not match decoded Note row")
        attachment = None
        for instruction, operands, _ in reversed(rows[:index]):
            if instruction not in ("__STMT__", "__NOTE__"):
                attachment = {
                    "instruction": instruction,
                    "operands": re.findall(r'"[^"]*"|\S+', operands) if operands else [],
                }
                break
        if attachment is None:
            raise ValueError("typed Note has no preceding instruction attachment")
        result.append({
            "text": raw["text"],
            "raw_type": raw["raw_type"],
            "subtype": raw["subtype"],
            "attachment": attachment,
        })
    return result


def decode_pou(name, b, cmap=None):
    """POU 본체 1개 → 사람이 읽는 텍스트 라인. (원본 형태 출력)"""
    rows, unk_i, unk_d = pou_rows(b, cmap)
    lines = []
    if rows:
        lines.append("  step | instr  | operand")
        lines.append("  -----+--------+--------")
        for i, (instr, dev, cmt) in enumerate(rows):
            if instr == "__STMT__":                 # Source-derived parser observation.
                lines.append(f"  {i:>4} | [라인 스테이트먼트] {dev}")
                continue
            if instr == "__NOTE__":                 # 코일 노트 (Note 컬럼)
                lines.append(f"  {i:>4} | [노트] {dev}")
                continue
            tail = f"  ; {cmt}" if cmt else ""
            lines.append(f"  {i:>4} | {instr:<6} | {dev}{tail}")
    return lines, unk_i, unk_d


def collect_pous(streams):
    """레지스트리 기반 POU 본체 + 코멘트맵 수집. 반환 ({name:(num,b)}, cmap, reg)."""
    reg = parse_pou_registry(streams)
    reg_names = set(reg[2]) if reg else None
    pous = {}
    for num, b in streams.items():
        if is_pou_body(b, reg_names):
            nm = find_pou_name(b)
            score = len(decode_il(b)) + len(line_statements(b))
            if nm not in pous or score > pous[nm][2]:
                pous[nm] = (num, b, score)
    cmap = device_comment_map(streams)
    return pous, cmap, reg


def project_info(arg):
    """프로젝트명 + PLC Information(프리앰블용, best-effort)."""
    name, plc = os.path.splitext(os.path.basename(arg))[0], "QCPU (Q mode)"
    try:
        with open(arg, "rb") as probe:
            is_ole = probe.read(8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        if os.path.isfile(arg) and is_ole:
            ole = bounded_ole.open_file(arg)
            try:
                if ole.exists("projectlist.xml"):
                    m = re.search(r"<szName>([^<]+)</szName>",
                                  bounded_ole.stream(ole, "projectlist.xml").decode("utf-8", "ignore"))
                    if m:
                        name = m.group(1)
                if ole.exists("_hdb"):                  # PLC 모드/모델: _hdb 서브스트림에서
                    sub = bounded_ole.open_nested(bounded_ole.stream(ole, "_hdb"))
                    try:
                        bodies = bounded_ole.all_streams(sub).values()
                        mode = model = None
                        for body in bodies:
                            t = body.decode("utf-16le", "ignore")
                            if not mode:
                                mm = re.search(r"[A-Z]CPU \([^)]+\)", t)
                                if mm:
                                    mode = mm.group(0)
                            if not model:
                                mm = re.search(r"Q\d{2}[A-Z]{2,4}", t)
                                if mm and ("UD" in mm.group(0) or "UV" in mm.group(0)):
                                    model = mm.group(0)
                            if mode and model:
                                break
                    finally:
                        sub.close()
                    if mode and model:
                        plc = f"{mode} {model}"
                    elif mode:
                        plc = mode
            finally:
                ole.close()
    except Exception:
        pass
    return name, plc


def _step_size(instr, operand):
    'IL 스텝 크기 표시용 근사값. GX exact Step No.는 Statement 토폴로지 의존이라 import 시 재계산한다.'
    op0 = operand.split()[0] if operand else ""
    if instr in ("SP.SOCOPEN", "SP.SOCSND", "SP.SOCRCV", "SP.SOCCLOSE"):
        return 12  # Official Issue #46 Q06UDV A/B export, plain U0/K/D/M.
    if instr == "MOV":
        return 3
    if instr in ("DMOV",):
        return 4
    if instr in ("PLS", "PLF"):
        return 2
    if instr == "OUT" and op0[:1] in ("T", "C"):
        return 4
    if instr == "$MOV":
        return 4 + max(1, len(operand) // 2)
    return 1


def _gx_row(*fields):
    """GX CSV 행: 전 필드 인용(내부 " 이중화) + 탭 구분."""
    return "\t".join('"' + str(f).replace('"', '""') + '"' for f in fields)


def gx_csv_for_pou(name, rows, proj, plc, typed_notes=None):
    'POU 1개 → GX Works2 IL CSV 텍스트(7컬럼 프리앰블 연속행 END).'
    out = [_gx_row(proj), _gx_row("PLC Information:", plc),
           _gx_row("Step No.", "Line Statement", "Instruction", "I/O(Device)", "Blank", "PI Statement", "Note")]
    step = 0
    has_typed_notes = typed_notes is not None
    note_records = iter(typed_notes or ())
    for instr, dev, cmt in rows:
        if instr == "__STMT__":                     # 라인 스테이트먼트 = Line Statement 컬럼 행
            out.append(_gx_row(step, dev, "", "", "", "", ""))
            continue
        if instr == "__NOTE__":                     # 코일 노트 = Note 컬럼(col[6]) 행 (step 빈칸)
            note = next(note_records, None)
            if note is None:
                if has_typed_notes:
                    raise ValueError("typed Note record is missing for a CSV Note row")
                note_text = dev
            else:
                if note.get("text") != dev:
                    raise ValueError("typed Note record text does not match CSV Note row")
                # Legacy length-framed Note records have no proven subtype and
                # retain the prior plain Note-column projection. Only the
                # Issue #39 raw-01 peripheral form changes the CSV text.
                note_text = f"*{dev}" if note.get("subtype") == "s" else dev
            out.append(_gx_row("", "", "", "", "", "", note_text))
            continue
        # 멀티 오퍼랜드 = 공백 분리하되, 따옴표 문자열 리터럴($MOV "WAIT MATRIAL" 등) 내부 공백은 보존
        if dev and '"' in dev:
            ops = re.findall(r'"[^"]*"|\S+', dev)
        else:
            ops = dev.split(" ") if dev else [""]
        out.append(_gx_row(step, "", instr, ops[0], "", "", ""))
        for extra in ops[1:]:                       # 멀티 오퍼랜드 = 연속행
            out.append(_gx_row("", "", "", extra, "", "", ""))
        step += _step_size(instr, dev)
    if not (rows and rows[-1][0] == "END"):     # 프로그램 종결 END가 이미 디코드됐으면 중복 부착 금지
        out.append(_gx_row(step, "", "END", "", "", "", ""))
    if has_typed_notes and next(note_records, None) is not None:
        raise ValueError("typed Note record has no CSV Note row")
    return "\r\n".join(out) + "\r\n"


def _csv_leaf_names(pous):
    """Validate all Windows CSV leaf names before creating an output directory."""
    names = {"comment.csv"}
    leaves = []
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{index}" for prefix in ("COM", "LPT") for index in range(1, 10)}
    for name in sorted(pous):
        if (not isinstance(name, str) or not name or name in {".", ".."}
                or name.endswith((" ", ".")) or any(ord(char) < 32 or char in '\\/:*?"<>|' for char in name)
                or name.split(".", 1)[0].upper() in reserved):
            raise ValueError(f"Unsafe POU CSV name: {name!r}")
        leaf = f"{name}.csv"
        folded = leaf.casefold()
        if folded in names:
            raise ValueError(f"Colliding POU CSV name: {leaf!r}")
        names.add(folded)
        leaves.append((name, leaf))
    return leaves


def _publish_csv_directory(outdir, staged):
    """Publish a complete sibling directory without touching an existing target."""
    if outdir.exists() or outdir.is_symlink():
        raise FileExistsError(f"CSV output directory must be new: {outdir}")
    if os.name == "nt":
        # Windows rename refuses an existing destination directory.
        os.rename(staged, outdir)
    elif sys.platform.startswith("linux"):
        # POSIX rename can replace a concurrently created empty directory.
        import ctypes
        import errno
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError(errno.ENOSYS, "No-replace directory rename is unavailable")
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        if renameat2(-100, os.fsencode(staged), -100, os.fsencode(outdir), 1) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), outdir)
    else:
        raise OSError("No-replace directory rename is unsupported on this platform")


def output_csv(arg, pous, cmap):
    """GX Works2 IL CSV 출력. 디렉터리 출력은 새 경로에만 발행하고 없으면 stdout(MAIN)."""
    proj, plc = project_info(arg)
    rest = [a for a in sys.argv[1:] if not a.startswith("-")]
    outdir = rest[1] if len(rest) > 1 else None
    if outdir:
        target = Path(outdir)
        if not target.name or target.exists() or target.is_symlink():
            raise FileExistsError(f"CSV output directory must be new: {outdir}")
        if not target.parent.is_dir():
            raise FileNotFoundError(f"CSV output parent directory is absent: {target.parent}")
        pou_leaves = _csv_leaf_names(pous)
        # Source-derived parser observation.
        order = {"X": 0, "Y": 1, "M": 2, "L": 3, "F": 4, "B": 5, "T": 6, "C": 7, "D": 8}

        def _dkey(d):
            m = re.match(r"([A-Z]+)(\d+)", d)
            if not m:
                return (99, 0)
            typ, num = m.group(1), m.group(2)
            return (order.get(typ, 50), int(num, 16 if typ in ("X", "Y", "B", "W") else 10))
        with tempfile.TemporaryDirectory(prefix=".gxw-csv-", dir=target.parent) as temporary:
            staged = Path(temporary) / "candidate"
            staged.mkdir()
            for nm, leaf in pou_leaves:
                rows, _, _ = pou_rows(pous[nm][1], cmap)
                with open(staged / leaf, "w", encoding="utf-16", newline="") as f:
                    f.write(gx_csv_for_pou(nm, rows, proj, plc, typed_note_records(pous[nm][1], cmap)))
            with open(staged / "COMMENT.csv", "w", encoding="utf-16", newline="") as f:
                lines = [_gx_row(proj), _gx_row("Device Name", "Comment")]
                lines += [_gx_row(d, c) for d, c in sorted(cmap.items(), key=lambda kv: _dkey(kv[0]))]
                f.write("\r\n".join(lines) + "\r\n")
            _publish_csv_directory(target, staged)
        print(f"GX CSV 출력: {outdir}/  (POU {len(pous)}개 + COMMENT.csv)")
    else:
        nm = "MAIN" if "MAIN" in pous else sorted(pous)[0]
        rows, _, _ = pou_rows(pous[nm][1], cmap)
        sys.stdout.write(gx_csv_for_pou(nm, rows, proj, plc, typed_note_records(pous[nm][1], cmap)))


def output_text(pous, cmap, reg, src):
    print(f"# 래더 덤프 — {src}")
    if reg:
        print(f"# POU 레지스트리(_hdb/{reg[0]}): count={reg[1]}, POU={reg[2]}")
    print(f"# 본체 디코드 {len(pous)}개: {', '.join(sorted(pous))}")
    all_unk_i, all_unk_d = set(), set()
    for nm in sorted(pous):
        num, b, _ = pous[nm]
        lines, ui, ud = decode_pou(nm, b, cmap)
        all_unk_i |= ui; all_unk_d |= ud
        print(f"\n## POU: {nm}  (_hdb/{num})")
        print("\n".join(lines) if lines else "  (빈 프로그램)")
    if all_unk_i or all_unk_d:
        print(f"\n## 미확인 토큰 (사전 확장 필요): 명령={sorted(all_unk_i)} 디바이스={sorted(all_unk_d)}")
    if cmap:
        print(f"\n## 디바이스 코멘트 ({len(cmap)})")
        for d, c in cmap.items():
            print(f"  - {d} = {c}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    as_csv = "--csv" in sys.argv
    if not args:
        print(__doc__); sys.exit(1)
    streams = load_all_substreams(args[0])
    pous, cmap, reg = collect_pous(streams)
    if as_csv:
        output_csv(args[0], pous, cmap)
    else:
        output_text(pous, cmap, reg, os.path.basename(args[0]))


if __name__ == "__main__":
    main()
