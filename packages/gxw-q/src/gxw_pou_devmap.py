#!/usr/bin/env python
# -*- coding: utf-8 -*-
'Source-derived parser observation.'
import sys
import re
from pathlib import Path
from collections import defaultdict, Counter

import gxw_ladder_reader as R

# --- 쓰기 목적지 오퍼랜드 규칙 (미츠비시 오퍼랜드 순서; arity는 GT 교차확인) ---
# Source-derived parser observation.
DEST_FIRST = {
    "OUT", "OUTH", "SET", "RST", "PLS", "PLSP", "PLF", "PLFP", "FF",
    "INC", "INCP", "DINC", "DINCP", "DEC", "DECP", "DDEC", "DDECP", "DNEG",
    "SFL", "SFR", "TTMR", "DATERD",
}
# Source-derived parser observation.
DEST_OP1 = {"BMOV", "BMOVP", "FMOV", "FMOVP", "DECO", "ENCO", "DMIN", "DMAX", "BTOW", "WTOB"}
DEST_OP1_RELAY = {"MC"}   # MC N,relay → relay(op1) 마스터컨트롤 에너자이즈
# Source-derived parser observation.
DEST_LAST = {
    "MOV", "MOVP", "DMOV", "DMOVP", "EMOV", "$MOV",
    "BCD", "BCDP", "BIN", "BINP", "FLT", "DFLT", "DINT", "EVAL",
    "+", "-", "*", "/", "D+", "D-", "D*", "D/", "E+", "E-", "E*", "E/",
}
# Source-derived parser observation.
NO_WRITE_CTRL = {"CALL", "XCALL", "FOR", "NEXT", "MCR", "END", "FEND", "RET", "BREAK", "DATEWR"}
# Source-derived parser observation.
KNOWN_READ = {
    "LD", "LDI", "AND", "ANI", "OR", "ORI", "ORB", "ANB", "INV",
    "MPS", "MPP", "MRD", "MEP", "MEF", "LDP", "LDF", "LDPI",
    "ANDP", "ANDPI", "ANDFI", "ORP", "ORF", "FEND", "RET", "END", "P400",
}

CONST_PFX = ("K", "H", "E")     # 상수
NONDEV_PFX = ("P", "N")          # Source-derived parser observation.
DEV_RE = re.compile(r"^(ZR|SM|SD|FD|X|Y|M|L|B|D|W|T|C|Z|G)\d")


def base_device(tok):
    '오퍼랜드 토큰 → 베이스 디바이스 키(수식자 제거, U\\G→G - 100 추출 정합). 디바이스 아니면 None.'
    if not tok:
        return None
    if tok[0] in NONDEV_PFX or tok[0] in CONST_PFX:
        return None                                   # P/N/상수(K/H/E)
    m = re.match(r"U\d+\\G(\d+)", tok)                # Source-derived parser observation.
    if m:
        return "G" + m.group(1)
    t = re.sub(r"\.[0-9A-Fa-f]+$", "", tok)           # .bit 제거 (D361.0 → D361)
    m = re.match(r"^([A-Za-z]+\d+)(?:ZZ?\d+)$", t)    # 인덱스 수식 제거 (ZR40080Z11 → ZR40080)
    if m:
        t = m.group(1)
    return t if DEV_RE.match(t) else None


def is_comparison(instr):
    return bool(re.search(r"[=<>]", instr))


def dest_index(instr, ntok):
    '명령 오퍼랜드수 → 쓰기 목적지 오퍼랜드 인덱스. 쓰기 없음이면 None.'
    if ntok == 0:
        return None
    if instr in DEST_FIRST:
        return 0
    if instr in DEST_OP1 or instr in DEST_OP1_RELAY:
        return 1 if ntok >= 2 else None
    if instr in DEST_LAST:
        return ntok - 1
    return None


def build_map(path):
    """반환 dict: write_owner{dev:set(POU)}, read_by{dev:set(POU)}, pou_devs{POU:set(dev)},
       winstr Counter(쓰기 기여 명령), unclassified Counter(쓰기 미분류 의심), pous(list)."""
    streams = R.load_all_substreams(path)
    pous, cmap, reg = R.collect_pous(streams)
    write_owner = defaultdict(set)
    read_by = defaultdict(set)
    pou_devs = defaultdict(set)
    winstr = Counter()
    unclassified = Counter()
    for nm in sorted(pous):
        b = pous[nm][1]
        rows, _, _ = R.pou_rows(b, cmap)
        for instr, dev, _cmt in rows:
            if instr in ("__STMT__", "__NOTE__"):
                continue
            toks = dev.split() if dev else []
            di = dest_index(instr, len(toks))
            had_dev = False
            for idx, tok in enumerate(toks):
                bd = base_device(tok)
                if bd is None:
                    continue
                had_dev = True
                pou_devs[nm].add(bd)
                if di is not None and idx == di:
                    write_owner[bd].add(nm)
                    winstr[instr] += 1
                else:
                    read_by[bd].add(nm)
            if (had_dev and di is None and instr not in KNOWN_READ
                    and instr not in NO_WRITE_CTRL and not is_comparison(instr)
                    and not instr.startswith("<")):
                unclassified[instr] += 1
    return {
        "write_owner": write_owner, "read_by": read_by, "pou_devs": pou_devs,
        "winstr": winstr, "unclassified": unclassified, "pous": sorted(pous),
    }


def _dev_sort_key(d):
    m = re.match(r"^([A-Za-z]+)(\d+)$", d)
    return (m.group(1), int(m.group(2))) if m else (d, 0)


def write_tsv(res, out_path):
    devs = sorted(set(res["write_owner"]) | set(res["read_by"]), key=_dev_sort_key)
    lines = ["device\twrite_owner_pous\tread_pous"]
    for d in devs:
        w = ";".join(sorted(res["write_owner"].get(d, ()), key=_dev_sort_key))
        r = ";".join(sorted(res["read_by"].get(d, ()), key=_dev_sort_key))
        lines.append(f"{d}\t{w}\t{r}")
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(devs)


def print_summary(res):
    wo, rb, pd = res["write_owner"], res["read_by"], res["pou_devs"]
    all_devs = set(wo) | set(rb)
    multi = {d: s for d, s in wo.items() if len(s) > 1}
    print(f"POU: {len(res['pous'])}  ({', '.join(res['pous'])})")
    print(f"고유 디바이스: {len(all_devs)}  | 쓰기 보유: {len(wo)}  | 다중-쓰기 POU(>1): {len(multi)}")
    print("\n=== POU별 참조 디바이스 수 (handoff-005 §4 대조) ===")
    for nm in res["pous"]:
        print(f"  {nm:<6} {len(pd[nm])}")
    print("\n=== 쓰기 기여 명령 census ===")
    for k, v in res["winstr"].most_common():
        print(f"  {k:<8} {v}")
    if res["unclassified"]:
        print("\n=== 쓰기 미분류 의심 명령(디바이스 오퍼랜드 보유·접점/비교/제어 아님) ===")
        for k, v in res["unclassified"].most_common():
            print(f"  {k:<8} {v}    (검토 필요 — 목적지 규칙 미등록)")
    else:
        print("\n쓰기 미분류 의심 명령: 없음 (현 GT 전 명령 분류 완료)")
    if multi:
        ex = sorted(multi.items(), key=lambda x: -len(x[1]))[:8]
        print("\n=== 다중-쓰기 디바이스 예 (정책 d 소유권 충돌 후보) ===")
        for d, s in ex:
            print(f"  {d:<10} ← {len(s)} POU: {';'.join(sorted(s, key=_dev_sort_key))}")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    path = argv[1]
    res = build_map(path)
    if "--by-pou" in argv:
        for nm in res["pous"]:
            print(f"{nm}\t{len(res['pou_devs'][nm])}")
        return 0
    if "--tsv" in argv:
        out = argv[argv.index("--tsv") + 1]
        n = write_tsv(res, out)
        print(f"TSV {n} devices → {out}")
    print_summary(res)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
