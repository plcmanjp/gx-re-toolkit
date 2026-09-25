#!/usr/bin/env python
'Source-derived parser observation.'
import sys, os, shutil, argparse, subprocess, tempfile, hashlib
from pathlib import Path

import gxw_bounded_ole as bounded_ole
import pythoncom
from win32com import storagecon

_HERE = Path(__file__).resolve().parent
from gxw_ladder_reader import DEVICE, _read_operand, INSTR   # Source-derived parser observation.

# 단순 1-오퍼랜드 명령(03 op 03 <operand>): 니모닉 → opcode. --edit-il이 IL로 위치지정.
_OP_BY_MNEM = {v: k for k, v in INSTR.items()}

READER = _HERE / "gxw_ladder_reader.py"
RW = storagecon.STGM_READWRITE | storagecon.STGM_SHARE_EXCLUSIVE
CREATE = storagecon.STGM_CREATE | storagecon.STGM_WRITE | storagecon.STGM_SHARE_EXCLUSIVE
SELF_CHECK_TIMEOUT_SECONDS = 30

# 디바이스명(긴 것 먼저) → (typecode, radix). 인코더가 최장 매칭에 사용.
_DEV_BY_NAME = sorted(((nm, (tc, radix)) for tc, (nm, radix) in DEVICE.items()),
                      key=lambda x: -len(x[0]))


# ── 오퍼랜드 인코더 (리더 _read_operand/_format_base 의 정확한 역함수, 수식자 미지원 v1) ──
def _frame(tc, val, w):
    if not 0 <= val < (1 << (8 * w)):
        raise ValueError(f"{w * 8}비트 프레임 범위 밖: {val}")
    f = 0x03 + w
    return bytes([f, tc]) + int(val).to_bytes(w, "little") + bytes([f])


def encode_operand(text):
    '디바이스/상수 → 프레임-폭 오퍼랜드 바이트. 폭=최소바이트(GX 관찰 규약). 수식자(U\\G Z .bit) 미지원.'
    t = text.strip()
    if not t:
        raise ValueError("빈 오퍼랜드")
    head = t[0].upper()
    if head == "K":                                  # 정수 상수 (부호)
        val = int(t[1:])
        if 0 <= val <= 0xFF:
            return _frame(0xe8, val, 1)
        if -0x8000 <= val <= 0xFFFF:
            return _frame(0xe8, val & 0xFFFF, 2)
        if -0x80000000 <= val <= 0xFFFFFFFF:
            return _frame(0xe9, val & 0xFFFFFFFF, 4)
        raise ValueError(f"K 상수는 현재 프레임 범위 밖: {text}")
    if head == "H":                                  # 16진 상수
        val = int(t[1:], 16)
        if not 0 <= val <= 0xFFFFFFFF:
            raise ValueError(f"H 상수는 현재 프레임 범위 밖: {text}")
        if val <= 0xFF:
            return _frame(0xea, val, 1)
        if val <= 0xFFFF:
            return _frame(0xea, val, 2)
        return _frame(0xeb, val, 4)
    for nm, (tc, radix) in _DEV_BY_NAME:              # 디바이스 (최장 매칭)
        if t.upper().startswith(nm) and len(t) > len(nm):
            try:
                val = int(t[len(nm):], radix)
            except ValueError:
                continue
            if not 0 <= val <= 0xFFFFFFFF:
                raise ValueError(f"디바이스 주소는 현재 프레임 범위 밖: {text}")
            w = 1 if val <= 0xFF else 2 if val <= 0xFFFF else 3 if val <= 0xFFFFFF else 4
            return _frame(tc, val, w)
    raise ValueError(f"미지원 오퍼랜드(수식자 포함은 v1 미지원 — --replace 바이트모드 사용): {text}")


def decode_operand_hex(h):
    """프레임 hex → IL 텍스트 (검증용, 리더 _read_operand 재사용)."""
    b = bytes.fromhex(h.replace(" ", ""))
    s, _ = _read_operand(b, 0)
    return s


# Source-derived parser observation.
def read_top(path, name):
    ole = bounded_ole.open_file(path)
    try:
        return bounded_ole.stream(ole, name)
    finally:
        ole.close()


def hdb_substreams(hdb):
    h = bounded_ole.open_nested(hdb)
    try:
        all_data = bounded_ole.all_streams(h)
        if any("/" in name for name in all_data):
            raise ValueError("nested _hdb stream path is not supported by the writer")
        return all_data
    finally:
        h.close()


def patch_hdb_substreams(hdb_bytes, targets, tmp):
    tmp.write_bytes(hdb_bytes)
    st = s = None
    try:
        st = pythoncom.StgOpenStorage(str(tmp), None, RW)
        for nm, data in targets.items():
            s = st.CreateStream(nm, CREATE, 0, 0)
            s.Write(data)
            s = None
        st.Commit(0)
        s = None
        st = None
        out = tmp.read_bytes()
        return out
    finally:
        s = None
        st = None
        tmp.unlink(missing_ok=True)

def write_streams(dst, streams):
    st = s = None
    try:
        st = pythoncom.StgOpenStorage(str(dst), None, RW)
        for name, data in streams.items():
            s = st.CreateStream(name, CREATE, 0, 0)
            s.Write(data)
            s = None
        st.Commit(0)
    finally:
        s = None
        st = None


def write_top_hdb(dst, new_hdb):
    write_streams(dst, {"_hdb": new_hdb})


def source_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _destination(src, out, in_place):
    src = Path(src)
    if not src.is_file():
        raise ValueError(f"입력 파일이 아님: {src}")
    if in_place:
        if out is not None:
            raise ValueError("--in-place와 --out은 함께 사용할 수 없음")
        backup = src.with_suffix(src.suffix + ".bak")
        if backup.exists():
            raise FileExistsError(f"기존 백업을 보존하기 위해 중단: {backup}")
        return src, backup
    dst = Path(out) if out else src.with_name(src.stem + "-edited" + src.suffix)
    if dst.exists():
        raise FileExistsError(f"기존 출력을 보존하기 위해 중단: {dst}")
    if not dst.parent.is_dir():
        raise ValueError(f"출력 디렉터리가 없음: {dst.parent}")
    return dst, None


def prepare_candidate(src, out=None, in_place=False, default_suffix="-edited", expected_sha256=None):
    src = Path(src)
    expected_sha256 = expected_sha256 or source_sha256(src)
    if not in_place and out is None:
        out = src.with_name(src.stem + default_suffix + src.suffix)
    dst, backup = _destination(src, out, in_place)
    if source_sha256(src) != expected_sha256:
        raise ValueError("입력이 준비 전 변경됨")
    fd, name = tempfile.mkstemp(prefix=".gxw-candidate-", suffix=src.suffix, dir=dst.parent)
    os.close(fd)
    candidate = Path(name)
    try:
        shutil.copy2(src, candidate)
        if source_sha256(candidate) != expected_sha256:
            raise ValueError("후보 복사본이 입력 snapshot과 다름")
        if source_sha256(src) != expected_sha256:
            raise ValueError("입력이 후보 복사 중 변경됨")
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise
    return candidate, dst, backup


def discard_candidate(candidate):
    Path(candidate).unlink(missing_ok=True)


def publish_candidate(candidate, src, dst, backup=None, expected_sha256=None):
    candidate, src, dst = Path(candidate), Path(src), Path(dst)
    if expected_sha256 is not None and source_sha256(src) != expected_sha256:
        raise ValueError("입력이 발행 직전 변경됨")
    if backup is None:
        if dst.exists():
            raise FileExistsError(f"기존 출력을 보존하기 위해 중단: {dst}")
        os.link(candidate, dst)
        try:
            candidate.unlink()
        except BaseException as error:
            try:
                if dst.exists() and os.path.samefile(candidate, dst):
                    dst.unlink()
            except BaseException as rollback_error:
                raise RuntimeError(f"후보 정리 실패 및 발행 rollback 실패: {rollback_error}") from error
            raise RuntimeError("후보 정리 실패로 발행을 rollback함") from error
        return
    backup = Path(backup)
    if backup.exists():
        raise FileExistsError(f"기존 백업을 보존하기 위해 중단: {backup}")
    os.link(src, backup)
    try:
        os.replace(candidate, src)
    except BaseException:
        backup.unlink(missing_ok=True)
        raise


def self_check(path):
    r = subprocess.run([sys.executable, str(READER), str(path)],
                       capture_output=True, text=True, encoding="utf-8",
                       timeout=SELF_CHECK_TIMEOUT_SECONDS)
    return r.returncode, r.stdout


# ── 핵심: 단일점 가드 + 치환 ──
def scan(hdb, subs, OLD):
    where = {nm: d.count(OLD) for nm, d in subs.items() if d.count(OLD)}
    return hdb.count(OLD), where


def do_replace(src, OLD, NEW, apply, in_place, out, allow_multi, allow_collision):
    if not OLD:
        print("  중단: OLD 빈 패턴. 파일을 읽거나 쓰지 않음.")
        return 7
    if in_place and out is not None:
        print("  중단: --in-place와 --out은 함께 사용할 수 없음. 파일을 읽거나 쓰지 않음.")
        return 8
    if apply and not allow_multi:
        # The strict path owns single-command publication.  The explicit --all
        # path below deliberately retains its established global semantics.
        import gxw_single_command
        return gxw_single_command.apply(src, OLD, NEW, in_place, out, allow_collision)
    input_sha256 = source_sha256(src)
    hdb = read_top(str(src), "_hdb")
    subs = hdb_substreams(hdb)
    total, where = scan(hdb, subs, OLD)
    new_total, _ = scan(hdb, subs, NEW)
    delta = len(NEW) - len(OLD)
    print(f"OLD={OLD.hex()} ({len(OLD)}B)  NEW={NEW.hex()} ({len(NEW)}B)  Δ={delta:+d}B")
    print(f"  OLD 출현: 총 {total}회, substreams={where}")
    print(f"  NEW 기존 출현(충돌): {new_total}회")
    if total == 0:
        print("  중단: OLD 패턴 미발견(인코딩 폭 불일치 가능 — --find로 실제 바이트 확인)."); return 1
    # dry-run 미리보기만 제한한다. 단일명령/복제 stream 대응의 동등성 근거는 아직 없다.
    if len(where) > 4 and not allow_multi:
        print(f"  중단: {len(where)}개 substream에 출현 — 다중 substream 미리보기 제한; 단일명령/복제 대응 미확인."); return 2
    if new_total and not allow_collision:
        print("  중단: NEW가 이미 존재(충돌) — 의도시 --allow-collision."); return 3

    targets = {nm: d.replace(OLD, NEW) for nm, d in subs.items() if OLD in d}
    if not apply:
        print("  [dry-run] --apply 없음 — 미작성. 탐색 미리보기이며 작성 안전판정이 아님.")
        # 미리보기: 임시로 메모리에서 치환 후 디코드는 생략(파일 필요), 변경 요약만.
        print(f"  변경 예정 substreams: { {nm: (len(subs[nm]), len(targets[nm])) for nm in targets} }")
        return 0

    candidate = None
    try:
        with tempfile.TemporaryDirectory(prefix='gxw-write-') as temporary:
            new_hdb = patch_hdb_substreams(hdb, targets, Path(temporary) / 'work.ole')
        candidate, dst, backup = prepare_candidate(src, out, in_place, expected_sha256=input_sha256)
        write_top_hdb(candidate, new_hdb)
        rc, sout = self_check(candidate)
        if rc != 0:
            print(f"  중단: self-check rc={rc}; 후보를 발행하지 않음.")
            return 9
        publish_candidate(candidate, src, dst, backup, input_sha256)
        candidate = None
        if backup is not None:
            print(f"  백업: {backup.name}")
        print(f"  작성: {dst}  ({dst.stat().st_size:,}B)  self-check rc={rc}")
        print("  무결성 계층(CAB·서명·레지스트리·위치DB) 전부 불변 - GX Works2 실측 권장.")
        return 0
    except Exception as error:
        print(f"  중단: 후보 작성/검증 실패: {error}")
        return 9
    finally:
        if candidate is not None:
            discard_candidate(candidate)


def build_il_locator(il):
    "단순 1-오퍼랜드 IL('LD M100' 'OUT Y20' 등) → (instr_bytes `03 op 03 <frame>`, operand_text).\n    복합 명령(타이머 프리셋 MOV 비교 응용 등)은 프레이밍이 달라 미지원 → --edit <instr_hex> 사용."
    toks = il.split()
    if len(toks) != 2:
        raise ValueError(f"--edit-il은 단순 1-오퍼랜드 명령만('LD M100'). '{il}'는 토큰 {len(toks)}개 — 복합명령은 --edit <instr_hex>(--find로 hex 획득).")
    mnem, operand = toks[0].upper(), toks[1]
    if mnem not in _OP_BY_MNEM:
        raise ValueError(f"--edit-il 미지원 니모닉 '{mnem}'(단순 접점/코일만: {sorted(_OP_BY_MNEM)}). 복합명령은 --edit <instr_hex>.")
    instr = bytes([0x03, _OP_BY_MNEM[mnem], 0x03]) + encode_operand(operand)
    return instr, operand


def cmd_find(src, op):
    OLD = encode_operand(op)
    hdb = read_top(str(src), "_hdb"); subs = hdb_substreams(hdb)
    total, where = scan(hdb, subs, OLD)
    print(f"operand {op} → frame {OLD.hex()}  ({decode_operand_hex(OLD.hex())})")
    print(f"  총 {total}회, substreams={where}")
    for nm, d in subs.items():
        idx = d.find(OLD)
        if idx >= 0:
            print(f"  [{nm}] 첫 컨텍스트 @{idx}: {d[max(0,idx-7):idx+len(OLD)+5].hex(' ')}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="GX Works2 .gxw 래더 in-place 편집 (단일명령 치환)")
    ap.add_argument("file")
    ap.add_argument("--find", metavar="OP")
    ap.add_argument("--encode", metavar="OP")
    ap.add_argument("--replace", nargs=2, metavar=("OLD_HEX", "NEW_HEX"))
    ap.add_argument("--edit", metavar="INSTR_HEX")
    ap.add_argument("--edit-il", metavar="IL", help="단순명령 IL로 위치지정 ('LD M100')")
    ap.add_argument("--set", nargs=2, metavar=("OLD_OP", "NEW_OP"))
    ap.add_argument("--rename-operand", nargs=2, metavar=("OLD_OP", "NEW_OP"))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--in-place", action="store_true")
    ap.add_argument("--out", metavar="PATH")
    ap.add_argument("--all", action="store_true", help="다중 출현 허용(전역)")
    ap.add_argument("--allow-collision", action="store_true")
    a = ap.parse_args()
    src = Path(a.file)
    out = Path(a.out) if a.out else None
    if not src.exists():
        print(f"파일 없음: {src}"); return 1

    if a.encode:
        b = encode_operand(a.encode)
        print(f"{a.encode} → {b.hex()}  (재디코드: {decode_operand_hex(b.hex())})"); return 0
    if a.find:
        return cmd_find(src, a.find)
    if a.replace:
        OLD = bytes.fromhex(a.replace[0].replace(" ", "")); NEW = bytes.fromhex(a.replace[1].replace(" ", ""))
        return do_replace(src, OLD, NEW, a.apply, a.in_place, out, a.all, a.allow_collision)
    if a.edit_il and a.set:
        try:
            instr, operand = build_il_locator(a.edit_il)
        except ValueError as e:
            print(f"중단: {e}"); return 7
        if a.set[0] != operand:
            print(f"중단: --set OLD '{a.set[0]}'가 IL 오퍼랜드 '{operand}'와 불일치."); return 8
        a.edit = instr.hex()    # 아래 --edit 경로로 위임
    if a.edit and a.set:
        instr = bytes.fromhex(a.edit.replace(" ", ""))
        of, nf = encode_operand(a.set[0]), encode_operand(a.set[1])
        if of not in instr:
            print(f"중단: instr_hex 안에 OLD operand {a.set[0]}({of.hex()}) 프레임 없음 — --find로 실제 바이트 확인."); return 4
        if instr.count(of) != 1:
            print(f"중단: instr_hex 안에 OLD operand가 {instr.count(of)}회 — 모호. 더 좁은 instr_hex 필요."); return 5
        NEW = instr.replace(of, nf)
        print(f"단일명령 치환: {a.set[0]}→{a.set[1]} | instr {instr.hex()} → {NEW.hex()}")
        return do_replace(src, instr, NEW, a.apply, a.in_place, out, a.all, a.allow_collision)
    if a.rename_operand:
        if not a.all:
            print("중단: --rename-operand는 전역(모든 사용처) — 단일명령 아님. --all 명시 필요."); return 6
        OLD, NEW = encode_operand(a.rename_operand[0]), encode_operand(a.rename_operand[1])
        return do_replace(src, OLD, NEW, a.apply, a.in_place, out, True, a.allow_collision)
    ap.print_help(); return 0


if __name__ == "__main__":
    sys.exit(main())
