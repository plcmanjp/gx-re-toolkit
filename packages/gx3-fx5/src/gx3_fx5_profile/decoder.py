"""FX5U Phase 2 record, comment and label decoders with partial preservation."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from typing import Any

from gx3_core import SafeGx3Archive

from .opcode_signatures import (
    UnknownOpcodeSignature,
    header_tokens as opcode_header_tokens,
    lookup_mnemonic,
    mil_stream,
)


class MiningRequired(ValueError):
    def __init__(self, object_kind: str, reason: str):
        super().__init__(reason)
        self.object_kind = object_kind
        self.reason = reason


def _connection(archive: SafeGx3Archive, entry: str) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.deserialize(archive.read(entry))
    connection.execute("PRAGMA query_only = ON")
    return connection


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}


def _block_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.lower().startswith("_guid/"):
        value = value[6:]
    return value.strip("{}").lower() or None


def _finding(
    kind: str, scope: str, locator: str, digest: str, reason: str
) -> dict[str, str]:
    return {
        "finding_code": "MINING_REQUIRED",
        "scope": scope,
        "object_kind": kind,
        "locator": locator,
        "digest": digest,
        "reason": reason,
    }


def _provenance(
    entry: str, store: str, locator: str, digest: str, relation: list[str]
) -> dict[str, Any]:
    return {
        "source_entry": entry,
        "source_store": store,
        "source_locator": locator,
        "source_digest": digest,
        "relation_evidence": relation,
    }


def _balanced_records(text: str, marker: str) -> list[str]:
    records: list[str] = []
    offset = 0
    while (start := text.find(marker, offset)) >= 0:
        cursor = start + len(marker) - 1
        depth = 0
        while cursor < len(text):
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        if depth:
            raise MiningRequired("record", "unbalanced serialized MIL record")
        records.append(text[start : cursor + 1])
        offset = cursor + 1
    return records


def _mil_operands(record: str) -> list[tuple[str, tuple[int, ...]]]:
    start = record.rfind(":as=[")
    if start < 0:
        return []
    bracket = start + 4
    depth = 0
    end = bracket
    while end < len(record):
        if record[end] == "[":
            depth += 1
        elif record[end] == "]":
            depth -= 1
            if depth == 0:
                break
        end += 1
    if depth:
        raise MiningRequired("operand", "unbalanced MIL operand list")
    values = record[bracket + 1 : end]
    items: list[str] = []
    cursor = 0
    while cursor < len(values):
        if values[cursor] in ": ":
            cursor += 1
            continue
        if cursor + 1 >= len(values) or values[cursor + 1] != "{":
            raise MiningRequired("operand", "unmined MIL operand token")
        item_start = cursor
        item_depth = 0
        while cursor < len(values):
            if values[cursor] == "{":
                item_depth += 1
            elif values[cursor] == "}":
                item_depth -= 1
                cursor += 1
                if item_depth == 0:
                    break
                continue
            cursor += 1
        if item_depth:
            raise MiningRequired("operand", "unbalanced MIL operand token")
        items.append(values[item_start:cursor])
    parsed: list[tuple[str, tuple[int, ...]]] = []
    for item in items:
        numbers = tuple(int(value) for value in re.findall(r"(?:a|v)=(-?\d+)", item))
        if item.startswith("M{"):
            parsed.append(("remote_bit" if "B{b=" in item else "k_device", numbers))
        elif item.startswith("B{"):
            parsed.append(("remote_word", numbers))
        elif item == "c{s=#:v=#:t=#}":
            # The observed SP.* string selector has no numeric payload.  Its
            # exact literal is carried in the corresponding MIL header.
            parsed.append(("string_literal", ()))
        elif item == "l{id=#}":
            # Local-label operands carry no numeric payload.  The exact
            # ``_lid/<LabelID>/<RowID>`` token is in the corresponding MIL header.
            parsed.append(("local_label", ()))
        elif item.startswith(("d{", "c{")) and len(numbers) == 1:
            parsed.append(("scalar", numbers))
        else:
            raise MiningRequired("operand", "unmined MIL operand form")
    return parsed


SCALAR_TAGS = frozenset(
    {
        "B",
        "D",
        "H_1",
        "K_1",
        "K_2",
        "L",
        "M",
        "R",
        "SfcS",
        "SM",
        "ST",
        "T",
        "X",
        "Y",
        "Z",
    }
)

# The three pairs below are the complete source-only observation.  They are
# deliberately not a family rule for Y/Ks operands.
_EXACT_MIL_Y_KS_MOV_OPERANDS = frozenset({
    ((512, 2), 100),
    ((528, 2), 110),
    ((544, 2), 120),
})

# An inline GX Works3 Note has a text descriptor followed by ``i`` or ``s``.
# Keep the instruction-marker boundary explicit so a recognized instruction is
# never reclassified as a Note merely because a later descriptor is textual.
INSTRUCTION_MARKERS = frozenset(
    {
        "A",
        "B",
        "EQ",
        "NE",
        "LT",
        "LE",
        "GT",
        "GE",
        "AddOpe",
        "SubOpe",
        "MulOpe",
        "DivOpe",
        "ANB",
        "AND",
        "ANI",
        "END",
        "FF",
        "FMOV",
        "FOR",
        "GOEND",
        "INC",
        "INV",
        "ME",
        "MOV",
        "MPP",
        "MPS",
        "MRD",
        "NEXT",
        "OR",
        "ORB",
        "OUT",
        "OUTH",
        "RST",
        "SET",
        "S_SOCOPEN",
    }
)

_LOCAL_LABEL_TOKEN = re.compile(r"^_lid/(\d+)/(\d+)$")
_LOCAL_LABEL_LOCATOR = re.compile(
    r"LabelID=([^;]+);RowID=([^;]+)(?:;ColumnID=2,15)?"
)
EXACT_ARITHMETIC = {
    ("AddOpe", ("A16s", "A16s", "A16s")): ("+", "+P"),
    ("AddOpe", ("A32s", "A32s", "A32s")): ("D+", "D+P"),
    ("AddOpe", ("Ass", "Ass", "Ass")): ("$+", "$+P"),
    ("AddOpe", ("A16", "A16", "A16")): ("B+", "B+P"),
    ("AddOpe", ("A16s", "A16s", "A16s", "A16")): ("BK+", "BK+P"),
    ("AddOpe", ("A16u", "A16u", "A16u", "A16")): ("BK+_U", "BK+P_U"),
    ("AddOpe", ("A16u", "A16u", "A16u")): ("+_U", "+P_U"),
    ("AddOpe", ("A32", "A32", "A32")): ("DB+", "DB+P"),
    ("AddOpe", ("A32s", "A32s", "A32s", "A16")): ("DBK+", "DBK+P"),
    ("AddOpe", ("A32u", "A32u", "A32u", "A16")): ("DBK+_U", "DBK+P_U"),
    ("AddOpe", ("A32u", "A32u", "A32u")): ("D+_U", "D+P_U"),
    ("SubOpe", ("A16s", "A16s", "A16s")): ("-", "-P"),
    ("SubOpe", ("A32s", "A32s", "A32s")): ("D-", "D-P"),
    ("SubOpe", ("A16", "A16", "A16")): ("B-", "B-P"),
    ("SubOpe", ("A16s", "A16s", "A16s", "A16")): ("BK-", "BK-P"),
    ("SubOpe", ("A16u", "A16u", "A16u", "A16")): ("BK-_U", "BK-P_U"),
    ("SubOpe", ("A16u", "A16u", "A16u")): ("-_U", "-P_U"),
    ("SubOpe", ("A32", "A32", "A32")): ("DB-", "DB-P"),
    ("SubOpe", ("A32s", "A32s", "A32s", "A16")): ("DBK-", "DBK-P"),
    ("SubOpe", ("A32u", "A32u", "A32u", "A16")): ("DBK-_U", "DBK-P_U"),
    ("SubOpe", ("A32u", "A32u", "A32u")): ("D-_U", "D-P_U"),
    ("MulOpe", ("A16s", "A16s", "A32s")): ("*", "*P"),
    ("MulOpe", ("A32s", "A32s", "A32sa")): ("D*", "D*P"),
    ("MulOpe", ("A16", "A16", "A32")): ("B*", "B*P"),
    ("MulOpe", ("A16u", "A16u", "A32u")): ("*_U", "*P_U"),
    ("MulOpe", ("A32", "A32", "A32a")): ("DB*", "DB*P"),
    ("MulOpe", ("A32u", "A32u", "A32ua")): ("D*_U", "D*P_U"),
    ("DivOpe", ("A32s", "A32s", "A32sa")): ("D/", "D/P"),
    ("DivOpe", ("A16", "A16", "A16a")): ("B/", "B/P"),
    ("DivOpe", ("A16s", "A16s", "A16sa")): ("/", "/P"),
    ("DivOpe", ("A16u", "A16u", "A16ua")): ("/_U", "/P_U"),
    ("DivOpe", ("A32", "A32", "A32a")): ("DB/", "DB/P"),
    ("DivOpe", ("A32u", "A32u", "A32ua")): ("D/_U", "D/P_U"),
}

def _format_operand(
    tags: list[str], value: tuple[str, tuple[int, ...]]
) -> tuple[str, int]:
    shape, numbers = value
    if shape == "local_label" and not numbers and tags:
        token = tags[0]
        if _LOCAL_LABEL_TOKEN.fullmatch(token) is None:
            raise MiningRequired(
                "operand", "local-label header token format is unmined"
            )
        return token, 1
    if shape == "string_literal" and not numbers and len(tags) >= 3:
        try:
            return _lddb_quoted_string_literal(list(tags), 0)
        except MiningRequired:
            pass
    # GX Works3 encodes an index register as a second numeric field under
    # ``Zs``.  These forms are source notation only: Neutral IR retains the
    # FX5U operand exactly and does not imply a Q-series mapping.
    if shape == "remote_bit" and tags[:3] == ["Us", "G", "Zs"] and len(numbers) == 3:
        return f"U{numbers[0]}\\G{numbers[1]}Z{numbers[2]}", 3
    if shape == "remote_bit" and tags[:3] == ["Us", "G", "Dots"] and len(numbers) == 3:
        return f"U{numbers[0]}\\G{numbers[1]}.{numbers[2]:X}", 3
    if shape == "remote_word" and tags[:2] == ["Us", "G"] and len(numbers) == 2:
        return f"U{numbers[0]}\\G{numbers[1]}", 2
    if (
        shape == "k_device"
        and tags[:2] in (["M", "Zs"], ["D", "Zs"], ["R", "Zs"], ["T", "Zs"])
        and len(numbers) == 2
    ):
        return f"{tags[0]}{numbers[0]}Z{numbers[1]}", 2
    if shape == "k_device" and tags[:2] == ["B", "Zs"] and len(numbers) == 2:
        return f"B{numbers[0]:X}Z{numbers[1]}", 2
    if shape == "k_device" and tags[:3] == ["M", "Zs", "Ks"] and len(numbers) == 3:
        return f"K{numbers[2]}M{numbers[0]}Z{numbers[1]}", 3
    if (
        shape == "k_device"
        and tags[:2] in (["B", "Ks"], ["L", "Ks"], ["M", "Ks"])
        and len(numbers) == 2
    ):
        base = f"{numbers[0]:X}" if tags[0] == "B" else str(numbers[0])
        if tags[0] == "B":
            base = f"{numbers[0]:03X}"
        return f"K{numbers[1]}{tags[0]}{base}", 2
    if shape == "k_device" and tags[:2] in (["D", "Dots"], ["SD", "Dots"]) and len(numbers) == 2:
        return f"{tags[0]}{numbers[0]}.{numbers[1]:X}", 2
    if shape != "scalar" or not tags or tags[0] not in SCALAR_TAGS or len(numbers) != 1:
        raise MiningRequired("operand", "MIL scalar operand type is unmined")
    prefix = {"K_1": "K", "K_2": "K", "H_1": "H", "SfcS": "S"}.get(tags[0], tags[0])
    if prefix in {"X", "Y"}:
        # Issue #30 official MIL anchors: 1057/1059/1060 -> X421/X423/X424.
        number = f"{numbers[0]:X}"
        if re.fullmatch(r"[0-7]+", number) is None:
            raise MiningRequired("operand", "MIL X/Y source spelling is invalid")
    else:
        number = f"{numbers[0]:X}" if prefix in {"B", "H"} else str(numbers[0])
    return f"{prefix}{number}", 1


def _format_source_authorized_operand(
    tags: list[str],
    value: tuple[str, tuple[int, ...]],
    signature: Any,
    operand_index: int,
    record: str,
) -> tuple[str, int] | None:
    """Render context-bound corpus forms without widening generic tag support."""
    shape, numbers = value
    marker = signature.header_marker
    logic_type = signature.logic_type
    vts = signature.operand_vts
    kinds = signature.operand_kinds
    all_tags = signature.header_operand_tags
    # Official FX5 exports corroborate these MOV directions independently of
    # target support.  Match the full signature and composite shape, not a
    # project hash or a globally admitted SD/Y tag.
    grouped_mov = (
        marker == "MOV" and not signature.pulse
        and vts == ("A16", "A16") and kinds == ("d", "M")
        and re.fullmatch(
            r"mc\{op=cl\{op=#:ct=a:as=\[as\{vt=A16\}:as\{vt=A16\}\]\}:"
            r"as=\[d\{s=#:a=\d+:vt=nn\}:M\{b=d\{s=#:a=\d+:vt=nn\}:m=c\{s=#:v=[24]\}\}\]\}",
            record,
        ) is not None
    )
    if grouped_mov and all_tags == ("SD", "M", "Ks") and ":v=4}" in record:
        if operand_index == 0 and shape == "scalar" and len(numbers) == 1 and numbers[0] >= 0:
            return f"SD{numbers[0]}", 1
    if grouped_mov and all_tags == ("D", "Y", "Ks"):
        if operand_index == 1 and shape == "k_device" and len(numbers) == 2 and numbers[1] == 2:
            base = f"{numbers[0]:X}"
            if re.fullmatch(r"[0-7]+", base):
                return f"K2Y{base}", 2
    socket_u0_tags = {
        ("SP_SOCOPEN", ("String", "U0", '"U0"', "K_1", "D", "M")),
        ("SP_SOCCLOSE", ("String", "U0", '"U0"', "K_1", "D", "M")),
        ("SP_SOCRCV", ("String", "U0", '"U0"', "K_1", "D", "D", "M")),
        ("SP_SOCSND", ("String", "U0", '"U0"', "K_1", "D", "D", "M")),
        ("SP_SOCOPEN", ("String", "U0", '"U0"', "K_1", "D", "D", "Dots")),
        ("SP_SOCCLOSE", ("String", "U0", '"U0"', "K_1", "D", "D", "Dots")),
        ("SP_SOCSND", ("String", "U0", '"U0"', "K_1", "D", "D", "D", "Dots")),
    }
    if any(number < 0 for number in numbers):
        if (marker, all_tags) in socket_u0_tags:
            raise MiningRequired("operand", "MIL exact socket operand is negative")
        return None
    if (
        shape == "string_literal"
        and operand_index == 0
        and tags[:3] == ["String", "U0", '"U0"']
        and (marker, all_tags) in socket_u0_tags
        and "c{s=#:v=#:t=#}" in record
    ):
        return '"U0"', 3
    if (
        marker == "FOR"
        and operand_index == 0
        and shape == "scalar"
        and numbers == (32,)
        and tags[:2] == ["K_1", "32"]
        and vts == ("A16",)
        and kinds == ("c",)
        and all_tags == ("K_1", "32")
    ):
        return "K32", 2
    if (
        marker == "MOV"
        and operand_index == 0
        and shape == "scalar"
        and len(numbers) == 1
        and vts == ("A16", "A16")
        and kinds == ("c", "d")
        and all_tags == ("K_1", str(numbers[0]), "D")
        and tags[:2] == ["K_1", str(numbers[0])]
        and re.fullmatch(
            rf"mc\{{op=cl\{{op=#:ct=a:as=\[as\{{vt=A16\}}:as\{{vt=A16\}}\]\}}:"
            rf"as=\[c\{{s=#:v={numbers[0]}:t=#:si=s\}}:d\{{s=#:a=\d+:vt=nn\}}\]\}}",
            record,
        )
    ):
        return f"K{numbers[0]}", 2
    if shape == "scalar" and len(numbers) == 1:
        number = numbers[0]
        if (
            marker == "MOV"
            and operand_index == 0
            and vts == ("A32", "A32")
            and kinds == ("c", "d")
            and all_tags == ("H_2", "D")
            and tags[:2] == ["H_2", "D"]
            and 0 <= number <= 0xFFFFFFFF
            and re.fullmatch(
                r"mc\{op=cl\{op=#:ct=p:as=\[as\{vt=A32\}:as\{vt=A32\}\]\}:"
                rf"as=\[c\{{s=#:v={number}:si=u\}}:d\{{s=#:a=\d+:vt=nn\}}\]\}}",
                record,
            )
        ):
            return f"H{number:X}", 1
        if (
            marker == "B"
            and logic_type in {"a", "l"}
            and operand_index == 0
            and vts == ("Abl",)
            and kinds == ("d",)
            and all_tags == ("F",)
            and tags[:1] == ["F"]
        ) or (
            marker == "RST"
            and logic_type == ""
            and operand_index == 0
            and vts == ("Abl",)
            and kinds == ("d",)
            and all_tags == ("F",)
            and tags[:1] == ["F"]
        ) or (
            marker == "A"
            and logic_type in {"l", "o"}
            and operand_index == 0
            and vts == ("Abl",)
            and kinds == ("d",)
            and all_tags == ("F",)
            and tags[:1] == ["F"]
        ) or (
            marker == "SET"
            and operand_index == 2
            and vts == ("A16", "A16", "Abl")
            and kinds in {("d", "d", "d"), ("d", "c", "d")}
            and all_tags in {("T", "D", "F"), ("T", "K_1", "F")}
            and tags[:1] == ["F"]
        ):
            return f"F{number}", 1
        if (
            marker == "MOV"
            and operand_index == 0
            and vts == ("A16", "A16")
            and kinds == ("d", "d")
            and all_tags == ("SD", "D")
            and tags[:1] == ["SD"]
            and re.fullmatch(
                rf"mc\{{op=cl\{{op=#:ct=a:as=\[as\{{vt=A16\}}:as\{{vt=A16\}}\]\}}:"
                rf"as=\[d\{{s=#:a={number}:vt=nn\}}:d\{{s=#:a=\d+:vt=nn\}}\]\}}",
                record,
            )
        ):
            return f"SD{number}", 1
        if (
            marker == "NE"
            and logic_type == "o"
            and operand_index == 0
            and vts == ("A16s", "A16s")
            and kinds == ("d", "d")
            and all_tags == ("SD", "D")
            and tags[:1] == ["SD"]
            and re.fullmatch(
                rf"mc\{{op=lct\{{op=#:lt=o:ct=a:as=\[as\{{vt=A16s\}}:as\{{vt=A16s\}}\]\}}:"
                rf"as=\[d\{{s=#:a={number}:vt=nn\}}:d\{{s=#:a=\d+:vt=nn\}}\]\}}",
                record,
            )
        ):
            return f"SD{number}", 1
        if (
            marker == "BMOV"
            and operand_index == 0
            and vts == ("A16", "A16", "A16")
            and kinds == ("d", "d", "c")
            and all_tags == ("SD", "D", "K_1")
            and tags[:1] == ["SD"]
            and re.fullmatch(
                rf"mc\{{op=cl\{{op=#:ct=a:as=\[as\{{vt=A16\}}:as\{{vt=A16\}}:as\{{vt=A16\}}\]\}}:"
                rf"as=\[d\{{s=#:a={number}:vt=nn\}}:d\{{s=#:a=\d+:vt=nn\}}:c\{{s=#:v=\d+:si=s\}}\]\}}",
                record,
            )
        ):
            return f"SD{number}", 1
        if (
            marker == "AddOpe"
            and operand_index in {0, 1}
            and vts == ("Ass", "Ass", "Ass")
            and kinds == ("d", "d", "d")
            and all_tags == ("W", "W", "D")
            and tags[:1] == ["W"]
        ):
            return f"W{number:X}", 1
    if shape == "k_device" and len(numbers) == 2:
        base, modifier = numbers
        if (
            marker == "MOV"
            and operand_index == 0
            and vts == ("A16", "A16")
            and kinds == ("M", "d")
            and all_tags == ("Y", "Ks", "D")
            and tags[:2] == ["Y", "Ks"]
        ):
            expected_target = next(
                (
                    target
                    for expected_operand, target in _EXACT_MIL_Y_KS_MOV_OPERANDS
                    if expected_operand == (base, modifier)
                ),
                None,
            )
            if expected_target is not None and re.fullmatch(
                rf"mc\{{op=cl\{{op=#:ct=a:as=\[as\{{vt=A16\}}:as\{{vt=A16\}}\]\}}:"
                rf"as=\[M\{{b=d\{{s=#:a={base}:vt=nn\}}:m=c\{{s=#:v={modifier}\}}\}}:"
                rf"d\{{s=#:a={expected_target}:vt=nn\}}\]\}}",
                record,
            ):
                return f"K{modifier}Y{base:X}", 2
        if (
            marker == "A"
            and logic_type == "a"
            and operand_index == 0
            and vts == ("Abl",)
            and kinds == ("M",)
            and all_tags == ("L", "Zs")
            and tags[:2] == ["L", "Zs"]
        ):
            return f"L{base}Z{modifier}", 2
        if (
            marker == "A"
            and logic_type in {"l", "o"}
            and operand_index == 0
            and vts == ("Abl",)
            and kinds == ("M",)
            and all_tags == ("F", "Zs")
            and tags[:2] == ["F", "Zs"]
        ):
            return f"F{base}Z{modifier}", 2
        if (
            marker == "OUT"
            and operand_index == 0
            and vts == ("Abl",)
            and kinds == ("M",)
            and all_tags == ("F", "Zs")
            and tags[:2] == ["F", "Zs"]
        ):
            return f"F{base}Z{modifier}", 2
        f_ks_context = (
            marker == "MOV"
            and operand_index == 0
            and vts == ("A16", "A16")
            and kinds == ("M", "M")
            and all_tags == ("F", "Ks", "M", "Ks")
        ) or (
            marker == "EQ"
            and logic_type == "a"
            and operand_index == 0
            and vts == ("A32s", "A32s")
            and kinds == ("M", "c")
            and all_tags == ("F", "Ks", "K_2")
        ) or (
            marker in {"LT", "EQ"}
            and logic_type == "a"
            and operand_index == 1
            and vts == ("A16s", "A16s")
            and kinds == ("c", "M")
            and all_tags == ("K_1", "F", "Ks")
        ) or (
            marker == "EQ"
            and logic_type == "a"
            and operand_index == 0
            and vts == ("A16s", "A16s")
            and kinds == ("M", "c")
            and all_tags == ("F", "Ks", "K_1")
        ) or (
            marker == "MOV"
            and operand_index == 0
            and vts == ("A16", "A16")
            and kinds == ("M", "d")
            and all_tags == ("F", "Ks", "D")
        )
        if f_ks_context and tags[:2] == ["F", "Ks"] and 1 <= modifier <= 8:
            return f"K{modifier}F{base}", 2
    return None


def _header_tokens(data: str) -> list[str]:
    return opcode_header_tokens(data)


def _decode_mil(data: str, expected_count: int) -> list[dict[str, Any]]:
    if data == "V1:1:1:1:ms{el=[ma{k=@BE/NOP:ps=[p{k=NUM:v=#}]}]}":
        if expected_count != 1:
            raise MiningRequired("record", "MIL NOP row count is unmined")
        return [
            {"kind": "instruction", "opcode": "NOP", "operands": [], "text": None}
        ]
    if ":ms{el=[ma{" in data:
        match = re.fullmatch(r"V1:\d+:\d+:\d+:(.*):([si]):ms\{el=\[ma\{.*", data)
        if match is None or expected_count != 1:
            raise MiningRequired("record", "unmined MIL statement record")
        return [
            {
                "kind": "statement",
                "opcode": None,
                "operands": [],
                "text": ("*" if match.group(2) == "s" else "") + match.group(1),
            }
        ]
    serialized = _balanced_records(data, "mc{")
    if not serialized:
        if _header_tokens(data) == ["END"] and expected_count == 1:
            return [
                {"kind": "instruction", "opcode": "END", "operands": [], "text": None}
            ]
        raise MiningRequired("record", "MIL block has no decoded instruction record")
    inline_note_count = data.count(":ma{k=@FE/NOTE")
    if len(serialized) + inline_note_count != expected_count:
        raise MiningRequired("record", "MIL and StepInfo instruction counts differ")
    tokens = _header_tokens(data)
    cursor = 0
    result: list[dict[str, Any]] = []
    try:
        oracle_stream = mil_stream(data)
    except ValueError as error:
        raise MiningRequired("opcode", str(error)) from error
    oracle_signatures = [
        signature
        for kind, signature in oracle_stream
        if kind == "instruction" and signature is not None
    ]
    if len(oracle_signatures) != len(serialized):
        raise MiningRequired("opcode", "opcode oracle and MIL record counts differ")
    def append_inline_notes() -> None:
        nonlocal cursor
        while (
            cursor + 1 < len(tokens)
            and tokens[cursor + 1] in {"i", "s"}
            and tokens[cursor] not in INSTRUCTION_MARKERS
        ):
            result.append(
                {
                    "kind": "note",
                    "opcode": None,
                    "operands": [],
                    "text": tokens[cursor],
                    "note_subtype": tokens[cursor + 1],
                }
            )
            cursor += 2

    for record_index, record in enumerate(serialized):
        append_inline_notes()
        if cursor >= len(tokens):
            raise MiningRequired(
                "opcode", "MIL header has fewer descriptors than records"
            )
        marker = tokens[cursor]
        cursor += 1
        try:
            opcode = lookup_mnemonic(oracle_signatures[record_index])
        except UnknownOpcodeSignature as error:
            raise MiningRequired(
                "opcode", "MIL instruction signature is absent from the approved oracle"
            ) from error
        operands: list[str] = []
        for operand_index, operand in enumerate(_mil_operands(record)):
            authorized = _format_source_authorized_operand(
                tokens[cursor:], operand, oracle_signatures[record_index], operand_index,
                record,
            )
            rendered, consumed = (
                authorized
                if authorized is not None
                else _format_operand(tokens[cursor:], operand)
            )
            operands.append(rendered)
            cursor += consumed
        result.append(
            {
                "kind": "instruction",
                "opcode": opcode,
                "operands": operands,
                "text": None,
            }
        )
    append_inline_notes()
    if cursor != len(tokens):
        raise MiningRequired("opcode", "MIL header has unused descriptors")
    return result


def _sqlite_text_key(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def _local_label_names(
    archive: SafeGx3Archive,
) -> tuple[dict[tuple[str, str], str], set[tuple[str, str]], str | None]:
    if "LabelData.db" not in archive.entries:
        return {}, set(), None
    connection = _connection(archive, "LabelData.db")
    try:
        if not {
            "LabelID",
            "RowID",
            "ColumnID",
            "ColumnStrValue",
            "ColumnIntValue",
        }.issubset(_columns(connection, "ColumnDataTbl")):
            return {}, set(), "LabelData ColumnDataTbl schema is unmined"
        rows = list(
            connection.execute(
                "SELECT LabelID,RowID,ColumnID,ColumnStrValue,ColumnIntValue "
                "FROM ColumnDataTbl"
            )
        )
    except sqlite3.DatabaseError:
        return {}, set(), "label schema or query is unmined"
    finally:
        connection.close()
    names: dict[tuple[str, str], str] = {}
    duplicates: set[tuple[str, str]] = set()
    for label_id, row_id, column_id, str_value, _int_value in rows:
        if column_id != 2:
            continue
        key_label = _sqlite_text_key(label_id)
        key_row = _sqlite_text_key(row_id)
        if key_label is None or key_row is None:
            continue
        key = (key_label, key_row)
        if key in names or key in duplicates:
            names.pop(key, None)
            duplicates.add(key)
            continue
        names[key] = str_value
    return names, duplicates, None


def _operand(
    token: str,
    position: int,
    provenance: dict[str, Any],
    label_names: dict[tuple[str, str], str],
    label_duplicates: set[tuple[str, str]],
    label_error: str | None,
) -> dict[str, Any]:
    match = _LOCAL_LABEL_TOKEN.fullmatch(token)
    if match is not None:
        if label_error:
            raise MiningRequired("operand", label_error)
        key = (match.group(1), match.group(2))
        if key in label_duplicates:
            raise MiningRequired(
                "operand", "local-label ColumnDataTbl lookup is not unique"
            )
        name = label_names.get(key)
        if not isinstance(name, str) or not name:
            raise MiningRequired(
                "operand", "local-label ColumnDataTbl lookup is absent"
            )
        lookup = f"ColumnDataTbl(LabelID,RowID,ColumnID=2)[{key[0]},{key[1]}]"
        return {
            "position": position,
            "raw_token": token,
            "kind": "local_label",
            "value": name,
            "width": None,
            "indirection": False,
            "index": None,
            "provenance": {
                **provenance,
                "relation_evidence": [*provenance["relation_evidence"], lookup],
            },
        }
    prefix = token.split("\\", 1)[0]
    kind = (
        "constant"
        if prefix.startswith(("K", "H")) and not re.match(r"K\d+[A-Z]", prefix)
        else "device"
    )
    return {
        "position": position,
        "raw_token": token,
        "kind": kind,
        "value": token,
        "width": None,
        "indirection": False,
        "index": None,
        "provenance": provenance,
    }


_LDDB_SCALAR_TAGS = frozenset(
    {
        "B", "D", "H_1", "K_1", "K_2", "L", "M", "R", "SfcS",
        "SD", "SM", "ST", "T", "X", "Y", "Z",
    }
)
_LDDB_COMMANDS: dict[str, tuple[str, tuple[int, ...]]] = {
    "c": ("OUT", (1, 2)),
    "OUT": ("OUT", (1, 2)),
    "OUT__16": ("OUT", (1, 2)),
    "SET": ("SET", (1,)),
    "RST": ("RST", (1, 2)),
    "RST__16": ("RST", (1,)),
    "ZRST": ("RST", (2,)),
    "MOV": ("MOV", (2,)),
    "MOVP": ("MOVP", (2,)),
    "DMOV": ("DMOV", (2,)),
    "DMOVP": ("DMOVP", (2,)),
    "FMOV": ("FMOV", (3,)),
    "FMOVP": ("FMOVP", (3,)),
    "BMOV": ("BMOV", (3,)),
    "BMOVP": ("BMOVP", (3,)),
    "INC": ("INC", (1,)),
    "INCP": ("INCP", (1,)),
    "DEC": ("DEC", (1,)),
    "DECP": ("DECP", (1,)),
}
_LDDB_PULSE_COMMANDS = {
    "OUT": "PLS",
    "c": "PLS",
    "MOV": "MOVP",
    "MOVP": "MOVP",
    "DMOVP": "DMOVP",
    "FMOV": "FMOVP",
    "FMOVP": "FMOVP",
    "BMOV": "BMOVP",
    "BMOVP": "BMOVP",
    "INC": "INCP",
    "INCP": "INCP",
    "DEC": "DECP",
    "DECP": "DECP",
}
_LDDB_END = "V1:0:end{type=end:dim=1x1}"
_LDDB_NOP = "V1:0:nop{nop=fnn{n=1}:dim=1x1}"

_LDDB_OPERAND_COUNTS: dict[str, tuple[int, ...]] = {
    "": (0,), "*": (3,), "+": (3,), "-": (3,), "ANB": (0,),
    "AND": (1,), "AND<": (2,), "AND<=": (2,), "AND<>": (2,),
    "AND=": (2,), "AND>=": (2,), "AND>": (2,), "ANDD<": (2,),
    "ANDD<=": (2,), "ANDD<>": (2,), "ANDD=": (2,),
    "ANDD>=": (2,), "ANDD>": (2,), "ANDF": (1,), "ANDFI": (1,),
    "ANDP": (1,), "ANDPI": (1,), "ANI": (1,), "ANIP": (1,),
    "BKRST": (2,), "BMOV": (3,), "BMOVP": (3,), "BSFL": (2,),
    "D*": (3,), "D+": (3,), "D-": (3,), "D/": (3,),
    "DATERD": (1,), "DATEWR": (1,), "DEC": (1,), "DECO": (3,),
    "DECP": (1,), "DINCP": (1,), "DMOV": (2,), "DMOVP": (2,),
    "DSFR": (1, 2), "DSFRP": (1, 2), "END": (0,), "FF": (1,),
    "FMOV": (3,), "FMOVP": (3,), "INC": (1,), "INCP": (1,),
    "INV": (0,), "LD": (1,), "LD<": (2,), "LD<=": (2,),
    "LD<>": (2,), "LD>": (2,), "LD=": (2,), "LD>=": (2,),
    "LDD<": (2,), "LDD<=": (2,), "LDD<>": (2,), "LDD=": (2,),
    "LDD>=": (2,), "LDD>": (2,), "LDF": (1,), "LDI": (1,),
    "LDFI": (1,), "LDP": (1,), "LDPI": (1,), "MEP": (0,),
    "MOV": (2,), "MOVP": (2,), "MPP": (0,), "MPS": (0,),
    "MRD": (0,), "NOP": (0,), "OR": (1,), "ORB": (0,),
    "ORF": (1,), "ORFI": (1,), "ORI": (1,), "OR<": (2,),
    "OR<=": (2,), "OR<>": (2,), "OR=": (2,), "OR>=": (2,),
    "OR>": (2,), "ORP": (1,), "ORIP": (1,), "ORD<": (2,),
    "ORD<=": (2,), "ORD<>": (2,), "ORD=": (2,), "ORD>=": (2,),
    "ORD>": (2,), "OUT": (1, 2), "OUTH": (2,), "PLS": (1,),
    "RST": (1, 2), "SET": (1,), "TRD": (1,), "TWR": (1,),
    "ZRST": (2,), "ZRSTP": (2,), "ANS": (3,), "DDRVA": (4,), "DDSZR": (4,),
    "DPLSV": (3,), "WTOB": (3,), "LIMIT": (4,), "INSTR": (4,),
    "/": (3,), "WSUM": (3,), "BCD": (2,), "BIN": (2,),
    "SUM": (2,), "LEN": (2,), "FOR": (1,), "NEXT": (0,),
    "GOEND": (0,), "IVDR": (5,), "IVCK": (5,), "RS2": (5,),
    "HEXA": (3,), "VAL": (1, 3), "VALP": (3,), "VAL_U": (3,),
    "VALP_U": (3,), "DVAL": (3,), "DVALP": (3,), "DVAL_U": (3,),
    "DVALP_U": (3,), "$+": (2, 3), "SP.SOCOPEN": (4,),
    "SP.SOCCLOSE": (4,), "SP.SOCRCV": (5,), "SP.SOCSND": (5,),
    "SP.ECPRTCL": (5,), "+P": (3,), "$MOV": (2,),
    "BTOW": (3,), "EVAL": (2,), "FLT2DINT": (2,),
}

# Source-derived parser observation.
# Source-derived parser observation.
# form and value-type signature together prevents a catalog mnemonic from
# becoming a wildcard decoder for an unmined serialization.
_LDDB_MINED_COMMANDS: dict[tuple[str, str, tuple[str, ...]], str] = {
    ("ANS", "a", ("A16", "A16", "Abl")): "ANS",
    ("OUTH__16", "a", ("Abl", "A16")): "OUTH",
    ("/", "a", ("A16s", "A16s", "A16sa")): "/",
    ("DIV", "a", ("A16s", "A16s", "A16sa")): "/",
    ("DDIV", "a", ("A32s", "A32s", "A32sa")): "D/",
    ("DMUL", "a", ("A32s", "A32s", "A32sa")): "D*",
    ("ADD", "a", ("A16s", "A16s", "A16s")): "+",
    ("DDRVA", "a", ("A32", "A32", "Aea", "Abl")): "DDRVA",
    ("DDSZR", "a", ("A32", "A32", "Aea", "Abl")): "DDSZR",
    ("DPLSV", "a", ("A32", "Aea", "Abl")): "DPLSV",
    ("WTOB", "a", ("A16", "A16", "A16")): "WTOB",
    ("BTOW", "a", ("A16", "A16", "A16")): "BTOW",
    ("EVAL", "a", ("Ass", "Ar32")): "EVAL",
    ("FLT2DINT", "a", ("Ar32", "A32s")): "FLT2DINT",
    ("LIMIT", "a", ("A16s", "A16s", "A16s", "A16s")): "LIMIT",
    ("INSTR", "a", ("Ass", "Ass", "A16", "A16")): "INSTR",
    ("SP.SOCOPEN", "p", ("Ass", "A16", "A16a", "Aba")): "SP.SOCOPEN",
    ("SP.SOCCLOSE", "p", ("Ass", "A16", "A16a", "Aba")): "SP.SOCCLOSE",
    ("SP.SOCRCV", "p", ("Ass", "A16", "A16a", "A16", "Aba")): "SP.SOCRCV",
    ("SP.SOCSND", "p", ("Ass", "A16", "A16a", "A16", "Aba")): "SP.SOCSND",
    ("SP.ECPRTCL", "p", ("Ass", "A16", "A16", "A16a", "Aba")): "SP.ECPRTCL",
    ("ZRSTP", "p", ("Aea", "Aea")): "ZRSTP",
    ("+P", "p", ("A16s", "A16s", "A16s")): "+P",
    ("SUB", "a", ("A16s", "A16s", "A16s")): "-",
    ("$MOV", "a", ("Ass", "Ass")): "$MOV",
}
_LDDB_MINED_MARKERS = frozenset(key[0] for key in _LDDB_MINED_COMMANDS)

_LDDB_EXACT_ARITIES = frozenset(
    {
        ("SFL", "a", ("A16", "A16"), 2),
        ("+", "a", ("A16s", "A16s"), 2),
        ("-", "a", ("A16s", "A16s"), 2),
        ("D+", "a", ("A32s", "A32s"), 2),
    }
)

_LDDB_PULSE_VARIANTS = {
    **_LDDB_PULSE_COMMANDS,
    "PLS": "PLS", "FF": "FF", "DINCP": "DINCP", "DSFR": "DSFRP",
    "DSFRP": "DSFRP", "VAL": "VALP", "VALP": "VALP",
    "S_SOCOPEN": "S_SOCOPEN", "SP_SOCOPEN": "SP_SOCOPEN",
    "S_SOCCLOSE": "S_SOCCLOSE", "SP_SOCCLOSE": "SP_SOCCLOSE",
    "S_SOCRCV": "S_SOCRCV", "SP_SOCRCV": "SP_SOCRCV",
    "S_SOCSND": "S_SOCSND", "SP_SOCSND": "SP_SOCSND",
    "S_ECPRTCL": "S_ECPRTCL", "SP_ECPRTCL": "SP_ECPRTCL",
}


def _lddb_bracket_payload(text: str, marker: str) -> str:
    start = text.find(marker)
    if start < 0:
        raise MiningRequired("record", "LDDB element has no argument payload")
    bracket = start + len(marker) - 1
    depth = 0
    for end in range(bracket, len(text)):
        if text[end] == "[":
            depth += 1
        elif text[end] == "]":
            depth -= 1
            if depth == 0:
                return text[bracket + 1 : end]
    raise MiningRequired("record", "LDDB argument payload is unbalanced")


def _lddb_top_level_values(payload: str) -> list[str]:
    values: list[str] = []
    cursor = 0
    while cursor < len(payload):
        if payload[cursor] in ": ":
            cursor += 1
            continue
        start = cursor
        brace = payload.find("{", cursor)
        if brace < cursor:
            raise MiningRequired("operand", "LDDB argument form is unmined")
        depth = 0
        for cursor in range(brace, len(payload)):
            if payload[cursor] == "{":
                depth += 1
            elif payload[cursor] == "}":
                depth -= 1
                if depth == 0:
                    values.append(payload[start : cursor + 1])
                    cursor += 1
                    break
        else:
            raise MiningRequired("operand", "LDDB argument is unbalanced")
    return values


def _lddb_descriptors(data: str) -> list[str]:
    prefix = data.split(":cb{fg=fg{", 1)[0]
    tokens = prefix.split(":")
    if not tokens or tokens[0] != "V1":
        raise MiningRequired("record", "LDDB logic header is unmined")
    first = next(
        (index for index, token in enumerate(tokens[1:], 1) if not token.isdigit()),
        len(tokens),
    )
    descriptors = tokens[first:]
    if not descriptors:
        raise MiningRequired("record", "LDDB logic header has no descriptors")
    return descriptors


def _lddb_xy_spelling(tag: str, number: int) -> str:
    """Recover observed LDDB display digits independently of MIL/comments.

    Issue #30 official export pairs serialized a=1143 with X477. MIL is
    validated separately; comment-DB ordinals do not enter this helper.
    """
    digits = f"{number:X}"
    if tag not in {"X", "Y"} or re.fullmatch(r"[0-7]+", digits) is None:
        raise MiningRequired("operand", "LDDB X/Y source spelling is invalid")
    return f"{tag}{digits}"


def _lddb_scalar_operand(tag: str, raw: str) -> str:
    # These device/constant tags have exact LDDB shapes and radices that are
    # not interchangeable with the generic scalar grammar below.  Keep the
    # full serialization in the approval key so near-matches fail closed.
    if tag in {"F", "DX"}:
        device = re.fullmatch(r"d\{s=#:a=(\d+):vt=nn\}", raw)
        if device is None:
            raise MiningRequired("operand", "LDDB scalar operand is unmined")
        number = int(device.group(1))
        return f"F{number}" if tag == "F" else f"DX{number:X}"
    if tag == "H_2":
        unsigned_hex = re.fullmatch(r"c\{s=#:v=(\d+):si=u\}", raw)
        if unsigned_hex is None:
            raise MiningRequired("operand", "LDDB scalar operand is unmined")
        number = int(unsigned_hex.group(1))
        if number > 0xFFFFFFFF:
            raise MiningRequired("operand", "LDDB H_2 constant exceeds 32 bits")
        return f"H{number:X}"
    if tag == "K_1":
        typed_decimal = re.fullmatch(r"c\{s=#:v=(-?\d+):t=#:si=s\}", raw)
        if typed_decimal is not None:
            number = int(typed_decimal.group(1))
            if not -0x8000 <= number <= 0x7FFF:
                raise MiningRequired("operand", "LDDB typed K_1 exceeds A16 signed range")
            return f"K{number}"
    match = re.fullmatch(r"[dc]\{s=#:([av])=(-?\d+):(?:vt=nn|si=(s|u))\}", raw)
    if match is None:
        raise MiningRequired("operand", "LDDB scalar operand is unmined")
    number = int(match.group(2))
    if match.group(3) == "u" and number < 0:
        raise MiningRequired("operand", "LDDB unsigned scalar operand is negative")
    if tag in {"K_1", "K_2"}:
        return f"K{number}"
    if tag == "H_1":
        return f"H{number:X}"
    if tag == "B":
        return f"B{number:X}"
    if tag in {"X", "Y"}:
        return _lddb_xy_spelling(tag, number)
    if tag in _LDDB_SCALAR_TAGS:
        return f"{tag}{number}"
    raise MiningRequired("operand", "LDDB operand tag is unmined")


def _lddb_quoted_string_literal(descriptors: list[str], cursor: int) -> tuple[str, int]:
    """Recover a String placeholder from its exact header triple.

    The grid argument is ``c{s=#:v=#:t=#}``; the literal lives in the
    descriptor stream as ``String``, bare text, and the matching quoted form.
    Empty, non-printable, quoted, or mismatched triples stay unmined.
    """
    triple = tuple(descriptors[cursor : cursor + 3])
    bare = triple[1] if len(triple) == 3 else ""
    quoted = triple[2] if len(triple) == 3 else ""
    if (
        len(triple) != 3
        or triple[0] != "String"
        or re.fullmatch(r"[A-Za-z0-9_\-,$]+", bare) is None
        or quoted != f'"{bare}"'
    ):
        raise MiningRequired(
            "operand", "LDDB String placeholder descriptor is unmined"
        )
    return quoted, cursor + 3


def _lddb_operand_at(
    descriptors: list[str],
    cursor: int,
    raw: str,
    *,
    allow_sd_indexed: bool = False,
    allow_f_grouped: bool = False,
) -> tuple[str, int]:
    """Consume one descriptor-complete scalar or observed composite operand."""
    if cursor >= len(descriptors):
        raise MiningRequired(
            "operand", "LDDB operand descriptor stream is shorter than its grid"
        )
    tag = descriptors[cursor]
    if raw == "c{s=#:v=#:t=#}":
        return _lddb_quoted_string_literal(descriptors, cursor)
    typed_decimal = re.fullmatch(r"c\{s=#:v=(-?\d+):t=#:si=s\}", raw)
    if tag == "K_1" and typed_decimal is not None:
        if descriptors[cursor + 1 : cursor + 2] != [typed_decimal.group(1)]:
            raise MiningRequired("operand", "LDDB typed K_1 descriptor differs")
        return _lddb_scalar_operand(tag, raw), cursor + 2
    remote = re.fullmatch(
        r"B\{b=d\{s=#:a=(-?\d+):vt=nn\}:e=d\{s=#:a=(-?\d+):vt=nn\}:vt=(?:i|wd)\}",
        raw,
    )
    if (
        remote is not None
        and tag == "Us"
        and descriptors[cursor + 1 : cursor + 2] == ["G"]
    ):
        unit, address = (int(item) for item in remote.groups())
        return f"U{unit}\\G{address}", cursor + 2
    indexed = re.fullmatch(
        r"M\{b=d\{s=#:a=(-?\d+):vt=nn\}:m=d\{s=#:a=(-?\d+):vt=nn\}\}",
        raw,
    )
    if (
        indexed is not None
        and (tag in {"B", "D", "F", "L", "M", "R", "T"} or (tag == "SD" and allow_sd_indexed))
        and descriptors[cursor + 1 : cursor + 2] == ["Zs"]
    ):
        base, index = (int(item) for item in indexed.groups())
        if tag in {"B", "F", "SD"} and (base < 0 or index < 0):
            raise MiningRequired("operand", "LDDB mined indexed device is negative")
        number = f"{base:X}" if tag == "B" else str(base)
        return f"{tag}{number}Z{index}", cursor + 2
    indexed_k = re.fullmatch(
        r"M\{b=M\{b=d\{s=#:a=(-?\d+):vt=nn\}:m=d\{s=#:a=(-?\d+):vt=nn\}\}:m=c\{s=#:v=(-?\d+)\}\}",
        raw,
    )
    if (
        indexed_k is not None
        and tag in {"M", "L", "B"}
        and descriptors[cursor + 1 : cursor + 3] == ["Zs", "Ks"]
    ):
        base, index, width = (int(item) for item in indexed_k.groups())
        if not 1 <= width <= 8:
            raise MiningRequired("operand", "LDDB indexed K-device width is unmined")
        number = f"{base:X}" if tag == "B" else str(base)
        return f"K{width}{tag}{number}Z{index}", cursor + 3
    remote_indexed = re.fullmatch(
        r"M\{b=(B\{b=d\{s=#:a=(-?\d+):vt=nn\}:e=d\{s=#:a=(-?\d+):vt=nn\}:vt=(?:i|wd)\}):m=d\{s=#:a=(-?\d+):vt=nn\}\}",
        raw,
    )
    if (
        remote_indexed is not None
        and tag == "Us"
        and descriptors[cursor + 1 : cursor + 3] == ["G", "Zs"]
    ):
        _base, unit, address, index = remote_indexed.groups()
        return f"U{int(unit)}\\G{int(address)}Z{int(index)}", cursor + 3
    remote_bit = re.fullmatch(
        r"M\{b=(B\{b=d\{s=#:a=(-?\d+):vt=nn\}:e=d\{s=#:a=(-?\d+):vt=nn\}\}):m=c\{s=#:v=(-?\d+)\}\}",
        raw,
    )
    if (
        remote_bit is not None
        and tag == "Us"
        and descriptors[cursor + 1 : cursor + 3] == ["G", "Dots"]
    ):
        _base, unit, address, bit = remote_bit.groups()
        if not 0 <= int(bit) <= 15:
            raise MiningRequired("operand", "LDDB remote bit index is unmined")
        return f"U{int(unit)}\\G{int(address)}.{int(bit):X}", cursor + 3
    composite = re.fullmatch(
        r"M\{b=d\{s=#:a=(-?\d+):vt=nn\}:m=c\{s=#:v=(-?\d+)\}\}", raw
    )
    if composite is not None and cursor + 1 < len(descriptors):
        base, modifier = (int(item) for item in composite.groups())
        suffix = descriptors[cursor + 1]
        if suffix == "Dots" and tag in {"D", "R", "SD"} and 0 <= modifier <= 15:
            return f"{tag}{base}.{modifier:X}", cursor + 2
        if (
            suffix == "Ks"
            and (tag in {"M", "L", "B", "X", "Y"} or (tag == "F" and allow_f_grouped))
            and 1 <= modifier <= 8
        ):
            if tag in {"X", "Y"}:
                return f"K{modifier}{_lddb_xy_spelling(tag, base)}", cursor + 2
            number = f"{base:X}" if tag == "B" else str(base)
            return f"K{modifier}{tag}{number}", cursor + 2
    return _lddb_scalar_operand(tag, raw), cursor + 1


@dataclass(frozen=True)
class _LddbGridElement:
    x: int
    y: int
    kind: str
    pulse: str
    signature: tuple[str, ...]
    args: list[str]
    has_note: bool
    note_subtype: str = ""


@dataclass(frozen=True)
class _LddbDecodedElement:
    x: int
    y: int
    kind: str
    instruction: str
    operands: tuple[str, ...]
    order: int
    span: int
    note: str = ""
    note_subtype: str = ""


def _lddb_elements(data: str) -> tuple[list[_LddbGridElement], list[tuple[int, int]]]:
    grid = data[data.index(":cb{fg=fg{") :]
    elements: list[_LddbGridElement] = []
    for record in _balanced_records(grid, "e{"):
        positions = list(re.finditer(r":pos=(\d+),(\d+)(?=[:}])", record))
        if not positions:
            raise MiningRequired("record", "LDDB grid element position is unmined")
        position = positions[-1]
        position_suffix = record[position.end() :]
        if position_suffix == "}":
            note_subtype = ""
        else:
            note_marker = re.fullmatch(r":note=c\{t=#:st=([^}:]+)\}\}", position_suffix)
            if note_marker is None:
                raise MiningRequired("record", "LDDB inline note placement is unmined")
            note_subtype = note_marker.group(1)
            if note_subtype not in {"i", "s"}:
                raise MiningRequired("record", "LDDB inline note subtype is unmined")
        if record.startswith("e{s=-:"):
            continue
        operation = re.search(r"op=(ct|cl)\{op=#:ct=([afp])(?=[:}])", record)
        if operation is None:
            raise MiningRequired("record", "LDDB grid operation is unmined")
        kind, pulse = operation.groups()
        if pulse == "f" and kind != "ct":
            raise MiningRequired("opcode", "LDDB falling command operation is unmined")
        arguments = (
            _lddb_top_level_values(_lddb_bracket_payload(record, ":args=["))
            if ":args=[" in record
            else []
        )
        has_note = bool(note_subtype)
        if has_note and (
            kind != "cl"
            or ":args=[" not in record
            or ("]:note=c{t=#:st=" + note_subtype + "}}:pos=") not in record
        ):
            raise MiningRequired("record", "LDDB inline note placement is unmined")
        elements.append(
            _LddbGridElement(
                int(position.group(1)),
                int(position.group(2)),
                kind,
                pulse,
                tuple(re.findall(r"as\{vt=([^}:]+)\}", record)),
                arguments,
                has_note,
                note_subtype,
            )
        )
    vertical = [(int(x), int(y)) for x, y in re.findall(r"v\{pos=(\d+),(\d+)\}", data)]
    if not elements:
        raise MiningRequired("record", "LDDB logic block has no grid elements")
    return elements, vertical


def _lddb_wire_positions(data: str) -> list[tuple[int, int]]:
    grid = data[data.index(":cb{fg=fg{") :]
    positions: list[tuple[int, int]] = []
    for record in _balanced_records(grid, "e{"):
        if not record.startswith("e{s=-:"):
            continue
        match = re.search(r":pos=(\d+),(\d+)\}$", record)
        if match is None:
            raise MiningRequired("record", "LDDB wire position is unmined")
        positions.append((int(match.group(1)), int(match.group(2))))
    return positions


def _lddb_comparison_width(signature: tuple[str, ...]) -> str:
    numeric = tuple(tag for tag in signature if tag.startswith(("A16", "A32")))
    # Older observed LDDB blocks omit the raw type signature; P006 treats
    # that exact absence as the 16-bit comparison form. A partial or mixed
    # signature is still ambiguous and remains fail-closed.
    if not numeric:
        return ""
    if len(numeric) != 2:
        raise MiningRequired("opcode", "LDDB comparison operand signature is unmined")
    if all(tag.startswith("A16") for tag in numeric):
        return ""
    if all(tag.startswith("A32") for tag in numeric):
        return "D"
    raise MiningRequired("opcode", "LDDB comparison width is mixed")


def _lddb_command(marker: str, pulse: str, signature: tuple[str, ...]) -> str:
    if marker in _LDDB_MINED_MARKERS:
        instruction = _LDDB_MINED_COMMANDS.get((marker, pulse, signature))
        if instruction is None:
            raise MiningRequired("opcode", "LDDB command signature is unmined")
        return instruction
    aliases = {
        "c": "OUT", "OUT__16": "OUT", "RST__16": "RST", "ZRST": "RST",
        "ME": "MEP", "MUL": "*", "S_SOCOPEN": "SP.SOCOPEN",
        "SP_SOCOPEN": "SP.SOCOPEN", "S_SOCCLOSE": "SP.SOCCLOSE",
        "SP_SOCCLOSE": "SP.SOCCLOSE", "S_SOCRCV": "SP.SOCRCV",
        "SP_SOCRCV": "SP.SOCRCV", "S_SOCSND": "SP.SOCSND",
        "SP_SOCSND": "SP.SOCSND", "S_ECPRTCL": "SP.ECPRTCL",
        "SP_ECPRTCL": "SP.ECPRTCL",
    }
    instruction = aliases.get(marker, marker)
    if pulse == "a":
        return instruction
    if pulse != "p":
        raise MiningRequired("opcode", "LDDB command pulse descriptor is unmined")
    if instruction == "INC" and any(tag.startswith("A32") for tag in signature):
        return "DINCP"
    pulse_marker = _LDDB_PULSE_VARIANTS.get(marker) or _LDDB_PULSE_VARIANTS.get(instruction)
    if pulse_marker is None:
        raise MiningRequired("opcode", "LDDB command pulse descriptor is unmined")
    return aliases.get(pulse_marker, pulse_marker)


def _lddb_validate_mined_scalar_context(
    instruction: str,
    signature: tuple[str, ...],
    tag: str,
    operand_index: int,
    raw: str,
    following_tag: str,
    descriptors: tuple[str, ...],
) -> None:
    """Bind newly mined scalar tags to their observed instruction positions."""
    if tag == "F":
        scalar = re.fullmatch(r"d\{s=#:a=\d+:vt=nn\}", raw) is not None
        grouped = (
            following_tag == "Ks"
            and re.fullmatch(
                r"M\{b=d\{s=#:a=\d+:vt=nn\}:m=c\{s=#:v=[1-8]\}\}", raw
            )
            is not None
        )
        approved = scalar and (
            (instruction in {"LDI", "RST"} and signature == ("Abl",) and operand_index == 0)
            or (instruction == "ANS" and signature == ("A16", "A16", "Abl") and operand_index == 2)
            or (
                instruction in {"LD", "OUT"}
                and signature == ("Abl",)
                and operand_index == 0
                and descriptors == ("F",)
            )
        ) or grouped and (
            (
                instruction in {"LD<", "LD=", "LD<>"}
                and signature == ("A16s", "A16s")
                and operand_index == 1
                and descriptors == ("K_1", "F", "Ks")
            )
            or (
                instruction == "LDD="
                and signature == ("A32s", "A32s")
                and operand_index == 0
                and descriptors == ("F", "Ks", "K_2")
            )
            or (
                instruction == "MOV"
                and signature == ("A16", "A16")
                and operand_index == 0
                and descriptors == ("F", "Ks", "M", "Ks")
            )
            or (
                instruction == "LD="
                and signature == ("A16s", "A16s")
                and operand_index == 0
                and descriptors == ("F", "Ks", "K_1")
            )
            or (
                instruction == "MOV"
                and signature == ("A16", "A16")
                and operand_index == 0
                and descriptors == ("F", "Ks", "D")
            )
        ) or (
            instruction in {"LD", "OUT"}
            and signature == ("Abl",)
            and operand_index == 0
            and following_tag == "Zs"
            and descriptors == ("F", "Zs")
            and re.fullmatch(
                r"M\{b=d\{s=#:a=\d+:vt=nn\}:m=d\{s=#:a=\d+:vt=nn\}\}", raw
            )
            is not None
        )
    elif tag == "DX":
        approved = (
            instruction == "LDI"
            and signature == ("Abl",)
            and operand_index == 0
            and re.fullmatch(r"d\{s=#:a=\d+:vt=nn\}", raw) is not None
        )
    elif tag == "H_2":
        approved = (
            instruction == "DMOVP"
            and signature == ("A32", "A32")
            and operand_index == 0
            and re.fullmatch(r"c\{s=#:v=\d+:si=u\}", raw) is not None
        )
    elif tag == "SD" and following_tag == "Zs":
        indexed = re.fullmatch(
            r"M\{b=d\{s=#:a=(\d+):vt=nn\}:m=d\{s=#:a=(\d+):vt=nn\}\}", raw
        )
        approved = indexed is not None and (
            (
                instruction == "DMOV"
                and signature == ("A32", "A32")
                and operand_index == 0
                and (
                    (
                        descriptors == ("SD", "Zs", "D")
                        and indexed.groups() == ("5500", "1")
                    )
                    or descriptors == ("SD", "Zs", "D", "Zs")
                )
            )
            or (
                instruction == "MOV"
                and signature == ("A16", "A16")
                and operand_index == 0
                and descriptors == ("SD", "Zs", "D", "Zs")
            )
            or (
                instruction in {"MOV", "DMOV"}
                and signature in {("A16", "A16"), ("A32", "A32")}
                and operand_index == 1
                and descriptors == ("D", "Zs", "SD", "Zs")
            )
            or (
                instruction == "D/"
                and signature == ("A32s", "A32s", "A32sa")
                and operand_index == 2
                and descriptors == ("D", "Zs", "K_2", "SD", "Zs")
            )
        )
    elif tag == "SD":
        return
    else:
        return
    if not approved:
        raise MiningRequired("operand", "LDDB mined scalar context is unmined")


def _lddb_instruction_from_element(
    element: _LddbGridElement,
    descriptors: list[str],
    cursor: int,
) -> tuple[str, tuple[str, ...], int]:
    if cursor >= len(descriptors):
        raise MiningRequired("opcode", "LDDB descriptor stream is shorter than its grid")
    marker = descriptors[cursor]
    cursor += 1
    if marker == "Zs":
        if cursor >= len(descriptors):
            raise MiningRequired("opcode", "LDDB indexed operation marker is incomplete")
        marker = descriptors[cursor]
        cursor += 1
    if marker in {"INV", "ME"} and not element.args:
        instruction = {"INV": "INV", "ME": "MEP"}[marker]
    elif element.kind == "ct":
        if marker in {"a", "b"}:
            instruction = "LDI" if marker == "b" else "LD"
            if element.pulse == "p":
                instruction = {"LD": "LDP", "LDI": "LDPI"}[instruction]
            elif element.pulse == "f":
                instruction = {"LD": "LDF", "LDI": "LDFI"}[instruction]
            elif element.pulse != "a":
                raise MiningRequired("opcode", "LDDB contact pulse descriptor is unmined")
        elif marker in {"=", "<>", "<", "<=", ">", ">="}:
            if element.pulse != "a":
                raise MiningRequired("opcode", "LDDB comparison pulse descriptor is unmined")
            instruction = "LD" + _lddb_comparison_width(element.signature) + marker
        else:
            raise MiningRequired("opcode", "LDDB contact descriptor is unmined")
    else:
        instruction = _lddb_command(marker, element.pulse, element.signature)
        if marker == "RST__16" and len(element.args) != 1:
            raise MiningRequired("operand", "LDDB RST__16 serialization is unmined")
    counts = _LDDB_OPERAND_COUNTS.get(instruction)
    exact_arity = (marker, element.pulse, element.signature, len(element.args))
    if (counts is None or len(element.args) not in counts) and exact_arity not in _LDDB_EXACT_ARITIES:
        raise MiningRequired("operand", "LDDB command argument count is unmined")
    operand_descriptor_start = cursor
    operands: list[str] = []
    validation: list[tuple[str, int, str, str]] = []
    for operand_index, raw in enumerate(element.args):
        tag = descriptors[cursor] if cursor < len(descriptors) else ""
        following_tag = descriptors[cursor + 1] if cursor + 1 < len(descriptors) else ""
        validation.append((tag, operand_index, raw, following_tag))
        operand, cursor = _lddb_operand_at(
            descriptors,
            cursor,
            raw,
            allow_sd_indexed=(tag == "SD" and following_tag == "Zs"),
            allow_f_grouped=(tag == "F" and following_tag == "Ks"),
        )
        operands.append(operand)
    descriptor_context = tuple(descriptors[operand_descriptor_start:cursor])
    if instruction == "SFL" and (
        descriptor_context != ("D", "K_1")
        or re.fullmatch(r"d\{s=#:a=\d+:vt=nn\}", element.args[0]) is None
        or re.fullmatch(r"c\{s=#:v=-?\d+:si=s\}", element.args[1]) is None
    ):
        raise MiningRequired("operand", "LDDB SFL scalar descriptors are unmined")
    if instruction == "SFL" and not -0x8000 <= int(operands[1][1:]) <= 0x7FFF:
        raise MiningRequired("operand", "LDDB SFL signed A16 constant is out of range")
    for tag, operand_index, raw, following_tag in validation:
        _lddb_validate_mined_scalar_context(
            instruction,
            element.signature,
            tag,
            operand_index,
            raw,
            following_tag,
            descriptor_context,
        )
    return instruction, tuple(operands), cursor


def _lddb_expression(operator: str, *parts: tuple[object, ...]) -> tuple[object, ...]:
    flattened: list[object] = []
    for part in parts:
        if part and part[0] == operator:
            flattened.extend(part[1:])
        else:
            flattened.append(part)
    return (operator, *flattened)


def _lddb_expression_leaves(expression: tuple[object, ...]) -> list[int]:
    if expression[0] == "leaf":
        return [int(expression[1])]
    return [
        leaf
        for part in expression[1:]
        for leaf in _lddb_expression_leaves(part)  # type: ignore[arg-type]
    ]


def _lddb_expression_order(
    expression: tuple[object, ...], elements: list[_LddbDecodedElement]
) -> int:
    leaves = _lddb_expression_leaves(expression)
    if not leaves:
        raise MiningRequired("record", "LDDB branch has no descriptor leaves")
    return min(elements[leaf].order for leaf in leaves)


def _lddb_contact_form(
    element: _LddbDecodedElement, mode: str
) -> tuple[str, tuple[str, ...]]:
    if element.instruction in {"INV", "MEP"}:
        if mode != "and":
            raise MiningRequired("record", "LDDB inline unary branch position is unmined")
        return element.instruction, ()
    mappings = {
        "LD": {"load": "LD", "and": "AND", "or": "OR"},
        "LDI": {"load": "LDI", "and": "ANI", "or": "ORI"},
        "LDP": {"load": "LDP", "and": "ANDP", "or": "ORP"},
        "LDPI": {"load": "LDPI", "and": "ANIP", "or": "ORIP"},
        "LDF": {"load": "LDF", "and": "ANDF", "or": "ORF"},
        "LDFI": {"load": "LDFI", "and": "ANDFI", "or": "ORFI"},
    }
    if element.instruction in mappings:
        return mappings[element.instruction][mode], element.operands
    match = re.fullmatch(r"LD(D?)(=|<>|<|<=|>|>=)", element.instruction)
    if match is not None:
        width, comparator = match.groups()
        prefix = {"load": "LD", "and": "AND", "or": "OR"}[mode]
        instruction = prefix + width + comparator
        if instruction not in _LDDB_OPERAND_COUNTS:
            raise MiningRequired("opcode", "LDDB comparison branch form is unmined")
        return instruction, element.operands
    raise MiningRequired("opcode", "LDDB contact form is unmined")


def _lddb_append_expression(
    expression: tuple[object, ...],
    elements: list[_LddbDecodedElement],
    semantic: list[dict[str, Any]],
    *,
    mode: str,
) -> None:
    operator = expression[0]
    if operator == "leaf":
        instruction, operands = _lddb_contact_form(elements[int(expression[1])], mode)
        semantic.append({"kind": "instruction", "opcode": instruction, "operands": list(operands), "text": None})
        return
    if mode == "and" and operator != "and":
        _lddb_append_expression(expression, elements, semantic, mode="load")
        semantic.append({"kind": "instruction", "opcode": "ANB", "operands": [], "text": None})
        return
    parts = expression[1:]
    if operator == "or":
        parts = tuple(sorted(parts, key=lambda part: _lddb_expression_order(part, elements)))  # type: ignore[arg-type]
    if not parts:
        raise MiningRequired("record", "LDDB graph expression is empty")
    first_mode = mode if operator == "and" and mode == "and" else "load"
    _lddb_append_expression(parts[0], elements, semantic, mode=first_mode)  # type: ignore[arg-type]
    join = "ANB" if operator == "and" else "ORB"
    leaf_mode = "and" if operator == "and" else "or"
    for part in parts[1:]:
        if part[0] == "leaf":  # type: ignore[index]
            _lddb_append_expression(part, elements, semantic, mode=leaf_mode)  # type: ignore[arg-type]
        else:
            _lddb_append_expression(part, elements, semantic, mode="load")  # type: ignore[arg-type]
            semantic.append({"kind": "instruction", "opcode": join, "operands": [], "text": None})


def _decode_lddb(data: str, blocktype: int, expected_count: int) -> list[dict[str, Any]]:
    if blocktype in {1, 2}:
        match = re.fullmatch(
            r"V1:1:(\d+):(.*):st\{st=c\{t=#:st=([is])\}:dim=0x1\}", data
        )
        if (
            match is None
            or expected_count != 1
            or int(match.group(1)) != len(match.group(2))
        ):
            raise MiningRequired("record", "LDDB statement record is unmined")
        return [
            {
                "kind": "statement",
                "opcode": None,
                "operands": [],
                "text": ("*" if match.group(3) == "s" else "") + match.group(2),
            }
        ]
    if blocktype == 5:
        if data != _LDDB_END or expected_count != 1:
            raise MiningRequired("record", "LDDB END record is unmined")
        return [
            {"kind": "instruction", "opcode": "END", "operands": [], "text": None}
        ]
    if blocktype == 3:
        if data != _LDDB_NOP or expected_count != 1:
            raise MiningRequired("record", "LDDB NOP record is unmined")
        return [
            {"kind": "instruction", "opcode": "NOP", "operands": [], "text": None}
        ]
    if blocktype != 0 or ":cb{fg=fg{" not in data:
        raise MiningRequired("record", "LDDB block type or logic grammar is unmined")
    dimension = re.search(r":cb\{fg=fg\{dim=(\d+)x(\d+):es=\[", data)
    if dimension is None:
        raise MiningRequired("record", "LDDB grid dimension is unmined")
    width, height = (int(value) for value in dimension.groups())
    elements, vertical = _lddb_elements(data)
    wires = _lddb_wire_positions(data)
    if width <= 0 or height <= 0 or any(
        element.x < 0 or element.y < 0 or element.x >= width or element.y >= height
        for element in elements
    ):
        raise MiningRequired("record", "LDDB grid element is outside its declared dimension")
    if any(x < 0 or y <= 0 or x > width or y >= height for x, y in vertical):
        raise MiningRequired("record", "LDDB vertical relation is outside its declared dimension")
    if any(x < 0 or y < 0 or x >= width or y >= height for x, y in wires):
        raise MiningRequired("record", "LDDB wire is outside its declared dimension")
    if len({(element.x, element.y) for element in elements}) != len(elements):
        raise MiningRequired("record", "LDDB grid has duplicate element positions")
    descriptors = _lddb_descriptors(data)
    decoded_elements: list[_LddbDecodedElement] = []
    descriptor_cursor = 0
    for order, element in enumerate(elements):
        instruction, operands, descriptor_cursor = _lddb_instruction_from_element(
            element, descriptors, descriptor_cursor
        )
        span = 3 if re.fullmatch(r"LD(?:D)?(?:=|<>|<|<=|>|>=)", instruction) else 1
        if element.x + span > width:
            raise MiningRequired("record", "LDDB grid operation exceeds its declared dimension")
        note = ""
        if element.has_note:
            if (
                descriptor_cursor + 1 >= len(descriptors)
                or not descriptors[descriptor_cursor]
                or descriptors[descriptor_cursor] != descriptors[descriptor_cursor + 1]
            ):
                raise MiningRequired("record", "LDDB inline note descriptor pair is unmined")
            note = descriptors[descriptor_cursor]
            descriptor_cursor += 2
        decoded_elements.append(
            _LddbDecodedElement(
                element.x,
                element.y,
                element.kind,
                instruction,
                operands,
                order,
                span,
                note,
                element.note_subtype,
            )
        )
    if descriptor_cursor != len(descriptors):
        raise MiningRequired("opcode", "LDDB header has unused descriptors")

    parent: dict[tuple[int, int], tuple[int, int]] = {}

    def find(node: tuple[int, int]) -> tuple[int, int]:
        parent.setdefault(node, node)
        if parent[node] != node:
            parent[node] = find(parent[node])
        return parent[node]

    def union(left: tuple[int, int], right: tuple[int, int]) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for y in range(height):
        union((0, 0), (0, y))
    occupied_primary: set[int] = set()
    for element in decoded_elements:
        if element.y == 0:
            occupied_primary.update(range(element.x, element.x + element.span))
    for x in range(width):
        if x not in occupied_primary:
            union((x, 0), (x + 1, 0))
    for x, y in wires:
        union((x, y), (x + 1, y))
    for x, y in vertical:
        union((x, y - 1), (x, y))

    edges: list[list[object]] = []
    commands: dict[tuple[int, int], list[int]] = {}
    for element in decoded_elements:
        left = find((element.x, element.y))
        if element.kind == "ct" or element.instruction in {"INV", "MEP"}:
            right = find((element.x + element.span, element.y))
            if left == right:
                raise MiningRequired("record", "LDDB contact is bypassed by its conductor graph")
            edges.append([left, right, ("leaf", element.order), element.order])
        else:
            commands.setdefault(left, []).append(element.order)
    source = find((0, 0))
    edges = [[find(edge[0]), find(edge[1]), edge[2], edge[3]] for edge in edges]  # type: ignore[arg-type]
    commands = {find(node): orders for node, orders in commands.items()}

    while True:
        parallel: dict[tuple[tuple[int, int], tuple[int, int]], list[tuple[int, list[object]]]] = {}
        for index, edge in enumerate(edges):
            parallel.setdefault((edge[0], edge[1]), []).append((index, edge))  # type: ignore[arg-type]
        group = next((items for items in parallel.values() if len(items) > 1), None)
        if group is not None:
            removed = {index for index, _edge in group}
            parts = sorted(
                (edge for _index, edge in group),
                key=lambda edge: _lddb_expression_order(edge[2], decoded_elements),  # type: ignore[arg-type]
            )
            edges = [edge for index, edge in enumerate(edges) if index not in removed]
            edges.append([
                parts[0][0], parts[0][1],
                _lddb_expression("or", *(part[2] for part in parts)),
                min(int(part[3]) for part in parts),
            ])
            continue
        incoming = Counter(edge[1] for edge in edges)
        outgoing = Counter(edge[0] for edge in edges)
        series_node = next((
            node for node in set(incoming) | set(outgoing)
            if node != source and node not in commands
            and incoming[node] == 1 and outgoing[node] == 1
        ), None)
        if series_node is None:
            break
        before = next(edge for edge in edges if edge[1] == series_node)
        after = next(edge for edge in edges if edge[0] == series_node)
        edges.remove(before)
        edges.remove(after)
        edges.append([
            before[0], after[1], _lddb_expression("and", before[2], after[2]),
            min(int(before[3]), int(after[3])),
        ])
    incoming = Counter(edge[1] for edge in edges)
    if any(count > 1 for count in incoming.values()):
        raise MiningRequired("record", "LDDB contact graph has an irreducible join")
    outgoing_edges: dict[tuple[int, int], list[list[object]]] = {}
    for edge in edges:
        outgoing_edges.setdefault(edge[0], []).append(edge)  # type: ignore[arg-type]

    decoded: list[dict[str, Any]] = []
    used: set[int] = set()
    active: set[tuple[int, int]] = set()

    def append_output_tree(node: tuple[int, int], *, loaded: bool) -> None:
        if node in active:
            raise MiningRequired("record", "LDDB contact graph is cyclic")
        active.add(node)
        command_orders = sorted(commands.get(node, []))
        branches = sorted(
            outgoing_edges.get(node, []),
            key=lambda edge: _lddb_expression_order(edge[2], decoded_elements),  # type: ignore[arg-type]
        )
        if loaded and not command_orders and not branches:
            raise MiningRequired("record", "LDDB contact path has no output command")
        actions: list[tuple[int, str, object]] = [
            (order, "command", order) for order in command_orders
        ] + [
            (_lddb_expression_order(edge[2], decoded_elements), "branch", edge)  # type: ignore[arg-type]
            for edge in branches
        ]
        actions.sort(key=lambda action: action[0])

        def append_branch(edge: list[object]) -> None:
            expression = edge[2]
            _lddb_append_expression(
                expression, decoded_elements, decoded,
                mode="and" if loaded else "load",  # type: ignore[arg-type]
            )
            used.update(_lddb_expression_leaves(expression))  # type: ignore[arg-type]
            append_output_tree(edge[1], loaded=True)  # type: ignore[arg-type]

        cursor = 0
        while cursor < len(actions):
            _order, kind, payload = actions[cursor]
            if kind == "command":
                order = int(payload)
                element = decoded_elements[order]
                decoded.append({"kind": "instruction", "opcode": element.instruction, "operands": list(element.operands), "text": None})
                if element.note:
                    decoded.append(
                        {
                            "kind": "note",
                            "opcode": None,
                            "operands": [],
                            "text": element.note,
                            "note_subtype": element.note_subtype,
                        }
                    )
                used.add(order)
                cursor += 1
                continue
            run_end = cursor
            while run_end < len(actions) and actions[run_end][1] == "branch":
                run_end += 1
            run = [action[2] for action in actions[cursor:run_end]]
            has_later_action = loaded and run_end < len(actions)
            if loaded and (len(run) > 1 or has_later_action):
                decoded.append({"kind": "instruction", "opcode": "MPS", "operands": [], "text": None})
            for index, edge in enumerate(run):
                if loaded and index > 0:
                    final = not has_later_action and index + 1 == len(run)
                    decoded.append({"kind": "instruction", "opcode": "MPP" if final else "MRD", "operands": [], "text": None})
                append_branch(edge)  # type: ignore[arg-type]
            if has_later_action:
                decoded.append({"kind": "instruction", "opcode": "MPP", "operands": [], "text": None})
            cursor = run_end
        active.remove(node)

    append_output_tree(source, loaded=False)
    if used != set(range(len(decoded_elements))):
        raise MiningRequired("record", "LDDB contact graph is disconnected")
    if len(decoded) != expected_count:
        raise MiningRequired("record", "LDDB and StepInfo instruction counts differ")
    return decoded


def decode_records(
    archive: SafeGx3Archive, pou: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    relations = pou["relations"]
    lddb = relations.get("lddb")
    mildb = relations.get("mildb")
    stepdb = relations.get("step_info")
    if not lddb or not stepdb:
        digest = hashlib.sha256(pou["pou_id"].encode()).hexdigest()
        return (
            [],
            [
                _finding(
                    "topology",
                    f"pou:{pou['pou_id']}",
                    "POU relations",
                    digest,
                    "POU database relation is unresolved",
                )
            ],
            {"total": 0, "decoded": 0, "partial": 0, "unknown": 0},
        )
    ladder = _connection(archive, lddb)
    mil: sqlite3.Connection | None = None
    step = _connection(archive, stepdb)
    try:
        if not {"id", "pos", "blocktype", "data"}.issubset(
            _columns(ladder, "LadderBlocks")
        ):
            raise MiningRequired("record", "LadderBlocks schema is unmined")
        if mildb:
            mil = _connection(archive, mildb)
            if not {"id", "pos", "data"}.issubset(_columns(mil, "MIL")):
                raise MiningRequired("record", "MIL schema is unmined")
        else:
            paired_mildb = lddb[:-8] + "_MilDB.db"
            if paired_mildb not in archive.entries:
                raise MiningRequired("topology", "same-stem empty MilDB cache is absent")
            mil = _connection(archive, paired_mildb)
            if (
                not {"id", "pos", "data"}.issubset(_columns(mil, "MIL"))
                or mil.execute("SELECT COUNT(*) FROM MIL").fetchone() != (0,)
            ):
                raise MiningRequired("topology", "same-stem MilDB is not an exact empty cache")
        if not {"Pos", "BlockID", "MilID"}.issubset(_columns(step, "T_Step")):
            raise MiningRequired("record", "StepInfo schema is unmined")
        ladder_rows = list(
            ladder.execute(
                "SELECT id,pos,blocktype,data FROM LadderBlocks ORDER BY pos,id"
            )
        )
        mil_rows = (
            list(mil.execute("SELECT id,pos,data FROM MIL ORDER BY pos,id"))
            if mildb
            else []
        )
        step_size = "StepSize" in _columns(step, "T_Step")
        step_query = (
            "SELECT Pos,BlockID,MilID,StepSize FROM T_Step ORDER BY Pos,BlockID,MilID"
            if step_size
            else "SELECT Pos,BlockID,MilID FROM T_Step ORDER BY Pos,BlockID,MilID"
        )
        step_rows = list(step.execute(step_query))
    except (MiningRequired, sqlite3.DatabaseError) as error:
        reason = (
            error.reason
            if isinstance(error, MiningRequired)
            else "SQLite record schema or query is unmined"
        )
        digest = hashlib.sha256(
            "\n".join(filter(None, (lddb, mildb, stepdb))).encode()
        ).hexdigest()
        return (
            [],
            [
                _finding(
                    "record",
                    f"pou:{pou['pou_id']}",
                    "LadderBlocks/MIL/T_Step",
                    digest,
                    reason,
                )
            ],
            {"total": 0, "decoded": 0, "partial": 0, "unknown": 0},
        )
    finally:
        ladder.close()
        if mil is not None:
            mil.close()
        step.close()
    label_names, label_duplicates, label_error = _local_label_names(archive)
    mil_by_id = {
        _block_id(row[0]): (float(row[1]), row[2])
        for row in mil_rows
        if _block_id(row[0]) is not None
        and isinstance(row[1], (int, float))
        and isinstance(row[2], str)
    }
    steps_by_id: dict[str, list[tuple[Any, ...]]] = {}
    for row in step_rows:
        block = _block_id(row[1])
        if block:
            steps_by_id.setdefault(block, []).append(row)
    records: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    decoded_count = unknown_count = 0
    source_step = 0
    for raw_id, position, blocktype, ladder_data in ladder_rows:
        block = _block_id(raw_id)
        block_steps = steps_by_id.get(block or "", [])
        mil_row = mil_by_id.get(block or "")
        source_text = (
            mil_row[1]
            if mil_row is not None
            else ladder_data
            if isinstance(ladder_data, str)
            else repr(ladder_data)
        )
        digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        locator = (
            f'MIL[id="{block or "invalid"}"]'
            if mildb
            else f'LadderBlocks[id="{block or "invalid"}"]'
        )
        provenance = _provenance(
            mildb or lddb,
            "MIL" if mildb else "LadderBlocks",
            locator,
            digest,
            [
                *(
                    ["MIL.id = LadderBlocks.id"]
                    if mildb
                    else ["same-stem MilDB.MIL row count = 0"]
                ),
                "T_Step.BlockID = LadderBlocks.id",
            ],
        )
        try:
            if (
                block is None
                or not isinstance(position, (int, float))
                or not isinstance(blocktype, int)
                or not isinstance(ladder_data, str)
            ):
                raise MiningRequired("record", "unsupported LadderBlocks row type")
            if mildb:
                if mil_row is None or mil_row[0] != float(position):
                    raise MiningRequired(
                        "record",
                        "MIL and LadderBlocks relation is missing or position differs",
                    )
                decoded = _decode_mil(mil_row[1], len(block_steps))
            else:
                decoded = _decode_lddb(ladder_data, blocktype, len(block_steps))
            for local_index, item in enumerate(decoded):
                base_id = f"{block}:{local_index}"
                tokens = item["operands"]
                item_provenance = provenance
                if item["kind"] == "note":
                    subtype = item.get("note_subtype")
                    if subtype not in {"i", "s"}:
                        raise MiningRequired("record", "LDDB inline note subtype is unmined")
                    item_provenance = {
                        **provenance,
                        "relation_evidence": [
                            *provenance["relation_evidence"],
                            f"lddb_inline_note_st={subtype}",
                        ],
                    }
                records.append(
                    {
                        "record_id": base_id,
                        "sequence": len(records),
                        "kind": item["kind"],
                        "step": source_step,
                        "opcode": item["opcode"],
                        "operands": [
                            _operand(
                                tokens[0],
                                0,
                                item_provenance,
                                label_names,
                                label_duplicates,
                                label_error,
                            )
                        ]
                        if tokens
                        else [],
                        "text": item["text"],
                        "provenance": item_provenance,
                        "status": "decoded",
                        "continues_record_id": None,
                    }
                )
                decoded_count += 1
                for operand_index, token in enumerate(tokens[1:], 1):
                    records.append(
                        {
                            "record_id": f"{base_id}:operand:{operand_index}",
                            "sequence": len(records),
                            "kind": "continuation",
                            "step": source_step,
                            "opcode": None,
                            "operands": [
                                _operand(
                                    token,
                                    operand_index,
                                    provenance,
                                    label_names,
                                    label_duplicates,
                                    label_error,
                                )
                            ],
                            "text": None,
                            "provenance": provenance,
                            "status": "decoded",
                            "continues_record_id": base_id,
                        }
                    )
                    decoded_count += 1
                if local_index < len(block_steps):
                    source_step += (
                        block_steps[local_index][3]
                        if step_size and isinstance(block_steps[local_index][3], int)
                        else 0
                    )
        except MiningRequired as error:
            count = max(1, len(block_steps))
            for local_index in range(count):
                records.append(
                    {
                        "record_id": f"{block or 'invalid'}:opaque:{local_index}",
                        "sequence": len(records),
                        "kind": "opaque",
                        "step": source_step,
                        "opcode": None,
                        "operands": [],
                        "text": None,
                        "provenance": provenance,
                        "status": "unknown",
                        "continues_record_id": None,
                    }
                )
                unknown_count += 1
                if local_index < len(block_steps):
                    source_step += (
                        block_steps[local_index][3]
                        if step_size and isinstance(block_steps[local_index][3], int)
                        else 0
                    )
            findings.append(
                _finding(
                    error.object_kind,
                    f"pou:{pou['pou_id']}",
                    locator,
                    digest,
                    error.reason,
                )
            )
    return (
        records,
        findings,
        {
            "total": len(records),
            "decoded": decoded_count,
            "partial": 0,
            "unknown": unknown_count,
        },
    )


def _device_id(row: tuple[Any, ...]) -> str | None:
    _seq, code, ext_code, ext_no, _is_local, high, low, bit = row
    if (
        not all(isinstance(value, int) for value in row)
        or high != 0
        or low < 0
        or bit < 0
    ):
        return None
    if bit > 16:
        return None
    if code == 35:
        if ext_code != 208 or ext_no <= 0:
            return None
        address = f"U{ext_no}\\G{low}"
        return address if bit == 0 else f"{address}.{bit - 1:X}"
    if ext_code != 0 or ext_no != 0:
        return None
    decimal_prefixes = {
        1: "M",
        2: "SM",
        3: "L",
        32: "D",
        33: "SD",
        39: "R",
        66: "T",
        74: "ST",
        101: "S",
    }
    octal_prefixes = {16: "X", 17: "Y"}
    if code in decimal_prefixes:
        address = f"{decimal_prefixes[code]}{low}"
    elif code in octal_prefixes:
        address = f"{octal_prefixes[code]}{low:o}"
    elif code == 20:
        number = f"{low:X}"
        address = "B" + (f"0{number}" if number[0] in "ABCDEF" else number)
    else:
        return None
    if bit == 0:
        return address
    if code not in {32, 33}:
        return None
    return f"{address}.{bit - 1:X}"


def _opaque_device_id(row: tuple[Any, ...]) -> str:
    """Return a stable non-semantic identity without guessing a device type."""
    payload = json.dumps(row[1:], ensure_ascii=False, separators=(",", ":"))
    return f"UNRESOLVED_DEVICE_{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def decode_comments(
    archive: SafeGx3Archive,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    names = sorted(
        name for name in archive.entries if re.fullmatch(r"[^/]+_DC\.db", name)
    )
    output: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    counts = Counter()
    for name in names:
        connection = _connection(archive, name)
        try:
            devices = {
                row[0]: row
                for row in connection.execute(
                    "SELECT SEQ,DevCode,ExtCode,ExtNo,IsLocal,DevNoHigh,DevNoLow,BitNo FROM DEVICE_DATA ORDER BY SEQ"
                )
            }
            comments = list(
                connection.execute(
                    "SELECT SEQ,DeviceSEQ,CmtNo,CmtData,DelFlag FROM COMMENT_DATA ORDER BY SEQ"
                )
            )
        except sqlite3.DatabaseError:
            findings.append(
                _finding(
                    "comment",
                    "project",
                    f"{name}:DEVICE_DATA/COMMENT_DATA",
                    archive.digest(name),
                    "device-comment schema or query is unmined",
                )
            )
            continue
        finally:
            connection.close()
        entry_digest = archive.digest(name)
        unknown_keys: list[str] = []
        for seq, device_seq, cmt_no, value, deleted in comments:
            counts["total"] += 1
            device_row = devices.get(device_seq)
            device = _device_id(device_row) if device_row else None
            if (
                device_row is None
                or not isinstance(cmt_no, int)
                or (deleted is None and not isinstance(value, str))
            ):
                counts["unknown"] += 1
                unknown_keys.append(str(seq))
                continue
            unresolved_device = device is None
            if unresolved_device:
                device = _opaque_device_id(device_row)
            is_local = bool(device_row[4])
            state = (
                "OBJECT_ABSENT"
                if deleted is not None
                else ("EMPTY_STRING" if value == "" else "VALUE_PRESENT")
            )
            stored_value = None if deleted is not None else value
            partial = cmt_no != 6 or is_local
            if unresolved_device:
                counts["unknown"] += 1
                unknown_keys.append(str(seq))
            else:
                counts["partial" if partial else "decoded"] += 1
            output.append(
                {
                    "scope": "program_device" if is_local else "common_device",
                    "program_id": None,
                    "device_id": device,
                    "language_slot": "English" if cmt_no == 6 else f"CmtNo:{cmt_no}",
                    "value_state": state,
                    "value": stored_value,
                    "provenance": _provenance(
                        name,
                        "COMMENT_DATA",
                        (
                            f"SEQ={seq};DeviceSEQ={device_seq};"
                            f"DEVICE_DATA={json.dumps(device_row[1:], ensure_ascii=False, separators=(',', ':'))}"
                        ),
                        entry_digest,
                        ["COMMENT_DATA.DeviceSEQ = DEVICE_DATA.SEQ"],
                    ),
                }
            )
        if unknown_keys:
            digest = hashlib.sha256("\n".join(unknown_keys).encode()).hexdigest()
            findings.append(
                _finding(
                    "comment",
                    "project",
                    f"{name}:unknown-comment-keys",
                    digest,
                    f"{len(unknown_keys)} comment rows have an unmined device or storage state",
                )
            )
    return (
        output,
        findings,
        {key: counts[key] for key in ("total", "decoded", "partial", "unknown")},
    )


def decode_labels(
    archive: SafeGx3Archive,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    if "LabelData.db" not in archive.entries:
        return [], [], {"total": 0, "decoded": 0, "partial": 0, "unknown": 0}
    connection = _connection(archive, "LabelData.db")
    try:
        types = dict(connection.execute("SELECT LabelID,LabelTypeID FROM LabelTbl"))
        rows = list(
            connection.execute(
                "SELECT LabelID,RowID,ColumnID,ColumnStrValue,ColumnIntValue FROM ColumnDataTbl ORDER BY LabelID,RowID,ColumnID"
            )
        )
    except sqlite3.DatabaseError:
        digest = archive.digest("LabelData.db")
        return (
            [],
            [
                _finding(
                    "label",
                    "project",
                    "LabelData.db:LabelTbl/ColumnDataTbl",
                    digest,
                    "label schema or query is unmined",
                )
            ],
            {"total": 0, "decoded": 0, "partial": 0, "unknown": 0},
        )
    finally:
        connection.close()
    cells = {(row[0], row[1], row[2]): row for row in rows}
    name_counts = Counter((row[0], row[1]) for row in rows if row[2] == 2)
    keys = sorted(
        {(row[0], row[1]) for row in rows if types.get(row[0]) in {5121, 5122}}
    )
    output: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    digest = archive.digest("LabelData.db")
    decoded = partial = unknown = 0
    for label_id, row_id in keys:
        name_cell = cells.get((label_id, row_id, 2))
        comment_cell = cells.get((label_id, row_id, 15))
        if name_counts[(label_id, row_id)] > 1:
            unknown += 1
            findings.append(
                _finding(
                    "label",
                    "project",
                    f"ColumnDataTbl[{label_id},{row_id},2]",
                    digest,
                    "label name cell is not unique",
                )
            )
            continue
        if name_cell is None or not isinstance(name_cell[3], str) or not name_cell[3]:
            unknown += 1
            findings.append(
                _finding(
                    "label",
                    "project",
                    f"ColumnDataTbl[{label_id},{row_id}]",
                    digest,
                    "label name cell is absent or unmined",
                )
            )
            continue
        local = types[label_id] == 5121
        if comment_cell is None:
            state, value = "SLOT_ABSENT", None
        elif not isinstance(comment_cell[3], str):
            unknown += 1
            findings.append(
                _finding(
                    "label",
                    "project",
                    f"ColumnDataTbl[{label_id},{row_id},15]",
                    digest,
                    "label English cell storage type is unmined",
                )
            )
            continue
        else:
            state, value = (
                ("EMPTY_STRING", "")
                if comment_cell[3] == ""
                else ("VALUE_PRESENT", comment_cell[3])
            )
        partial += int(local)
        decoded += int(not local)
        output.append(
            {
                "scope": "local_label" if local else "global_label",
                "program_id": None,
                "label_id": name_cell[3],
                "language_slot": "English",
                "value_state": state,
                "value": value,
                "provenance": _provenance(
                    "LabelData.db",
                    "ColumnDataTbl",
                    f"LabelID={label_id};RowID={row_id};ColumnID=2,15",
                    digest,
                    [
                        "LabelTbl.LabelID = ColumnDataTbl.LabelID",
                        "ColumnID 2=name",
                        "ColumnID 15=English",
                    ],
                ),
            }
        )
        if local:
            findings.append(
                _finding(
                    "label",
                    "project",
                    f"LabelID={label_id};RowID={row_id}",
                    digest,
                    "local label program-to-POU relation is not decoded",
                )
            )
    return (
        output,
        findings,
        {
            "total": len(keys),
            "decoded": decoded,
            "partial": partial,
            "unknown": unknown,
        },
    )


def bind_local_label_programs(
    labels: list[dict[str, Any]],
    findings: list[dict[str, str]],
    coverage: dict[str, int],
    pous: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    observed: dict[str, set[str]] = {}
    for pou in pous:
        pou_id = pou["pou_id"]
        for record in pou["records"]:
            for operand in record["operands"]:
                raw = operand.get("raw_token")
                if not isinstance(raw, str):
                    continue
                match = _LOCAL_LABEL_TOKEN.fullmatch(raw)
                if match is None:
                    continue
                observed.setdefault(match.group(1), set()).add(pou_id)
    bound_keys: set[tuple[str, str]] = set()
    for item in labels:
        if item.get("scope") != "local_label":
            continue
        parsed = _LOCAL_LABEL_LOCATOR.fullmatch(
            item["provenance"]["source_locator"]
        )
        if parsed is None:
            continue
        label_id, row_id = parsed.group(1), parsed.group(2)
        owners = observed.get(label_id, set())
        if len(owners) != 1:
            continue
        item["program_id"] = next(iter(owners))
        bound_keys.add((label_id, row_id))
        coverage["partial"] -= 1
        coverage["decoded"] += 1
    remaining: list[dict[str, str]] = []
    for finding in findings:
        parsed = _LOCAL_LABEL_LOCATOR.fullmatch(finding.get("locator", ""))
        if (
            finding.get("object_kind") == "label"
            and finding.get("reason")
            == "local label program-to-POU relation is not decoded"
            and parsed is not None
            and (parsed.group(1), parsed.group(2)) in bound_keys
        ):
            continue
        remaining.append(finding)
    return labels, remaining, coverage


def devmap(pous: list[dict[str, Any]]) -> list[dict[str, Any]]:
    writes = {"OUT", "SET", "RST", "PLS"}
    rows: dict[str, dict[str, set[str]]] = {}
    for pou in pous:
        for record in pou["records"]:
            for operand in record["operands"]:
                if operand["kind"] != "device":
                    continue
                row = rows.setdefault(
                    operand["raw_token"],
                    {"read_pous": set(), "write_pous": set(), "unknown_pous": set()},
                )
                opcode = record["opcode"] or ""
                target = (
                    "write_pous"
                    if opcode in writes
                    else (
                        "read_pous"
                        if opcode.startswith(("LD", "AND", "OR"))
                        else "unknown_pous"
                    )
                )
                row[target].add(pou["pou_id"])
    return [
        {"device_id": device, **{key: sorted(value) for key, value in groups.items()}}
        for device, groups in sorted(rows.items())
    ]
