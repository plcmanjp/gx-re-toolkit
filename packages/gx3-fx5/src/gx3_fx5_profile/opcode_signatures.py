"""Fail-closed FX5U MIL opcode signatures approved from BULK-ALL.

The runtime table is a frozen signature-to-mnemonic map. It does not read a
corpus path or hash. Provenance constants record the source GX3 and official
export SHA-256 values used to approve the table.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_NAME = "plcman.gx3.phase2-opcode-oracle"
SCHEMA_VERSION = 1
SOURCE_GX3_SHA256 = "9e32b9bb3595c06c1074180ce1c4bfd22fef5a6fe939aca161e46f032d561234"
SOURCE_REBUILD_EXPORT_SHA256 = (
    "4cc07ca8afcef19a6eeeab8faae69fcf3a3370c7732a21fb619aba2f0f52dea0"
)
SOURCE_REOPEN_EXPORT_SHA256 = SOURCE_REBUILD_EXPORT_SHA256
OFFICIAL_INSTRUCTION_COUNT = 2412

_OPERAND_TAGS = frozenset(
    {
        "B",
        "BLs",
        "C",
        "CC",
        "CN",
        "D",
        "DT",
        "Dots",
        "DX",
        "DY",
        "E",
        "ED",
        "F",
        "FD",
        "G",
        "H",
        "H_1",
        "H_2",
        "I",
        "J",
        "Jn",
        "K",
        "K_1",
        "K_2",
        "K_4",
        "Ks",
        "L",
        "LC",
        "LZ",
        "M",
        "P",
        "R",
        "RD",
        "S",
        "SD",
        "SDT",
        "SM",
        "ST",
        "STC",
        "SW",
        "SfcS",
        "String",
        "T",
        "TM",
        "U",
        "UD",
        "UDT",
        "Un",
        "Us",
        "W",
        "X",
        "Y",
        "Z",
        "Zs",
        "u0",
        '"u0"',
    }
)

# Width rules below follow decoder.py _format_operand / _decode_mil. A and B are
# both instruction markers and device tags; operand width must come from the
# record payload, not from greedily consuming every operand-like token.
_SCALAR_TAGS = frozenset(
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
_NOTE_FLAGS = frozenset({"i", "s"})
_COMPOUND_SUFFIXES = frozenset({"BLs", "Dots", "Ks", "Zs"})
_REMOTE_PREFIXES = frozenset({"U", "Un", "Us"})


class UnknownOpcodeSignature(KeyError):
    """Raised when a record signature is absent from the approved table."""


class OpcodeSignature(tuple):
    """Exact MIL instruction signature used as the runtime mapping key."""

    __slots__ = ()

    def __new__(
        cls,
        form: str,
        header_marker: str,
        logic_type: str,
        pulse: bool,
        operand_vts: tuple[str, ...],
        operand_kinds: tuple[str, ...],
        header_operand_tags: tuple[str, ...],
        inner_op: str,
    ) -> "OpcodeSignature":
        return super().__new__(
            cls,
            (
                form,
                header_marker,
                logic_type,
                bool(pulse),
                tuple(operand_vts),
                tuple(operand_kinds),
                tuple(header_operand_tags),
                inner_op,
            ),
        )

    @property
    def form(self) -> str:
        return self[0]

    @property
    def header_marker(self) -> str:
        return self[1]

    @property
    def logic_type(self) -> str:
        return self[2]

    @property
    def pulse(self) -> bool:
        return self[3]

    @property
    def operand_vts(self) -> tuple[str, ...]:
        return self[4]

    @property
    def operand_kinds(self) -> tuple[str, ...]:
        return self[5]

    @property
    def header_operand_tags(self) -> tuple[str, ...]:
        return self[6]

    @property
    def inner_op(self) -> str:
        return self[7]

    def as_dict(self) -> dict[str, Any]:
        return {
            "form": self.form,
            "header_marker": self.header_marker,
            "header_operand_tags": list(self.header_operand_tags),
            "inner_op": self.inner_op,
            "logic_type": self.logic_type,
            "operand_kinds": list(self.operand_kinds),
            "operand_vts": list(self.operand_vts),
            "pulse": self.pulse,
        }


def canonical_signature_key(signature: OpcodeSignature) -> str:
    return json.dumps(
        signature.as_dict(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def semantic_signature(signature: OpcodeSignature) -> OpcodeSignature:
    """Separate opcode identity from source-specific operand representation.

    ``inner_op`` retains the operation, arity, value types and execution
    contract. Header operand tags, decoded value-type copies and storage kinds
    describe the concrete operands in one archive; the decoder still consumes
    them when rendering operand values, but they must not create a new opcode.
    """
    return OpcodeSignature(
        signature.form,
        signature.header_marker,
        signature.logic_type,
        signature.pulse,
        (),
        (),
        (),
        signature.inner_op,
    )


_BASE_LOGIC_MNEMONICS = {
    ("A", "l"): "LD",
    ("B", "l"): "LDI",
    ("A", "a"): "AND",
    ("B", "a"): "ANI",
    ("A", "o"): "OR",
    ("B", "o"): "ORI",
}
_ZERO_OPERAND_CONTACTS = frozenset({"ANB", "INV", "MPS", "MRD", "MPP", "ORB"})
_ZERO_OPERAND_COILS = frozenset({"GOEND", "NEXT"})
_DIRECT_COIL_ARITIES = {
    "DECO": frozenset({3}),
    "FOR": frozenset({1}),
    "HEXA": frozenset({3}),
    "IVCK": frozenset({5}),
    "IVDR": frozenset({5}),
    "RS2": frozenset({5}),
    "RST": frozenset({1, 2}),
    "OUTH": frozenset({2}),
}


def structural_mnemonic(signature: OpcodeSignature) -> str:
    """Decode catalog-backed MIL forms that are independent of operand values.

    These forms are corroborated by the installed GX Works3 FX5U instruction
    catalog's FooterMilCode and by the field corpus. Target-CPU support remains
    a downstream decision; recognizing IVCK/IVDR/RS2 here does not approve a Q
    implementation.
    """
    if signature.form == "logic" and not signature.pulse:
        expected = (
            "op=lct{op=#:lt="
            + signature.logic_type
            + ":ct=a:as=[as{vt=Abl}]}"
        )
        mnemonic = _BASE_LOGIC_MNEMONICS.get(
            (signature.header_marker, signature.logic_type)
        )
        if mnemonic is not None and signature.inner_op == expected:
            return mnemonic
    if (
        signature.form == "contact"
        and not signature.pulse
        and not signature.operand_vts
        and signature.header_marker in _ZERO_OPERAND_CONTACTS
        and signature.inner_op == "op=sct{op=#:ct=a}"
    ):
        return signature.header_marker
    if (
        signature.form == "contact"
        and not signature.operand_vts
        and signature.header_marker == "ME"
        and signature.inner_op
        == ("op=sct{op=#:ct=p}" if signature.pulse else "op=sct{op=#:ct=f}")
    ):
        return "MEP" if signature.pulse else "MEF"
    if (
        signature.form == "coil"
        and not signature.pulse
        and not signature.operand_vts
        and signature.header_marker in _ZERO_OPERAND_COILS
        and signature.inner_op == "op=cl{op=#:ct=a}"
    ):
        return signature.header_marker
    if (
        signature.form == "coil"
        and not signature.pulse
        and len(signature.operand_vts)
        in _DIRECT_COIL_ARITIES.get(signature.header_marker, frozenset())
        and signature.inner_op
        == "op=cl{op=#:ct=a:as=["
        + ":".join(f"as{{vt={value_type}}}" for value_type in signature.operand_vts)
        + "]}"
    ):
        return signature.header_marker
    if (
        signature.form == "coil"
        and not signature.pulse
        and signature.header_marker == "OUT"
        and signature.inner_op
        == "op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=A16}]}"
    ):
        return "OUT"
    if (
        signature.form == "coil"
        and signature.pulse
        and signature.header_marker == "S_ECPRTCL"
        and signature.inner_op
        == "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}"
    ):
        return "SP.ECPRTCL"
    exact_socket_forms = {
        (
            "SP_SOCOPEN",
            ("Ass", "A16", "A16a", "Aba"),
            ("c", "c", "d", "M"),
            ("String", "U0", '"U0"', "K_1", "D", "D", "Dots"),
        ): "SP.SOCOPEN",
        (
            "SP_SOCCLOSE",
            ("Ass", "A16", "A16a", "Aba"),
            ("c", "c", "d", "M"),
            ("String", "U0", '"U0"', "K_1", "D", "D", "Dots"),
        ): "SP.SOCCLOSE",
        (
            "SP_SOCSND",
            ("Ass", "A16", "A16a", "A16", "Aba"),
            ("c", "c", "d", "d", "M"),
            ("String", "U0", '"U0"', "K_1", "D", "D", "D", "Dots"),
        ): "SP.SOCSND",
    }
    if signature.form == "coil" and signature.pulse:
        socket = exact_socket_forms.get(
            (
                signature.header_marker,
                signature.operand_vts,
                signature.operand_kinds,
                signature.header_operand_tags,
            )
        )
        expected_inner = (
            "op=cl{op=#:ct=p:as=["
            + ":".join(f"as{{vt={value_type}}}" for value_type in signature.operand_vts)
            + "]}"
        )
        if socket is not None and signature.inner_op == expected_inner:
            return socket
    tags = signature.header_operand_tags
    if (
        signature.form == "coil" and signature.header_marker == "AddOpe"
        and not signature.pulse and signature.operand_vts == ("Ass", "Ass")
        and signature.operand_kinds == ("c", "d") and len(tags) == 4
        and tags[0] == "String" and tags[3] == "D"
        and re.fullmatch(r"[A-Za-z0-9_\-,$]+", tags[1])
        and tags[2] == f'"{tags[1]}"'
        and signature.inner_op == "op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}"
    ):
        return "$+"
    raise UnknownOpcodeSignature(canonical_signature_key(signature))


def signature_from_mapping(payload: Mapping[str, Any]) -> OpcodeSignature:
    return OpcodeSignature(
        str(payload["form"]),
        str(payload["header_marker"]),
        str(payload.get("logic_type", "")),
        bool(payload.get("pulse", False)),
        tuple(str(item) for item in payload.get("operand_vts", ())),
        tuple(str(item) for item in payload.get("operand_kinds", ())),
        tuple(str(item) for item in payload.get("header_operand_tags", ())),
        str(payload.get("inner_op", "")),
    )


def signature_from_key(key: str) -> OpcodeSignature:
    payload = json.loads(key)
    if not isinstance(payload, dict):
        raise UnknownOpcodeSignature(key)
    return signature_from_mapping(payload)


def _balanced_from(text: str, start: int) -> tuple[str, int]:
    brace = text.find("{", start)
    if brace < 0:
        raise ValueError("serialized MIL token has no opening brace")
    depth = 0
    cursor = brace
    while cursor < len(text):
        char = text[cursor]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : cursor + 1], cursor + 1
        cursor += 1
    raise ValueError("unbalanced serialized MIL token")


def _ms_items(data: str) -> list[str]:
    marker = ":ms{el=["
    start = data.find(marker)
    if start < 0:
        return []
    index = start + len(marker)
    depth = 1
    cursor = index
    while cursor < len(data):
        char = data[cursor]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                body = data[index:cursor]
                break
        cursor += 1
    else:
        raise ValueError("unbalanced MIL ms{el list")
    items: list[str] = []
    offset = 0
    while offset < len(body):
        if body[offset] in ": ":
            offset += 1
            continue
        if body.startswith("mc{", offset) or body.startswith("ma{", offset):
            item, offset = _balanced_from(body, offset)
            items.append(item)
            continue
        raise ValueError("unmined MIL ms{el item")
    return items


def header_tokens(data: str) -> list[str]:
    tokens = data.split(":ms{el=", 1)[0].split(":")
    first = next(
        (
            index
            for index, token in enumerate(tokens[1:], 1)
            if not token.isdigit()
        ),
        len(tokens),
    )
    descriptors = tokens[first:]
    # GX Works3 stores an inline Note text directly in the colon-delimited
    # header.  A Note beginning with whitespace may therefore contain a colon
    # of its own (for example `` Step Jump: 0``).  Preserve that colon as text
    # only when the resulting descriptor is closed by the exact Note flag.
    # Other non-whitespace colon forms remain separate descriptors and are
    # consequently rejected by the normal fail-closed consumers.
    normalized: list[str] = []
    cursor = 0
    while cursor < len(descriptors):
        token = descriptors[cursor]
        if token.startswith(" "):
            flag = cursor + 1
            while flag < len(descriptors) and descriptors[flag] not in _NOTE_FLAGS:
                flag += 1
            if flag < len(descriptors):
                normalized.append(":".join(descriptors[cursor:flag]))
                normalized.append(descriptors[flag])
                cursor = flag + 1
                continue
        normalized.append(token)
        cursor += 1
    return normalized


def is_operand_header_tag(token: str) -> bool:
    return (
        token in _OPERAND_TAGS
        or token.isdigit()
        or token.startswith(("K_", "H_"))
        or _quoted_token(token)
    )


def _strip_numbers(text: str) -> str:
    return re.sub(r"(=)(-?\d+)", r"\1#", text)


def _inner_op(record: str) -> str:
    match = re.search(r"op=(lct|sct|cl)\{", record)
    if match is None:
        return ""
    blob, _end = _balanced_from(record, match.start())
    return _strip_numbers(blob)


def _operand_vts(record: str) -> tuple[str, ...]:
    return tuple(re.findall(r"as\{vt=([^}:]+)\}", record))


def _bracket_list(text: str, start: int) -> tuple[str, int]:
    if start >= len(text) or text[start] != "[":
        raise ValueError("serialized MIL list has no opening bracket")
    depth = 0
    cursor = start
    while cursor < len(text):
        char = text[cursor]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[start : cursor + 1], cursor + 1
        cursor += 1
    raise ValueError("unbalanced serialized MIL list")


def _as_items(blob: str) -> list[str]:
    values = blob[1:-1]
    items: list[str] = []
    cursor = 0
    while cursor < len(values):
        if values[cursor] in ": ":
            cursor += 1
            continue
        item, cursor = _balanced_from(values, cursor)
        items.append(item)
    return items


def _operand_kinds(record: str) -> tuple[str, ...]:
    return tuple(item.split("{", 1)[0] for item in _operand_payloads(record))


def _operand_payloads(record: str) -> list[str]:
    offset = 0
    lists: list[list[str]] = []
    while True:
        start = record.find(":as=[", offset)
        if start < 0:
            break
        blob, _end = _bracket_list(record, start + 4)
        lists.append(_as_items(blob))
        offset = start + 1
    for items in reversed(lists):
        payloads = [item for item in items if not item.startswith("as{")]
        if payloads:
            return payloads
    return []


def _classify_operand_item(item: str) -> tuple[str, tuple[int, ...]]:
    numbers = tuple(int(value) for value in re.findall(r"(?:a|v)=(-?\d+)", item))
    if item.startswith("M{"):
        return ("remote_bit" if "B{b=" in item else "k_device", numbers)
    if item.startswith("B{"):
        return ("remote_word", numbers)
    if item == "c{s=#:v=#:t=#}":
        return ("string_literal", ())
    if item.startswith(("d{", "c{")) and len(numbers) == 1:
        return ("scalar", numbers)
    return ("unknown", numbers)


def _quoted_token(token: str) -> bool:
    return len(token) >= 2 and token[0] == '"' and token[-1] == '"'


def _decoder_operand_width(tags: Sequence[str], item: str) -> int | None:
    if not tags:
        return None
    shape, numbers = _classify_operand_item(item)
    prefix2 = [tags[0], tags[1]] if len(tags) > 1 else []
    prefix3 = [tags[0], tags[1], tags[2]] if len(tags) > 2 else []
    if shape == "string_literal" and not numbers and len(prefix3) == 3:
        bare, quoted = prefix3[1:3]
        if (
            prefix3[0] == "String"
            and re.fullmatch(r"[A-Za-z0-9_\-,$]+", bare)
            and quoted == f'"{bare}"'
        ):
            return 3
    if shape == "remote_bit" and prefix3 == ["Us", "G", "Zs"] and len(numbers) == 3:
        return 3
    if shape == "remote_bit" and prefix3 == ["Us", "G", "Dots"] and len(numbers) == 3:
        return 3
    if shape == "remote_word" and prefix2 == ["Us", "G"] and len(numbers) == 2:
        return 2
    if (
        shape == "k_device"
        and prefix2 in (["M", "Zs"], ["D", "Zs"], ["R", "Zs"])
        and len(numbers) == 2
    ):
        return 2
    if shape == "k_device" and prefix2 == ["B", "Zs"] and len(numbers) == 2:
        return 2
    if shape == "k_device" and prefix3 == ["M", "Zs", "Ks"] and len(numbers) == 3:
        return 3
    if (
        shape == "k_device"
        and prefix2 in (["B", "Ks"], ["L", "Ks"], ["M", "Ks"])
        and len(numbers) == 2
    ):
        return 2
    if (
        shape == "k_device"
        and prefix2 in (["D", "Dots"], ["SD", "Dots"])
        and len(numbers) == 2
    ):
        return 2
    if shape == "scalar" and tags[0] in _SCALAR_TAGS and len(numbers) == 1:
        return 1
    return None


def _source_authorized_operand_width(
    marker: str, tags: Sequence[str], item: str
) -> int | None:
    """Return only descriptor widths proven by an exact source tuple."""
    if (
        marker in {"SP_SOCOPEN", "SP_SOCCLOSE", "SP_SOCRCV", "SP_SOCSND"}
        and list(tags[:3]) == ["String", "U0", '"U0"']
        and item == "c{s=#:v=#:t=#}"
    ):
        return 3
    if (
        marker == "FOR"
        and list(tags[:2]) == ["K_1", "32"]
        and item == "c{s=#:v=32:t=#:si=s}"
    ):
        return 2
    expanded_decimal = re.fullmatch(r"c\{s=#:v=(-?\d+):t=#:si=s\}", item)
    if (
        marker == "MOV"
        and expanded_decimal is not None
        and list(tags[:2]) == ["K_1", expanded_decimal.group(1)]
    ):
        return 2
    if (
        marker in {"NE", "MOV", "BMOV"}
        and re.fullmatch(r"d\{s=#:a=-?\d+:vt=nn\}", item) is not None
        and list(tags[:2]) == ["SD", "D"]
    ):
        # Descriptor width only.  decoder.py verifies the complete raw
        # instruction shape, signature, and source scalar before rendering.
        return 1
    return None


def _generic_operand_width(tags: Sequence[str]) -> int:
    if not tags:
        raise ValueError("MIL header has fewer descriptors than records")
    if tags[0] == "String":
        width = 1
        while width < len(tags) and width < 3 and (
            tags[width] == "u0" or _quoted_token(tags[width])
        ):
            width += 1
        return width
    if tags[0] in _REMOTE_PREFIXES and len(tags) > 1 and tags[1] == "G":
        if len(tags) > 2 and tags[2] in {"Dots", "Zs"}:
            return 3
        return 2
    if len(tags) > 1 and tags[1] == "Zs":
        if len(tags) > 2 and tags[2] == "Ks":
            return 3
        return 2
    if len(tags) > 1 and tags[1] in _COMPOUND_SUFFIXES:
        return 2
    return 1


def _consume_operand_tags(
    tokens: Sequence[str], cursor: int, record: str, marker: str = ""
) -> tuple[tuple[str, ...], int]:
    tags: list[str] = []
    for item in _operand_payloads(record):
        rest = tokens[cursor:]
        width = _source_authorized_operand_width(marker, rest, item)
        if width is None:
            width = _decoder_operand_width(rest, item)
        if width is None:
            width = _generic_operand_width(rest)
        if width <= 0 or cursor + width > len(tokens):
            raise ValueError("MIL header has fewer descriptors than records")
        tags.extend(tokens[cursor : cursor + width])
        cursor += width
    return tuple(tags), cursor


def _consume_note(tokens: Sequence[str], cursor: int) -> int:
    if cursor >= len(tokens):
        raise ValueError("MIL header has fewer descriptors than notes")
    if cursor + 1 < len(tokens) and tokens[cursor + 1] in _NOTE_FLAGS:
        return cursor + 2
    for index in range(cursor + 1, len(tokens)):
        if tokens[index] in _NOTE_FLAGS:
            return index + 1
    raise ValueError("unmined MIL note descriptor")


def signature_from_mil_record(
    record: str,
    header_marker: str,
    header_operand_tags: Sequence[str] = (),
) -> OpcodeSignature:
    if "op=lct{" in record:
        form = "logic"
    elif "op=sct{" in record:
        form = "contact"
    elif "op=cl{" in record:
        form = "coil"
    else:
        raise ValueError("MIL instruction form is unmined")
    logic = re.search(r"lt=([lao])", record)
    return OpcodeSignature(
        form,
        header_marker,
        logic.group(1) if logic else "",
        "ct=p" in record,
        _operand_vts(record),
        _operand_kinds(record),
        tuple(header_operand_tags),
        _inner_op(record),
    )


def mil_stream(
    data: str,
) -> list[tuple[str, OpcodeSignature | None]]:
    items = _ms_items(data)
    tokens = header_tokens(data)
    if not items:
        if tokens == ["END"]:
            return [("end", OpcodeSignature("end", "END", "", False, (), (), (), ""))]
        raise ValueError("MIL block has no instruction record")
    mc_items = [item for item in items if item.startswith("mc{")]
    ma_items = [item for item in items if item.startswith("ma{")]
    if not mc_items:
        if not ma_items:
            raise ValueError("unmined MIL element")
        if len(ma_items) == 1:
            return [("note", None)]
        stream = [("note", None) for _ in ma_items]
        cursor = 0
        for _item in ma_items:
            cursor = _consume_note(tokens, cursor)
        if cursor != len(tokens):
            raise ValueError("MIL header has unused descriptors")
        return stream
    stream: list[tuple[str, OpcodeSignature | None]] = []
    cursor = 0
    for item in items:
        if item.startswith("ma{"):
            cursor = _consume_note(tokens, cursor)
            stream.append(("note", None))
            continue
        if not item.startswith("mc{"):
            raise ValueError("unmined MIL element")
        if cursor >= len(tokens):
            raise ValueError("MIL header has fewer descriptors than records")
        marker = tokens[cursor]
        cursor += 1
        tags, cursor = _consume_operand_tags(tokens, cursor, item, marker)
        stream.append(("instruction", signature_from_mil_record(item, marker, tags)))
    if cursor != len(tokens):
        raise ValueError("MIL header has unused descriptors")
    return stream


def instruction_signatures_from_mil(data: str) -> list[OpcodeSignature]:
    return [
        signature
        for kind, signature in mil_stream(data)
        if signature is not None and kind in {"instruction", "end"}
    ]


def freeze_table(
    pairs: Iterable[tuple[OpcodeSignature | Mapping[str, Any] | str, str]],
) -> dict[str, str]:
    table: dict[str, str] = {}
    conflicts: list[dict[str, Any]] = []
    for signature, mnemonic in pairs:
        if isinstance(signature, str):
            key = signature
        elif isinstance(signature, OpcodeSignature):
            key = canonical_signature_key(signature)
        else:
            key = canonical_signature_key(signature_from_mapping(signature))
        previous = table.get(key)
        if previous is None:
            table[key] = mnemonic
        elif previous != mnemonic:
            conflicts.append(
                {
                    "signature": json.loads(key),
                    "mnemonics": [previous, mnemonic],
                }
            )
    if conflicts:
        raise ValueError(
            "opcode signature conflict: "
            + json.dumps(conflicts[:8], ensure_ascii=True, sort_keys=True)
        )
    return table


def lookup_mnemonic(
    signature: OpcodeSignature | Mapping[str, Any] | str,
    table: Mapping[str, str] | None = None,
) -> str:
    """Return the approved official mnemonic for an exact record signature."""
    mapping = OPCODE_TABLE if table is None else table
    if isinstance(signature, str):
        key = signature
    elif isinstance(signature, OpcodeSignature):
        key = canonical_signature_key(signature)
    else:
        key = canonical_signature_key(signature_from_mapping(signature))
    try:
        return mapping[key]
    except KeyError as exact_error:
        if table is None:
            source_authorized = SOURCE_AUTHORIZED_OPCODE_TABLE.get(key)
            if source_authorized is not None:
                return source_authorized
            generalized = canonical_signature_key(
                semantic_signature(
                    signature_from_key(key)
                    if isinstance(signature, str)
                    else signature_from_mapping(signature)
                    if not isinstance(signature, OpcodeSignature)
                    else signature
                )
            )
            try:
                return SEMANTIC_OPCODE_TABLE[generalized]
            except KeyError:
                try:
                    return structural_mnemonic(
                        signature_from_key(key)
                        if isinstance(signature, str)
                        else signature_from_mapping(signature)
                        if not isinstance(signature, OpcodeSignature)
                        else signature
                    )
                except UnknownOpcodeSignature:
                    pass
        raise UnknownOpcodeSignature(key) from exact_error


# BEGIN APPROVED_OPCODE_ROWS
_APPROVED_ROWS: tuple[tuple[str, str], ...] = (
    ("{\"form\":\"coil\",\"header_marker\":\"ACOS\",\"header_operand_tags\":[\"_lid/16135670382422534381/183\",\"_lid/16135670382422534381/184\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ACOS"),
    ("{\"form\":\"coil\",\"header_marker\":\"ACOS\",\"header_operand_tags\":[\"_lid/16135670382422534381/185\",\"_lid/16135670382422534381/186\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "ACOSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DADD"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DADD_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DADDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DADDP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "ADD"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "ADD_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "ADDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "ADDP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"_lid/16135670382422534381/77\",\"_lid/16135670382422534381/78\",\"_lid/16135670382422534381/79\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":false}", "DEADD"),
    ("{\"form\":\"coil\",\"header_marker\":\"ADD\",\"header_operand_tags\":[\"_lid/16135670382422534381/80\",\"_lid/16135670382422534381/81\",\"_lid/16135670382422534381/82\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":true}", "DEADDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ALT\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "ALT"),
    ("{\"form\":\"coil\",\"header_marker\":\"ALT\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "ALTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"AND\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WAND"),
    ("{\"form\":\"coil\",\"header_marker\":\"AND\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":false}", "DAND"),
    ("{\"form\":\"coil\",\"header_marker\":\"AND\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WANDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"AND\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":true}", "DANDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ASIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/175\",\"_lid/16135670382422534381/176\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ASIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"ASIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/177\",\"_lid/16135670382422534381/178\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "ASINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ATAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/191\",\"_lid/16135670382422534381/192\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ATAN"),
    ("{\"form\":\"coil\",\"header_marker\":\"ATAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/193\",\"_lid/16135670382422534381/194\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "ATANP"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16\"],\"pulse\":false}", "BK+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16\"],\"pulse\":false}", "BK+_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A16\"],\"pulse\":false}", "DBK+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A16\"],\"pulse\":false}", "DBK+_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16\"],\"pulse\":true}", "BK+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16\"],\"pulse\":true}", "BK+P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A16\"],\"pulse\":true}", "DBK+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A16\"],\"pulse\":true}", "DBK+P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "B+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "D+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "D+_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":false}", "DB+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "B+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "D+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "D+P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":true}", "DB+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "+_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "+P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/293\",\"_lid/16135670382422534381/294\",\"_lid/16135670382422534381/295\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\",\"Ass\"],\"pulse\":false}", "$+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/296\",\"_lid/16135670382422534381/297\",\"_lid/16135670382422534381/298\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\",\"Ass\"],\"pulse\":true}", "$+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/71\",\"_lid/16135670382422534381/72\",\"_lid/16135670382422534381/73\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":false}", "E+"),
    ("{\"form\":\"coil\",\"header_marker\":\"AddOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/74\",\"_lid/16135670382422534381/75\",\"_lid/16135670382422534381/76\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":true}", "E+P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "BAND"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "BAND_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DBAND"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DBAND_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "BANDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "BANDP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DBANDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DBANDP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BCD\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "BCD"),
    ("{\"form\":\"coil\",\"header_marker\":\"BCD\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DBCD"),
    ("{\"form\":\"coil\",\"header_marker\":\"BCD\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "BCDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BCD\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DBCDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "BIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"BIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DBIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"BIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "BINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DBINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/303\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16s\",\"Ass\"],\"pulse\":false}", "BINDA"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/304\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16s\",\"Ass\"],\"pulse\":true}", "BINDAP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/305\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16u\",\"Ass\"],\"pulse\":false}", "BINDA_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/306\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16u\",\"Ass\"],\"pulse\":true}", "BINDAP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/307\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32s\",\"Ass\"],\"pulse\":false}", "DBINDA"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/308\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32s\",\"Ass\"],\"pulse\":true}", "DBINDAP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/309\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32u\",\"Ass\"],\"pulse\":false}", "DBINDA_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BINDA\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/310\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32u\",\"Ass\"],\"pulse\":true}", "DBINDAP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "BKAND"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKAND\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "BKANDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP="),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP=_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP=P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP=P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP<="),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP<=_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP<=P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP<=P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP<"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP<_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP<P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP<P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP>="),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP>=_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP>=P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP>=P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP>"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP>_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP>P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP>P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP<>"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":false}", "BKCMP<>_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP<>P"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Abl\",\"A16\"],\"pulse\":true}", "BKCMP<>P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "BKOR"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "BKORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKRST\",\"header_operand_tags\":[\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"A16\"],\"pulse\":false}", "BKRST"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKRST\",\"header_operand_tags\":[\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"A16\"],\"pulse\":true}", "BKRSTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKXNR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "BKXNR"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKXNR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "BKXNRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKXOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "BKXOR"),
    ("{\"form\":\"coil\",\"header_marker\":\"BKXOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "BKXORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BLKMOV\",\"header_operand_tags\":[\"M\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"Abl\",\"A16\"],\"pulse\":false}", "BLKMOVB"),
    ("{\"form\":\"coil\",\"header_marker\":\"BLKMOV\",\"header_operand_tags\":[\"M\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"Abl\",\"A16\"],\"pulse\":true}", "BLKMOVBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BMOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "BMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"BMOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "BMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BON\",\"header_operand_tags\":[\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"Abl\",\"A16\"],\"pulse\":false}", "BON"),
    ("{\"form\":\"coil\",\"header_marker\":\"BON\",\"header_operand_tags\":[\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"Abl\",\"A16\"],\"pulse\":false}", "DBON"),
    ("{\"form\":\"coil\",\"header_marker\":\"BON\",\"header_operand_tags\":[\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"Abl\",\"A16\"],\"pulse\":true}", "BONP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BON\",\"header_operand_tags\":[\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"Abl\",\"A16\"],\"pulse\":true}", "DBONP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BRST\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "BRST"),
    ("{\"form\":\"coil\",\"header_marker\":\"BRST\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "BRSTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BSET\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "BSET"),
    ("{\"form\":\"coil\",\"header_marker\":\"BSET\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "BSETP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BSFL\",\"header_operand_tags\":[\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"A16\"],\"pulse\":false}", "BSFL"),
    ("{\"form\":\"coil\",\"header_marker\":\"BSFL\",\"header_operand_tags\":[\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"A16\"],\"pulse\":true}", "BSFLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BSFR\",\"header_operand_tags\":[\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"A16\"],\"pulse\":false}", "BSFR"),
    ("{\"form\":\"coil\",\"header_marker\":\"BSFR\",\"header_operand_tags\":[\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"A16\"],\"pulse\":true}", "BSFRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"BTOW\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "BTOW"),
    ("{\"form\":\"coil\",\"header_marker\":\"BTOW\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "BTOWP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CCD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16a\",\"A16\"],\"pulse\":false}", "CCD"),
    ("{\"form\":\"coil\",\"header_marker\":\"CCD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16a\",\"A16\"],\"pulse\":true}", "CCDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CML\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "CML"),
    ("{\"form\":\"coil\",\"header_marker\":\"CML\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DCML"),
    ("{\"form\":\"coil\",\"header_marker\":\"CML\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "CMLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CML\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DCMLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CML\",\"header_operand_tags\":[\"M\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"Abl\"],\"pulse\":false}", "CMLB"),
    ("{\"form\":\"coil\",\"header_marker\":\"CML\",\"header_operand_tags\":[\"M\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"Abl\"],\"pulse\":true}", "CMLBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16a\",\"Aba\"],\"pulse\":false}", "TCMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16a\",\"Aba\"],\"pulse\":true}", "TCMPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Aba\"],\"pulse\":false}", "CMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Aba\"],\"pulse\":false}", "CMP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Aba\"],\"pulse\":false}", "DCMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Aba\"],\"pulse\":false}", "DCMP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"Aba\"],\"pulse\":true}", "CMPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"Aba\"],\"pulse\":true}", "CMPP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Aba\"],\"pulse\":true}", "DCMPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Aba\"],\"pulse\":true}", "DCMPP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"_lid/16135670382422534381/61\",\"_lid/16135670382422534381/62\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"d\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Aba\"],\"pulse\":false}", "DECMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CMP\",\"header_operand_tags\":[\"_lid/16135670382422534381/63\",\"_lid/16135670382422534381/64\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"d\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Aba\"],\"pulse\":true}", "DECMPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"COS\",\"header_operand_tags\":[\"_lid/16135670382422534381/159\",\"_lid/16135670382422534381/160\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "COS"),
    ("{\"form\":\"coil\",\"header_marker\":\"COS\",\"header_operand_tags\":[\"_lid/16135670382422534381/161\",\"_lid/16135670382422534381/162\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "COSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"CRC\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "CRC"),
    ("{\"form\":\"coil\",\"header_marker\":\"CRC\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "CRCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/10\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A16s\"],\"pulse\":true}", "DABINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/11\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A16u\"],\"pulse\":false}", "DABIN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/12\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A16u\"],\"pulse\":true}", "DABINP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/13\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A32s\"],\"pulse\":false}", "DDABIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/14\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A32s\"],\"pulse\":true}", "DDABINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/15\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A32u\"],\"pulse\":false}", "DDABIN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/16\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A32u\"],\"pulse\":true}", "DDABINP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DABIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/9\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A16s\"],\"pulse\":false}", "DABIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP="),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP=_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP=P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_EQ\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP=P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP<="),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP<=_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP<=P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP<=P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP<"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP<_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP<P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_GT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP<P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP>="),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP>=_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP>=P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP>=P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP>"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP>_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP>P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_LT\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP>P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP<>"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":false}", "DBKCMP<>_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP<>P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DBKCMP_NE\",\"header_operand_tags\":[\"D\",\"D\",\"M\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=Abl}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"Abl\",\"A16\"],\"pulse\":true}", "DBKCMP<>P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16s\"],\"pulse\":false}", "DEC"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16u\"],\"pulse\":false}", "DEC_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32s\"],\"pulse\":false}", "DDEC"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32u\"],\"pulse\":false}", "DDEC_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16s\"],\"pulse\":true}", "DECP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16u\"],\"pulse\":true}", "DECP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32s\"],\"pulse\":true}", "DDECP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32u\"],\"pulse\":true}", "DDECP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/207\",\"_lid/16135670382422534381/208\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DEG"),
    ("{\"form\":\"coil\",\"header_marker\":\"DEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/209\",\"_lid/16135670382422534381/210\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DEGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DFMOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A16\"],\"pulse\":false}", "DFMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"DFMOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A16\"],\"pulse\":true}", "DFMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIS\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "DIS"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIS\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "DISP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16sa\"],\"pulse\":false}", "DIV"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16ua\"],\"pulse\":false}", "DIV_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":false}", "DDIV"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":false}", "DDIV_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16sa\"],\"pulse\":true}", "DIVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16ua\"],\"pulse\":true}", "DIVP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":true}", "DDIVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":true}", "DDIVP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"_lid/16135670382422534381/113\",\"_lid/16135670382422534381/114\",\"_lid/16135670382422534381/115\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":false}", "DEDIV"),
    ("{\"form\":\"coil\",\"header_marker\":\"DIV\",\"header_operand_tags\":[\"_lid/16135670382422534381/116\",\"_lid/16135670382422534381/117\",\"_lid/16135670382422534381/118\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":true}", "DEDIVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DRCL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":false}", "DRCL"),
    ("{\"form\":\"coil\",\"header_marker\":\"DRCL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":true}", "DRCLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DRCR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":false}", "DRCR"),
    ("{\"form\":\"coil\",\"header_marker\":\"DRCR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":true}", "DRCRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DROL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":false}", "DROL"),
    ("{\"form\":\"coil\",\"header_marker\":\"DROL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":true}", "DROLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DROR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":false}", "DROR"),
    ("{\"form\":\"coil\",\"header_marker\":\"DROR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":true}", "DRORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DSCL2"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DSCL2_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DSCL2P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DSCL2P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSFL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "DSFL"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSFL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "DSFLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSFR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "DSFR"),
    ("{\"form\":\"coil\",\"header_marker\":\"DSFR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "DSFRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DUTY\",\"header_operand_tags\":[\"D\",\"D\",\"SM\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"Abl\"],\"pulse\":false}", "DUTY"),
    ("{\"form\":\"coil\",\"header_marker\":\"DXCH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DXCH"),
    ("{\"form\":\"coil\",\"header_marker\":\"DXCH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DXCHP"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16sa\"],\"pulse\":false}", "/"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16ua\"],\"pulse\":false}", "/_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16a\"],\"pulse\":false}", "B/"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":false}", "D/"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":false}", "D/_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32a\"],\"pulse\":false}", "DB/"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16sa\"],\"pulse\":true}", "/P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16ua\"],\"pulse\":true}", "/P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16a\"],\"pulse\":true}", "B/P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":true}", "D/P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":true}", "D/P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32a\"],\"pulse\":true}", "DB/P"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/107\",\"_lid/16135670382422534381/108\",\"_lid/16135670382422534381/109\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":false}", "E/"),
    ("{\"form\":\"coil\",\"header_marker\":\"DivOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/110\",\"_lid/16135670382422534381/111\",\"_lid/16135670382422534381/112\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":true}", "E/P"),
    ("{\"form\":\"coil\",\"header_marker\":\"EBCD\",\"header_operand_tags\":[\"_lid/16135670382422534381/135\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DEBCD"),
    ("{\"form\":\"coil\",\"header_marker\":\"EBCD\",\"header_operand_tags\":[\"_lid/16135670382422534381/136\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DEBCDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EBIN\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/137\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DEBIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"EBIN\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/138\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DEBINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EMAX\",\"header_operand_tags\":[\"_lid/16135670382422534381/249\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ar32\",\"Ar32a\",\"A16\"],\"pulse\":false}", "EMAX"),
    ("{\"form\":\"coil\",\"header_marker\":\"EMAX\",\"header_operand_tags\":[\"_lid/16135670382422534381/250\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ar32\",\"Ar32a\",\"A16\"],\"pulse\":true}", "EMAXP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EMIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/251\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ar32\",\"Ar32a\",\"A16\"],\"pulse\":false}", "EMIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"EMIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/252\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ar32\",\"Ar32a\",\"A16\"],\"pulse\":true}", "EMINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EMOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/147\",\"_lid/16135670382422534381/148\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DEMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"EMOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/149\",\"_lid/16135670382422534381/150\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DEMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"END\",\"header_operand_tags\":[],\"inner_op\":\"op=cl{op=#:ct=a}\",\"logic_type\":\"\",\"operand_kinds\":[],\"operand_vts\":[],\"pulse\":false}", "END"),
    ("{\"form\":\"coil\",\"header_marker\":\"ENEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/141\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\"],\"operand_vts\":[\"Ar32\"],\"pulse\":false}", "DENEG"),
    ("{\"form\":\"coil\",\"header_marker\":\"ENEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/142\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\"],\"operand_vts\":[\"Ar32\"],\"pulse\":true}", "DENEGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ERINIT\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Aba\"],\"pulse\":false}", "ERINIT"),
    ("{\"form\":\"coil\",\"header_marker\":\"ESQR\",\"header_operand_tags\":[\"_lid/16135670382422534381/215\",\"_lid/16135670382422534381/216\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Ar32\"],\"pulse\":false}", "DESQR"),
    ("{\"form\":\"coil\",\"header_marker\":\"ESQR\",\"header_operand_tags\":[\"_lid/16135670382422534381/217\",\"_lid/16135670382422534381/218\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Ar32\"],\"pulse\":true}", "DESQRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ESQRT\",\"header_operand_tags\":[\"_lid/16135670382422534381/253\",\"_lid/16135670382422534381/254\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Awad}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Awad\",\"Ar32\"],\"pulse\":false}", "ESQRT"),
    ("{\"form\":\"coil\",\"header_marker\":\"ESQRT\",\"header_operand_tags\":[\"_lid/16135670382422534381/255\",\"_lid/16135670382422534381/256\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Awad}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Awad\",\"Ar32\"],\"pulse\":true}", "ESQRTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ESTR\",\"header_operand_tags\":[\"_lid/16135670382422534381/323\",\"D\",\"_lid/16135670382422534381/324\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=A16a}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"l\"],\"operand_vts\":[\"Ar32\",\"A16a\",\"Ass\"],\"pulse\":false}", "DESTR"),
    ("{\"form\":\"coil\",\"header_marker\":\"ESTR\",\"header_operand_tags\":[\"_lid/16135670382422534381/325\",\"D\",\"_lid/16135670382422534381/326\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=A16a}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"l\"],\"operand_vts\":[\"Ar32\",\"A16a\",\"Ass\"],\"pulse\":true}", "DESTRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EVAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/127\",\"_lid/16135670382422534381/128\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ar32\"],\"pulse\":false}", "EVAL"),
    ("{\"form\":\"coil\",\"header_marker\":\"EVAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/129\",\"_lid/16135670382422534381/130\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ar32\"],\"pulse\":true}", "EVALP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EXP\",\"header_operand_tags\":[\"_lid/16135670382422534381/219\",\"_lid/16135670382422534381/220\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "EXP"),
    ("{\"form\":\"coil\",\"header_marker\":\"EXP\",\"header_operand_tags\":[\"_lid/16135670382422534381/221\",\"_lid/16135670382422534381/222\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "EXPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FDEL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "FDEL"),
    ("{\"form\":\"coil\",\"header_marker\":\"FDEL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "FDELP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FF\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "FF"),
    ("{\"form\":\"coil\",\"header_marker\":\"FINS\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "FINS"),
    ("{\"form\":\"coil\",\"header_marker\":\"FINS\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "FINSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A16s\"],\"pulse\":false}", "FLT2INT"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/2\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A16s\"],\"pulse\":true}", "FLT2INTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/3\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A16u\"],\"pulse\":false}", "FLT2UINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/4\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A16u\"],\"pulse\":true}", "FLT2UINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/5\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A32s\"],\"pulse\":false}", "FLT2DINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/6\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A32s\"],\"pulse\":true}", "FLT2DINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/7\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A32u\"],\"pulse\":false}", "FLT2UDINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"FLT2INT\",\"header_operand_tags\":[\"_lid/16135670382422534381/8\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ar32\",\"A32u\"],\"pulse\":true}", "FLT2UDINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"FMOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "FMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"FMOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "FMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_ACOS\",\"header_operand_tags\":[\"_lid/16135670382422534381/187\",\"_lid/16135670382422534381/188\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DACOS"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_ACOS\",\"header_operand_tags\":[\"_lid/16135670382422534381/189\",\"_lid/16135670382422534381/190\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DACOSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_ASIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/179\",\"_lid/16135670382422534381/180\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DASIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_ASIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/181\",\"_lid/16135670382422534381/182\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DASINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_ATAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/195\",\"_lid/16135670382422534381/196\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DATAN"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_ATAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/197\",\"_lid/16135670382422534381/198\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DATANP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_COS\",\"header_operand_tags\":[\"_lid/16135670382422534381/163\",\"_lid/16135670382422534381/164\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DCOS"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_COS\",\"header_operand_tags\":[\"_lid/16135670382422534381/165\",\"_lid/16135670382422534381/166\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DCOSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_DEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/211\",\"_lid/16135670382422534381/212\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DDEG"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_DEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/213\",\"_lid/16135670382422534381/214\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DDEGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_EVAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/131\",\"_lid/16135670382422534381/132\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ar32\"],\"pulse\":false}", "DEVAL"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_EVAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/133\",\"_lid/16135670382422534381/134\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ar32\"],\"pulse\":true}", "DEVALP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_EXP\",\"header_operand_tags\":[\"_lid/16135670382422534381/223\",\"_lid/16135670382422534381/224\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DEXP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_EXP\",\"header_operand_tags\":[\"_lid/16135670382422534381/225\",\"_lid/16135670382422534381/226\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DEXPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_LOG10\",\"header_operand_tags\":[\"_lid/16135670382422534381/245\",\"_lid/16135670382422534381/246\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DLOG10"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_LOG10\",\"header_operand_tags\":[\"_lid/16135670382422534381/247\",\"_lid/16135670382422534381/248\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DLOG10P"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_RAD\",\"header_operand_tags\":[\"_lid/16135670382422534381/203\",\"_lid/16135670382422534381/204\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DRAD"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_RAD\",\"header_operand_tags\":[\"_lid/16135670382422534381/205\",\"_lid/16135670382422534381/206\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DRADP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_SIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/155\",\"_lid/16135670382422534381/156\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DSIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_SIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/157\",\"_lid/16135670382422534381/158\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DSINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_TAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/171\",\"_lid/16135670382422534381/172\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DTAN"),
    ("{\"form\":\"coil\",\"header_marker\":\"F_TAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/173\",\"_lid/16135670382422534381/174\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DTANP"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "GBIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "GBIN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "DGBIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "DGBIN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":true}", "GBINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":true}", "GBINP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":true}", "DGBINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"GBIN\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":true}", "DGBINP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "GRY"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "GRY_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "DGRY"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "DGRY_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":true}", "GRYP"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":true}", "GRYP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":true}", "DGRYP"),
    ("{\"form\":\"coil\",\"header_marker\":\"GRY\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":true}", "DGRYP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"HOURM\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16a}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16a\",\"Abl\"],\"pulse\":false}", "HOURM"),
    ("{\"form\":\"coil\",\"header_marker\":\"HOURM\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32a}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32a\",\"Abl\"],\"pulse\":false}", "DHOURM"),
    ("{\"form\":\"coil\",\"header_marker\":\"HTOS\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16\"],\"pulse\":false}", "HTOS"),
    ("{\"form\":\"coil\",\"header_marker\":\"HTOS\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A32\"],\"pulse\":false}", "DHTOS"),
    ("{\"form\":\"coil\",\"header_marker\":\"HTOS\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16\"],\"pulse\":true}", "HTOSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"HTOS\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A32\"],\"pulse\":true}", "DHTOSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16s\"],\"pulse\":false}", "INC"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16u\"],\"pulse\":false}", "INC_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32s\"],\"pulse\":false}", "DINC"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32u\"],\"pulse\":false}", "DINC_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16s\"],\"pulse\":true}", "INCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16u\"],\"pulse\":true}", "INCP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32s\"],\"pulse\":true}", "DINCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INC\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32u\"],\"pulse\":true}", "DINCP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"INSTR\",\"header_operand_tags\":[\"_lid/16135670382422534381/333\",\"_lid/16135670382422534381/334\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\",\"A16\"],\"pulse\":false}", "INSTR"),
    ("{\"form\":\"coil\",\"header_marker\":\"INSTR\",\"header_operand_tags\":[\"_lid/16135670382422534381/335\",\"_lid/16135670382422534381/336\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\",\"A16\"],\"pulse\":true}", "INSTRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/119\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16s\",\"Ar32\"],\"pulse\":false}", "INT2FLT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/120\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16s\",\"Ar32\"],\"pulse\":true}", "INT2FLTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/121\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16u\",\"Ar32\"],\"pulse\":false}", "UINT2FLT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/122\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A16u\",\"Ar32\"],\"pulse\":true}", "UINT2FLTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/123\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32s\",\"Ar32\"],\"pulse\":false}", "DINT2FLT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/124\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32s\",\"Ar32\"],\"pulse\":true}", "DINT2FLTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/125\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32u\",\"Ar32\"],\"pulse\":false}", "UDINT2FLT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2FLT\",\"header_operand_tags\":[\"D\",\"_lid/16135670382422534381/126\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"l\"],\"operand_vts\":[\"A32u\",\"Ar32\"],\"pulse\":true}", "UDINT2FLTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16u\"],\"pulse\":false}", "INT2UINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A32s\"],\"pulse\":false}", "INT2DINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A32u\"],\"pulse\":false}", "INT2UDINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16s\"],\"pulse\":false}", "UINT2INT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A32s\"],\"pulse\":false}", "UINT2DINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A32u\"],\"pulse\":false}", "UINT2UDINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A16s\"],\"pulse\":false}", "DINT2INT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A16u\"],\"pulse\":false}", "DINT2UINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32u\"],\"pulse\":false}", "DINT2UDINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A16s\"],\"pulse\":false}", "UDINT2INT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A16u\"],\"pulse\":false}", "UDINT2UINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32s\"],\"pulse\":false}", "UDINT2DINT"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16u\"],\"pulse\":true}", "INT2UINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A32s\"],\"pulse\":true}", "INT2DINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A32u\"],\"pulse\":true}", "INT2UDINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16s\"],\"pulse\":true}", "UINT2INTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A32s\"],\"pulse\":true}", "UINT2DINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A32u\"],\"pulse\":true}", "UINT2UDINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A16s\"],\"pulse\":true}", "DINT2INTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A16u\"],\"pulse\":true}", "DINT2UINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32u\"],\"pulse\":true}", "DINT2UDINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A16s\"],\"pulse\":true}", "UDINT2INTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A16u\"],\"pulse\":true}", "UDINT2UINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"INT2INT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32s\"],\"pulse\":true}", "UDINT2DINTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LEFT\",\"header_operand_tags\":[\"_lid/16135670382422534381/331\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\"],\"pulse\":false}", "LEFT"),
    ("{\"form\":\"coil\",\"header_marker\":\"LEFT\",\"header_operand_tags\":[\"_lid/16135670382422534381/332\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\"],\"pulse\":true}", "LEFTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LEN\",\"header_operand_tags\":[\"_lid/16135670382422534381/327\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A16\"],\"pulse\":false}", "LEN"),
    ("{\"form\":\"coil\",\"header_marker\":\"LEN\",\"header_operand_tags\":[\"_lid/16135670382422534381/328\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\"],\"operand_vts\":[\"Ass\",\"A16\"],\"pulse\":true}", "LENP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "LIMIT"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "LIMIT_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DLIMIT"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DLIMIT_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "LIMITP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "LIMITP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DLIMITP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LIMIT\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DLIMITP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOG\",\"header_operand_tags\":[\"_lid/16135670382422534381/227\",\"_lid/16135670382422534381/228\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LOG"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOG\",\"header_operand_tags\":[\"_lid/16135670382422534381/229\",\"_lid/16135670382422534381/230\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "LOGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOG10\",\"header_operand_tags\":[\"_lid/16135670382422534381/241\",\"_lid/16135670382422534381/242\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LOG10"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOG10\",\"header_operand_tags\":[\"_lid/16135670382422534381/243\",\"_lid/16135670382422534381/244\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "LOG10P"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOGE\",\"header_operand_tags\":[\"_lid/16135670382422534381/231\",\"_lid/16135670382422534381/232\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "DLOGE"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOGE\",\"header_operand_tags\":[\"_lid/16135670382422534381/233\",\"_lid/16135670382422534381/234\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "DLOGEP"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOGTRG\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "LOGTRG"),
    ("{\"form\":\"coil\",\"header_marker\":\"LOGTRGR\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "LOGTRGR"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16sa\",\"A16\"],\"pulse\":false}", "MAX"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16ua\",\"A16\"],\"pulse\":false}", "MAX_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32sa\",\"A16\"],\"pulse\":false}", "DMAX"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32ua\",\"A16\"],\"pulse\":false}", "DMAX_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16sa\",\"A16\"],\"pulse\":true}", "MAXP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16ua\",\"A16\"],\"pulse\":true}", "MAXP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32sa\",\"A16\"],\"pulse\":true}", "DMAXP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MAX\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32ua\",\"A16\"],\"pulse\":true}", "DMAXP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16\"],\"pulse\":false}", "MEAN"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16\"],\"pulse\":false}", "MEAN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A16\"],\"pulse\":false}", "DMEAN"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A16\"],\"pulse\":false}", "DMEAN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16\"],\"pulse\":true}", "MEANP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16\"],\"pulse\":true}", "MEANP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A16\"],\"pulse\":true}", "DMEANP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MEAN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A16\"],\"pulse\":true}", "DMEANP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16sa\",\"A16\"],\"pulse\":false}", "MIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16ua\",\"A16\"],\"pulse\":false}", "MIN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32sa\",\"A16\"],\"pulse\":false}", "DMIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32ua\",\"A16\"],\"pulse\":false}", "DMIN_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16sa\",\"A16\"],\"pulse\":true}", "MINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16ua\",\"A16\"],\"pulse\":true}", "MINP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32sa}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32sa\",\"A16\"],\"pulse\":true}", "DMINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MIN\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32ua}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32ua\",\"A16\"],\"pulse\":true}", "DMINP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "SMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "SMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "MOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "MOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"M\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"Abl\"],\"pulse\":false}", "MOVB"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"M\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"Abl\",\"Abl\"],\"pulse\":true}", "MOVBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/143\",\"_lid/16135670382422534381/144\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "EMOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/145\",\"_lid/16135670382422534381/146\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "EMOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/299\",\"_lid/16135670382422534381/300\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "$MOV"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/301\",\"_lid/16135670382422534381/302\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":true}", "$MOVP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/339\",\"_lid/16135670382422534381/340\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Asd}:as{vt=Asd}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Asd\",\"Asd\"],\"pulse\":false}", "$MOV_WS"),
    ("{\"form\":\"coil\",\"header_marker\":\"MOV\",\"header_operand_tags\":[\"_lid/16135670382422534381/341\",\"_lid/16135670382422534381/342\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Asd}:as{vt=Asd}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Asd\",\"Asd\"],\"pulse\":true}", "$MOVP_WS"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A32s\"],\"pulse\":false}", "MUL"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A32u\"],\"pulse\":false}", "MUL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":false}", "DMUL"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":false}", "DMUL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A32s\"],\"pulse\":true}", "MULP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A32u\"],\"pulse\":true}", "MULP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":true}", "DMULP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":true}", "DMULP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"_lid/16135670382422534381/101\",\"_lid/16135670382422534381/102\",\"_lid/16135670382422534381/103\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":false}", "DEMUL"),
    ("{\"form\":\"coil\",\"header_marker\":\"MUL\",\"header_operand_tags\":[\"_lid/16135670382422534381/104\",\"_lid/16135670382422534381/105\",\"_lid/16135670382422534381/106\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":true}", "DEMULP"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A32s\"],\"pulse\":false}", "*"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A32u\"],\"pulse\":false}", "*_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A32\"],\"pulse\":false}", "B*"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":false}", "D*"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":false}", "D*_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32a\"],\"pulse\":false}", "DB*"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A32s\"],\"pulse\":true}", "*P"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A32u\"],\"pulse\":true}", "*P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A32\"],\"pulse\":true}", "B*P"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32sa}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32sa\"],\"pulse\":true}", "D*P"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32ua}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32ua\"],\"pulse\":true}", "D*P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32a\"],\"pulse\":true}", "DB*P"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/95\",\"_lid/16135670382422534381/96\",\"_lid/16135670382422534381/97\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":false}", "E*"),
    ("{\"form\":\"coil\",\"header_marker\":\"MulOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/98\",\"_lid/16135670382422534381/99\",\"_lid/16135670382422534381/100\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":true}", "E*P"),
    ("{\"form\":\"coil\",\"header_marker\":\"NDIS\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "NDIS"),
    ("{\"form\":\"coil\",\"header_marker\":\"NDIS\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "NDISP"),
    ("{\"form\":\"coil\",\"header_marker\":\"NEG\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "NEG"),
    ("{\"form\":\"coil\",\"header_marker\":\"NEG\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32\"],\"pulse\":false}", "DNEG"),
    ("{\"form\":\"coil\",\"header_marker\":\"NEG\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":true}", "NEGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"NEG\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32\"],\"pulse\":true}", "DNEGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"NEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/139\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\"],\"operand_vts\":[\"Ar32\"],\"pulse\":false}", "ENEG"),
    ("{\"form\":\"coil\",\"header_marker\":\"NEG\",\"header_operand_tags\":[\"_lid/16135670382422534381/140\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\"],\"operand_vts\":[\"Ar32\"],\"pulse\":true}", "ENEGP"),
    ("{\"form\":\"coil\",\"header_marker\":\"NUNI\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "NUNI"),
    ("{\"form\":\"coil\",\"header_marker\":\"NUNI\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "NUNIP"),
    ("{\"form\":\"coil\",\"header_marker\":\"OR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WOR"),
    ("{\"form\":\"coil\",\"header_marker\":\"OR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":false}", "DOR"),
    ("{\"form\":\"coil\",\"header_marker\":\"OR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"OR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":true}", "DORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"OUT\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "OUT"),
    ("{\"form\":\"coil\",\"header_marker\":\"OUT\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "PLF"),
    ("{\"form\":\"coil\",\"header_marker\":\"OUT\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "PLS"),
    ("{\"form\":\"coil\",\"header_marker\":\"PID\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "PID"),
    ("{\"form\":\"coil\",\"header_marker\":\"POP\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "POP"),
    ("{\"form\":\"coil\",\"header_marker\":\"POP\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "POPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"POW\",\"header_operand_tags\":[\"_lid/16135670382422534381/235\",\"_lid/16135670382422534381/236\",\"_lid/16135670382422534381/237\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":false}", "POW"),
    ("{\"form\":\"coil\",\"header_marker\":\"POW\",\"header_operand_tags\":[\"_lid/16135670382422534381/238\",\"_lid/16135670382422534381/239\",\"_lid/16135670382422534381/240\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":true}", "POWP"),
    ("{\"form\":\"coil\",\"header_marker\":\"PRUN\",\"header_operand_tags\":[\"M\",\"Ks\",\"M\",\"Ks\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"M\",\"M\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "PRUN"),
    ("{\"form\":\"coil\",\"header_marker\":\"PRUN\",\"header_operand_tags\":[\"M\",\"Ks\",\"M\",\"Ks\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"M\",\"M\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DPRUN"),
    ("{\"form\":\"coil\",\"header_marker\":\"PRUN\",\"header_operand_tags\":[\"M\",\"Ks\",\"M\",\"Ks\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"M\",\"M\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "PRUNP"),
    ("{\"form\":\"coil\",\"header_marker\":\"PRUN\",\"header_operand_tags\":[\"M\",\"Ks\",\"M\",\"Ks\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"M\",\"M\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DPRUNP"),
    ("{\"form\":\"coil\",\"header_marker\":\"RAD\",\"header_operand_tags\":[\"_lid/16135670382422534381/199\",\"_lid/16135670382422534381/200\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "RAD"),
    ("{\"form\":\"coil\",\"header_marker\":\"RAD\",\"header_operand_tags\":[\"_lid/16135670382422534381/201\",\"_lid/16135670382422534381/202\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "RADP"),
    ("{\"form\":\"coil\",\"header_marker\":\"RAMPF\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16a\",\"A16\"],\"pulse\":false}", "RAMPF"),
    ("{\"form\":\"coil\",\"header_marker\":\"RCL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "RCL"),
    ("{\"form\":\"coil\",\"header_marker\":\"RCL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "RCLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"RCR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "RCR"),
    ("{\"form\":\"coil\",\"header_marker\":\"RCR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "RCRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"RIGHT\",\"header_operand_tags\":[\"_lid/16135670382422534381/329\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\"],\"pulse\":false}", "RIGHT"),
    ("{\"form\":\"coil\",\"header_marker\":\"RIGHT\",\"header_operand_tags\":[\"_lid/16135670382422534381/330\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\"],\"pulse\":true}", "RIGHTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"RND\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "RND"),
    ("{\"form\":\"coil\",\"header_marker\":\"RND\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":true}", "RNDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ROL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "ROL"),
    ("{\"form\":\"coil\",\"header_marker\":\"ROL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "ROLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ROR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "ROR"),
    ("{\"form\":\"coil\",\"header_marker\":\"ROR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "RORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ROTC\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A16}:as{vt=A16}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16\",\"A16\",\"Aba\"],\"pulse\":false}", "ROTC"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "SCL"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "SCL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DSCL"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DSCL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "SCLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "SCLP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DSCLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DSCLP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "SCL2"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "SCL2_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "SCL2P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SCL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "SCL2P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SERMM\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16a\",\"A16\"],\"pulse\":false}", "SERMM"),
    ("{\"form\":\"coil\",\"header_marker\":\"SERMM\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32a\",\"A16\"],\"pulse\":false}", "DSERMM"),
    ("{\"form\":\"coil\",\"header_marker\":\"SERMM\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16a\",\"A16\"],\"pulse\":true}", "SERMMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SERMM\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32a\",\"A16\"],\"pulse\":true}", "DSERMMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SET\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "SET"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "SFL"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFL\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "SFLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "SFR"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "SFRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFRD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "SFRD"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFRD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "SFRDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFTL\",\"header_operand_tags\":[\"M\",\"M\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Abl}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"Aea\",\"Abl\",\"A16\",\"A16\"],\"pulse\":false}", "SFTL"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFTL\",\"header_operand_tags\":[\"M\",\"M\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Abl}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"Aea\",\"Abl\",\"A16\",\"A16\"],\"pulse\":true}", "SFTLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFTR\",\"header_operand_tags\":[\"M\",\"M\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Abl}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"Aea\",\"Abl\",\"A16\",\"A16\"],\"pulse\":false}", "SFTR"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFTR\",\"header_operand_tags\":[\"M\",\"M\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Abl}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"Aea\",\"Abl\",\"A16\",\"A16\"],\"pulse\":true}", "SFTRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFWR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "SFWR"),
    ("{\"form\":\"coil\",\"header_marker\":\"SFWR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "SFWRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/151\",\"_lid/16135670382422534381/152\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "SIN"),
    ("{\"form\":\"coil\",\"header_marker\":\"SIN\",\"header_operand_tags\":[\"_lid/16135670382422534381/153\",\"_lid/16135670382422534381/154\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "SINP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SJIS2WS\",\"header_operand_tags\":[\"_lid/16135670382422534381/343\",\"_lid/16135670382422534381/344\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Asd}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Asd\"],\"pulse\":false}", "SJIS2WS"),
    ("{\"form\":\"coil\",\"header_marker\":\"SJIS2WS\",\"header_operand_tags\":[\"_lid/16135670382422534381/345\",\"_lid/16135670382422534381/346\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Asd}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Asd\"],\"pulse\":true}", "SJIS2WSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SJIS2WSB\",\"header_operand_tags\":[\"_lid/16135670382422534381/347\",\"_lid/16135670382422534381/348\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Asd}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Asd\"],\"pulse\":false}", "SJIS2WSB"),
    ("{\"form\":\"coil\",\"header_marker\":\"SJIS2WSB\",\"header_operand_tags\":[\"_lid/16135670382422534381/349\",\"_lid/16135670382422534381/350\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Asd}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Asd\"],\"pulse\":true}", "SJIS2WSBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SORTTBL\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16}:as{vt=A16}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16\",\"A16\",\"A16u\",\"A16\"],\"pulse\":false}", "SORTTBL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SORTTBL\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "SORTTBL"),
    ("{\"form\":\"coil\",\"header_marker\":\"SORTTBL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16}:as{vt=A16}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16\",\"A16\",\"A16u\",\"A16\"],\"pulse\":false}", "SORTTBL2_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SORTTBL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "SORTTBL2"),
    ("{\"form\":\"coil\",\"header_marker\":\"SORTTBL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A16}:as{vt=A16}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A16\",\"A16\",\"A32u\",\"A16\"],\"pulse\":false}", "DSORTTBL2_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SORTTBL2\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}:as{vt=A16}:as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\",\"A16\",\"A32\",\"A16\"],\"pulse\":false}", "DSORTTBL2"),
    ("{\"form\":\"coil\",\"header_marker\":\"SP_DEVST\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}:as{vt=A16}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\",\"A16\",\"Aba\"],\"pulse\":true}", "SP.DEVST"),
    ("{\"form\":\"coil\",\"header_marker\":\"SQRT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "SQRT"),
    ("{\"form\":\"coil\",\"header_marker\":\"SQRT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":false}", "DSQRT"),
    ("{\"form\":\"coil\",\"header_marker\":\"SQRT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "SQRTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SQRT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\"],\"pulse\":true}", "DSQRTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STOH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16a\"],\"pulse\":false}", "STOH"),
    ("{\"form\":\"coil\",\"header_marker\":\"STOH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16a\"],\"pulse\":false}", "DSTOH"),
    ("{\"form\":\"coil\",\"header_marker\":\"STOH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16a\"],\"pulse\":true}", "STOHP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STOH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16a\"],\"pulse\":true}", "DSTOHP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/311\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16sa}:as{vt=A16s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16sa\",\"A16s\",\"Ass\"],\"pulse\":false}", "STR"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/312\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16sa}:as{vt=A16s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16sa\",\"A16s\",\"Ass\"],\"pulse\":true}", "STRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/313\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16ua}:as{vt=A16u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16ua\",\"A16u\",\"Ass\"],\"pulse\":false}", "STR_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/314\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16ua}:as{vt=A16u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16ua\",\"A16u\",\"Ass\"],\"pulse\":true}", "STRP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/315\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16sa}:as{vt=A32s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16sa\",\"A32s\",\"Ass\"],\"pulse\":false}", "DSTR"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/316\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16sa}:as{vt=A32s}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16sa\",\"A32s\",\"Ass\"],\"pulse\":true}", "DSTRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/317\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16ua}:as{vt=A32u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16ua\",\"A32u\",\"Ass\"],\"pulse\":false}", "DSTR_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"D\",\"D\",\"_lid/16135670382422534381/318\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16ua}:as{vt=A32u}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"l\"],\"operand_vts\":[\"A16ua\",\"A32u\",\"Ass\"],\"pulse\":true}", "DSTRP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"_lid/16135670382422534381/319\",\"D\",\"_lid/16135670382422534381/320\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=A16a}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"l\"],\"operand_vts\":[\"Ar32\",\"A16a\",\"Ass\"],\"pulse\":false}", "ESTR"),
    ("{\"form\":\"coil\",\"header_marker\":\"STR\",\"header_operand_tags\":[\"_lid/16135670382422534381/321\",\"D\",\"_lid/16135670382422534381/322\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=A16a}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"l\"],\"operand_vts\":[\"Ar32\",\"A16a\",\"Ass\"],\"pulse\":true}", "ESTRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STRDEL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16\",\"A16\"],\"pulse\":false}", "STRDEL"),
    ("{\"form\":\"coil\",\"header_marker\":\"STRDEL\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16\",\"A16\"],\"pulse\":true}", "STRDELP"),
    ("{\"form\":\"coil\",\"header_marker\":\"STRINS\",\"header_operand_tags\":[\"_lid/16135670382422534381/337\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\"],\"pulse\":false}", "STRINS"),
    ("{\"form\":\"coil\",\"header_marker\":\"STRINS\",\"header_operand_tags\":[\"_lid/16135670382422534381/338\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=Ass}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"Ass\",\"A16\"],\"pulse\":true}", "STRINSP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DSUB"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DSUB_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DSUBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DSUBP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "SUB"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "SUB_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "SUBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "SUBP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"_lid/16135670382422534381/89\",\"_lid/16135670382422534381/90\",\"_lid/16135670382422534381/91\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":false}", "DESUB"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUB\",\"header_operand_tags\":[\"_lid/16135670382422534381/92\",\"_lid/16135670382422534381/93\",\"_lid/16135670382422534381/94\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Ar32\"],\"pulse\":true}", "DESUBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUM\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "SUM"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUM\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":false}", "DSUM"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUM\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "SUMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SUM\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\"],\"pulse\":true}", "DSUMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SWAP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "SWAP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SWAP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32\"],\"pulse\":false}", "DSWAP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SWAP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":true}", "SWAPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"SWAP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A32\"],\"pulse\":true}", "DSWAPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"S_DEVLD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\",\"A16\"],\"pulse\":false}", "S.DEVLD"),
    ("{\"form\":\"coil\",\"header_marker\":\"S_DEVLD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\",\"A16\"],\"pulse\":true}", "SP.DEVLD"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16\"],\"pulse\":false}", "BK-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16\"],\"pulse\":false}", "BK-_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A16\"],\"pulse\":false}", "DBK-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A16\"],\"pulse\":false}", "DBK-_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16\"],\"pulse\":true}", "BK-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16\"],\"pulse\":true}", "BK-P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A16\"],\"pulse\":true}", "DBK-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A16\"],\"pulse\":true}", "DBK-P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "B-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "D-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "D-_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":false}", "DB-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "B-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "D-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "D-P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":true}", "DB-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "-_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"K_1\",\"K_1\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"c\",\"c\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "-P_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/83\",\"_lid/16135670382422534381/84\",\"_lid/16135670382422534381/85\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":false}", "E-"),
    ("{\"form\":\"coil\",\"header_marker\":\"SubOpe\",\"header_operand_tags\":[\"_lid/16135670382422534381/86\",\"_lid/16135670382422534381/87\",\"_lid/16135670382422534381/88\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\",\"Ar32\"],\"pulse\":true}", "E-P"),
    ("{\"form\":\"coil\",\"header_marker\":\"TADD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A16a}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16a\",\"A16a\"],\"pulse\":false}", "TADD"),
    ("{\"form\":\"coil\",\"header_marker\":\"TADD\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}:as{vt=A16a}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16a\",\"A16a\"],\"pulse\":true}", "TADDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"TAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/167\",\"_lid/16135670382422534381/168\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "TAN"),
    ("{\"form\":\"coil\",\"header_marker\":\"TAN\",\"header_operand_tags\":[\"_lid/16135670382422534381/169\",\"_lid/16135670382422534381/170\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":true}", "TANP"),
    ("{\"form\":\"coil\",\"header_marker\":\"TEST\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"Abl\"],\"pulse\":false}", "TEST"),
    ("{\"form\":\"coil\",\"header_marker\":\"TEST\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A16}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\",\"Abl\"],\"pulse\":false}", "DTEST"),
    ("{\"form\":\"coil\",\"header_marker\":\"TEST\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"Abl\"],\"pulse\":true}", "TESTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"TEST\",\"header_operand_tags\":[\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A16}:as{vt=Abl}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A16\",\"Abl\"],\"pulse\":true}", "DTESTP"),
    ("{\"form\":\"coil\",\"header_marker\":\"TRD\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16a\"],\"pulse\":false}", "TRD"),
    ("{\"form\":\"coil\",\"header_marker\":\"TRD\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16a\"],\"pulse\":true}", "TRDP"),
    ("{\"form\":\"coil\",\"header_marker\":\"TSUB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A16a}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16a\",\"A16a\"],\"pulse\":false}", "TSUB"),
    ("{\"form\":\"coil\",\"header_marker\":\"TSUB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}:as{vt=A16a}:as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16a\",\"A16a\"],\"pulse\":true}", "TSUBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"TTMR\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16\"],\"pulse\":false}", "TTMR"),
    ("{\"form\":\"coil\",\"header_marker\":\"TWR\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16a\"],\"pulse\":false}", "TWR"),
    ("{\"form\":\"coil\",\"header_marker\":\"TWR\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16a\"],\"pulse\":true}", "TWRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"UNI\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "UNI"),
    ("{\"form\":\"coil\",\"header_marker\":\"UNI\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "UNIP"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/17\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16sa}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16sa\",\"A16s\"],\"pulse\":false}", "VAL"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/18\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16sa}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16sa\",\"A16s\"],\"pulse\":true}", "VALP"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/19\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16ua}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16ua\",\"A16u\"],\"pulse\":false}", "VAL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/20\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16ua}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16ua\",\"A16u\"],\"pulse\":true}", "VALP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/21\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16sa}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16sa\",\"A32s\"],\"pulse\":false}", "DVAL"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/22\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16sa}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16sa\",\"A32s\"],\"pulse\":true}", "DVALP"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/23\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Ass}:as{vt=A16ua}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16ua\",\"A32u\"],\"pulse\":false}", "DVAL_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"VAL\",\"header_operand_tags\":[\"_lid/16135670382422534381/24\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16ua}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"d\",\"d\"],\"operand_vts\":[\"Ass\",\"A16ua\",\"A32u\"],\"pulse\":true}", "DVALP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"WS2SJIS\",\"header_operand_tags\":[\"_lid/16135670382422534381/351\",\"_lid/16135670382422534381/352\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Asd}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Asd\",\"Ass\"],\"pulse\":false}", "WS2SJIS"),
    ("{\"form\":\"coil\",\"header_marker\":\"WS2SJIS\",\"header_operand_tags\":[\"_lid/16135670382422534381/353\",\"_lid/16135670382422534381/354\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Asd}:as{vt=Ass}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Asd\",\"Ass\"],\"pulse\":true}", "WS2SJISP"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSFL\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WSFL"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSFL\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WSFLP"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSFR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WSFR"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSFR\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WSFRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A32s\",\"A16\"],\"pulse\":false}", "WSUM"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A32u\",\"A16\"],\"pulse\":false}", "WSUM_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32a\",\"A16\"],\"pulse\":false}", "DWSUM"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32a\",\"A16\"],\"pulse\":false}", "DWSUM_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A32s}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A32s\",\"A16\"],\"pulse\":true}", "WSUMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A32u}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A32u\",\"A16\"],\"pulse\":true}", "WSUMP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32a\",\"A16\"],\"pulse\":true}", "DWSUMP"),
    ("{\"form\":\"coil\",\"header_marker\":\"WSUM\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32a}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32a\",\"A16\"],\"pulse\":true}", "DWSUMP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"WTOB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WTOB"),
    ("{\"form\":\"coil\",\"header_marker\":\"WTOB\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WTOBP"),
    ("{\"form\":\"coil\",\"header_marker\":\"XCH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "XCH"),
    ("{\"form\":\"coil\",\"header_marker\":\"XCH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "XCHP"),
    ("{\"form\":\"coil\",\"header_marker\":\"XNR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WXNR"),
    ("{\"form\":\"coil\",\"header_marker\":\"XNR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":false}", "DXNR"),
    ("{\"form\":\"coil\",\"header_marker\":\"XNR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WXNRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"XNR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":true}", "DXNRP"),
    ("{\"form\":\"coil\",\"header_marker\":\"XOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":false}", "WXOR"),
    ("{\"form\":\"coil\",\"header_marker\":\"XOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":false}", "DXOR"),
    ("{\"form\":\"coil\",\"header_marker\":\"XOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\",\"A16\"],\"pulse\":true}", "WXORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"XOR\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32}:as{vt=A32}:as{vt=A32}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32\",\"A32\",\"A32\"],\"pulse\":true}", "DXORP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16a}:as{vt=A16a}:as{vt=A16a}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16a\",\"A16a\",\"Aba\"],\"pulse\":false}", "TZCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"Aba\"],\"pulse\":false}", "ZCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"Aba\"],\"pulse\":false}", "ZCP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"Aba\"],\"pulse\":false}", "DZCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"Aba\"],\"pulse\":false}", "DZCP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16a}:as{vt=A16a}:as{vt=A16a}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16a\",\"A16a\",\"A16a\",\"Aba\"],\"pulse\":true}", "TZCPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"Aba\"],\"pulse\":true}", "ZCPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"Aba\"],\"pulse\":true}", "ZCPP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"Aba\"],\"pulse\":true}", "DZCPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"Aba\"],\"pulse\":true}", "DZCPP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"_lid/16135670382422534381/65\",\"_lid/16135670382422534381/66\",\"_lid/16135670382422534381/67\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Aea}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\",\"d\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Aea\",\"Aba\"],\"pulse\":false}", "DEZCP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZCP\",\"header_operand_tags\":[\"_lid/16135670382422534381/68\",\"_lid/16135670382422534381/69\",\"_lid/16135670382422534381/70\",\"M\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}:as{vt=Aea}:as{vt=Aba}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"l\",\"l\",\"l\",\"d\"],\"operand_vts\":[\"Aea\",\"Aea\",\"Aea\",\"Aba\"],\"pulse\":true}", "DEZCPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16s\"],\"pulse\":false}", "ZONE"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16u\"],\"pulse\":false}", "ZONE_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A32s\"],\"pulse\":false}", "DZONE"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A32u\"],\"pulse\":false}", "DZONE_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16s}:as{vt=A16s}:as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\",\"A16s\",\"A16s\"],\"pulse\":true}", "ZONEP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16u}:as{vt=A16u}:as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\",\"A16u\",\"A16u\"],\"pulse\":true}", "ZONEP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32s}:as{vt=A32s}:as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\",\"A32s\",\"A32s\"],\"pulse\":true}", "DZONEP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZONE\",\"header_operand_tags\":[\"D\",\"D\",\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A32u}:as{vt=A32u}:as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\",\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\",\"A32u\",\"A32u\"],\"pulse\":true}", "DZONEP_U"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPOP\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "ZPOP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPOP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "ZPOP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPOPP\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "ZPOPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPOPP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":true}", "ZPOPP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPUSH\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":false}", "ZPUSH"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPUSH\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=a:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":false}", "ZPUSH"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPUSHP\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}:as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16\",\"A16\"],\"pulse\":true}", "ZPUSHP"),
    ("{\"form\":\"coil\",\"header_marker\":\"ZPUSHP\",\"header_operand_tags\":[\"D\"],\"inner_op\":\"op=cl{op=#:ct=p:as=[as{vt=A16}]}\",\"logic_type\":\"\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"A16\"],\"pulse\":true}", "ZPUSHP"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "ANDF"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "ANDP"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Abl}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "LD"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "LDF"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "LDP"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "ORF"),
    ("{\"form\":\"logic\",\"header_marker\":\"A\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "ORP"),
    ("{\"form\":\"logic\",\"header_marker\":\"B\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "ANDFI"),
    ("{\"form\":\"logic\",\"header_marker\":\"B\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "ANDPI"),
    ("{\"form\":\"logic\",\"header_marker\":\"B\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "LDFI"),
    ("{\"form\":\"logic\",\"header_marker\":\"B\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "LDPI"),
    ("{\"form\":\"logic\",\"header_marker\":\"B\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=f:as=[as{vt=Abl}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":false}", "ORFI"),
    ("{\"form\":\"logic\",\"header_marker\":\"B\",\"header_operand_tags\":[\"M\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=p:as=[as{vt=Abl}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\"],\"operand_vts\":[\"Abl\"],\"pulse\":true}", "ORPI"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ANDDT="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ANDTM="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "LDDT="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "LDTM="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ORDT="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ORTM="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "AND="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "AND=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ANDD="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ANDD=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "LD="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "LD=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "LDD="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "LDD=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "OR="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "OR=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ORD="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ORD=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"_lid/16135670382422534381/25\",\"_lid/16135670382422534381/26\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LDE="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"_lid/16135670382422534381/257\",\"_lid/16135670382422534381/258\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "LD$="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"_lid/16135670382422534381/269\",\"_lid/16135670382422534381/270\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "AND$="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"_lid/16135670382422534381/281\",\"_lid/16135670382422534381/282\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "OR$="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"_lid/16135670382422534381/37\",\"_lid/16135670382422534381/38\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ANDE="),
    ("{\"form\":\"logic\",\"header_marker\":\"EQ\",\"header_operand_tags\":[\"_lid/16135670382422534381/49\",\"_lid/16135670382422534381/50\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ORE="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ANDDT>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ANDTM>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "LDDT>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "LDTM>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ORDT>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ORTM>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "AND>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "AND>=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ANDD>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ANDD>=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "LD>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "LD>=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "LDD>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "LDD>=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "OR>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "OR>=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ORD>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ORD>=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"_lid/16135670382422534381/267\",\"_lid/16135670382422534381/268\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "LD$>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"_lid/16135670382422534381/279\",\"_lid/16135670382422534381/280\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "AND$>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"_lid/16135670382422534381/291\",\"_lid/16135670382422534381/292\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "OR$>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"_lid/16135670382422534381/35\",\"_lid/16135670382422534381/36\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LDE>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"_lid/16135670382422534381/47\",\"_lid/16135670382422534381/48\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ANDE>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GE\",\"header_operand_tags\":[\"_lid/16135670382422534381/59\",\"_lid/16135670382422534381/60\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ORE>="),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ANDDT>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ANDTM>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "LDDT>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "LDTM>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ORDT>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ORTM>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "AND>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "AND>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ANDD>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ANDD>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "LD>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "LD>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "LDD>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "LDD>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "OR>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "OR>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ORD>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ORD>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"_lid/16135670382422534381/261\",\"_lid/16135670382422534381/262\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "LD$>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"_lid/16135670382422534381/273\",\"_lid/16135670382422534381/274\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "AND$>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"_lid/16135670382422534381/285\",\"_lid/16135670382422534381/286\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "OR$>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"_lid/16135670382422534381/29\",\"_lid/16135670382422534381/30\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LDE>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"_lid/16135670382422534381/41\",\"_lid/16135670382422534381/42\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ANDE>"),
    ("{\"form\":\"logic\",\"header_marker\":\"GT\",\"header_operand_tags\":[\"_lid/16135670382422534381/53\",\"_lid/16135670382422534381/54\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ORE>"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ANDDT<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ANDTM<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "LDDT<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "LDTM<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ORDT<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ORTM<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "AND<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "AND<=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ANDD<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ANDD<=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "LD<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "LD<=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "LDD<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "LDD<=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "OR<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "OR<=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ORD<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ORD<=_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"_lid/16135670382422534381/263\",\"_lid/16135670382422534381/264\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "LD$<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"_lid/16135670382422534381/275\",\"_lid/16135670382422534381/276\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "AND$<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"_lid/16135670382422534381/287\",\"_lid/16135670382422534381/288\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "OR$<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"_lid/16135670382422534381/31\",\"_lid/16135670382422534381/32\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LDE<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"_lid/16135670382422534381/43\",\"_lid/16135670382422534381/44\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ANDE<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LE\",\"header_operand_tags\":[\"_lid/16135670382422534381/55\",\"_lid/16135670382422534381/56\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ORE<="),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ANDDT<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ANDTM<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "LDDT<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "LDTM<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ORDT<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ORTM<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "AND<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "AND<_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ANDD<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ANDD<_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "LD<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "LD<_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "LDD<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "LDD<_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "OR<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "OR<_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ORD<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ORD<_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"_lid/16135670382422534381/265\",\"_lid/16135670382422534381/266\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "LD$<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"_lid/16135670382422534381/277\",\"_lid/16135670382422534381/278\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "AND$<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"_lid/16135670382422534381/289\",\"_lid/16135670382422534381/290\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "OR$<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"_lid/16135670382422534381/33\",\"_lid/16135670382422534381/34\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LDE<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"_lid/16135670382422534381/45\",\"_lid/16135670382422534381/46\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ANDE<"),
    ("{\"form\":\"logic\",\"header_marker\":\"LT\",\"header_operand_tags\":[\"_lid/16135670382422534381/57\",\"_lid/16135670382422534381/58\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ORE<"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ANDDT<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ANDTM<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "LDDT<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "LDTM<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Adt}:as{vt=Adt}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Adt\",\"Adt\",\"A16\"],\"pulse\":false}", "ORDT<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Atm}:as{vt=Atm}:as{vt=A16}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\",\"d\"],\"operand_vts\":[\"Atm\",\"Atm\",\"A16\"],\"pulse\":false}", "ORTM<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "AND<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "AND<>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ANDD<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ANDD<>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "LD<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "LD<>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "LDD<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "LDD<>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16s}:as{vt=A16s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16s\",\"A16s\"],\"pulse\":false}", "OR<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A16u}:as{vt=A16u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A16u\",\"A16u\"],\"pulse\":false}", "OR<>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32s\",\"A32s\"],\"pulse\":false}", "ORD<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"D\",\"D\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=A32u}:as{vt=A32u}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"d\",\"d\"],\"operand_vts\":[\"A32u\",\"A32u\"],\"pulse\":false}", "ORD<>_U"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"_lid/16135670382422534381/259\",\"_lid/16135670382422534381/260\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "LD$<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"_lid/16135670382422534381/27\",\"_lid/16135670382422534381/28\"],\"inner_op\":\"op=lct{op=#:lt=l:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"l\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "LDE<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"_lid/16135670382422534381/271\",\"_lid/16135670382422534381/272\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "AND$<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"_lid/16135670382422534381/283\",\"_lid/16135670382422534381/284\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ass}:as{vt=Ass}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ass\",\"Ass\"],\"pulse\":false}", "OR$<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"_lid/16135670382422534381/39\",\"_lid/16135670382422534381/40\"],\"inner_op\":\"op=lct{op=#:lt=a:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"a\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ANDE<>"),
    ("{\"form\":\"logic\",\"header_marker\":\"NE\",\"header_operand_tags\":[\"_lid/16135670382422534381/51\",\"_lid/16135670382422534381/52\"],\"inner_op\":\"op=lct{op=#:lt=o:ct=a:as=[as{vt=Ar32}:as{vt=Ar32}]}\",\"logic_type\":\"o\",\"operand_kinds\":[\"l\",\"l\"],\"operand_vts\":[\"Ar32\",\"Ar32\"],\"pulse\":false}", "ORE<>"),
)
# END APPROVED_OPCODE_ROWS

# Source-derived parser observation.
# deliberately bypass the semantic table below so no tag, arity or pulse
# generalization can turn one observed serialization into a wildcard.
_SOURCE_AUTHORIZED_ROWS: tuple[tuple[OpcodeSignature, str], ...] = (
    (
        OpcodeSignature(
            "coil", "SET", "", False,
            ("A16", "A16", "Abl"), ("d", "d", "d"), ("T", "D", "F"),
            "op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=Abl}]}",
        ),
        "ANS",
    ),
    (
        OpcodeSignature(
            "coil", "SET", "", False,
            ("A16", "A16", "Abl"), ("d", "c", "d"), ("T", "K_1", "F"),
            "op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=Abl}]}",
        ),
        "ANS",
    ),
    (
        OpcodeSignature(
            "coil", "AddOpe", "", False,
            ("A32s", "A32s"), ("c", "d"), ("K_2", "Z"),
            "op=cl{op=#:ct=a:as=[as{vt=A32s}:as{vt=A32s}]}",
        ),
        "D+",
    ),
    (
        OpcodeSignature(
            "coil", "SP_SOCOPEN", "", True,
            ("Ass", "A16", "A16a", "Aba"), ("c", "c", "d", "d"),
            ("String", "u0", '"u0"', "K_1", "D", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}",
        ),
        "SP.SOCOPEN",
    ),
    (
        OpcodeSignature(
            "coil", "SP_SOCCLOSE", "", True,
            ("Ass", "A16", "A16a", "Aba"), ("c", "c", "d", "d"),
            ("String", "u0", '"u0"', "K_1", "D", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}",
        ),
        "SP.SOCCLOSE",
    ),
    (
        OpcodeSignature(
            "coil", "SP_SOCOPEN", "", True,
            ("Ass", "A16", "A16a", "Aba"), ("c", "c", "d", "d"),
            ("String", "U0", '"U0"', "K_1", "D", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}",
        ),
        "SP.SOCOPEN",
    ),
    (
        OpcodeSignature(
            "coil", "SP_SOCCLOSE", "", True,
            ("Ass", "A16", "A16a", "Aba"), ("c", "c", "d", "d"),
            ("String", "U0", '"U0"', "K_1", "D", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16a}:as{vt=Aba}]}",
        ),
        "SP.SOCCLOSE",
    ),
    (
        OpcodeSignature(
            "coil", "SP_SOCRCV", "", True,
            ("Ass", "A16", "A16a", "A16", "Aba"),
            ("c", "c", "d", "d", "d"),
            ("String", "U0", '"U0"', "K_1", "D", "D", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16a}:as{vt=A16}:as{vt=Aba}]}",
        ),
        "SP.SOCRCV",
    ),
    (
        OpcodeSignature(
            "coil", "SP_SOCSND", "", True,
            ("Ass", "A16", "A16a", "A16", "Aba"),
            ("c", "c", "d", "d", "d"),
            ("String", "U0", '"U0"', "K_1", "D", "D", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Ass}:as{vt=A16}:as{vt=A16a}:as{vt=A16}:as{vt=Aba}]}",
        ),
        "SP.SOCSND",
    ),
    (
        OpcodeSignature(
            "coil", "RST", "", True,
            ("Aea", "Aea"), ("d", "d"), ("M", "M"),
            "op=cl{op=#:ct=p:as=[as{vt=Aea}:as{vt=Aea}]}",
        ),
        "ZRSTP",
    ),
    (
        OpcodeSignature(
            "coil", "FOR", "", False, ("A16",), ("c",), ("K_1", "32"),
            "op=cl{op=#:ct=a:as=[as{vt=A16}]}",
        ),
        "FOR",
    ),
)

OPCODE_TABLE: dict[str, str] = freeze_table(_APPROVED_ROWS)
SOURCE_AUTHORIZED_OPCODE_TABLE: dict[str, str] = freeze_table(_SOURCE_AUTHORIZED_ROWS)
SEMANTIC_OPCODE_TABLE: dict[str, str] = freeze_table(
    (semantic_signature(signature_from_key(key)), mnemonic)
    for key, mnemonic in _APPROVED_ROWS
)


def replace_approved_rows(
    module_source: str, table: Mapping[str, str]
) -> str:
    begin = "# BEGIN APPROVED_OPCODE_ROWS\n"
    end = "# END APPROVED_OPCODE_ROWS\n"
    start = module_source.find(begin)
    stop = module_source.find(end)
    if start < 0 or stop < 0 or stop <= start:
        raise ValueError("opcode signature module is missing approved-row markers")
    rows = ",\n".join(
        f"    ({json.dumps(key, ensure_ascii=True)}, {json.dumps(mnemonic, ensure_ascii=True)})"
        for key, mnemonic in sorted(table.items())
    )
    body = "_APPROVED_ROWS: tuple[tuple[str, str], ...] = (\n" + (
        rows + ",\n" if rows else ""
    ) + ")\n"
    return module_source[: start + len(begin)] + body + module_source[stop:]
