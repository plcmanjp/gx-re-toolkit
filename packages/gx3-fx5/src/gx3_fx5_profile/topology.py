"""Discover project and POU topology using relations inside one GX3 snapshot."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import unicodedata
from typing import Any

from gx3_core import Finding, SafeGx3Archive, parse_xml


def _digest(archive: SafeGx3Archive, name: str) -> str:
    return archive.digest(name)


def _entry_ci(archive: SafeGx3Archive, expected: str) -> str:
    matches = [
        name for name in archive.entries if name.casefold() == expected.casefold()
    ]
    if len(matches) != 1:
        raise ValueError(f"GX3 must contain exactly one {expected}")
    return matches[0]


def discover_project(archive: SafeGx3Archive) -> dict[str, Any]:
    config_entry = _entry_ci(archive, "Config.xml")
    root = parse_xml(archive.read(config_entry))
    config = root if root.tag == "Config" else root.find(".//Config")
    if config is None:
        raise ValueError("Config.xml has no Config element")
    title = config.get("Title", "")
    return {
        "cpu": config.get("Unit", ""),
        "unit_id": config.get("UnitId", ""),
        "title_digest": hashlib.sha256(title.encode("utf-8")).hexdigest(),
        "provenance": {
            "source_entry": config_entry,
            "source_locator": "/Config/@Unit,/Config/@UnitId,/Config/@Title",
            "source_digest": _digest(archive, config_entry),
            "relation_evidence": "single normalized Config.xml entry",
        },
    }


def _utf16_strings(body: bytes) -> list[str]:
    ascii_pattern = rb"(?:[ -~]\x00){2,}"
    ascii_names = sorted(
        {
            match.group().decode("utf-16le")
            for match in re.finditer(ascii_pattern, body)
            if re.fullmatch(r"[A-Za-z0-9_]+", match.group().decode("utf-16le"))
            and not match.group().decode("utf-16le").isdecimal()
        }
    )
    if ascii_names:
        return ascii_names
    found: set[str] = set()
    for offset in (0, 1):
        chars: list[str] = []
        for index in range(offset, len(body) - 1, 2):
            code = int.from_bytes(body[index : index + 2], "little")
            char = chr(code)
            category = unicodedata.category(char)
            if char == "_" or char.isalnum() or category.startswith("L"):
                chars.append(char)
            else:
                if 2 <= len(chars) <= 128:
                    found.add("".join(chars))
                chars = []
        if 2 <= len(chars) <= 128:
            found.add("".join(chars))
    candidates = sorted(
        value for value in found if not value.isdecimal() and not value.startswith("@")
    )
    ascii_candidates = [
        value
        for value in candidates
        if any(char.isascii() and char.isalnum() for char in value)
    ]
    return ascii_candidates or candidates


def _program_names(body: bytes, expected_count: int) -> list[str]:
    """Read the observed length-prefixed Program.qpg identifier table.

    Token scanning is retained solely for the old singleton fixture layout.
    A multi-POU archive must expose exactly ``expected_count`` length-prefixed,
    file-safe names in table order; adjacent captions and text never qualify.
    """
    names: list[str] = []
    for offset in range(2, len(body) - 1):
        byte_length = int.from_bytes(body[offset - 2 : offset], "little")
        if byte_length < 4 or byte_length > 130 or byte_length % 2:
            continue
        if offset + byte_length > len(body):
            continue
        if body[offset + byte_length - 2 : offset + byte_length] != b"\x00\x00":
            continue
        try:
            name = body[offset : offset + byte_length - 2].decode("utf-16le")
        except UnicodeDecodeError:
            continue
        if re.fullmatch(r"[A-Za-z0-9_]{1,64}", name):
            names.append(name)
    if len(names) == expected_count and len(set(name.casefold() for name in names)) == len(names):
        return names
    if expected_count == 1:
        fallback = _utf16_strings(body)
        return fallback if len(fallback) == 1 else []
    return []


def _link_ids(body: bytes) -> list[str]:
    values = [match.decode("ascii") for match in re.findall(rb"\d+", body)]
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _block_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if normalized.casefold().startswith("_guid/"):
        normalized = normalized[6:]
    normalized = normalized.strip("{}").casefold()
    return normalized or None


def _connection(archive: SafeGx3Archive, entry: str) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.deserialize(archive.read(entry))
    connection.execute("PRAGMA query_only = ON")
    return connection


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}


def _lddb_step_relation(
    archive: SafeGx3Archive, lddb: str, step_info: str
) -> dict[str, float] | None:
    """Return a proven LadderBlocks to StepInfo block identity relation."""
    ladder: sqlite3.Connection | None = None
    step: sqlite3.Connection | None = None
    try:
        ladder = _connection(archive, lddb)
        step = _connection(archive, step_info)
        if {"id", "pos"} - _columns(ladder, "LadderBlocks"):
            return None
        tables = {row[0] for row in step.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"T_Block", "T_Step"}.issubset(tables):
            return None
        if {"Pos", "BlockID"} - _columns(step, "T_Block"):
            return None
        if {"Pos", "BlockID", "MilID"} - _columns(step, "T_Step"):
            return None
        ladder_rows = list(ladder.execute("SELECT id,pos FROM LadderBlocks ORDER BY pos,id"))
        step_blocks = list(step.execute("SELECT Pos,BlockID FROM T_Block ORDER BY Pos,BlockID"))
        step_rows = list(step.execute("SELECT BlockID FROM T_Step ORDER BY Pos,BlockID,MilID"))
    except sqlite3.DatabaseError:
        return None
    finally:
        if ladder is not None:
            ladder.close()
        if step is not None:
            step.close()
    ladder_by_id: dict[str, float] = {}
    for raw_id, position in ladder_rows:
        block = _block_id(raw_id)
        if block is None or not isinstance(position, (int, float)) or block in ladder_by_id:
            return None
        ladder_by_id[block] = float(position)
    step_by_id: dict[str, float] = {}
    for position, raw_id in step_blocks:
        block = _block_id(raw_id)
        if (
            block is None
            or not isinstance(position, (int, float))
            or block in step_by_id
        ):
            return None
        step_by_id[block] = float(position)
    step_row_ids = {_block_id(row[0]) for row in step_rows}
    if None in step_row_ids:
        return None
    if (
        not ladder_by_id
        or ladder_by_id != step_by_id
        or not step_row_ids.issubset(step_by_id)
    ):
        return None
    return ladder_by_id


def _mil_relation(
    archive: SafeGx3Archive, mildb: str, ladder_by_id: dict[str, float]
) -> bool:
    connection: sqlite3.Connection | None = None
    try:
        connection = _connection(archive, mildb)
        if {"id", "pos"} - _columns(connection, "MIL"):
            return False
        rows = list(connection.execute("SELECT id,pos FROM MIL ORDER BY pos,id"))
    except sqlite3.DatabaseError:
        return False
    finally:
        if connection is not None:
            connection.close()
    mil_by_id: dict[str, float] = {}
    for raw_id, position in rows:
        block = _block_id(raw_id)
        if block is None or not isinstance(position, (int, float)) or block in mil_by_id:
            return False
        mil_by_id[block] = float(position)
    return mil_by_id == ladder_by_id


def _mil_is_empty_cache(archive: SafeGx3Archive, mildb: str) -> bool:
    """Accept cache absence only for an exact empty MIL table schema."""
    connection: sqlite3.Connection | None = None
    try:
        connection = _connection(archive, mildb)
        if {"id", "pos", "data"} - _columns(connection, "MIL"):
            return False
        return connection.execute("SELECT COUNT(*) FROM MIL").fetchone() == (0,)
    except sqlite3.DatabaseError:
        return False
    finally:
        if connection is not None:
            connection.close()


def _assign_dynamic_database_pairs(
    archive: SafeGx3Archive,
    ordered: list[dict[str, Any]],
    lddbs: dict[str, str],
    mildbs: dict[str, str],
) -> tuple[set[str], set[str], set[str]]:
    """Preserve each independently proven StepInfo-LDDB and LDDB-MilDB link."""
    lddb_candidates: list[
        tuple[dict[str, Any], list[tuple[str, dict[str, float]]]]
    ] = []
    for pou in ordered:
        step_info = pou["relations"]["step_info"]
        if step_info is None:
            lddb_candidates.append((pou, []))
            continue
        candidates: list[tuple[str, dict[str, float]]] = []
        for stem, lddb in lddbs.items():
            relation = _lddb_step_relation(archive, lddb, step_info)
            if relation is not None:
                candidates.append((stem, relation))
        lddb_candidates.append((pou, candidates))

    unique_lddb_claims: dict[str, int] = {}
    for _pou, candidates in lddb_candidates:
        if len(candidates) == 1:
            stem = candidates[0][0]
            unique_lddb_claims[stem] = unique_lddb_claims.get(stem, 0) + 1

    lddb_assignments: list[tuple[dict[str, Any], str, dict[str, float]]] = []
    for pou, candidates in lddb_candidates:
        if len(candidates) != 1:
            continue
        stem, ladder_by_id = candidates[0]
        if unique_lddb_claims[stem] == 1:
            lddb_assignments.append((pou, stem, ladder_by_id))

    mildb_candidates: list[tuple[dict[str, Any], str, list[str]]] = []
    for pou, lddb_stem, ladder_by_id in lddb_assignments:
        candidates = [
            mil_stem
            for mil_stem, mildb in mildbs.items()
            if _mil_relation(archive, mildb, ladder_by_id)
        ]
        mildb_candidates.append((pou, lddb_stem, candidates))

    unique_mildb_claims: dict[str, int] = {}
    for _pou, _lddb_stem, candidates in mildb_candidates:
        if len(candidates) == 1:
            stem = candidates[0]
            unique_mildb_claims[stem] = unique_mildb_claims.get(stem, 0) + 1

    assigned_lddb: set[str] = set()
    assigned_mildb: set[str] = set()
    empty_mildb: set[str] = set()
    for pou, lddb_stem, _ladder_by_id in lddb_assignments:
        pou["relations"]["lddb"] = lddbs[lddb_stem]
        pou["provenance"]["relation_evidence"] += (
            "; unique StepInfo-LDDB block identity relation"
        )
        assigned_lddb.add(lddb_stem)
    for pou, _lddb_stem, candidates in mildb_candidates:
        if len(candidates) != 1:
            continue
        mildb_stem = candidates[0]
        if unique_mildb_claims[mildb_stem] != 1:
            continue
        pou["relations"]["mildb"] = mildbs[mildb_stem]
        pou["provenance"]["relation_evidence"] += (
            "; unique LDDB-MilDB block identity and position relation"
        )
        assigned_mildb.add(mildb_stem)
    for pou, lddb_stem, candidates in mildb_candidates:
        if candidates or lddb_stem not in mildbs:
            continue
        if _mil_is_empty_cache(archive, mildbs[lddb_stem]):
            pou["provenance"]["relation_evidence"] += (
                "; same-stem MilDB has an exact empty MIL cache"
            )
            empty_mildb.add(lddb_stem)
    return assigned_lddb, assigned_mildb, empty_mildb


def discover_pous(archive: SafeGx3Archive) -> dict[str, Any]:
    links = sorted(
        name
        for name in archive.entries
        if re.fullmatch(r"ConvertData/\d+/PouLinkOrder\.info", name)
    )
    findings: list[Finding] = []
    ordered: list[dict[str, Any]] = []
    order = 0
    if len(links) > 1:
        findings.append(
            Finding(
                "FX5_LINK_CONTAINER_ORDER_AMBIGUOUS",
                "project",
                "execution_order",
                "ConvertData/*/PouLinkOrder.info",
                hashlib.sha256("\n".join(links).encode("utf-8")).hexdigest(),
                "Multiple link-order containers do not serialize a global ordering relation",
                "SOURCE_GLOBAL_ORDER_NOT_SERIALIZED",
            )
        )
    for link in links:
        container = link.rsplit("/", 1)[0]
        qpg = f"{container}/Program.qpg"
        ids = _link_ids(archive.read(link))
        names = _program_names(archive.read(qpg), len(ids)) if qpg in archive.entries else []
        names_match = len(names) == len(ids)
        if not names_match:
            findings.append(
                Finding(
                    "FX5_POU_NAME_RELATION_AMBIGUOUS",
                    "project",
                    "pou_name",
                    qpg,
                    _digest(archive, qpg) if qpg in archive.entries else "",
                    f"linked_pou_count={len(ids)}; candidate_name_count={len(names)}; only singleton identity is proven",
                )
            )
        for local_index, pou_id in enumerate(ids):
            step = f"{pou_id}_StepInfo.db"
            pcode = f"ConvertData/{pou_id}/PouPCode.pcode"
            missing = [entry for entry in (step, pcode) if entry not in archive.entries]
            if missing:
                findings.append(
                    Finding(
                        "FX5_POU_OBJECT_MISSING",
                        "pou",
                        "topology",
                        pou_id,
                        "",
                        "missing related entries: " + ",".join(missing),
                    )
                )
            ordered.append(
                {
                    "pou_id": pou_id,
                    "name": names[local_index] if names_match else None,
                    "language": "Ladder",
                    "execution_order": order if len(links) == 1 else None,
                    "program_kind": "program",
                    "relations": {
                        "link_order": link,
                        "program_qpg": qpg if qpg in archive.entries else None,
                        "step_info": step if step in archive.entries else None,
                        "pcode": pcode if pcode in archive.entries else None,
                        "lddb": None,
                        "mildb": None,
                    },
                    "provenance": {
                        "source_entry": link,
                        "source_locator": f"numeric-token[{local_index}]",
                        "source_digest": _digest(archive, link),
                        "relation_evidence": "PouLinkOrder ID with same-ID StepInfo and PouPCode entries",
                    },
                }
            )
            order += 1

    lddbs = {
        name[:-8]: name
        for name in archive.entries
        if re.fullmatch(r"[^/]+_LDDB\.db", name)
    }
    mildbs = {
        name[:-9]: name
        for name in archive.entries
        if re.fullmatch(r"[^/]+_MilDB\.db", name)
    }
    paired = sorted(set(lddbs) & set(mildbs))
    assigned_lddb: set[str] = set()
    assigned_mildb: set[str] = set()
    empty_mildb: set[str] = set()
    if len(ordered) == 1 and len(paired) == 1:
        stem = paired[0]
        ordered[0]["relations"]["lddb"] = lddbs[stem]
        assigned_lddb.add(stem)
        if _mil_is_empty_cache(archive, mildbs[stem]):
            ordered[0]["provenance"]["relation_evidence"] += (
                "; unique singleton LDDB with same-stem exact empty MIL cache"
            )
            empty_mildb.add(stem)
        else:
            ordered[0]["relations"]["mildb"] = mildbs[stem]
            ordered[0]["provenance"]["relation_evidence"] += (
                "; unique singleton LDDB/MilDB pair"
            )
            assigned_mildb.add(stem)
    elif len(ordered) > 1 and len(paired) == len(ordered):
        assigned_lddb, assigned_mildb, empty_mildb = (
            _assign_dynamic_database_pairs(archive, ordered, lddbs, mildbs)
        )
    elif paired:
        findings.append(
            Finding(
                "FX5_POU_DATABASE_RELATION_AMBIGUOUS",
                "project",
                "pou_database",
                "*_LDDB.db,*_MilDB.db",
                hashlib.sha256("\n".join(paired).encode("ascii")).hexdigest(),
                f"pou_count={len(ordered)}; paired_database_count={len(paired)}; no proven per-POU relation",
            )
        )

    assigned_pairs = assigned_lddb & (assigned_mildb | empty_mildb)
    if paired and len(assigned_pairs) != len(paired) and not any(
        item.code == "FX5_POU_DATABASE_RELATION_AMBIGUOUS" for item in findings
    ):
        findings.append(
            Finding(
                "FX5_POU_DATABASE_RELATION_AMBIGUOUS",
                "project",
                "pou_database",
                "*_LDDB.db,*_MilDB.db",
                hashlib.sha256("\n".join(paired).encode("ascii")).hexdigest(),
                f"pou_count={len(ordered)}; paired_database_count={len(paired)}; no unique StepInfo-LDDB-MilDB relation",
            )
        )
    return {
        "pous": ordered,
        "unassigned_database_pairs": [
            {
                "stem_digest": hashlib.sha256(stem.encode("ascii")).hexdigest(),
                "lddb": lddbs[stem],
                "mildb": mildbs[stem],
            }
            for stem in paired
            if stem not in assigned_pairs
        ],
        "findings": [finding.to_dict() for finding in findings],
    }
