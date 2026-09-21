from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any
import xml.etree.ElementTree as ET

from . import TOOL_VERSION
from .archive import ArchiveError, SafeGx3Archive, sha256_file, sqlite_connection
from .schema_validator import SchemaValidationError, validate as validate_against_schema
from .signatures import FORM_SIGNATURES
from .provenance import source_commit


class MiningRequired(ValueError):
    pass



def parse(source) -> dict[str, Any]:
    try:
        archive = SafeGx3Archive(source)
    except (ArchiveError, OSError) as error:
        return _fatal("0" * 64, str(error), read_only_unchanged=False)
    profile, findings = _detect_profile(archive)
    if profile["decision"] != "SUPPORTED":
        ir = _envelope(archive, profile, [], [], [], findings, {"total": 0, "decoded": 0, "partial": 0, "unknown": 0}, {"total": 0, "decoded": 0, "partial": 0, "unknown": 0})
        validate_ir(ir)
        return ir
    topology, topology_findings = _topology(archive)
    findings.extend(topology_findings)
    pous: list[dict[str, Any]] = []
    candidate_pairs = {item["pou_id"]: _candidate_pairs(archive, item) for item in topology["pous"]}
    pair_users: dict[tuple[str, str], list[str]] = {}
    for pou_id, candidates in candidate_pairs.items():
        if len(candidates) == 1:
            pair_users.setdefault(candidates[0], []).append(pou_id)
    ambiguous_pous = {
        pou_id
        for users in pair_users.values()
        if len(users) > 1
        for pou_id in users
    }
    for item in topology["pous"]:
        if item["pou_id"] in ambiguous_pous:
            records = []
            local_findings = [_finding("MINING_REQUIRED", "topology", f"pou:{item['pou_id']}", "LDDB/MilDB carrier pair is ambiguous across POU")]
        else:
            records, local_findings = _decode_pou(archive, item, candidate_pairs[item["pou_id"]])
        pous.append({**item, "records": records})
        findings.extend(local_findings)
    comments, comment_findings, comment_coverage = _carrier_census(archive, "comment")
    labels, label_findings, label_coverage = _carrier_census(archive, "label")
    findings.extend(comment_findings + label_findings)
    after = sha256_file(source)
    if archive.input_sha256 != after:
        return _fatal(archive.input_sha256, "input SHA-256 changed during read")
    ir = _envelope(archive, profile, pous, comments, labels, findings, comment_coverage, label_coverage)
    validate_ir(ir)
    return ir


def _fatal(digest: str, reason: str, *, read_only_unchanged: bool = False) -> dict[str, Any]:
    provenance = {"source_entry": "archive", "source_store": "ZIP", "source_locator": "archive", "source_digest": digest, "relation_evidence": ["fatal container gate"]}
    finding = {"finding_code": "MINING_REQUIRED", "scope": "project", "object_kind": "profile", "locator": "archive", "digest": digest, "reason": "FATAL: " + reason}
    return {"report_name": "plcman.gx3.run-report", "report_version": "1.0.0", "status": "FATAL", "producer": {"package": "gx3-r-parser-toolkit", "version": TOOL_VERSION, "source_commit": source_commit()}, "input": {"display_id": digest[:16], "byte_count": 0, "sha256": digest, "read_only_unchanged": read_only_unchanged}, "findings": [finding]}


def _detect_profile(archive: SafeGx3Archive) -> tuple[dict[str, Any], list[dict[str, str]]]:
    evidence = [name for name in ("Config.xml", "!!Config.xml") if name in archive.entries]
    if len(evidence) != 2 or archive.entries[evidence[0]] != archive.entries[evidence[1]]:
        return {"profile_id": "mitsubishi.gx3.r04cpu.ladder", "decision": "AMBIGUOUS", "evidence": evidence}, [_finding("MINING_REQUIRED", "profile", "Config.xml", "dual Config evidence is missing or differs")]
    try:
        root = ET.fromstring(archive.entries["Config.xml"].decode("utf-8-sig"))
        config = root.find(".//Config")
        if config is None:
            unit, unit_id = None, None
        else:
            unit, unit_id = config.attrib.get("Unit"), config.attrib.get("UnitId")
    except (UnicodeDecodeError, ET.ParseError, AttributeError):
        unit, unit_id = None, None
    if (unit, str(unit_id)) == ("R04", "4097"):
        decision, reason = "SUPPORTED", None
    elif unit is not None and unit_id is not None:
        decision, reason = "UNSUPPORTED", "Config explicitly selects a non-R04CPU Unit/UnitId"
    else:
        decision, reason = "AMBIGUOUS", "R04CPU Unit/UnitId evidence is absent or ambiguous"
    findings = [] if reason is None else [_finding("MINING_REQUIRED", "profile", "Config.xml", reason)]
    return {"profile_id": "mitsubishi.gx3.r04cpu.ladder", "decision": decision, "config_unit": unit, "config_unit_id": str(unit_id) if unit_id is not None else None, "evidence": evidence}, findings


def _topology(archive: SafeGx3Archive) -> tuple[dict[str, Any], list[dict[str, str]]]:
    order_paths = sorted(name for name in archive.entries if name.endswith("/PouLinkOrder.info"))
    findings: list[dict[str, str]] = []
    pous: list[dict[str, Any]] = []
    seen: set[str] = set()
    for order_path in order_paths:
        try:
            ids = [line.strip() for line in archive.entries[order_path].decode("ascii").splitlines() if line.strip()]
        except UnicodeDecodeError:
            findings.append(_finding("MINING_REQUIRED", "topology", order_path, "POU order is not ASCII")); continue
        program_root = order_path.rsplit("/", 1)[0]
        qpg_path = program_root + "/Program.qpg"
        names = _qpg_names(archive.entries.get(qpg_path, b""))
        names_match = names is not None and len(names) == len(ids)
        if not names_match:
            findings.append(_finding("MINING_REQUIRED", "topology", qpg_path, "POU name slots are absent, malformed, or do not match PouLinkOrder cardinality"))
        for original_ordinal, pou_id in enumerate(ids):
            if not pou_id.isdecimal() or pou_id in seen:
                findings.append(_finding("MINING_REQUIRED", "topology", order_path, "invalid or duplicate POU id")); continue
            seen.add(pou_id)
            step = f"{pou_id}_StepInfo.db"
            pcode = f"ConvertData/{pou_id}/PouPCode.pcode"
            if step not in archive.entries or pcode not in archive.entries:
                findings.append(_finding("MINING_REQUIRED", "topology", f"pou:{pou_id}", "StepInfo or PCode carrier missing"))
            pous.append({"pou_id": pou_id, "order": len(pous), "program_container": program_root, "name": names[original_ordinal] if names_match else None, "stepinfo": step, "pcode": pcode})
    if not pous:
        findings.append(_finding("MINING_REQUIRED", "topology", "PouLinkOrder.info", "no internally evidenced POU"))
    if len(order_paths) > 1:
        findings.append(_finding("MINING_REQUIRED", "topology", "project", "multiple POU containers have no evidenced global execution order"))
        for item in pous:
            findings.append(_finding("MINING_REQUIRED", "topology", f"pou:{item['pou_id']}", "global execution order across POU containers is unmined"))
    return {"pous": pous}, findings


def _qpg_names(data: bytes) -> list[str] | None:
    # Names are accepted only when the complete carrier is an exact UTF-16LE
    # slot stream. Skipping an unparsed slot would silently shift later names.
    if not data or len(data) % 2:
        return None
    try:
        decoded = data.decode("utf-16le")
    except UnicodeDecodeError:
        return None
    slots = decoded.split("\0")
    if slots and slots[-1] == "":
        slots.pop()
    if not slots or any(not slot or any(not char.isprintable() for char in slot) for slot in slots):
        return None
    return slots


def _block_key(value: object) -> str:
    return str(value).removeprefix("_guid/").strip("{}").casefold()


def _candidate_pairs(archive: SafeGx3Archive, pou: dict[str, Any]) -> list[tuple[str, str]]:
    try:
        step = sqlite_connection(archive.entries[pou["stepinfo"]])
        block_rows = list(step.execute("SELECT Pos,BlockID FROM T_Block ORDER BY Pos,BlockID"))
    except Exception:
        return []
    finally:
        if "step" in locals():
            step.close()
    blocks = {_block_key(row[1]) for row in block_rows}
    candidates: list[tuple[str, str]] = []
    for lddb_name in sorted(name for name in archive.entries if name.endswith("_LDDB.db")):
        mil_name = lddb_name[:-len("_LDDB.db")] + "_MilDB.db"
        if mil_name not in archive.entries:
            continue
        try:
            db = sqlite_connection(archive.entries[lddb_name])
            raw_ids = [_block_key(row[0]) for row in db.execute("SELECT id FROM LadderBlocks")]
            db.close()
            ids = set(raw_ids)
            if ids and ids == blocks and len(raw_ids) == len(ids):
                candidates.append((lddb_name, mil_name))
        except Exception:
            continue
    return candidates


def _decode_pou(archive: SafeGx3Archive, pou: dict[str, Any], candidates: list[tuple[str, str]] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    try:
        step = sqlite_connection(archive.entries[pou["stepinfo"]])
        block_rows = list(step.execute("SELECT Pos,BlockID FROM T_Block ORDER BY Pos,BlockID"))
        step_rows = list(step.execute("SELECT Pos,BlockID,StepSize FROM T_Step ORDER BY Pos,BlockID"))
    except Exception:
        return [], [_finding("MINING_REQUIRED", "topology", f"pou:{pou['pou_id']}", "StepInfo table shape is unmined")]
    finally:
        if 'step' in locals(): step.close()
    blocks = {_block_key(row[1]) for row in block_rows}
    block_keys = [_block_key(row[1]) for row in block_rows]
    step_keys = [_block_key(row[1]) for row in step_rows]
    if len(block_keys) != len(set(block_keys)) or any(key not in blocks for key in step_keys) or not step_rows:
        return [], [_finding("MINING_REQUIRED", "topology", f"pou:{pou['pou_id']}", "StepInfo block or step relation is duplicate or orphaned")]
    if candidates is None:
        candidates = _candidate_pairs(archive, pou)
    if len(candidates) != 1:
        return [], [_finding("MINING_REQUIRED", "topology", f"pou:{pou['pou_id']}", "LDDB/MilDB relation is absent or ambiguous")]
    lddb_name, mil_name = candidates[0]
    lddb, mildb = sqlite_connection(archive.entries[lddb_name]), sqlite_connection(archive.entries[mil_name])
    try:
        ladder_rows = list(lddb.execute("SELECT id,pos,blocktype,data FROM LadderBlocks ORDER BY pos,id"))
        mil_rows = list(mildb.execute("SELECT id,pos,data FROM MIL ORDER BY pos,id"))
        ladder = {_block_key(row[0]): row for row in ladder_rows}
        mil = {_block_key(row[0]): row for row in mil_rows}
    except Exception:
        return [], [_finding("MINING_REQUIRED", "record", f"pou:{pou['pou_id']}", "LadderBlocks/MIL schema is unmined")]
    finally:
        lddb.close(); mildb.close()
    if len(ladder_rows) != len(ladder) or len(mil_rows) != len(mil) or len(ladder) != len(blocks) or len(mil) != len(blocks) or set(ladder) != blocks or set(mil) != blocks or set(ladder) != set(mil):
        return [], [_finding("MINING_REQUIRED", "topology", f"pou:{pou['pou_id']}", "StepInfo/LDDB/MilDB block relation is not an exact bijection")]
    sizes = Counter({_block_key(row[1]): int(row[2]) for row in step_rows if isinstance(row[2], int)})
    step_sizes: dict[str, list[int]] = {}
    for row in step_rows:
        if isinstance(row[2], int):
            step_sizes.setdefault(_block_key(row[1]), []).append(int(row[2]))
    records: list[dict[str, Any]] = []
    current_step = 0
    for block_id in [_block_key(row[1]) for row in block_rows]:
        data = mil.get(block_id, (None, None, None))[2]
        locator = f"pou:{pou['pou_id']}/{mil_name}:MIL[id={block_id}]"
        digest = hashlib.sha256(str(data).encode()).hexdigest()
        try:
            decoded = _decode_mil(str(data))
            if not decoded: raise MiningRequired("empty MIL decode")
            block_sizes = step_sizes.get(block_id, [])
            if len(block_sizes) != len(decoded): raise MiningRequired("StepInfo instruction cardinality is unmined")
            for decoded_index, (opcode, operands) in enumerate(decoded):
                rid = f"{pou['pou_id']}:{len(records)}"
                primary = operands[:1]
                provenance = _provenance(mil_name, "MIL", locator, digest, len(archive.entries[mil_name]))
                records.append({"record_id": rid, "sequence": len(records), "kind": "instruction", "step": current_step, "opcode": opcode, "operands": [_operand(value, index, provenance) for index, value in enumerate(primary)], "text": None, "status": "decoded", "continues_record_id": None, "provenance": provenance})
                for value in operands[1:]:
                    records.append({"record_id": f"{rid}:operand:{len(records)}", "sequence": len(records), "kind": "continuation", "step": None, "opcode": None, "operands": [_operand(value, 0, provenance)], "text": None, "status": "decoded", "continues_record_id": rid, "provenance": provenance})
                current_step += block_sizes[decoded_index]
        except MiningRequired as error:
            unknown_sizes = step_sizes.get(block_id, [])
            if not unknown_sizes: unknown_sizes = [1]
            for size in unknown_sizes:
                records.append({"record_id": f"{pou['pou_id']}:{len(records)}", "sequence": len(records), "kind": "opaque", "step": current_step, "opcode": None, "operands": [], "text": None, "status": "unknown", "continues_record_id": None, "provenance": _provenance(mil_name, "MIL", locator, digest, len(archive.entries[mil_name]))})
                current_step += size
            findings.append(_finding("MINING_REQUIRED", "record", locator, str(error), digest))
    return records, findings


def _decode_form_stream(data: str) -> list[tuple[str, list[str]]]:
    header, separator, payload = data.partition(":ms{el=[")
    if not separator or not payload.endswith("]}"):
        raise MiningRequired("unrecognized MIL envelope")
    semantic = _consume_header(header)
    inner = payload[:-2]
    starts = list(re.finditer(r"mc\{op=(?:lct|cl|sct)", inner))
    if not starts:
        raise MiningRequired("MIL has no accepted segments")
    if starts[0].start() != 0:
        raise MiningRequired("MIL payload leading bytes are unconsumed")
    segments: list[str] = []
    for index, match in enumerate(starts):
        raw = inner[match.start():starts[index + 1].start() if index + 1 < len(starts) else len(inner)]
        if raw.endswith(":"):
            raw = raw[:-1]
        segments.append(raw)
    if len(semantic) != len(segments):
        raise MiningRequired("header and segment cardinality is unmined")
    decoded: list[tuple[str, list[str]]] = []
    for header_form, raw in zip(semantic, segments, strict=True):
        canonical = re.sub(r"(?<=[av]=)-?\d+", "#", raw)
        candidates = []
        for opcode, form in FORM_SIGNATURES.items():
            if form["segment"] != canonical:
                continue
            if header_form[0] == "contact" and form.get("marker") == header_form[1]:
                candidates.append((opcode, form))
            elif header_form[0] == "header" and form.get("header") == header_form[1]:
                candidates.append((opcode, form))
        if len(candidates) != 1:
            raise MiningRequired("unapproved R04 form signature")
        opcode, form = candidates[0]
        values = [device or constant for device, constant in re.findall(r"(?:d\{s=#:a=(-?\d+)|c\{s=#:v=(-?\d+))", raw)]
        kinds = form["operands"]
        if len(values) != len(kinds):
            raise MiningRequired("form operand arity is unmined")
        decoded.append((opcode, [kind + value for kind, value in zip(kinds, values, strict=True)]))
    return decoded


def _consume_header(header: str) -> list[tuple[str, str]]:
    tokens = header.split(":")
    if len(tokens) < 3 or tokens[0] != "V1" or not tokens[1].isdecimal():
        raise MiningRequired("unrecognized MIL header")
    semantic_start = next((index for index, token in enumerate(tokens[2:], 2) if token in {"A", "B", "OUT", "SET", "RST", "MOV", "BMOV", "FMOV", "ANB", "ORB", "MPS", "MRD", "MPP", "FEND", "END"}), None)
    if semantic_start is None or any(not token.isdecimal() for token in tokens[2:semantic_start]):
        raise MiningRequired("unapproved R04 numeric header grammar")
    forms: list[tuple[str, str]] = []
    numeric: list[str] = []
    index = semantic_start
    while index < len(tokens):
        token = tokens[index]
        if token in {"A", "B"} and index + 1 < len(tokens) and tokens[index + 1] == "M":
            forms.append(("contact", token)); numeric.extend(("1", "1")); index += 2
        elif token in {"OUT", "SET", "RST"} and index + 1 < len(tokens) and tokens[index + 1] == "M":
            forms.append(("header", token)); numeric.extend(("3", "1")); index += 2
        elif token == "MOV" and tokens[index + 1:index + 3] == ["D", "D"]:
            forms.append(("header", "MOV")); numeric.extend(("3", "1", "1")); index += 3
        elif token == "BMOV" and index + 3 < len(tokens) and tokens[index + 1:index + 3] == ["D", "D"] and re.fullmatch(r"K_-?\d+", tokens[index + 3]):
            forms.append(("header", "BMOV")); numeric.extend(("4", "1", "1", "3")); index += 4
        elif token == "FMOV" and index + 3 < len(tokens) and re.fullmatch(r"K_-?\d+", tokens[index + 1]) and tokens[index + 2] == "D" and re.fullmatch(r"K_-?\d+", tokens[index + 3]):
            forms.append(("header", "FMOV")); numeric.extend(("4", "3", "1", "3")); index += 4
        elif token in {"ANB", "ORB", "MPS", "MRD", "MPP", "FEND", "END"}:
            forms.append(("header", token)); numeric.append("4" if token == "FEND" else "3"); index += 1
        else:
            raise MiningRequired("unapproved MIL header token")
    if tokens[2:semantic_start] != numeric or int(tokens[1]) != len(numeric):
        raise MiningRequired("R04 header descriptor weight mismatch")
    return forms


def _decode_mil(data: str) -> list[tuple[str, list[str]]]:
    return _decode_form_stream(data)


def _provenance(carrier: str, table: str, locator: str, digest: str, byte_count: int = 0) -> dict[str, object]:
    return {"source_entry": carrier, "source_store": table, "source_locator": locator, "source_digest": digest, "relation_evidence": [f"{table} row relation", f"byte_count={byte_count}"]}


def _operand(value: str, position: int, provenance: dict[str, object]) -> dict[str, object]:
    kind = "constant" if value.startswith("K") else "device" if value[:1] in {"M", "D"} else None
    return {"position": position, "raw_token": value, "kind": kind, "value": value[1:] if kind else None, "width": None, "indirection": None, "index": None, "provenance": provenance}


def _finding(code: str, object_kind: str, locator: str, reason: str, digest: str | None = None) -> dict[str, str]:
    kind = object_kind if object_kind in {"profile", "topology", "record", "opcode", "operand", "comment", "label", "parameter"} else "topology"
    return {"finding_code": "MINING_REQUIRED", "scope": "project" if locator == "project" else "pou" if locator.startswith("pou:") else "project", "object_kind": kind, "locator": locator or "GX3", "reason": reason, "digest": digest or hashlib.sha256(locator.encode()).hexdigest()}


def _carrier_census(archive: SafeGx3Archive, kind: str) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    names = sorted(name for name in archive.entries if (name.endswith("_DC.db") if kind == "comment" else name == "LabelData.db"))
    findings: list[dict[str, str]] = []
    items: list[dict[str, Any]] = []
    total = 0
    for name in names:
        try:
            database = sqlite_connection(archive.entries[name])
            table = "COMMENT_DATA" if kind == "comment" else "LabelTbl"
            count = int(database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            total += count
            database.close()
            findings.append(_finding("MINING_REQUIRED", kind, f"{name}:{table}", "Phase 4 carrier census only; row layout is unmined", archive.digest(name)))
            provenance = _provenance(name, table, f"{name}:{table}", archive.digest(name), len(archive.entries[name]))
            for index in range(count):
                identifier = f"MINING_REQUIRED_{archive.digest(name)[:16]}_{index:08d}"
                common = {"scope": "common_device" if kind == "comment" else "global_label", "program_id": None, "language_slot": "unknown", "value_state": "OBJECT_ABSENT", "value": None, "provenance": provenance}
                items.append({**common, "device_id" if kind == "comment" else "label_id": identifier})
        except Exception:
            findings.append(_finding("MINING_REQUIRED", kind, name, "carrier schema is unmined", archive.digest(name)))
    if not names:
        findings.append(_finding("MINING_REQUIRED", kind, "project", "carrier absent or unmined"))
    return items, findings, {"total": total, "decoded": 0, "partial": 0, "unknown": total}


def _envelope(archive: SafeGx3Archive, profile: dict[str, Any], raw_pous: list[dict[str, Any]], comments: list[dict[str, Any]], labels: list[dict[str, Any]], findings: list[dict[str, str]], comment_coverage: dict[str, int], label_coverage: dict[str, int]) -> dict[str, Any]:
    config = "Config.xml" if "Config.xml" in archive.entries else next(iter(archive.entries), "archive")
    provenance = _provenance(config, "XML", "Project/Config", archive.digest(config) if config in archive.entries else archive.input_sha256, len(archive.entries.get(config, b"")))
    pous: list[dict[str, Any]] = []
    for item in raw_pous:
        records = item["records"]
        local = [finding for finding in findings if finding["scope"] == "pou" and f"pou:{item['pou_id']}" in finding["locator"]]
        pous.append({"pou_id": item["pou_id"], "name": item["name"] or "UNRESOLVED_" + hashlib.sha256(item["pou_id"].encode()).hexdigest()[:12], "language": "Ladder", "execution_order": item["order"], "program_kind": "PRG", "relations": [item["stepinfo"], item["pcode"]], "records": records, "findings": local})
    all_records = [record for pou in pous for record in pou["records"]]
    if profile["decision"] == "SUPPORTED" and findings and not any(item["object_kind"] in {"profile", "topology"} for item in findings):
        findings.append(_finding("MINING_REQUIRED", "topology", "project", "project has partial child coverage"))
    def count(items: list[dict[str, Any]]) -> dict[str, int]:
        decoded = sum(item.get("status") == "decoded" for item in items); partial = sum(item.get("status") == "partial" for item in items); return {"total": len(items), "decoded": decoded, "partial": partial, "unknown": len(items) - decoded - partial}
    coverage = {"project": {"total": 1, "decoded": int(profile["decision"] == "SUPPORTED" and not findings), "partial": int(profile["decision"] == "SUPPORTED" and bool(findings)), "unknown": int(profile["decision"] != "SUPPORTED")}, "pou": {"total": len(pous), "decoded": sum(not item["findings"] for item in pous), "partial": sum(bool(item["findings"]) for item in pous), "unknown": 0}, "record": count(all_records), "comment": comment_coverage, "label": label_coverage}
    return {"schema_name": "plcman.gx3.neutral-ir", "schema_version": "1.0.0", "producer": {"package": "gx3-r-parser-toolkit", "version": TOOL_VERSION, "source_commit": source_commit()}, "input": {"display_id": archive.input_sha256[:16], "byte_count": archive.source.stat().st_size, "sha256": archive.input_sha256, "read_only_unchanged": True}, "profile": {"profile_id": "mitsubishi.gx3.r04cpu.ladder", "contract_version": "1.0.0", "family": "RCPU", "cpu_ui_selection": "R04CPU" if profile["decision"] == "SUPPORTED" else "MINING_REQUIRED", "language": "Ladder", "detector_status": profile["decision"], "evidence": [provenance]}, "project": {"project_id": archive.input_sha256[:16], "provenance": provenance}, "pous": pous, "comments": comments, "labels": labels, "findings": sorted(findings, key=lambda value: (value["scope"], value["object_kind"], value["locator"], value["digest"])), "coverage": coverage}


def validate_ir(value: dict[str, Any]) -> None:
    try:
        validate_against_schema(value)
    except SchemaValidationError as error:
        raise ValueError(f"Neutral IR schema invalid: {error}") from error
    for key, count in value["coverage"].items():
        if set(count) != {"total", "decoded", "partial", "unknown"} or count["total"] != count["decoded"] + count["partial"] + count["unknown"]: raise ValueError(f"coverage conservation failed: {key}")
    pou_ids = [pou["pou_id"] for pou in value["pous"]]
    if len(pou_ids) != len(set(pou_ids)) or [pou["execution_order"] for pou in value["pous"]] != list(range(len(value["pous"]))):
        raise ValueError("POU identity or execution order invalid")
    all_records: list[dict[str, Any]] = []
    for pou in value["pous"]:
        seen: set[str] = set()
        records = pou["records"]
        if [record["sequence"] for record in records] != list(range(len(records))):
            raise ValueError("record sequence is not contiguous")
        instructions = {record["record_id"] for record in records if record["kind"] == "instruction"}
        for record in records:
            if record["record_id"] in seen: raise ValueError("duplicate record identifier")
            seen.add(record["record_id"])
            if set(record) != {"record_id", "sequence", "kind", "step", "opcode", "operands", "text", "provenance", "status", "continues_record_id"}: raise ValueError("record schema invalid")
            if record["kind"] == "continuation" and record["continues_record_id"] not in instructions:
                raise ValueError("continuation target is missing or not instruction")
        all_records.extend(records)
    record_counts = value["coverage"]["record"]
    actual = {"total": len(all_records), "decoded": sum(record["status"] == "decoded" for record in all_records), "partial": sum(record["status"] == "partial" for record in all_records), "unknown": sum(record["status"] == "unknown" for record in all_records)}
    if record_counts != actual or value["coverage"]["comment"]["total"] != len(value["comments"]) or value["coverage"]["label"]["total"] != len(value["labels"]):
        raise ValueError("coverage does not match actual objects")
    for key, identifier in (("comments", "device_id"), ("labels", "label_id")):
        rows = value[key]
        order = [(row["scope"], row.get("program_id") or "", row[identifier], row["language_slot"]) for row in rows]
        if order != sorted(order) or len(order) != len(set(order)):
            raise ValueError(f"{key} canonical order invalid")
    required_kinds = {"project": {"profile", "topology"}, "pou": {"topology"}, "record": {"record", "opcode", "operand"}, "comment": {"comment"}, "label": {"label"}}
    finding_kinds = {finding["object_kind"] for finding in value["findings"] if finding["finding_code"] == "MINING_REQUIRED"}
    for key, count in value["coverage"].items():
        if count["partial"] or count["unknown"]:
            if not finding_kinds.intersection(required_kinds[key]):
                raise ValueError(f"{key} partial or unknown coverage lacks matching finding")
