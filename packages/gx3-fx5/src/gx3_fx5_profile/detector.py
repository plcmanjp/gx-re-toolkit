"""Detect the proven FX5-family GX3 profile from internal evidence.

The GX Works3 installation's CPU identity table records ``FX5UCPU=528`` and
does not assign FX5UC a separate CPU identity.  FX5UC is therefore accepted
only through the same exact ``Config.xml`` tuple already proven for FX5U.
GX Works3 1.128 fixtures prove the separate ``FX5UJ/529`` and ``FX5S/530``
tuples.  The detector never fabricates a separate FX5UC identity.
"""

from __future__ import annotations

import hashlib
import re

from gx3_core import (
    Finding,
    ProfileDecision,
    ProfileEvidence,
    SafeGx3Archive,
    parse_xml,
)

PROFILE_ID = "mitsubishi.gx3.fx5u.ladder"
SUPPORTED_CONFIG_IDENTITIES = {
    ("FX5U", "528"): ("FX5U", "FX5UC"),
    ("FX5UJ", "529"): ("FX5UJ",),
    ("FX5S", "530"): ("FX5S",),
}


def _config(archive: SafeGx3Archive):
    configs = [name for name in archive.entries if name.casefold() == "config.xml"]
    if len(configs) != 1:
        raise ValueError("GX3 must contain exactly one Config.xml")
    root = parse_xml(archive.read(configs[0]))
    if root.tag == "Config":
        return root
    config = root.find(".//Config")
    if config is None:
        raise ValueError("Config.xml has no Config element")
    return config


def detect(archive: SafeGx3Archive) -> ProfileEvidence:
    findings: list[Finding] = []
    evidence: list[str] = []
    try:
        config = _config(archive)
    except ValueError as error:
        return ProfileEvidence(
            PROFILE_ID,
            ProfileDecision.AMBIGUOUS,
            findings=(
                Finding(
                    "FX5_CONFIG_AMBIGUOUS",
                    "project",
                    "config",
                    "Config.xml",
                    "",
                    str(error),
                ),
            ),
        )

    unit = config.get("Unit", "")
    unit_id = config.get("UnitId", "")
    evidence.extend((f"config.unit={unit}", f"config.unit_id={unit_id}"))
    supported_families = SUPPORTED_CONFIG_IDENTITIES.get((unit, unit_id))
    if supported_families is None:
        digest = (
            hashlib.sha256(archive.read("Config.xml")).hexdigest()
            if "Config.xml" in archive.entries
            else ""
        )
        return ProfileEvidence(
            PROFILE_ID,
            ProfileDecision.UNSUPPORTED,
            tuple(evidence),
            (
                Finding(
                    "FX5_PROFILE_UNSUPPORTED",
                    "project",
                    "profile",
                    "Config.xml",
                    digest,
                    "Config identity is not an approved FX5-family tuple",
                ),
            ),
        )
    evidence.append("profile.cpu_families=" + ",".join(supported_families))

    links = sorted(
        name
        for name in archive.entries
        if re.fullmatch(r"ConvertData/\d+/PouLinkOrder\.info", name)
    )
    if not links:
        findings.append(
            Finding(
                "FX5_POU_RELATION_MISSING",
                "project",
                "topology",
                "ConvertData/*/PouLinkOrder.info",
                "",
                "No POU link-order relation was found",
            )
        )
    linked_ids: list[str] = []
    invalid_links = 0
    for link in links:
        body = archive.read(link)
        ids = re.findall(rb"\d+", body)
        if not ids:
            invalid_links += 1
            continue
        for value in ids:
            pou_id = value.decode("ascii")
            if pou_id not in linked_ids:
                linked_ids.append(pou_id)
    missing = [
        pou_id
        for pou_id in linked_ids
        if f"{pou_id}_StepInfo.db" not in archive.entries
        or f"ConvertData/{pou_id}/PouPCode.pcode" not in archive.entries
    ]
    evidence.extend(
        (f"relations.link_order={len(links)}", f"relations.pou_ids={len(linked_ids)}")
    )
    if invalid_links or missing:
        findings.append(
            Finding(
                "FX5_POU_RELATION_INCOMPLETE",
                "project",
                "topology",
                "PouLinkOrder.info",
                "",
                f"invalid_link_files={invalid_links}; missing_related_pous={len(missing)}",
            )
        )

    lddb_stems = {
        name[:-8] for name in archive.entries if re.fullmatch(r"[^/]+_LDDB\.db", name)
    }
    mildb_stems = {
        name[:-9] for name in archive.entries if re.fullmatch(r"[^/]+_MilDB\.db", name)
    }
    database_pairs = lddb_stems & mildb_stems
    evidence.append(f"relations.ladder_database_pairs={len(database_pairs)}")
    if not database_pairs:
        findings.append(
            Finding(
                "FX5_LADDER_DATABASE_MISSING",
                "project",
                "topology",
                "*_LDDB.db,*_MilDB.db",
                "",
                "No paired Ladder/MIL database was found",
            )
        )

    parameter_entries = sorted(
        name for name in archive.entries if name.upper().endswith((".PRM", ".DAT"))
    )
    evidence.append(f"parameters.observed={len(parameter_entries)}")
    evidence.append(f"sqlite.validated={len(archive.sqlite_evidence)}")
    decision = (
        ProfileDecision.SUPPORTED
        if linked_ids and not findings
        else ProfileDecision.AMBIGUOUS
    )
    return ProfileEvidence(PROFILE_ID, decision, tuple(evidence), tuple(findings))
