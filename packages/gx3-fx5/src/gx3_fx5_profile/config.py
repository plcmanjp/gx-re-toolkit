"""Resolve CPU identity only at the two supported XML locations."""
from gx3_core import SafeGx3Archive, parse_xml


def resolve_config(archive: SafeGx3Archive):
    entries = [name for name in archive.entries if name.casefold() == "config.xml"]
    if len(entries) != 1:
        raise ValueError("GX3 must contain exactly one Config.xml")
    body = archive.read(entries[0])
    mirrors = [name for name in archive.entries if name.casefold() == "!!config.xml"]
    if len(mirrors) > 1 or (mirrors and archive.read(mirrors[0]) != body):
        raise ValueError("dual Config evidence differs")
    root = parse_xml(body)
    # Count every node, including the root, before choosing an allowed location.
    # Identical duplicates are still ambiguous evidence, never deduplicated.
    candidates = list(root.iter("Config"))
    identities = sorted((node.get("Unit", ""), node.get("UnitId", "")) for node in candidates)
    if len(candidates) != 1:
        raise ValueError(f"Config node count={len(candidates)}; identities={identities!r}")
    config = candidates[0]
    if config is not root and not any(child is config for child in root):
        raise ValueError(f"Config must be the root or a direct wrapper child; identities={identities!r}")
    return entries[0], config
