"""Resolve CPU identity only at the two supported XML locations."""
from gx3_core import SafeGx3Archive, parse_xml


def _shape_without_title(node):
    """Compare mirror semantics while treating the display title as nuisance."""
    return (
        node.tag,
        tuple(sorted((key, value) for key, value in node.attrib.items() if key != "Title")),
        node.text or "",
        node.tail or "",
        tuple(_shape_without_title(child) for child in node),
    )


def resolve_config(archive: SafeGx3Archive):
    entries = [name for name in archive.entries if name.casefold() == "config.xml"]
    if len(entries) != 1:
        raise ValueError("GX3 must contain exactly one Config.xml")
    body = archive.read(entries[0])
    root = parse_xml(body)
    mirrors = [name for name in archive.entries if name.casefold() == "!!config.xml"]
    if len(mirrors) > 1:
        raise ValueError("dual Config evidence differs")
    if mirrors and archive.read(mirrors[0]) != body:
        mirror = parse_xml(archive.read(mirrors[0]))
        if _shape_without_title(mirror) != _shape_without_title(root):
            raise ValueError("dual Config evidence differs")
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
