"""Resolve CPU identity only at the two supported XML locations."""
from gx3_core import SafeGx3Archive, parse_xml
from xml.parsers import expat


def _shape_without_config_title(node):
    """Ignore only Config's display Title; preserve all other XML fields."""
    return (
        node.tag,
        tuple(sorted((key, value) for key, value in node.attrib.items()
                     if node.tag != "Config" or key != "Title")),
        node.text or "",
        node.tail or "",
        tuple(_shape_without_config_title(child) for child in node),
    )


def _xml_comparison_boundary(body):
    """Inspect already budget-validated XML without dropping non-element data."""
    parser = expat.ParserCreate()
    miscellaneous = False
    declaration = None

    def found_miscellaneous(*_args):
        nonlocal miscellaneous
        miscellaneous = True

    def found_declaration(version, encoding, standalone):
        nonlocal declaration
        declaration = (version, encoding, standalone)

    parser.CommentHandler = found_miscellaneous
    parser.ProcessingInstructionHandler = found_miscellaneous
    parser.XmlDeclHandler = found_declaration
    parser.Parse(body.decode("utf-8-sig"), True)
    return miscellaneous, declaration


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
        mirror_body = archive.read(mirrors[0])
        mirror = parse_xml(mirror_body)
        primary_misc, primary_declaration = _xml_comparison_boundary(body)
        mirror_misc, mirror_declaration = _xml_comparison_boundary(mirror_body)
        # Unknown comment/PI meaning never receives the Title-only exception.
        if (primary_misc or mirror_misc or primary_declaration != mirror_declaration
                or _shape_without_config_title(mirror) != _shape_without_config_title(root)):
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
