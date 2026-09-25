"""Bounded XML parsing for small GX3 metadata documents."""

from __future__ import annotations

# The wrapper below bounds bytes and rejects DTD/entity declarations before parsing.
import xml.etree.ElementTree as element_tree  # nosec B405
from xml.parsers import expat

MAX_XML_BYTES = 1024 * 1024
MAX_XML_DEPTH = 64
MAX_XML_NODES = 10000


def parse_xml(body: bytes) -> element_tree.Element:
    if len(body) > MAX_XML_BYTES:
        raise ValueError("XML metadata exceeds the configured byte budget")
    try:
        decoded = body.decode("utf-8-sig")
        guard = expat.ParserCreate()
        depth = nodes = 0
        def start(_name: str, _attrs: dict[str, str]) -> None:
            nonlocal depth, nodes
            depth += 1
            nodes += 1
            if depth > MAX_XML_DEPTH or nodes > MAX_XML_NODES:
                raise ValueError("XML metadata exceeds the node or depth budget")
        def end(_name: str) -> None:
            nonlocal depth
            depth -= 1
        def forbidden(*_args: object) -> None:
            raise ValueError("XML DTD and entity declarations are not allowed")
        guard.StartElementHandler = start
        guard.EndElementHandler = end
        guard.StartDoctypeDeclHandler = forbidden
        guard.EntityDeclHandler = forbidden
        guard.ExternalEntityRefHandler = forbidden
        guard.Parse(decoded, True)
        return element_tree.fromstring(decoded)  # nosec B314
    except (UnicodeError, element_tree.ParseError, expat.ExpatError) as error:
        raise ValueError("XML metadata is not valid UTF-8 XML") from error
