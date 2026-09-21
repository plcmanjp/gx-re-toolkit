"""Bounded XML parsing for small GX3 metadata documents."""

from __future__ import annotations

# The wrapper below bounds bytes and rejects DTD/entity declarations before parsing.
import xml.etree.ElementTree as element_tree  # nosec B405

MAX_XML_BYTES = 1024 * 1024


def parse_xml(body: bytes) -> element_tree.Element:
    if len(body) > MAX_XML_BYTES:
        raise ValueError("XML metadata exceeds the configured byte budget")
    upper = body.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("XML DTD and entity declarations are not allowed")
    try:
        # Byte bounding and DTD/entity rejection constrain the stdlib parser.
        return element_tree.fromstring(body.decode("utf-8-sig"))  # nosec B314
    except (UnicodeError, element_tree.ParseError) as error:
        raise ValueError("XML metadata is not valid UTF-8 XML") from error
