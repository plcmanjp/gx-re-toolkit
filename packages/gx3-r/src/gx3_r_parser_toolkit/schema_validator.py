'Source-derived parser observation.'

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any




class SchemaValidationError(ValueError):
    pass


def load_schema() -> dict[str, Any]:
    from importlib import resources
    return json.loads((resources.files(__package__) / 'schemas' / 'neutral-ir-1.0.0.schema.json').read_text(encoding='utf-8'))

def validate(value: Any, schema: dict[str, Any] | None = None) -> None:
    root = schema if schema is not None else load_schema()
    _validate(value, root, root, "$")


def _resolve(reference: str, root: dict[str, Any]) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaValidationError(f"unsupported schema reference: {reference}")
    value: Any = root
    for part in reference[2:].split("/"):
        if not isinstance(value, dict) or part not in value:
            raise SchemaValidationError(f"unresolved schema reference: {reference}")
        value = value[part]
    if not isinstance(value, dict):
        raise SchemaValidationError(f"schema reference is not an object: {reference}")
    return value


def _validate(value: Any, schema: dict[str, Any], root: dict[str, Any], location: str) -> None:
    if "$ref" in schema:
        _validate(value, _resolve(schema["$ref"], root), root, location)
    if "not" in schema:
        try:
            _validate(value, schema["not"], root, location)
        except SchemaValidationError:
            pass
        else:
            raise SchemaValidationError(f"{location}: prohibited schema branch matched")
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{location}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{location}: value outside enum")
    kind = schema.get("type")
    checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if kind is not None:
        if isinstance(kind, list):
            if not any(checks[item](value) for item in kind):
                raise SchemaValidationError(f"{location}: expected one of {kind}")
        elif kind not in checks or not checks[kind](value):
            raise SchemaValidationError(f"{location}: expected {kind}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise SchemaValidationError(f"{location}: below minLength")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise SchemaValidationError(f"{location}: pattern mismatch")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value < schema.get("minimum", value):
        raise SchemaValidationError(f"{location}: below minimum")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise SchemaValidationError(f"{location}: missing required property {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                raise SchemaValidationError(f"{location}: additional properties {extras}")
        for key, child in properties.items():
            if key in value:
                _validate(value[key], child, root, f"{location}.{key}")
    if isinstance(value, list):
        if "items" in schema:
            for index, child in enumerate(value):
                _validate(child, schema["items"], root, f"{location}[{index}]")
        if "contains" in schema:
            matches = 0
            for child in value:
                try:
                    _validate(child, schema["contains"], root, location)
                    matches += 1
                except SchemaValidationError:
                    continue
            if matches < schema.get("minContains", 1):
                raise SchemaValidationError(f"{location}: contains/minContains failed")
    for child in schema.get("allOf", []):
        if "if" in child:
            try:
                _validate(value, child["if"], root, location)
            except SchemaValidationError:
                if "else" in child:
                    _validate(value, child["else"], root, location)
            else:
                if "then" in child:
                    _validate(value, child["then"], root, location)
        else:
            _validate(value, child, root, location)
