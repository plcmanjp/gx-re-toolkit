from __future__ import annotations

import json
import re

def source_commit() -> str:
    """Return artifact-only provenance; never inspect ancestor Git."""
    try:
        from importlib import resources
        value = json.loads((resources.files(__package__) / '_provenance.json').read_text(encoding='utf-8'))
        source_commit = value.get('source_commit')
        return source_commit if isinstance(source_commit, str) and re.fullmatch(r'[0-9a-f]{40}', source_commit) else '0000000000000000000000000000000000000000'
    except (FileNotFoundError, json.JSONDecodeError, ModuleNotFoundError):
        return '0000000000000000000000000000000000000000'

def _git_head() -> str | None:
    return None
