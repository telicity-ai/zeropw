"""Human-readable rendering of a folded environment document (docs/team-sync.md section 5.5).

``strip_document`` produces the view ``team show``/``team log``/``team diff`` render: every
ciphertext, DEK wrap, nonce and signature is removed.  ``to_yaml`` is an output-only YAML subset
writer (dicts, lists, and quoted-when-needed scalars) -- there is no YAML input anywhere in
ZeroPW (docs/team-sync.md section 11), so this never needs to parse anything back.
"""

from __future__ import annotations

import json
import re
from typing import Any

_YAML_NEEDS_QUOTING = re.compile(r'^[\s]|[\s]$|^$|^[-?:,\[\]{}#&*!|>\'"%@`]|[:#]\s|[\n\t]')
_YAML_RESERVED = {"true", "false", "null", "yes", "no", "~"}


def strip_document(doc: dict[str, Any]) -> dict[str, Any]:
    """The value-free view: no ciphertext, no DEK wraps, no device-record signatures/public keys."""
    members = {}
    for fp, member in (doc.get("members") or {}).items():
        members[fp] = {"name": member.get("name"), "role": member.get("role"), "status": member.get("status")}
    dek = doc.get("dek") or {}
    secrets_view = {}
    for secret_id, entry in (doc.get("secrets") or {}).items():
        versions = {}
        for version_id, record in (entry.get("versions") or {}).items():
            versions[version_id] = {"status": record.get("status"), "generation": record.get("generation"),
                                    "public": dict(record.get("public") or {})}
        secrets_view[secret_id] = {"kind": entry.get("kind"), "active_version": entry.get("active_version"),
                                   "versions": versions}
    return {
        "env_id": doc.get("env_id"),
        "format": doc.get("format"),
        "owner": doc.get("owner"),
        "members": members,
        "dek": {"current": dek.get("current"), "generations": sorted((dek.get("generations") or {}).keys())},
        "connections": {cid: dict(entry) for cid, entry in (doc.get("connections") or {}).items()},
        "secrets": secrets_view,
        "settings": dict(doc.get("settings") or {}),
    }


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text.lower() in _YAML_RESERVED or _YAML_NEEDS_QUOTING.search(text):
        return json.dumps(text)  # a double-quoted YAML scalar follows JSON string escaping rules
    return text


def _yaml_lines(value: Any, indent: int) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        if not value:
            return [f"{pad}{{}}"]
        for key, item in value.items():
            key_text = _yaml_scalar(str(key))
            if isinstance(item, dict) and item:
                lines.append(f"{pad}{key_text}:")
                lines.extend(_yaml_lines(item, indent + 1))
            elif isinstance(item, list) and item:
                lines.append(f"{pad}{key_text}:")
                lines.extend(_yaml_lines(item, indent))
            else:
                lines.append(f"{pad}{key_text}: {_yaml_scalar_or_empty(item)}")
    elif isinstance(value, list):
        if not value:
            return [f"{pad}[]"]
        for item in value:
            if isinstance(item, (dict, list)) and item:
                sub = _yaml_lines(item, indent + 1)
                lines.append(f"{pad}-")
                lines.extend(sub)
            else:
                lines.append(f"{pad}- {_yaml_scalar_or_empty(item)}")
    else:
        lines.append(f"{pad}{_yaml_scalar(value)}")
    return lines


def _yaml_scalar_or_empty(item: Any) -> str:
    if isinstance(item, dict):
        return "{}"
    if isinstance(item, list):
        return "[]"
    return _yaml_scalar(item)


def to_yaml(value: Any) -> str:
    lines = _yaml_lines(value, 0)
    return "\n".join(lines) + "\n"
