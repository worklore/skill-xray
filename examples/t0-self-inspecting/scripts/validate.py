#!/usr/bin/env python3
"""Validate the package by reading its own files (no network, no writes)."""
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")
AGENTS = (ROOT / "AGENTS.md").read_text(encoding="utf-8") if (ROOT / "AGENTS.md").exists() else ""
def require_match(m, message) -> "re.Match":   # return-arrow must not read as a write
    if m is None:
        raise SystemExit(message)
    return m
print("valid")
