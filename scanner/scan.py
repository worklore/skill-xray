#!/usr/bin/env python3
"""
skill-xray mechanical scanner — the injection-proof layer.

Reads an agent Skill (or any text-instruction bundle: a SKILL.md, a plugin
directory, a worklore story .md) as DATA and never executes or follows it.
Emits a deterministic JSON capability manifest: a content hash, the concrete
signals found (with file:line evidence), and a capability TIER (T0-T4).

This layer exists precisely because the thing under review may contain text
crafted to manipulate an LLM reviewer. Regexes cannot be prompt-injected, so
the mechanical findings are the trustworthy backbone; the agent's intent pass
(see SKILL.md) reads THIS output, not the raw skill, to write the human report.

The tier describes BLAST RADIUS (what the skill can touch), never intent or
safety. It is an informational disclosure, not a security seal. A clean scan
means "no high-risk capability strings were found in this exact artifact",
not "harmless".

Usage:
    python3 scan.py <path-to-skill-dir-or-file> [--json]

Exit code is always 0 on a successful scan (the tier is data, not a verdict);
non-zero only on usage/IO error.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Files worth reading as instruction/text/code. Binary and vendored trees are
# hashed for provenance but not pattern-scanned.
TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".mjs",
    ".ts", ".rb", ".pl", ".ps1", ".yaml", ".yml", ".json", ".toml", ".cfg",
    ".ini", ".env", ".rc", "",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".dart_tool"}
MAX_BYTES = 2_000_000  # per file, to bound work on pathological inputs

Severity = str  # "info" | "network" | "local" | "elevated" | "opaque"

# Each rule: (category, severity, human explanation, compiled regex).
# Severity drives the tier; see tier_for(). Patterns are intentionally broad —
# false positives are acceptable (a human reads the report), false negatives
# are not.
RULES: list[tuple[str, Severity, str, re.Pattern]] = []


def rule(cat: str, sev: Severity, why: str, pat: str, flags=re.I):
    RULES.append((cat, sev, why, re.compile(pat, flags)))


# --- OPAQUE: un-reviewable. Fetch-then-execute and obfuscation. Forces T4:
#     static review cannot see what actually runs. ---
rule("remote-exec", "opaque",
     "downloads code from the network and pipes it straight into a shell",
     r"(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")
rule("remote-exec", "opaque",
     "evaluates the output of a network download",
     r"(?:eval|exec|source|Invoke-Expression|iex)\b[^\n]*(?:curl|wget|https?://)")
rule("remote-exec", "opaque",
     "decodes a blob and executes it",
     r"base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba)?sh\b")
rule("remote-exec", "opaque",
     "runtime instruction to fetch a URL and follow/run its contents",
     r"(?:read|fetch|load|follow|execute|run)\b[^\n]{0,40}\bhttps?://[^\s'\"]+"
     r"[^\n]{0,40}\b(?:instruction|steps|follow|then run|and run|execute)")
rule("obfuscation", "opaque",
     "long base64-looking blob (hidden payload or evasion of this scanner)",
     r"[A-Za-z0-9+/]{120,}={0,2}")
rule("obfuscation", "opaque",
     "zero-width or bidirectional unicode control chars (hidden text)",
     r"[​‌‍⁠‪-‮⁦-⁩]")

# --- ELEVATED: persistence, privilege, secrets, destruction, out-of-project
#     writes. The "survives reboot" / "read my passwords" class. Forces T3. ---
rule("persistence", "elevated",
     "edits agent memory/config that persists across sessions",
     r"(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|settings\.local\.json|"
     r"settings\.json|\.claude/|\.codex/|\.config/)")
rule("persistence", "elevated",
     "edits shell startup or scheduler (persists across reboot)",
     r"(?:\.bashrc|\.zshrc|\.zshenv|\.profile|\.bash_profile|crontab|"
     r"launchctl|systemctl|LaunchAgents|LaunchDaemons|/etc/)")
rule("persistence", "elevated",
     "installs or registers a hook that runs automatically",
     r"\bhooks?\b[^\n]{0,30}(?:PreToolUse|PostToolUse|SessionStart|Stop|"
     r"pre-commit|post-commit|install)")
rule("secrets", "elevated",
     "references credential/secret file locations",
     r"(?:\.aws/|\.ssh/|id_rsa|id_ed25519|\.netrc|\.npmrc|\.env\b|"
     r"credentials|keychain|secret[_-]?key|private[_-]?key|password|"
     r"\.pgpass|\.git-credentials|GITHUB_TOKEN|AWS_SECRET)")
rule("destructive", "elevated",
     "destructive filesystem or disk command",
     r"(?:\brm\s+-rf?\b|\bdd\s+if=|\bmkfs\b|>\s*/dev/sd|chmod\s+-R?\s*777|"
     r"\bshred\b|:\(\)\s*\{\s*:\|:)")
rule("privilege", "elevated",
     "escalates privileges",
     r"\bsudo\b|\bdoas\b|\bsu\s+-\b|osascript.*administrator")
rule("exfil", "elevated",
     "raw socket / netcat (possible exfiltration channel)",
     r"\b(?:nc|ncat|netcat)\b|/dev/tcp/")

# --- NETWORK: outbound calls. Forces at least T2. ---
rule("network", "network",
     "makes outbound network requests",
     r"\b(?:curl|wget|https?://|urllib|requests\.(?:get|post)|fetch\(|"
     r"axios|http\.client|Net::HTTP|WebClient)\b")

# --- LOCAL: runs bundled code / writes files. Forces at least T1. ---
rule("exec-local", "local",
     "runs a shell/process locally",
     r"\b(?:subprocess|os\.system|child_process|exec[lv]?p?\(|Process\.run|"
     r"system\()\b")
rule("filewrite", "local",
     "writes or deletes files",
     r"\b(?:open\([^)]*['\"][wa]|writeFile|>>?\s*[\w./-]+|fs\.write|"
     r"\bmv\b|\bcp\b|\brm\b|\btee\b)\b")

SEV_RANK = {"info": 0, "local": 1, "network": 2, "elevated": 3, "opaque": 4}
TIER_OF_SEV = {0: "T0", 1: "T1", 2: "T2", 3: "T3", 4: "T4"}
TIER_LABEL = {
    "T0": "Inert — no scanned capability strings; instructional text only",
    "T1": "Local — runs bundled code / writes files, no network",
    "T2": "Network — makes outbound calls (endpoints listed)",
    "T3": "Elevated — persistence, secrets, privilege, or destructive actions",
    "T4": "Opaque — fetches/decodes code at runtime; cannot be statically reviewed",
}


@dataclass
class Finding:
    category: str
    severity: str
    why: str
    file: str
    line: int
    evidence: str


@dataclass
class Report:
    artifact: str
    sha256: str
    files_scanned: int
    tier: str
    tier_label: str
    endpoints: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    disclaimer: str = (
        "skill-xray reports observed CAPABILITY (blast radius) for this exact "
        "artifact hash. It is an informational disclosure, not a safety seal: "
        "a clean scan does not mean the skill is harmless, and a high tier does "
        "not mean it is malicious. Read the report and the source; the runtime "
        "permission system remains the real control."
    )


URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_dir() or any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def scan(root: Path) -> Report:
    hasher = hashlib.sha256()
    findings: list[Finding] = []
    endpoints: set[str] = set()
    n = 0
    for p in iter_files(root):
        try:
            raw = p.read_bytes()[:MAX_BYTES]
        except OSError:
            continue
        # Hash path + bytes so the artifact id is stable and order-independent.
        hasher.update(str(p.relative_to(root) if root.is_dir() else p.name)
                      .encode())
        hasher.update(raw)
        if p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        n += 1
        try:
            text = raw.decode("utf-8", "replace")
        except Exception:
            continue
        rel = str(p.relative_to(root) if root.is_dir() else p.name)
        for i, line in enumerate(text.splitlines(), 1):
            for cat, sev, why, pat in RULES:
                if pat.search(line):
                    findings.append(Finding(
                        cat, sev, why, rel, i, line.strip()[:200]))
            for m in URL_RE.findall(line):
                endpoints.add(m.rstrip(".,);"))

    max_sev = max((SEV_RANK[f.severity] for f in findings), default=0)
    tier = TIER_OF_SEV[max_sev]
    # De-dup identical findings (same rule hitting many lines is noise); keep
    # first occurrence per (category, why, file).
    seen = set()
    uniq: list[Finding] = []
    for f in sorted(findings, key=lambda f: (-SEV_RANK[f.severity], f.file, f.line)):
        key = (f.category, f.why, f.file)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return Report(
        artifact=str(root),
        sha256=hasher.hexdigest(),
        files_scanned=n,
        tier=tier,
        tier_label=TIER_LABEL[tier],
        endpoints=sorted(endpoints),
        findings=[asdict(f) for f in uniq],
    )


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    if not args:
        print(__doc__.strip().splitlines()[-3], file=sys.stderr)
        print("usage: python3 scan.py <path> [--json]", file=sys.stderr)
        return 2
    root = Path(args[0]).expanduser()
    if not root.exists():
        print(f"no such path: {root}", file=sys.stderr)
        return 2
    report = scan(root)
    print(json.dumps(asdict(report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
