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

# Bump when detection changes so a tier can be compared meaningfully across
# server (publish-time) and client (reproduction-time) runs. A drift report
# carries this so we never compare tiers computed by different rule sets.
SCANNER_VERSION = "0.3.2"

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
     # `source(?!\s*:)` so a citation label "source: <link>" doesn't match the
     # shell builtin `source`.
     r"(?:eval|exec|source(?!\s*:)|Invoke-Expression|iex)\b[^\n]*(?:curl|wget|https?://)")
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

# --- ELEVATED: privilege, secrets, destruction. The "read my passwords" /
#     "survives reboot" class. Forces T3. (Persistence is context-aware — see
#     the CONFIG/WRITE/HOME regexes and the scan loop below.) ---
# STRUCTURAL, language-independent signals only. To make an agent touch a
# credential the skill must name the PATH (universal across languages and
# phrasings), or hardcode the secret inline. Bare prose words like "password"
# are NOT matched — enumerating verbs in one language is a losing game and
# blind to paraphrase/other languages. Prose intent ("read the user's keys",
# in any language) is the AGENT layer's job, not the regex's.
rule("secrets", "elevated",
     "references credential/secret file locations",
     r"(?:\.aws/|\.ssh/|id_rsa|id_ed25519|\.netrc|\.npmrc|\.env\b|\.pgpass|"
     r"\.git-credentials|/etc/shadow|keychain|GITHUB_TOKEN|AWS_SECRET)")
rule("secrets", "elevated",
     "hardcoded secret assigned inline",
     r"(?:password|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
     r"s?\s*[=:]\s*[\"']?[\w./+-]{8,}")
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
rule("persistence", "elevated",
     "installs or registers a hook that runs automatically",
     r"\bhooks?\b[^\n]{0,30}(?:PreToolUse|PostToolUse|SessionStart|Stop|"
     r"pre-commit|post-commit|install)")

# --- LOCAL: runs bundled code. Forces at least T1. ---
rule("exec-local", "local",
     "runs a shell/process locally",
     r"\b(?:subprocess|os\.system|child_process|exec[lv]?p?\(|Process\.run|"
     r"system\()\b")

# --- Context-aware detection (handled in the scan loop, not as flat rules),
#     so a *reference* or a skill *reading its own repo* isn't mistaken for an
#     *action on the user's environment*. This is what separates "cites a URL"
#     from "fetches a URL", and "reads its own AGENTS.md" from "edits your
#     ~/.claude/CLAUDE.md". ---

# Agent-config / shell-startup / scheduler files.
CONFIG_FILE = re.compile(
    r"(?:CLAUDE\.md|AGENTS\.md|SOUL\.md|MEMORY\.md|\.cursorrules|"
    r"settings\.local\.json|settings\.json|\.claude/|\.codex/|"
    r"\.bashrc|\.zshrc|\.zshenv|\.profile|\.bash_profile|"
    r"crontab|launchctl|systemctl|LaunchAgents|LaunchDaemons)", re.I)
# A write/mutate operation on the same line as the file.
WRITE_CTX = re.compile(
    r"(?:>>|write_text|writeFile|fs\.write|open\([^)]*['\"][wa]\+?['\"]|"
    r"\bappend\b|\btee\b|\bsed\s+-i|Add-Content|Set-Content|echo[^\n]*>>?|"
    r"\binstall(?:s|ed|ing)?\b|\binto\b|\bwrite[s]?\s+to\b|\bmodif|\bedit)", re.I)
# The USER's environment, as opposed to a repo-relative path (ROOT/..., ./...).
HOME_ANCHOR = re.compile(
    r"(?:~/|\$HOME|\$\{HOME\}|expanduser|/Users/[^/\s]+/|/home/[^/\s]+/|"
    r"/etc/|/Library/)", re.I)
# The agent's drop-in skills directory: installing a skill *into* it is the
# standard, documented way skills are added — structurally distinct from
# editing existing agent config/startup (CLAUDE.md, settings.json, shell rc).
SKILLS_DIR = re.compile(r"(?:\.claude|\.codex|\.cursor)/skills/", re.I)
# A genuine outbound call. curl/wget count only alongside a URL (so prose like
# "auto-curl" doesn't match); code HTTP clients count on their own.
SHELL_FETCH = re.compile(r"(?<![\w-])(?:curl|wget)\b", re.I)
CODE_CALL = re.compile(
    r"\b(?:fetch\(|requests\.(?:get|post|put|delete|request|head)|"
    r"urllib|urlopen|httpx?\.|http\.client|axios|XMLHttpRequest|Net::HTTP|"
    r"WebClient|HttpClient|Invoke-WebRequest|iwr)\b", re.I)
# A real file-write via an explicit API/command. Deliberately excludes bare
# '>'/'>' redirects — they collide with markdown blockquotes ("> text") and
# type arrows ("-> T"); an append to a config file is still caught by
# WRITE_CTX above.
FILE_WRITE = re.compile(
    r"(?:open\([^)]*['\"][wa]\+?['\"]|write_text|writeFile|fs\.write(?:File|Sync)?|"
    r"\btee\s|\bsed\s+-i|Add-Content|Set-Content|\brm\s+-|\bmv\s+[~./\w]|"
    r"\bcp\s+[~./\w])", re.I)

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
    # Which detection backend produced this. skill-xray does not compete on
    # detection — it is a disclosure + provenance layer, and an external
    # scanner (e.g. claude-skill-antivirus, snyk) can feed findings in as
    # another backend. See docs/backends.md for the adapter contract; the
    # severity a backend reports is mapped onto our tiers, and its own
    # "safe / do not install" verdict is deliberately dropped.
    backend: str = "builtin"


@dataclass
class Report:
    artifact: str
    sha256: str
    files_scanned: int
    tier: str
    tier_label: str
    backends: list[str] = field(default_factory=lambda: ["builtin"])
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


def detect(text: str, rel: str) -> tuple[list[Finding], set[str]]:
    """Run the built-in static detection over one text unit (a file or an
    in-memory string). Returns (findings, endpoints). Pure and side-effect free
    so the same logic serves both a directory scan and a single-string scan —
    which is what keeps the server (publish-time) and the client (reproduction-
    time) computing the SAME tier for the same bytes."""
    findings: list[Finding] = []
    endpoints: set[str] = set()
    for i, line in enumerate(text.splitlines(), 1):
        for cat, sev, why, pat in RULES:
            if pat.search(line):
                findings.append(Finding(cat, sev, why, rel, i, line.strip()[:200]))

        # Config/persistence: editing the user's agent config or startup is
        # elevated; naming/reading a repo-relative config file (a skill
        # inspecting its own repo) is disclosed but not alarming.
        if CONFIG_FILE.search(line):
            acts = WRITE_CTX.search(line) or HOME_ANCHOR.search(line)
            if not acts:
                findings.append(Finding(
                    "config-ref", "info",
                    "names a config/agent file, repo-relative and without a "
                    "write (likely self-inspection, not an action)",
                    rel, i, line.strip()[:200]))
            elif SKILLS_DIR.search(line):
                # Installing a skill INTO the agent's skills dir is the
                # documented way skills are added — not a silent edit of
                # existing config/startup. Disclosed (it runs in later
                # sessions), but the thing to review is that skill, so: local.
                findings.append(Finding(
                    "skill-install", "local",
                    "installs a skill into the agent's skills directory — the "
                    "standard way skills are added; it runs in later sessions, "
                    "so the thing to review is that skill", rel, i,
                    line.strip()[:200]))
            else:
                findings.append(Finding(
                    "persistence", "elevated",
                    "edits your agent config or startup so the change persists "
                    "across sessions", rel, i, line.strip()[:200]))

        # Network: a URL inside an actual call is a capability; a bare URL in
        # prose/manifest is a reference (listed in endpoints, not a finding).
        urls = [u.rstrip(".,);") for u in URL_RE.findall(line)]
        for u in urls:
            endpoints.add(u)
        if CODE_CALL.search(line) or (SHELL_FETCH.search(line) and urls):
            findings.append(Finding(
                "network", "network", "makes an outbound network request",
                rel, i, line.strip()[:200]))

        # File writes: explicit write ops only (not any '>').
        if FILE_WRITE.search(line):
            findings.append(Finding(
                "filewrite", "local", "writes or deletes files",
                rel, i, line.strip()[:200]))
    return findings, endpoints


def _finalize(artifact: str, sha256: str, files_scanned: int,
              findings: list[Finding], endpoints: set[str],
              backends_run: list[str]) -> Report:
    max_sev = max((SEV_RANK[f.severity] for f in findings), default=0)
    tier = TIER_OF_SEV[max_sev]
    seen, uniq = set(), []
    for f in sorted(findings, key=lambda f: (-SEV_RANK[f.severity], f.file, f.line)):
        key = (f.backend, f.category, f.why, f.file)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return Report(
        artifact=artifact, sha256=sha256, files_scanned=files_scanned,
        tier=tier, tier_label=TIER_LABEL[tier], backends=backends_run,
        endpoints=sorted(endpoints), findings=[asdict(f) for f in uniq],
    )


def scan_text(text: str, name: str = "SKILL.md") -> Report:
    """Scan a single in-memory string (a story's markdown, one SKILL.md).
    The sha256 is over `name` + text, matching the per-file hashing in scan()
    so a one-file skill and its string form produce the same hash."""
    hasher = hashlib.sha256()
    hasher.update(name.encode())
    hasher.update(text.encode("utf-8"))
    findings, endpoints = detect(text, name)
    return _finalize(name, hasher.hexdigest(), 1, findings, endpoints, ["builtin"])


def scan(root: Path, backends: tuple[str, ...] = ("builtin",)) -> Report:
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
        f, e = detect(text, rel)
        findings.extend(f)
        endpoints |= e

    # Optional external detection backends. skill-xray does not compete on
    # detection: another scanner can be plugged in here and its findings merged.
    # An adapter is a callable(root: Path) -> list[Finding], each Finding tagged
    # with its `backend` name and a severity from SEV_RANK; its own
    # "safe/do-not-install" verdict is dropped — only findings cross the border.
    # See docs/backends.md. The registry ships empty: a backend is wired only
    # after it is itself audited (with skill-xray) and verified.
    ran = ["builtin"]
    for name in backends:
        if name == "builtin":
            continue
        adapter = EXTERNAL_BACKENDS.get(name)
        if adapter is None:
            print(f"skill-xray: backend '{name}' not available; skipping",
                  file=sys.stderr)
            continue
        try:
            findings.extend(adapter(root))
            ran.append(name)
        except Exception as e:  # a backend must never crash the disclosure
            print(f"skill-xray: backend '{name}' failed: {e}", file=sys.stderr)

    return _finalize(str(root), hasher.hexdigest(), n, findings, endpoints, ran)


# name -> callable(root: Path) -> list[Finding]. Empty by design; see the note
# in scan() and docs/backends.md. Register a backend only after auditing it.
EXTERNAL_BACKENDS: dict[str, "callable"] = {}


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    if not args:
        print("usage: python3 scan.py <path> [--json] [--backend NAME ...]",
              file=sys.stderr)
        return 2
    root = Path(args[0]).expanduser()
    if not root.exists():
        print(f"no such path: {root}", file=sys.stderr)
        return 2
    # --backend may repeat; builtin always runs.
    backends = ["builtin"]
    for i, a in enumerate(argv):
        if a == "--backend" and i + 1 < len(argv):
            backends.append(argv[i + 1])
    report = scan(root, backends=tuple(backends))
    print(json.dumps(asdict(report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
