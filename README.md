# skill-xray

**See what an agent Skill can do before you run it.**

An agent Skill is text — and sometimes bundled code — that an AI agent *reads
and executes* with your permissions. A skill you have not read is untrusted
code you are about to run. There have been real abuses: a skill that told the
agent to read the user's `~/.aws/credentials` and `~/.ssh/id_rsa`, and one that
appended persistence instructions to the user's system-level `CLAUDE.md` so it
survived reboots.

The only real defence is to read every line before you run it. That is tedious,
so almost nobody does. `skill-xray` does the reading — mechanically — and hands
back a short, honest report of what the skill can touch, plus a **capability
tier (T0–T4)** bound to a **content hash**.

> **skill-xray discloses capability. It does not certify safety.**
> A clean report means *"no high-risk capability was found in this exact
> artifact"* — never *"harmless"*. A high tier means *"scrutinise this"* — not
> *"malicious"*. It is an informational label, not a security seal. Read the
> report, read the source, and let the runtime permission system do the gating.

Part of the [worklore](https://worklore.dev) project.

## Why not just "safe / unsafe"?

Because no automated tool can honestly promise "harmless":

- **Natural-language instructions are the primary attack surface.** "Text-only"
  is *not* the safe floor — a skill made entirely of prose can tell the agent to
  exfiltrate your secrets. The text *is* the executable logic.
- **The reviewer is an LLM the skill can attack.** A malicious skill can embed
  text aimed at the *reviewing* agent. So the trustworthy backbone here is a
  plain regex scanner that **cannot be prompt-injected**; the agent's judgement
  pass reads the scanner's output, not the raw skill.
- **Time-of-check ≠ time-of-use.** A skill that fetches remote content at
  runtime can be clean when reviewed and hostile when run. That whole class is
  tier **T4 — opaque**: flagged, never blessed.
- **Provenance.** The report is valid for exactly one `sha256`. Re-check on
  change, or the badge is a bait-and-switch.

## What the analysis provides

Two layers:

1. **`scanner/scan.py`** — the mechanical, injection-proof layer. Walks the
   target as *data* (never executes it) and emits deterministic JSON:
   - `sha256` — a stable content hash of the exact artifact reviewed
   - `tier` — T0–T4 (the highest-severity capability found)
   - `endpoints` — every URL referenced
   - `findings` — each with **category, severity, why, and `file:line`
     evidence**

2. **The `skill-xray` skill** (`skills/skill-xray/SKILL.md`) — the agent reads
   the scanner JSON (not the raw skill) and writes a plain-language
   `XRAY-REPORT.md`, adding the judgement a regex can't make: distinguishing
   *expected* capability (a deploy skill that writes files, an install step that
   drops a skill into `~/.claude/skills/`) from the *covert* kind (silently
   editing `CLAUDE.md`, reading credential files, `curl | bash`).

### What each finding category means

| Category | Severity | What it flags |
|---|---|---|
| `remote-exec` | opaque | downloads/decodes code and runs it, or tells the agent to fetch a URL and follow it → **T4** |
| `obfuscation` | opaque | long base64 blobs, zero-width/bidi unicode — hidden payloads or scanner evasion → **T4** |
| `persistence` | elevated | edits agent memory/config (`CLAUDE.md`, `settings.json`, hooks) or shell/scheduler startup → **T3** |
| `secrets` | elevated | references credential/key file locations (`~/.aws`, `~/.ssh`, `.env`, tokens) → **T3** |
| `destructive` | elevated | `rm -rf`, `dd`, `mkfs`, fork bombs, `chmod 777` → **T3** |
| `privilege` | elevated | `sudo`/`doas`/privilege escalation → **T3** |
| `exfil` | elevated | raw sockets / netcat → **T3** |
| `network` | network | outbound HTTP / library calls → **T2** |
| `exec-local` | local | runs a shell/process locally → **T1** |
| `filewrite` | local | writes or deletes files → **T1** |

### Tiers

| Tier | Meaning |
|------|---------|
| **T0** | Inert — instructional text only; no scanned capability strings |
| **T1** | Local — runs bundled code / writes files, no network |
| **T2** | Network — makes outbound calls (endpoints listed) |
| **T3** | Elevated — persistence, secrets, privilege, or destructive actions |
| **T4** | Opaque — fetches/decodes code at runtime; **cannot** be statically reviewed |

A higher tier is not automatically worse — a legitimate deploy skill is
honestly T3. The tier says *how hard to look*; the report says *what to look at*.

## Usage

```bash
# Mechanical scan (JSON) — works on a skill dir, a SKILL.md, a plugin, or a worklore story .md
python3 scanner/scan.py path/to/skill

# Generate a tier badge SVG
python3 scanner/badge.py T3 > xray-badge.svg
```

Then, in an agent, invoke the `skill-xray` skill on the same target to get the
human report. The scanner has **no dependencies** (Python 3.9+ stdlib only).

## Badge

```
[![skill-xray](https://worklore.dev/v1/badge/xray/<sha256-12>.svg)](https://github.com/worklore/skill-xray)
```

The badge shows the tier, not a pass/fail. It links back here so a reader can
learn what the tier means — and what it deliberately does not promise.

## Worklore stories are skills too

A [worklore](https://worklore.dev) story is text you hand an agent to reproduce
work — the same trust model as a skill. skill-xray runs on a story's `.md`
unchanged, so every story can carry an honest capability tier: most are T0–T2,
and a story that tells your agent to `curl | bash` *should* surface as T4 before
you run it.

## License

MIT — see [LICENSE](LICENSE).
