# Detection backends

skill-xray is **not another scanner**. The market already has good detection —
[Snyk agent-scan / MCP-Scan](https://github.com/snyk/agent-scan),
[Cisco's IDE scanner](https://blogs.cisco.com/ai/introducing-the-ai-agent-security-scanner-for-ides-verify-your-agents),
[claude-skill-antivirus](https://github.com/claude-world/claude-skill-antivirus)
(9 engines), and enterprise platforms like Kaspersky AI Protect. Competing on
detection would be a losing, dishonest race.

What those tools mostly do **not** do — and what skill-xray is — is the honest
presentation layer on top:

1. **Capability disclosure, not a verdict.** They tend to output "✅ SAFE" /
   "DO NOT INSTALL". skill-xray never says "safe". It reports what a skill can
   touch (blast radius) as a tier + findings, and leaves the decision to you.
2. **Provenance.** Every report is bound to the artifact's `sha256`. A review
   is valid for exactly one version; most scanners don't pin this.
3. **One frame over many engines.** Detection can come from the built-in
   scanner and/or external backends, merged into one disclosure.

## The built-in backend

`scanner/scan.py` ships a zero-dependency, stdlib-only, static scanner. It reads
the target as data and never executes it, so it cannot be prompt-injected. It is
the default and always runs. It is deliberately conservative (it over-flags;
reading the findings is what closes them).

## Adding an external backend

An adapter is a callable:

```python
def adapter(root: pathlib.Path) -> list[Finding]: ...
```

It runs an external scanner over `root`, parses its structured output, and
returns `Finding`s — each tagged `backend="<name>"`, with a `severity` from
`SEV_RANK` (`info | local | network | elevated | opaque`). Register it:

```python
from scan import EXTERNAL_BACKENDS
EXTERNAL_BACKENDS["antivirus"] = adapter
```

Then `python3 scan.py <path> --backend antivirus` merges its findings with the
built-in ones; the report's `backends` list records what actually ran, and each
finding carries its `backend` so provenance is explicit.

**Two rules for any adapter:**

- **Only findings cross the border — never the verdict.** If the external tool
  says "Safe to install", that string does not appear anywhere in skill-xray's
  output. We map its per-finding severity onto our tiers and drop its overall
  recommendation. Importing a "safe" verdict would reintroduce the exact
  false-confidence antipattern skill-xray exists to avoid.
- **Audit the backend before you trust it.** An external scanner is itself a
  dependency you're about to run. Run skill-xray on *it* first (a Node/npm tool
  will surface real capability), pin the version, and only then register it.

## Example mapping: claude-skill-antivirus

[claude-skill-antivirus](https://github.com/claude-world/claude-skill-antivirus)
(MIT, Node ≥18, static pattern-matching, programmatic API returning
`{critical, high, medium, low, info}`) is a natural backend. Suggested severity
map (adjust per finding category):

| claude-skill-antivirus | skill-xray severity | tier floor |
|---|---|---|
| `critical` (destructive, exfil, remote-exec) | `elevated` / `opaque` if fetch-execute | T3 / T4 |
| `high` (secrets, persistence) | `elevated` | T3 |
| `medium` (network) | `network` | T2 |
| `low` (local writes/exec) | `local` | T1 |
| `info` | `info` | T0 |

Status: **not yet wired.** The registry ships empty on purpose — this is the
contract, not a shipped integration. Wiring it is tracked as a GitHub issue, and
step one there is to audit claude-skill-antivirus with skill-xray and pin it.
