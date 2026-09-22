"""
skill-xray behavioral-signal catalog — the human-editable red-flag list.

These patterns flag TEXT that tries to manipulate the agent reading a skill:
prompt injection, instructions to deceive the user, exfiltration intent, safety
bypass, authority/urgency pressure, and self-propagation. They are a SEPARATE
axis from the capability tier: the tier says what a skill *can touch* (blast
radius); these say whether the skill's own words *wave red flags*.

Honest limits — read before trusting any of this:
  • This is TRIAGE, not detection. Static patterns catch known, obvious phrasings.
    They do NOT catch novel or contextual attacks (the hard, unsolved case where
    even frontier models fail); expect false negatives on anything adaptive.
  • Patterns are English- and phrasing-dependent. A determined attacker paraphrases
    around them. Add languages and variants below.
  • A hit is NOT a verdict. A security tutorial legitimately quotes "ignore
    previous instructions". Every hit means "a human should read this line",
    nothing more.

To add a signal: append one dict {id, category, why, pattern}. `pattern` is a
regex, matched case-insensitively, one line at a time. Keep it specific enough
to be useful and broad enough to catch the obvious variants. No code changes.
"""

BEHAVIORAL_SIGNALS = [
    # --- instruction override / prompt injection -----------------------------
    {"id": "override-ignore-previous", "category": "prompt-injection",
     "why": "tells the agent to ignore or override its prior/system instructions",
     "pattern": r"\b(?:ignore|disregard|forget|override)\b[^\n]{0,40}"
                r"\b(?:previous|prior|earlier|above|all)\b[^\n]{0,20}"
                r"\b(?:instruction|prompt|rule|context|message)s?\b"},
    {"id": "override-role-reassign", "category": "prompt-injection",
     "why": "reassigns the agent's role or persona",
     "pattern": r"\byou are now\b|\bfrom now on,? you\b"
                r"|\bact as (?:if you are )?[^\n]{0,30}\b(?:with no|without)\b"},
    {"id": "override-new-instructions", "category": "prompt-injection",
     "why": "injects a fresh 'real/updated' instruction block for the agent",
     "pattern": r"\b(?:new|updated|real|actual|true)\s+"
                r"(?:instruction|directive|task|system\s+prompt)s?\b\s*:"},

    # --- deception: hide activity from the user ------------------------------
    {"id": "deceive-hide-from-user", "category": "deception",
     "why": "instructs the agent to hide its actions from the user",
     "pattern": r"\b(?:do\s*n['o]?t|never|without)\b[^\n]{0,30}"
                r"\b(?:tell|inform|mention|show|notify|alert|warn)\b[^\n]{0,20}"
                r"\b(?:the\s+)?(?:user|human|owner|them)\b"},
    {"id": "deceive-silently", "category": "deception",
     "why": "instructs the agent to act silently / covertly",
     "pattern": r"\b(?:silently|quietly|secretly|covertly|in the background)\b[^\n]{0,30}"
                r"\b(?:run|send|delete|install|modify|copy|upload|email|exfiltrate)\b"},
    {"id": "deceive-keep-secret", "category": "deception",
     "why": "instructs the agent to keep something secret",
     "pattern": r"\bkeep (?:this|it) (?:a )?secret\b|\bdo\s*n['o]?t reveal\b"
                r"|\bhide (?:this|it) from\b"},

    # --- exfiltration intent (the capability layer catches the mechanics) ----
    {"id": "exfil-send-secrets", "category": "exfiltration",
     "why": "prose directing secrets/credentials/env to be sent outward",
     "pattern": r"\b(?:send|upload|post|exfiltrate|leak|forward|email|transmit)\b[^\n]{0,40}"
                r"\b(?:password|secret|token|api[_-]?key|credential|\.env|"
                r"environment variable|private key|wallet)s?\b"},
    {"id": "exfil-to-url", "category": "exfiltration",
     "why": "prose directing data/output to be sent to a URL or server",
     "pattern": r"\b(?:send|upload|post|forward|report)\b[^\n]{0,30}"
                r"\b(?:to|at)\b[^\n]{0,20}https?://"},

    # --- safety / confirmation bypass ---------------------------------------
    {"id": "bypass-confirmation", "category": "safety-bypass",
     "why": "tells the agent to skip confirmation or auto-approve",
     "pattern": r"\b(?:do\s*n['o]?t|never|no need to|skip)\b[^\n]{0,20}"
                r"\b(?:ask|confirm|prompt|check with|request permission)\b"
                r"|\bauto[- ]?approve\b|\balways say yes\b"
                r"|\bapprove (?:all|everything|automatically)\b"},
    {"id": "bypass-safety", "category": "safety-bypass",
     "why": "tells the agent to disable or ignore its safety/guardrails",
     "pattern": r"\b(?:ignore|bypass|disable|turn off|override)\b[^\n]{0,20}"
                r"\b(?:safety|guardrail|filter|policy|restriction|safeguard)s?\b"},

    # --- authority / urgency pressure on the model --------------------------
    {"id": "pressure-authority-urgency", "category": "manipulation",
     "why": "uses authority or urgency framing to pressure the agent into acting",
     "pattern": r"\bas (?:an? )?(?:admin|administrator|root|owner|developer),?\s+"
                r"you (?:must|should|need to)\b"
                r"|\byou (?:have|are given) (?:full )?permission to\b"
                r"|\b(?:this is )?(?:urgent|critical|an emergency)\b[^\n]{0,30}"
                r"\b(?:you must|immediately|right now)\b"},

    # --- self-propagation / spreading ---------------------------------------
    {"id": "self-propagate", "category": "self-propagation",
     "why": "instructs the agent to copy or replicate the skill elsewhere",
     "pattern": r"\b(?:copy|replicate|install|write|add)\b[^\n]{0,20}"
                r"\b(?:yourself|this skill|these instructions)\b[^\n]{0,30}"
                r"\b(?:into|to)\b[^\n]{0,15}\b(?:every|all|other|each)\b"},
]
