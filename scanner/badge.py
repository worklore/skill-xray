#!/usr/bin/env python3
"""Generate a tier badge SVG. Usage: python3 badge.py T0|T1|T2|T3|T4 [--hash abc123]"""
import sys

TIERS = {
    "T0": ("#3fb950", "inert"),
    "T1": ("#58a6ff", "local"),
    "T2": ("#d29922", "network"),
    "T3": ("#f0883e", "elevated"),
    "T4": ("#f85149", "opaque"),
}


def svg(tier: str, note: str) -> str:
    color, word = TIERS[tier]
    right = f"{tier} {word}"
    lw, rw = 66, 8 + len(right) * 7          # label / value widths
    w = lw + rw
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="skill-xray: {right}">
<title>skill-xray: {right}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="{lw}" height="20" fill="#24292f"/>
<rect x="{lw}" width="{rw}" height="20" fill="{color}"/>
<rect width="{w}" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="{lw/2}" y="14">skill-xray</text>
<text x="{lw + rw/2}" y="14">{right}</text>
</g></svg>'''


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("-")]
    tier = (args[0] if args else "T0").upper()
    if tier not in TIERS:
        print(f"unknown tier {tier}; use T0..T4", file=sys.stderr)
        return 2
    print(svg(tier, tier))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
