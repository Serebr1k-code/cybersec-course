#!/usr/bin/env python3
"""Remove later duplicate '## ' sections in the pre-quiz body of lessons that
were concurrently deepened by two agents (collision). Keeps the first
occurrence of each heading; drops subsequent sections with the same heading."""
from __future__ import annotations
import re, sys

FILES = [
    "tool-bulk-extractor", "spec-dvr-camera", "af-detection-methodology",
    "net-cloud-vpcflow", "net-vpn", "net-ics-scada", "net-voip",
    "net-tls-decrypt-deep", "macos-launchservices", "linux-container-escape",
    "linux-network-artifacts", "macos-apple-silicon", "net-arp-mac",
    "linux-package-logs", "forensics-cicd",
]

def dedupe(text: str) -> tuple[str, list[str]]:
    m = re.search(r"^## Квиз\s*$", text, re.MULTILINE)
    if not m:
        return text, ["no-quiz"]
    head, tail = text[:m.start()], text[m.start():]
    lines = head.split("\n")
    out: list[str] = []
    seen: set[str] = set()
    dropped: list[str] = []
    i = 0
    cur_drop = False
    while i < len(lines):
        line = lines[i]
        if line.startswith("## "):
            h = line.strip()
            if h in seen:
                cur_drop = True
                dropped.append(h)
                i += 1
                continue
            seen.add(h)
            cur_drop = False
        if not cur_drop:
            out.append(line)
        i += 1
    newhead = "\n".join(out)
    # collapse >2 blank lines
    newhead = re.sub(r"\n{3,}", "\n\n", newhead)
    return newhead + tail, dropped

def main() -> int:
    base = "content/forensics/"
    for lid in FILES:
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        new, dropped = dedupe(s)
        if new != s:
            open(path, "w", encoding="utf-8").write(new)
        print(f"{lid}: dropped={dropped}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
