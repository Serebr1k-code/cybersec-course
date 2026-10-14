#!/usr/bin/env python3
"""lab-align.py — audit lab<->lesson alignment (docs/LABS.md rules).

Three normative rules (see docs/LABS.md "Правила качества лаборатории"):

  (A) LAB SUBSET OF LESSON. A lab may use ONLY tools the lesson itself teaches.
      A required tool that the lesson body never mentions is a hard defect
      (the "unmentioned tool" class — the bug the user reported: a network
      lesson whose lab needs `tshark` while the text only talks about `tcpdump`).

  (B) TRY-IT-YOURSELF. Every lab must pose a concrete hands-on task with a real
      `check`. A lab whose `check` always passes (empty / `grep -q ''` / `true`)
      with no hidden bundle `expect`, or whose task text has no actionable
      command, is passive -> flagged.

  (C) PREREQUISITE REMINDER. Each lab should include at least one sub-step drawn
      from the lesson's prerequisite path (frontmatter `prerequisites:` + the
      `parent` hub). We approximate "touches a prerequisite" by tool overlap:
      at least one tool the lab invokes is taught by a lesson on that path.

Required tools for a lab come from the strongest signals:
  * the bundle's emulated `tools` keys (content/labs/<id>.json) — the tools the
    student actually invokes in the emulated console;
  * tool names in backticked commands inside the bundle `task.md` and the
    front-matter `hints`.
The lesson body is everything after the closing `---` of the front-matter.

Usage:
  python3 tools/lab-align.py [--content DIR] [--category CAT] [--json]
                             [--limit N] [--specialized-only] [--flag FLAG]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

CONTENT = "content"
LABS = "labs"

# canonical tool name -> body regex
TOOL_PATTERNS = {
    "tshark": r"\btshark\b",
    "tcpdump": r"\btcpdump\b",
    "nmap": r"\bnmap\b",
    "naabu": r"\bnaabu\b",
    "gdb": r"\bgdb\b",
    "objdump": r"\bobjdump\b",
    "readelf": r"\breadelf\b",
    "nm": r"\bnm\b",
    "dig": r"\bdig\b",
    "nslookup": r"\bnslookup\b",
    "whois": r"\bwhois\b",
    "curl": r"\bcurl\b",
    "wget": r"\bwget\b",
    "jq": r"\bjq\b",
    "grep": r"\bgrep\b",
    "strings": r"\bstrings\b",
    "base64": r"\bbase64\b",
    "file": r"\bfile\b",
    "unzip": r"\bunzip\b",
    "tar": r"\btar\b",
    "xxd": r"\bxxd\b",
    "hexdump": r"\bhexdump\b",
    "exiftool": r"\bexiftool\b",
    "openssl": r"\bopenssl\b",
    "nc": r"\bnc\b|\bnetcat\b|\bncat\b",
    "socat": r"\bsocat\b",
    "git": r"\bgit\b",
    "hashcat": r"\bhashcat\b",
    "john": r"\bjohn\b",
    "sqlmap": r"\bsqlmap\b",
    "ffuf": r"\bffuf\b",
    "nuclei": r"\bnuclei\b",
    "gobuster": r"\bgobuster\b",
    "wfuzz": r"\bwfuzz\b",
    "feroxbuster": r"\bferoxbuster\b",
    "httpx": r"\bhttpx\b",
    "hydra": r"\bhydra\b",
    "kubectl": r"\bkubectl\b",
    "aws": r"\baws\b",
    "gcloud": r"\bgcloud\b",
    "volatility": r"\bvolatility\b|\bvol\.py\b|\bvol3\b",
    "sleuthkit": r"\bfls\b|\bicat\b|\bmactime\b|\bsleuthkit\b|\btsk_\b|\bfsstat\b",
    "sqlite3": r"\bsqlite3\b",
    "mongosh": r"\bmongosh\b|\bmongo\b",
    "redis-cli": r"\bredis-cli\b",
    "tesseract": r"\btesseract\b",
    "zbarimg": r"\bzbarimg\b",
    "steghide": r"\bsteghide\b",
    "stegseek": r"\bstegseek\b",
    "zsteg": r"\bzsteg\b",
    "binwalk": r"\bbinwalk\b",
    "apktool": r"\bapktool\b",
    "jadx": r"\bjadx\b",
    "objection": r"\bobjection\b",
    "yara": r"\byara\b",
    "gpg": r"\bgpg\b",
    "ssh": r"\bssh\b",
    "whatweb": r"\bwhatweb\b",
    "sslscan": r"\bsslscan\b",
    "websocat": r"\bwebsocat\b",
    "commix": r"\bcommix\b",
    "tplmap": r"\btplmap\b",
    "grpcurl": r"\bgrpcurl\b",
    "responder": r"\bresponder\b",
    "ntlmrelayx": r"\bntlmrelayx\b",
    "searchsploit": r"\bsearchsploit\b",
    "smtp-user-enum": r"\bsmtp-user-enum\b",
    "pdfinfo": r"\bpdfinfo\b",
    "sox": r"\bsox\b",
    "gitleaks": r"\bgitleaks\b",
    "googler": r"\bgoogler\b",
    "subfinder": r"\bsubfinder\b",
    "sherlock": r"\bsherlock\b",
    "argocd": r"\bargocd\b",
    "cryptsetup": r"\bcryptsetup\b",
    "keytool": r"\bkeytool\b",
    "plutil": r"\bplutil\b",
    "ffprobe": r"\bffprobe\b",
    "ffmpeg": r"\bffmpeg\b",
    "md5sum": r"\bmd5sum\b|\bmd5\b",
    "sha256sum": r"\bsha256sum\b|\bsha256\b",
    "sha1sum": r"\bsha1sum\b|\bsha1\b",
    "ROPGadget": r"\bROPgadget\b",
    "ruby": r"\bruby\b",
    "php": r"\bphp\b",
    "java": r"\bjava\b",
    "node": r"\bnode\b",
    "pm3": r"\bpm3\b|\bproxmark\b",
    "regripper": r"\bregripper\b|\brip\.pl\b",
    "evtx": r"\bevtxexport\b|\bevtxdump\b",
    "adb": r"\badb\b",
    "qemu": r"\bqemu\b",
    "mdadm": r"\bmdadm\b",
    "lvm": r"\bvgscan\b|\bpvscan\b|\blvm\b",
    "btrfs": r"\bbtrfs\b",
    "ldd": r"\bldd\b",
    "strace": r"\bstrace\b",
    "ltrace": r"\bltrace\b",
    "radare2": r"\bradare2\b|\br2\b|\brizin\b",
    "ghidra": r"\bghidra\b",
    "binutils": r"\bobjdump\b|\breadelf\b",
}

# generic/basic tools — being unmentioned is a weak signal (often supplied by the
# emulator and used only incidentally). Reported separately, not as hard fails.
BASIC = {"grep", "base64", "file", "strings", "unzip", "tar", "jq", "xxd",
         "hexdump", "curl", "wget", "cat", "echo", "ls", "sed", "awk",
         "md5sum", "sha256sum", "sha1sum"}

# backtick first-word aliases -> canonical
ALIAS = {
    "tshark": "tshark", "tcpdump": "tcpdump", "nmap": "nmap", "gdb": "gdb",
    "objdump": "objdump", "readelf": "readelf", "nm": "nm", "dig": "dig",
    "whois": "whois", "curl": "curl", "wget": "wget", "jq": "jq", "grep": "grep",
    "strings": "strings", "base64": "base64", "file": "file", "unzip": "unzip",
    "tar": "tar", "xxd": "xxd", "hexdump": "hexdump", "exiftool": "exiftool",
    "openssl": "openssl", "nc": "nc", "ncat": "nc", "netcat": "nc",
    "socat": "socat", "git": "git", "hashcat": "hashcat", "john": "john",
    "sqlmap": "sqlmap", "ffuf": "ffuf", "nuclei": "nuclei", "gobuster": "gobuster",
    "wfuzz": "wfuzz", "feroxbuster": "feroxbuster", "httpx": "httpx",
    "hydra": "hydra", "kubectl": "kubectl", "aws": "aws", "gcloud": "gcloud",
    "volatility": "volatility", "vol.py": "volatility", "vol3": "volatility",
    "fls": "sleuthkit", "icat": "sleuthkit", "mactime": "sleuthkit",
    "fsstat": "sleuthkit", "sqlite3": "sqlite3", "mongosh": "mongosh",
    "mongo": "mongosh", "redis-cli": "redis-cli", "tesseract": "tesseract",
    "zbarimg": "zbarimg", "steghide": "steghide", "stegseek": "stegseek",
    "zsteg": "zsteg", "binwalk": "binwalk", "apktool": "apktool", "jadx": "jadx",
    "objection": "objection", "yara": "yara", "gpg": "gpg", "ssh": "ssh",
    "whatweb": "whatweb", "sslscan": "sslscan", "websocat": "websocat",
    "commix": "commix", "tplmap": "tplmap", "grpcurl": "grpcurl",
    "responder": "responder", "ntlmrelayx": "ntlmrelayx",
    "searchsploit": "searchsploit", "pdfinfo": "pdfinfo", "sox": "sox",
    "gitleaks": "gitleaks", "googler": "googler", "subfinder": "subfinder",
    "sherlock": "sherlock", "argocd": "argocd", "cryptsetup": "cryptsetup",
    "keytool": "keytool", "plutil": "plutil", "ffprobe": "ffprobe",
    "ffmpeg": "ffmpeg", "md5sum": "md5sum", "sha256sum": "sha256sum",
    "sha1sum": "sha1sum", "ROPgadget": "ROPgadget", "ruby": "ruby", "php": "php",
    "java": "java", "node": "node", "pm3": "pm3", "regripper": "regripper",
    "evtxexport": "evtx", "evtxdump": "evtx", "adb": "adb", "qemu": "qemu",
    "mdadm": "mdadm", "vgscan": "lvm", "pvscan": "lvm", "ldd": "ldd",
    "strace": "strace", "ltrace": "ltrace", "r2": "radare2",
    "radare2": "radare2", "ghidra": "ghidra",
}

# actionable (try-it-yourself) task verbs — RU imperative + EN
ACTION_VERBS = re.compile(
    r"\b(найд\w+|запиш\w+|определ\w+|выполн\w+|запуст\w+|извлек\w+|собер\w+|"
    r"расшифр\w+|посчита\w+|добуд\w+|восстанов\w+|открой|сравн\w+|провер\w+|"
    r"разбер\w+|дизассемблир\w+|декодир\w+|перевед\w+|вытащ\w+|настро\w+|"
    r"exploit|decode|extract|find|run|write|analyze|parse)\b",
    re.IGNORECASE)


def parse_front(body):
    if not body.startswith("---"):
        return "", body
    end = body.find("\n---", 3)
    if end == -1:
        return "", body
    return body[3:end], body[end + 4:]


def fm_lab_block(fm):
    lines = fm.splitlines()
    out, inlab = [], False
    for ln in lines:
        if re.match(r"^lab:\s*$", ln):
            inlab = True
            continue
        if inlab:
            if ln.startswith((" ", "\t")):
                out.append(ln)
            elif ln.strip() == "":
                out.append(ln)
            else:
                break
    return "\n".join(out)


def fm_value(fm, key):
    m = re.search(r"^%s:\s*(.*)$" % re.escape(key), fm, re.M)
    return m.group(1).strip() if m else ""


def fm_list(fm, key):
    m = re.search(r"^%s:\s*(.*)$" % re.escape(key), fm, re.M)
    if not m:
        return []
    v = m.group(1).strip()
    if v.startswith("["):
        return [x.strip().strip("\"'") for x in v.strip("[]").split(",") if x.strip()]
    return [v.strip("\"'")] if v and v != "[]" else []


def lab_toolset(lab):
    m = re.search(r"toolset:\s*\[([^\]]*)\]", lab)
    return [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []


def fm_lab_check(lab):
    m = re.search(r"^\s*check:\s*(.+)$", lab, re.M)
    return m.group(1).strip() if m else ""


def tools_in_commands(text):
    """canonical tools whose command appears in a backtick / code context."""
    found = set()
    spans = re.findall(r"`([^`]+)`", text)
    for s in spans:
        for w in re.findall(r"[A-Za-z_][A-Za-z0-9_.\-]*", s):
            c = ALIAS.get(w)
            if c:
                found.add(c)
    return found


def body_tools(body):
    return {t for t in TOOL_PATTERNS if re.search(TOOL_PATTERNS[t], body, re.IGNORECASE)}


def mentioned(tool, body):
    pat = TOOL_PATTERNS.get(tool)
    return bool(pat) and re.search(pat, body, re.IGNORECASE) is not None


def trivial_check(check):
    """A check that always passes: empty, `true`/`:`, or an empty grep pattern."""
    c = check.strip().strip("\"'").strip()
    if not c:
        return True
    if re.match(r"^(true|:)\s*$", c):
        return True
    if re.search(r"grep\s+-[a-zA-Z]*q[a-zA-Z]*\s+(''|\"\")(\s|$)", c):
        return True
    return False


def load_bundle(root, lid):
    bp = os.path.join(root, LABS, lid + ".json")
    if not os.path.exists(bp):
        return None
    try:
        return json.load(open(bp, encoding="utf-8"))
    except Exception:
        return None


def load_lessons(root, cats):
    """id -> {cat,path,fm,body,lab,check,req_tools,has_expect,task,body_tools}."""
    lessons = {}
    for cat in cats:
        cdir = os.path.join(root, cat)
        if not os.path.isdir(cdir):
            continue
        for f in sorted(os.listdir(cdir)):
            if not f.endswith(".md") or f.startswith((".", "_")):
                continue
            path = os.path.join(cdir, f)
            raw = open(path, encoding="utf-8", errors="replace").read()
            fm, body = parse_front(raw)
            lid = fm_value(fm, "id") or f[:-3]
            lessons[lid] = {
                "id": lid, "stem": f[:-3], "cat": cat, "path": path,
                "fm": fm, "body": body,
                "lab": fm_lab_block(fm), "check": fm_lab_check(fm_lab_block(fm)),
                "prereq": fm_list(fm, "prerequisites"),
                "parent": fm_value(fm, "parent").strip("\"'"),
                "body_tools": body_tools(body),
            }
    return lessons


def enrich(lessons, root):
    for lid, L in lessons.items():
        lab = L["lab"]
        if not lab.strip():
            continue
        req, task, has_expect = set(), "", False
        b = load_bundle(root, L["stem"]) or load_bundle(root, lid)
        if b:
            req |= set((b.get("tools") or {}).keys())
            has_expect = bool(b.get("expect"))
            for e in b.get("fs", []):
                if str(e.get("path", "")).endswith("task.md"):
                    task = e.get("text", "")
        req |= tools_in_commands(task)
        req |= tools_in_commands(lab)
        L["req_tools"] = req
        L["task"] = task
        L["has_expect"] = has_expect


def prereq_chain(lid, lessons, depth=3):
    """BFS over prerequisites + parent hub (bounded)."""
    seen, frontier = set(), [lid]
    for _ in range(depth):
        nxt = []
        for x in frontier:
            L = lessons.get(x)
            if not L:
                continue
            for p in L["prereq"] + ([L["parent"]] if L["parent"] else []):
                if p and p not in seen and p != lid:
                    seen.add(p)
                    nxt.append(p)
        frontier = nxt
    return seen


def keywords(text):
    return set(w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{3,}|[А-Яа-яЁё]{5,}", text))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--content", default=CONTENT)
    ap.add_argument("--category", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--specialized-only", action="store_true")
    ap.add_argument("--flag", default=None,
                    help="only show this flag: untaught_tool|weak_tool|passive|no_prereq|unrelated")
    args = ap.parse_args()

    root = args.content
    cats = [args.category] if args.category else sorted(
        d for d in os.listdir(root)
        if os.path.isdir(os.path.join(root, d)) and not d.startswith((".", "_")))

    lessons = load_lessons(root, cats)
    enrich(lessons, root)

    flags = defaultdict(list)   # flag -> [finding]
    per_cat = defaultdict(Counter)  # flag -> Counter(category)
    total = 0
    for lid, L in lessons.items():
        if not L["lab"].strip():
            continue
        total += 1
        cat = L["cat"]
        req = L.get("req_tools", set())
        missing = sorted(t for t in req if t in TOOL_PATTERNS and not mentioned(t, L["body"]))
        hard = [t for t in missing if t not in BASIC]
        weak = [t for t in missing if t in BASIC]

        # (A) untaught tool
        if hard:
            flags["untaught_tool"].append({"id": lid, "cat": cat, "tools": hard})
            per_cat["untaught_tool"][cat] += 1
        if weak and not args.specialized_only:
            flags["weak_tool"].append({"id": lid, "cat": cat, "tools": weak})
            per_cat["weak_tool"][cat] += 1

        # (B) passive / always-pass
        task = L.get("task", "")
        no_action = bool(task) and not ACTION_VERBS.search(task) and "`" not in task
        if trivial_check(L["check"]) and not L.get("has_expect"):
            flags["passive"].append({"id": lid, "cat": cat, "why": "trivial check, no bundle expect",
                                     "check": L["check"]})
            per_cat["passive"][cat] += 1
        elif no_action and not L.get("has_expect"):
            flags["passive"].append({"id": lid, "cat": cat, "why": "no actionable command in task"})
            per_cat["passive"][cat] += 1

        # (C) no prerequisite reminder
        chain = prereq_chain(lid, lessons)
        req_meaningful = req - BASIC
        if chain and req_meaningful:
            chain_tools = set()
            for p in chain:
                if p in lessons:
                    chain_tools |= (lessons[p]["body_tools"] - BASIC)
                    chain_tools |= (lessons[p].get("req_tools", set()) - BASIC)
            lab_text = L.get("task", "") + "\n" + L["lab"]
            referenced = any(re.search(r"\b" + re.escape(p) + r"\b", lab_text)
                             for p in chain)
            if not referenced and chain_tools and not (req_meaningful & chain_tools):
                flags["no_prereq"].append({"id": lid, "cat": cat,
                                           "req": sorted(req_meaningful), "chain": sorted(chain)[:4]})
                per_cat["no_prereq"][cat] += 1

        # (D) unrelated topic (coarse token overlap)
        if task:
            body_kw = keywords(L["body"])
            task_kw = keywords(task) | keywords(L["lab"])
            if task_kw and len(task_kw & body_kw) / max(1, len(task_kw)) < 0.10:
                flags["unrelated"].append({"id": lid, "cat": cat})
                per_cat["unrelated"][cat] += 1

    order = ["untaught_tool", "weak_tool", "passive", "no_prereq", "unrelated"]
    if args.flag:
        order = [args.flag]

    if args.json:
        out = {"total_labs": total,
               "counts": {f: len(flags[f]) for f in order},
               "per_category": {f: dict(per_cat[f]) for f in order},
               "findings": {f: flags[f] for f in order}}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    print(f"total labs with lab: block = {total}")
    for f in order:
        print(f"\n== {f}: {len(flags[f])} ==")
        for c, n in per_cat[f].most_common():
            print(f"   {c}: {n}")
    if args.limit:
        for f in order:
            flags[f] = flags[f][:args.limit]
    print("\n--- samples ---")
    for f in order:
        for fd in flags[f][:20]:
            print(f"  [{f}] {fd['cat']}/{fd['id']}: {fd.get('tools') or fd.get('why') or fd.get('req') or ''}")


if __name__ == "__main__":
    main()
