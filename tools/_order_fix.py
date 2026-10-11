#!/usr/bin/env python3
"""_order_fix.py — analyze + fix learning order for a set of categories.

Modes:
  report  (default): print per-parent proposed new order + flag suspicious mis-parents
  apply            : write new order (and re-parent map) back to frontmatter

Only touches `order:` and `parent:` lines. Never ids/titles/bodies/quiz.
"""
from __future__ import annotations
import os, re, json, sys, collections, argparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "content"))
DIFF_RANK = {"beginner": 1, "easy": 2, "medium": 3, "hard": 4, "expert": 5}
OWNED = ["cloud", "crypto", "forensics", "misc", "mobile", "osint", "pwn", "reversing", "stego"]
# categories handled by in-flight rank agents -> do not touch order/parent
SKIP = {"web", "network", "hardware"}


def parse_fm(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.startswith("---"):
        return None, text
    end = text.find("\n---", 3)
    if end == -1:
        return None, text
    fmraw = text[3:end]
    d = {}
    for line in fmraw.splitlines():
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        d[k] = v.strip('"').strip("'")
    return d, text


def load():
    L = {}
    for cat in sorted(os.listdir(ROOT)):
        cdir = os.path.join(ROOT, cat)
        if not os.path.isdir(cdir) or cat.startswith((".", "_")):
            continue
        for fn in sorted(os.listdir(cdir)):
            if not fn.endswith(".md") or fn.startswith((".", "_")):
                continue
            p = os.path.join(cdir, fn)
            fm, text = parse_fm(p)
            if fm is None:
                continue
            fm["_file"] = p
            fm["_text"] = text
            L[fm.get("id") or fn[:-3]] = fm
    return L


def diff_rank(fm):
    return DIFF_RANK.get((fm.get("difficulty") or "medium").lower(), 3)


def old_order(fm):
    try:
        return int(fm.get("order") or 0)
    except ValueError:
        return 0


def order_children(kids, L):
    """Topological order respecting prereqs among siblings, preferring easier first."""
    kidset = set(kids)
    # indegree from prerequisites that are also siblings
    indeg = {k: 0 for k in kids}
    adj = collections.defaultdict(list)
    for k in kids:
        pre = L[k].get("prerequisites") or []
        if isinstance(pre, str):
            pre = [x.strip() for x in pre.strip("[]").split(",") if x.strip()]
        for p in pre:
            if p in kidset and p != k:
                adj[p].append(k)
                indeg[k] += 1
    import heapq
    heap = []
    for k in kids:
        if indeg[k] == 0:
            heapq.heappush(heap, (diff_rank(L[k]), old_order(L[k]), k))
    out = []
    while heap:
        d, o, k = heapq.heappop(heap)
        out.append(k)
        for n in adj[k]:
            indeg[n] -= 1
            if indeg[n] == 0:
                heapq.heappush(heap, (diff_rank(L[n]), old_order(L[n]), n))
    if len(out) != len(kids):  # cycle among siblings -> fall back
        out = sorted(kids, key=lambda k: (diff_rank(L[k]), old_order(L[k]), k))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="report", choices=["report", "apply"])
    ap.add_argument("--cats", default=",".join(OWNED))
    ap.add_argument("--reparent", default="", help="json file {child: newparent}")
    args = ap.parse_args()
    cats = [c.strip() for c in args.cats.split(",") if c.strip()]

    L = load()
    reparent = {}
    if args.reparent and os.path.exists(args.reparent):
        reparent = json.load(open(args.reparent))

    # apply reparent in-memory
    for child, newp in reparent.items():
        if child in L:
            L[child]["parent"] = newp

    children = collections.defaultdict(list)
    for lid, fm in L.items():
        children[(fm.get("parent") or "").strip()].append(lid)

    def has_problem(kids):
        orders = [old_order(L[k]) for k in kids]
        if len(set(orders)) != len(orders):
            return True, "dup_order"
        seq = sorted(kids, key=lambda k: (old_order(L[k]), k))
        ranks = [diff_rank(L[k]) for k in seq]
        for i in range(1, len(ranks)):
            if ranks[i] < ranks[i - 1]:
                return True, f"diff_drop:{ranks[i-1]}->{ranks[i]}"
        return False, ""

    changes = {}  # file -> (new_order, new_parent)
    report = []
    for cat in cats:
        cat_ids = [l for l in L if L[l].get("category") == cat]
        for pid in cat_ids:
            kids = children.get(pid, [])
            if not kids:
                continue
            prob, why = has_problem(kids)
            forced = any(k in reparent for k in kids)
            if not prob and not forced:
                continue
            newk = order_children(kids, L)
            old_seq = sorted(kids, key=lambda k: (old_order(L[k]), k))
            if newk == old_seq and not forced:
                continue  # already correct
            # decide whether the reorder actually improves (non-decreasing) difficulty
            ranks = [diff_rank(L[k]) for k in newk]
            improved = all(ranks[i] >= ranks[i - 1] for i in range(1, len(ranks)))
            is_dup = "dup_order" in why
            if not improved and not is_dup and not forced:
                continue  # prereq-forced drop -> leave as-is (no churn)
            # assign new order values: reuse existing value-set if unique, else renumber
            vals = sorted(old_order(L[k]) for k in kids)
            if len(set(vals)) == len(vals):
                newvals = vals
            else:
                base = 0 if min(vals) == 0 else 1
                newvals = list(range(base, base + len(kids)))
            report.append((cat, pid, why, [(L[k].get("title"), old_order(L[k]), diff_rank(L[k])) for k in old_seq],
                           [(L[k].get("title"), diff_rank(L[k])) for k in newk]))
            for i, k in enumerate(newk):
                if old_order(L[k]) != newvals[i] or k in reparent:
                    changes[L[k]["_file"]] = (newvals[i], (L[k].get("parent") or "").strip())

    print(f"# parents with real problems: {len(report)}; files to edit: {len(changes)}")
    for cat, pid, why, old, new in report:
        print(f"\n[{cat}] {pid}  ({why})")
        print("  OLD:", [(t[:34], o, d) for t, o, d in old])
        print("  NEW:", [(t[:34], d) for t, d in new])

    if args.mode == "apply":
        n = 0
        for path, (neword, newparent) in changes.items():
            with open(path, encoding="utf-8") as f:
                text = f.read()
            end = text.find("\n---", 3)
            head, tail = text[:end], text[end:]
            head2 = re.sub(r"(?m)^order:\s*.*$", f"order: {neword}", head, count=1)
            if re.search(r"(?m)^parent:\s*.*$", head2):
                head2 = re.sub(r"(?m)^parent:\s*.*$", f"parent: {newparent}", head2, count=1)
            else:
                head2 = head2.rstrip() + f"\nparent: {newparent}"
            with open(path, "w", encoding="utf-8") as f:
                f.write(head2 + tail)
            n += 1
        print(f"\nAPPLIED: {n} files updated")


if __name__ == "__main__":
    main()
