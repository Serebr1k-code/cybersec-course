#!/usr/bin/env python3
"""_prereq_fix.py — FINAL prerequisite-ordering pass for the content tree.

Goal: make the reading order (nested pre-order DFS: a parent, then its children
sorted by `order`) a valid topological order of the `prerequisites` graph, and
keep every sibling group's `order` unique + contiguous 0,1,2,...

What it edits (ONLY these two frontmatter fields):
  * `order` — recomputed per parent so children are topologically ordered by
    their subtree dependencies, tie-broken by intrinsic difficulty then the
    previous order (stable, preserves pedagogical intent).
  * `parent` — ONLY to fix a hard inversion where a lesson lists as a
    prerequisite one of its own descendants (impossible to satisfy by ordering):
    the descendant prerequisite is lifted to the inversion node's parent.

It never creates files and never touches ids/titles/bodies/quiz.

Usage:
  python3 tools/_prereq_fix.py            # dry-run: report before/after, write nothing
  python3 tools/_prereq_fix.py --apply    # write `order`/`parent` back
"""
from __future__ import annotations
import os, re, sys, heapq

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "content"))
DIFF_RANK = {"beginner": 1, "easy": 2, "medium": 3, "hard": 4, "expert": 5}
APPLY = "--apply" in sys.argv
REPARENT = "--reparent" in sys.argv


def parse_fm(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.startswith("---"):
        return None, text
    end = text.find("\n---", 3)
    if end == -1:
        return None, text
    fm = text[3:end]
    d = {}
    for line in fm.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if v.startswith("[") and v.endswith("]"):
            d[k] = [x.strip().strip('"').strip("'") for x in v[1:-1].split(",") if x.strip()]
        else:
            d[k] = v.strip('"').strip("'")
    return d, text


def load():
    lessons = {}
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
            fm["_id"] = fm.get("id") or fn[:-3]
            lessons[fm["_id"]] = fm
    return lessons


def int_order(fm):
    try:
        return int(fm.get("order"))
    except (TypeError, ValueError):
        return 10 ** 6


def build(lessons, parent):
    ch = {}
    for lid, fm in lessons.items():
        p = parent.get(lid, (fm.get("parent") or "").strip())
        if p:
            ch.setdefault(p, []).append(lid)
    return ch


def subtree_sets(lessons, ch):
    memo = {}

    def s(l):
        if l in memo:
            return memo[l]
        r = {l}
        for c in ch.get(l, []):
            r |= s(c)
        memo[l] = r
        return r
    for l in lessons:
        s(l)
    return memo


def topo(kids, lessons, order, edges):
    """Order siblings so that `edges` (a before b) are satisfied.

    Acyclic part: Kahn with difficulty/old-order tie-break. When a cycle blocks
    progress, break it with Eades' heuristic (emit the remaining node with the
    highest outdeg-indeg) so we minimise the number of back-edges instead of
    scrambling the whole group.
    """
    indeg = {k: 0 for k in kids}
    outdeg = {k: 0 for k in kids}
    adj = {}
    for a, b in edges:
        if a == b or a not in indeg or b not in indeg:
            continue
        if b not in adj.setdefault(a, set()):
            adj[a].add(b)
            indeg[b] += 1
            outdeg[a] += 1
    rank = lambda k: (DIFF_RANK.get(lessons[k].get("difficulty"), 3), order.get(k, 0), k)
    h = [rank(k) for k in kids if indeg[k] == 0]
    heapq.heapify(h)
    remaining = set(kids)
    out = []
    while remaining:
        while h and h[0][2] not in remaining:
            heapq.heappop(h)
        if h:
            _, _, k = heapq.heappop(h)
        else:
            k = max(remaining, key=lambda x: (outdeg[x] - indeg[x], -DIFF_RANK.get(lessons[x].get("difficulty"), 3), -order.get(x, 0), x))
        remaining.discard(k)
        out.append(k)
        for n in sorted(adj.get(k, [])):
            if n in remaining:
                indeg[n] -= 1
                if indeg[n] == 0:
                    heapq.heappush(h, rank(n))
    return out


def plan_cat(cat, lessons, parent, ch, sub, neworder):
    cat_ids = [l for l, f in lessons.items() if f.get("category") == cat]
    roots = [l for l in cat_ids if not parent.get(l)]
    pe = []
    for l in cat_ids:
        for p in lessons[l].get("prerequisites", []):
            if p in lessons and lessons[p].get("category") == cat:
                pe.append((p, l))

    def proc(par):
        kids = ch.get(par, [])
        if not kids:
            return

        def top(n):
            for c in kids:
                if n in sub[c]:
                    return c
            return None
        edges = set()
        for a, b in pe:
            ca, cb = top(a), top(b)
            if ca and cb and ca != cb:
                edges.add((ca, cb))
        ol = topo(kids, lessons, {k: int_order(lessons[k]) for k in kids}, edges)
        # Preserve the existing 0- or 1-based offset to avoid needless churn:
        # only the RELATIVE sequence matters to the app.
        vals = [int_order(lessons[k]) for k in kids]
        vals = [v for v in vals if v < 10 ** 6]
        base = 1 if (vals and min(vals) >= 1) else 0
        for i, k in enumerate(ol):
            neworder[k] = base + i
            proc(k)
    for r in roots:
        neworder[r] = int_order(lessons[r]) if int_order(lessons[r]) < 10 ** 6 else 0
        proc(r)


def reading_index(lessons, parent, ch, cat):
    cat_ids = [l for l, f in lessons.items() if f.get("category") == cat]
    roots = sorted([l for l in cat_ids if not parent.get(l)])
    idx = {}

    def dfs(lid, path):
        if lid in path or lid in idx:
            return
        idx[lid] = len(idx)
        for c in sorted(ch.get(lid, []), key=lambda k: (int_order(lessons[k]), k)):
            dfs(c, path + [lid])
    for r in roots:
        dfs(r, [])
    for l in cat_ids:
        idx.setdefault(l, len(idx))
    return idx


def count_viol(lessons, parent, ch, cat):
    idx = reading_index(lessons, parent, ch, cat)
    n = 0
    for l in [x for x, f in lessons.items() if f.get("category") == cat]:
        for p in lessons[l].get("prerequisites", []):
            if p in lessons and lessons[p].get("category") == cat and idx.get(p, 10 ** 9) >= idx.get(l, -1):
                n += 1
    return n


def main():
    lessons = load()
    parent = {lid: (fm.get("parent") or "").strip() for lid, fm in lessons.items()}
    cats = sorted(set(f.get("category") for f in lessons.values()))

    def rebuild():
        ch = {}
        for lid, p in parent.items():
            if p:
                ch.setdefault(p, []).append(lid)
        return ch

    def ancestors(l):
        seen = set()
        p = parent.get(l, "")
        while p and p not in seen:
            seen.add(p)
            p = parent.get(p, "")
        return seen

    def kids_of(p):
        return [c for c, pp in parent.items() if pp == p]

    # ---- Phase 1: fix hard inversions (prereq is a descendant of the node) ----
    inversion_fixes = []
    for cat in cats:
        cat_ids = [l for l, f in lessons.items() if f.get("category") == cat]
        for l in cat_ids:
            for p in lessons[l].get("prerequisites", []):
                if p in lessons and lessons[p].get("category") == cat and p != l:
                    ch = rebuild()
                    if p in subtree_sets(lessons, ch).get(l, set()):
                        gp = parent.get(l)
                        if gp is None or parent.get(p) == gp or len(kids_of(gp)) >= 4:
                            continue
                        parent[p] = gp
                        inversion_fixes.append((p, l))

    # ---- Phase 2 (+3): iterate order topo-sort and (optionally) re-parent ----
    before = {}
    for cat in cats:
        before[cat] = count_viol(lessons, parent, rebuild(), cat)
    orig_order = {lid: int_order(fm) for lid, fm in lessons.items()}
    orig_parent = dict(parent)

    neworder = {}
    moves = []
    for it in range(8):
        ch = rebuild()
        sub = subtree_sets(lessons, ch)
        neworder = {}
        for cat in cats:
            plan_cat(cat, lessons, parent, ch, sub, neworder)
        for l, o in neworder.items():
            lessons[l]["order"] = str(o)
        if not REPARENT:
            break
        ch = rebuild()
        moved = 0
        for cat in cats:
            idx = reading_index(lessons, parent, ch, cat)
            for l in [x for x, f in lessons.items() if f.get("category") == cat]:
                prereqs = [p for p in lessons[l].get("prerequisites", [])
                           if p in lessons and lessons[p].get("category") == cat]
                prereqs.sort(key=lambda q: -idx.get(q, -1))
                placed = False
                for p in prereqs:
                    if idx.get(p, 10 ** 9) < idx.get(l, -1):
                        continue  # already satisfied
                    if not parent.get(l) or parent.get(l) == p:
                        continue
                    if p in ancestors(l) or l in ancestors(p):
                        continue
                    # walk up from p until we find a parent with room
                    cand = p
                    for _ in range(10):
                        if not cand:
                            break
                        if cand == l or cand in ancestors(l) or l in ancestors(cand):
                            cand = parent.get(cand)
                            continue
                        if parent.get(l) == cand or len(kids_of(cand)) >= 4:
                            cand = parent.get(cand)
                            continue
                        parent[l] = cand
                        moves.append((l, cand))
                        moved += 1
                        placed = True
                        break
                    if placed:
                        break
            ch = rebuild()
        if moved == 0:
            break

    after = {}
    for cat in cats:
        after[cat] = count_viol(lessons, parent, rebuild(), cat)

    # ---- validate the planned structure ----
    issues = []
    chv = rebuild()
    for lid, kids in chv.items():
        if len(kids) > 4:
            issues.append(f">{4} children: {lid} has {len(kids)}")
    for cat in cats:
        roots = [l for l, f in lessons.items() if f.get("category") == cat and not parent.get(l)]
        if len(roots) != 1:
            issues.append(f"{cat}: {len(roots)} roots {roots}")
    # cycle detection
    color = {}

    def dfs_cycle(n):
        color[n] = 1
        for c in chv.get(n, []):
            if color.get(c) == 1:
                issues.append(f"cycle via {n}->{c}")
            elif color.get(c, 0) == 0:
                dfs_cycle(c)
        color[n] = 2
    for n in list(lessons):
        if color.get(n, 0) == 0:
            dfs_cycle(n)
    for lid, p in parent.items():
        if p and p not in lessons:
            issues.append(f"dangling parent {lid}->{p}")
        if p == lid:
            issues.append(f"self-parent {lid}")
    print(f"VALIDATION issues={len(issues)}")
    for x in issues[:20]:
        print("  !", x)

    # ---- write ----
    written_order = 0
    written_parent = 0
    for lid, fm in lessons.items():
        text = fm["_text"]
        newt = text
        o = neworder.get(lid)
        if o is not None and orig_order[lid] != o:
            newt, c = re.subn(r"^(order:\s*).*$", lambda m: m.group(1) + str(o), newt, count=1, flags=re.MULTILINE)
            if c == 0:
                newt = re.sub(r"^(id:.*)$", lambda m: m.group(1) + "\norder: " + str(o), newt, count=1, flags=re.MULTILINE)
            written_order += 1
        pnew = parent.get(lid)
        if pnew is not None and (fm.get("parent") or "").strip() != pnew:
            newt, c = re.subn(r"^(parent:\s*).*$", lambda m: m.group(1) + pnew, newt, count=1, flags=re.MULTILINE)
            if c == 0:
                newt = re.sub(r"^(id:.*)$", lambda m: m.group(1) + "\nparent: " + pnew, newt, count=1, flags=re.MULTILINE)
            written_parent += 1
        fm["_text"] = newt
    if APPLY:
        for lid, fm in lessons.items():
            with open(fm["_file"], "w", encoding="utf-8") as f:
                f.write(fm["_text"])

    print(f"{'cat':12} {'before':>7} {'after':>6}")
    for cat in cats:
        print(f"{cat:12} {before[cat]:>7} {after[cat]:>6}")
    print(f"TOTAL before={sum(before.values())} after={sum(after.values())}")
    print(f"order changes={'WRITTEN' if APPLY else 'planned'}={written_order}  "
          f"parent changes={written_parent}  reparent_moves={len(moves)}  "
          f"inversion_fixes={inversion_fixes}")


if __name__ == "__main__":
    main()
