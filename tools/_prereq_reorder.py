#!/usr/bin/env python3
"""_prereq_reorder.py — reorder siblings so the reading order respects the
`prerequisites` graph (a lesson must not appear before a lesson it names).

Reading order = pre-order DFS; within each parent, children are ordered by
`order`.  For each parent we build a constraint graph among its children:
child A must precede child B if some node in A's subtree is a prerequisite of
some node in B's subtree.  We topologically sort (stable by current order) and
write back contiguous 1..N `order:` values.

Only `order:` lines are ever modified.

Usage:
  python3 tools/_prereq_reorder.py            # report only
  python3 tools/_prereq_reorder.py --apply     # write changes
"""
from __future__ import annotations
import os
import re
import sys
import collections

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "content"))
DIFF_RANK = {"beginner": 1, "easy": 2, "medium": 3, "hard": 4, "expert": 5}


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
            lessons[fm.get("id") or fn[:-3]] = fm
    return lessons


def int_order(fm):
    try:
        return int(fm.get("order"))
    except (TypeError, ValueError):
        return 10 ** 6


def main():
    apply = "--apply" in sys.argv
    lessons = load()

    children = collections.defaultdict(list)
    for lid, fm in lessons.items():
        par = (fm.get("parent") or "").strip()
        if par:
            children[par].append(lid)

    # memoized descendant sets (iterative to avoid recursion limits)
    desc_cache = {}

    def descendants(root):
        if root in desc_cache:
            return desc_cache[root]
        stack = [root]
        seen = set()
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            for c in children.get(n, []):
                if c not in seen:
                    stack.append(c)
        desc_cache[root] = seen
        return seen

    # all parent nodes with >=2 children
    parents = [p for p in children if len(children[p]) >= 2]
    changed_files = 0
    cycles = []
    parents_touched = 0

    for parent in parents:
        kids = children[parent]
        kidset = set(kids)
        # descendant -> owning child
        owner = {}
        for k in kids:
            for d in descendants(k):
                owner.setdefault(d, k)
        # build constraint graph among children
        succ = collections.defaultdict(set)  # a -> set(b): a before b
        indeg = {k: 0 for k in kids}
        for lid, fm in lessons.items():
            pre = fm.get("prerequisites") or []
            if isinstance(pre, str):
                pre = [x.strip() for x in pre.strip("[]").split(",") if x.strip()]
            a_owner = owner.get(lid)
            if a_owner is None:
                continue
            for p in pre:
                b_owner = owner.get(p)
                if b_owner is None or b_owner == a_owner:
                    continue
                # b_owner (subtree containing the prereq) must come BEFORE a_owner
                if a_owner not in succ[b_owner]:
                    succ[b_owner].add(a_owner)
                    indeg[a_owner] += 1
        # stable tie-break by current order, difficulty, id
        cur = sorted(kids, key=lambda k: (int_order(lessons[k]),
                                          DIFF_RANK.get((lessons[k].get("difficulty") or "medium").lower(), 3),
                                          k))
        # Kahn with a heap keyed by current position
        pos = {k: i for i, k in enumerate(cur)}
        import heapq
        heap = [(pos[k], k) for k in kids if indeg[k] == 0]
        heapq.heapify(heap)
        out = []
        seen = set()
        while heap:
            _, n = heapq.heappop(heap)
            if n in seen:
                continue
            seen.add(n)
            out.append(n)
            for m in sorted(succ.get(n, []), key=lambda x: pos.get(x, 1 << 30)):
                if m in seen:
                    continue
                indeg[m] -= 1
                if indeg[m] <= 0:
                    heapq.heappush(heap, (pos.get(m, 1 << 30), m))
        leftover = [k for k in cur if k not in seen]
        if leftover:
            cycles.append((parent, leftover))
            out.extend(leftover)

        new_order = {k: i + 1 for i, k in enumerate(out)}
        # did anything actually change?
        changed = any(int_order(lessons[k]) != new_order[k] for k in kids)
        if not changed:
            continue
        parents_touched += 1
        if apply:
            for k in kids:
                fm = lessons[k]
                txt = fm["_text"]
                # re-read to avoid clobbering concurrent writes
                with open(fm["_file"], encoding="utf-8") as f:
                    cur_txt = f.read()
                m = re.match(r"^---\n(.*?)\n---\n", cur_txt, re.S)
                if not m:
                    continue
                body = re.sub(r"(?m)^order:\s*.*$", "order: %d" % new_order[k], m.group(1), count=1)
                newtxt = cur_txt[:m.start(1)] + body + cur_txt[m.end(1):]
                if newtxt != cur_txt:
                    with open(fm["_file"], "w", encoding="utf-8") as f:
                        f.write(newtxt)
                    changed_files += 1
        print(f"{'APPLY' if apply else 'PLAN '} {parent}: " +
              ", ".join(f"{k}={int_order(lessons[k])}->{new_order[k]}" for k in kids
                        if int_order(lessons[k]) != new_order[k]))

    print(f"\nparents_touched={parents_touched} files_changed={changed_files} cycles={len(cycles)}")
    for p, lo in cycles[:20]:
        print("  CYCLE at", p, "->", lo)


if __name__ == "__main__":
    main()
