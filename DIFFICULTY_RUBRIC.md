# Difficulty & Order Rubric (web category)

Authored by **rank-web-a** for the systematic re-rank of `content/web/`.
`rank-web-b` handles the remaining files (see **File split** below).

## The formula

```
FINAL stars = clamp(1..5, round(0.6*INTRINSIC + 0.4*PREREQ_DEPTH))
```

`difficulty:` string mapping: `1=beginner, 2=easy, 3=medium, 4=hard, 5=expert`.

### INTRINSIC (1-5) — complexity of the CORE new technique in THIS lesson
Rate by the **actual technique the lesson teaches**, NOT by how advanced the
topic *sounds*. Ignore prerequisites (they are captured by PREREQ_DEPTH).

| Score | Meaning |
|------|---------|
| 1 | beginner — recognize a format / run one tool with defaults / base-N decode / trivial |
| 2 | easy — one well-known technique with a few flags / simple script / light theory |
| 3 | medium — combine 2-3 concepts / custom scripting / some math or parsing / non-obvious steps |
| 4 | hard — multi-step exploit / deep tooling / bypass mitigations / real crypto-math / debugging |
| 5 | expert — research-level / kernel-browser-hardware fault / heavy math (lattice, Coppersmith) / chaining many primitives / no standard tooling |

**Calibration:** "DNA steganography" = base-4 encoding + a little biology theory,
solvable by a quick brute-force with a small shift → INTRINSIC ≈ 2 → FINAL easy/medium.
Do **not** rate by topic prestige.

### PREREQ_DEPTH (1-5) — how much you must already know
Base = BFS depth of the node from the category root (`web-http-basics`, depth 0):

| BFS depth | base |
|-----------|------|
| 0-1 | 1 |
| 2-3 | 2 |
| 4-6 | 3 |
| 7-9 | 4 |
| 10+ | 5 |

Adjust by the length of the lesson's `prerequisites` list: **+1 if `len(prerequisites) >= 3`**
(so a node that needs three prior lessons is treated as one depth band deeper).
Cap at 5.

## Order normalization

For every parent:
1. `order` values of its children must be **unique and contiguous** `0,1,2,...`.
2. Prerequisite / intro lessons first.
3. Difficulty roughly **non-decreasing** along a branch.
4. Sort key used: `(FINAL_star, old_order)` (stable — preserves the existing
   pedagogical intent for ties).

## Re-parenting

A lesson whose `parent` is clearly the wrong hub (topic does not belong under that
branch) is re-parented to the correct hub **in the same category** (`web`).
Constraints always hold: acyclic, exactly one root (`web-http-basics`),
no node with more than 4 children.

## File split (coordination between rank-web-a and rank-web-b)

`content/web/` has **181** files. Sorted **alphabetically by filename**:

* **rank-web-a (this agent)** — the **FIRST 90** files (index 1..90,
  `db-elasticsearch.md` … `web-playbook-file-to-rce.md`).
* **rank-web-b** — the remaining **91** files (index 91..181,
  `web-playbook-injection-triage.md` … `web-zip-slip.md`).

Both agents edit ONLY `difficulty`, `order`, `parent` — never ids/titles/bodies/quiz.

### Shared parents (children on both sides of the split)
For a parent whose children span the split, the **full union ordering** is computed
with the same sort key. rank-web-a writes the new `order` for its own children and
records the intended order for rank-web-b's children in
`DIFFICULTY_SPLIT_HANDOFF.md`. rank-web-b should apply the recorded values for its
children so the union stays contiguous. Parents already contiguous under the union
key are left untouched.
