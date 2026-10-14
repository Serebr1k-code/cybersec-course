#!/usr/bin/env python3
"""Convert inline flow-list quiz options to block style for the Go parser.

The content loader (internal/content parseQuizYAML) only reads options from
block-style bullets, NOT from inline `options: [a, b]`. This rewrites
`  options: ['a', 'b']` into the block form.
"""
import re
import sys

OPT_RE = re.compile(r'^(\s*)options:\s*\[(.*)\]\s*$')


def split_opts(inner: str):
    out, cur, q = [], '', None
    i = 0
    while i < len(inner):
        c = inner[i]
        if q:
            if c == q:
                q = None
            else:
                cur += c
        elif c in ('"', "'"):
            q = c
        elif c == ',':
            out.append(cur.strip())
            cur = ''
        else:
            cur += c
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return [o for o in out if o]


def convert(text: str) -> str:
    lines = text.split('\n')
    out = []
    for ln in lines:
        m = OPT_RE.match(ln)
        if m:
            indent = m.group(1)
            opts = split_opts(m.group(2))
            if len(opts) >= 2:
                out.append(f'{indent}options:')
                for o in opts:
                    o = o.replace('"', "'")
                    out.append(f'{indent}  - "{o}"')
                continue
        out.append(ln)
    return '\n'.join(out)


if __name__ == '__main__':
    for path in sys.argv[1:]:
        with open(path, encoding='utf-8') as f:
            t = f.read()
        n = convert(t)
        if n != t:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(n)
            print('converted', path)
        else:
            print('unchanged', path)
