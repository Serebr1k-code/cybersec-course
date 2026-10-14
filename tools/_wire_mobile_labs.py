#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wire the orphan lab bundles produced by the b1/b2 mobile generators into the
lessons' front-matter `lab:` block (the generators passed lab= to write_lesson
but the older helper never emitted the front-matter block). Re-uses the EXACT
lab specs by importing the generators with write_lesson stubbed out."""
import importlib.util
import os
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)

import _newlesson  # noqa: E402

CAPTURED = []


def _stub(m, body, lab=None):
    CAPTURED.append((dict(m), body, lab))


_newlesson.write_lesson = _stub

for gen in ('_gen_mobile_gaps_b1.py', '_gen_mobile_gaps_b2.py'):
    spec = importlib.util.spec_from_file_location(gen[:-3], os.path.join(TOOLS, gen))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

_yaml = _newlesson._yaml


def lab_block(lab):
    L = ['lab:', '  kind: shell']
    if lab.get('title'):
        L.append('  title: ' + _yaml(lab['title']))
    L.append('  toolset: [' + ', '.join(lab.get('toolset', ['core', 'grep'])) + ']')
    L.append('  workdir: ' + lab['workdir'])
    L.append('  files: [' + ', '.join(lab['files']) + ']')
    L.append('  check: ' + _yaml(lab['check']))
    L.append('  hints:')
    for h in lab['hints']:
        L.append('    - ' + _yaml(h))
    return '\n'.join(L)


patched = 0
for m, body, lab in CAPTURED:
    if lab is None:
        continue
    p = os.path.join(ROOT, 'content', m['category'], m['id'] + '.md')
    if not os.path.exists(p):
        print('missing lesson, skip:', m['id'])
        continue
    t = open(p, encoding='utf-8').read()
    if '\nlab:' in t or t.startswith('lab:'):
        print('already wired:', m['id'])
        continue
    # frontmatter ends at the second '---'
    lines = t.split('\n')
    assert lines[0] == '---', m['id']
    end = lines.index('---', 1)
    lines[end:end] = lab_block(lab).split('\n')
    open(p, 'w', encoding='utf-8').write('\n'.join(lines))
    print('wired lab:', m['id'])
    patched += 1

print('patched', patched)
