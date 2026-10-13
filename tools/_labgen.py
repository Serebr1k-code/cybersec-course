#!/usr/bin/env python3
"""Authoring helper: write content/labs/<id>.json bundles and inject the `lab:`
front-matter block into a lesson, from a compact Python spec.

Not part of the engine — a content-authoring convenience (like _rw.py).
Usage: import labs_from_spec(SPECS) from this module, or run a spec file.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTENT = os.path.join(ROOT, 'content')


def _yaml_scalar(s):
    # Single-quote YAML scalar, escaping embedded single quotes.
    return "'" + str(s).replace("'", "''") + "'"


def lab_block(spec):
    lines = ['lab:', '  kind: shell']
    if spec.get('title'):
        lines.append('  title: ' + _yaml_scalar(spec['title']))
    if spec.get('toolset'):
        lines.append('  toolset: [' + ', '.join(spec['toolset']) + ']')
    lines.append('  workdir: ' + spec['workdir'])
    if spec.get('files'):
        lines.append('  files: [' + ', '.join(spec['files']) + ']')
    lines.append('  check: ' + _yaml_scalar(spec['check']))
    if spec.get('hints'):
        lines.append('  hints:')
        for h in spec['hints']:
            lines.append('    - ' + _yaml_scalar(h))
    return '\n'.join(lines)


def write_bundle(spec):
    bundle = {
        'id': spec['id'],
        'workdir': spec['workdir'],
        'hostname': spec.get('hostname', 'lab'),
    }
    if spec.get('vars'):
        bundle['vars'] = spec['vars']
    if spec.get('env'):
        bundle['env'] = spec['env']
    if spec.get('expect'):
        bundle['expect'] = spec['expect']
    bundle['fs'] = spec.get('fs', [])
    if spec.get('tools'):
        bundle['tools'] = spec['tools']
    path = os.path.join(CONTENT, 'labs', spec['id'] + '.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write('\n')
    return path


def inject_lesson(spec):
    """Insert the lab block before the closing `---` of the lesson front-matter."""
    path = os.path.join(CONTENT, spec['category'], spec['id'] + '.md')
    with open(path, encoding='utf-8') as f:
        text = f.read()
    if '\nlab:\n' in text:
        raise SystemExit(f'{spec["id"]}: already has a lab block')
    if not text.startswith('---\n'):
        raise SystemExit(f'{spec["id"]}: no front-matter')
    end = text.index('\n---', 4)
    block = lab_block(spec)
    new = text[:end] + '\n' + block + text[end:]
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new)
    return path


def apply(spec):
    path = os.path.join(CONTENT, spec['category'], spec['id'] + '.md')
    with open(path, encoding='utf-8') as f:
        if '\nlab:\n' in f.read():
            print(f"{spec['id']}: already labbed — skipped (bundle untouched)")
            return None
    write_bundle(spec)
    inject_lesson(spec)
    return spec['id']


def main():
    if len(sys.argv) < 2:
        print('usage: _labgen.py <spec_module.py>', file=sys.stderr)
        return 1
    import importlib.util
    p = sys.argv[1]
    s = importlib.util.spec_from_file_location('spec', p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    for spec in m.SPECS:
        print('wrote', apply(spec))
    return 0


if __name__ == '__main__':
    sys.exit(main())
