#!/usr/bin/env python3
"""Report real_content_words (thin-lessons.py metric) for given files."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("tl", os.path.join(os.path.dirname(__file__), "thin-lessons.py"))
tl = importlib.util.module_from_spec(spec); spec.loader.exec_module(tl)
for path in sys.argv[1:]:
    raw = open(path, encoding="utf-8").read()
    _, body = tl.split_frontmatter(raw)
    print(f"{tl.real_content_words(body):>5}  {path}")
