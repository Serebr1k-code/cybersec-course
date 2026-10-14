import sys, importlib.util
spec = importlib.util.spec_from_file_location("tl", "tools/thin-lessons.py")
tl = importlib.util.module_from_spec(spec); spec.loader.exec_module(tl)
for p in sys.argv[1:]:
    t=open(p,encoding='utf-8').read()
    _,body=tl.split_frontmatter(t)
    print(f"{tl.real_content_words(body):5d}  {p}")
