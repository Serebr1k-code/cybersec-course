#!/usr/bin/env python3
"""Batch C1d — final top-off for doc-odf."""
from __future__ import annotations
import re, sys

ADD = """## Ключевое, что нужно запомнить

ODF — это ZIP-контейнер с открытым стандартом, где метаданные лежат в отдельной части
`meta.xml`, текст — в `content.xml`, а манифест `META-INF/manifest.xml` перечисляет
все части и признаки шифрования. Поле `meta:initial-creator` фиксирует первого автора,
`meta:editing-cycles` — число правок, а `text:tracked-changes` и `office:annotation`
могут хранить удалённый текст и комментарии. Разбор всегда начинается с распаковки и
чтения XML, а не с открытия документа в редакторе — редактор покажет лишь финальную
версию и скроет служебные данные."""

def main() -> int:
    path = "content/forensics/doc-odf.md"
    s = open(path, encoding="utf-8").read()
    m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
    if not m:
        print("SKIP (no quiz)"); return 1
    out = s[:m.start()] + ADD + "\n\n" + s[m.start():]
    open(path, "w", encoding="utf-8").write(out)
    print("appended doc-odf")
    return 0

if __name__ == "__main__":
    sys.exit(main())
