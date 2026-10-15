#!/usr/bin/env python3
"""Batch T3b: tiny second pass for linux-package-logs (1177 -> 1200+)."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["linux-package-logs"] = """## Сводный пример расследования

Соберём всё в один практический сценарий. На сервере найден подозрительный
`/usr/bin/nc.traditional`, и нужно понять его происхождение:

1. `grep -i netcat /var/log/dpkg.log` → установлен `03:20:11`;
2. `grep -i netcat /var/log/apt/history.log` → `Commandline: apt-get install -y ...`;
3. `last -a | head` → вход по SSH с `203.0.113.5` в `03:19`;
4. `dpkg -S /usr/bin/nc.traditional` → файл принадлежит пакету `netcat-traditional`;
5. `grep -i netcat /var/log/dpkg.log | grep remove` → удалён в `03:40`.

Пять источников сходятся: злоумышленник вошёл, поставил netcat, использовал и удалил.
Отсутствие записи о пакете заставило бы искать артефакты ручной установки — `stat`,
`bash_history`, `/tmp`."""

def main() -> int:
    base = "content/forensics/"
    for lid, add in ADDS.items():
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
        if not m:
            print("SKIP (no quiz):", lid); continue
        out = s[:m.start()] + add + "\n\n" + s[m.start():]
        open(path, "w", encoding="utf-8").write(out)
        print("deepened", lid, "+", len(add.split()), "tokens")
    return 0

if __name__ == "__main__":
    sys.exit(main())
