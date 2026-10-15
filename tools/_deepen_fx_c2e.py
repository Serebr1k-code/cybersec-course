#!/usr/bin/env python3
"""Batch C2e — last top-off for mal-script-js, container-runtime."""
from __future__ import annotations
import re, sys

ADDS = {
"mal-script-js": r"""## Ключевой вывод

Разбор скриптовой малвари — это дисциплина **статического** анализа: определить тип,
снять слои обфускации, выписать IOC и восстановить цепочку, ни разу не запустив
образец. Тот, кто умеет декодировать PowerShell и JavaScript без исполнения, видит
атаку целиком — от фишингового вложения до второго этапа — и документирует её
воспроизводимо.""",
"forensics-cloud-container-runtime": r"""## Ключевой вывод

Побег из контейнера почти всегда оставляет следы на хосте: изменённый бинарник
рантайма, процессы вне namespace, необычные монтирования. Сопоставление версий,
конфигураций и логов на двух уровнях — единственный способ отличить реальный побег
от ложной тревоги.""",
}

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
        print("appended", lid)
    return 0

if __name__ == "__main__":
    sys.exit(main())
