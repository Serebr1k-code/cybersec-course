#!/usr/bin/env python3
"""Batch C3d — final top-off for forensics-cloud-serverless, spec-gps, doc-xps."""
from __future__ import annotations
import re, sys

ADDS = {
"doc-xps": r"""## Ключевой вывод

XPS — это ZIP-контейнер на основе Open Packaging Conventions, где страницы описаны XML,
а текст лежит в атрибутах `UnicodeString` элементов `Glyphs`. Разбор не требует
специального рендера: достаточно распаковать пакет, прочитать `Metadata/`, извлечь текст
из `*.fpage`, вытащить ресурсы из `Resources/` и проверить цифровую подпись. Это делает
XPS удобным объектом как в CTF, так и в реальной экспертизе документов.""",
"spec-gps": r"""## Ключевой вывод

GPS-трек — это набор точек с координатами и временем, но его доказательная сила зависит
от трёх вещей: источника, точности и корректного времени. Слабый сигнал можно заглушить
или подделать, точность в помещении падает, а часы устройства «уезжают». Поэтому трек
всегда нормализуют в UTC, сопровождают HDOP, сопоставляют с другими источниками и
проверяют на физическую проходимость маршрута.""",
"forensics-cloud-serverless": r"""## Ключевой вывод

В serverless нет диска и памяти для анализа — остаются только логи, метрики и
конфигурация. Поэтому расследование начинается с логирования, а не с изъятия носителя.
Сопоставляя логи выполнения, конфигурацию роли и аудит изменений кода, можно восстановить
и действия функции, и того, кто её изменил.""",
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
