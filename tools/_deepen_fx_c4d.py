#!/usr/bin/env python3
"""Batch C4d — final top-off for media-deepfake, tool-xways, web-mongodb-redis."""
from __future__ import annotations
import re, sys

ADDS = {
"media-deepfake": r"""## Что важно помнить

Подделка медиа — не вопрос «да или нет», а вопрос степени уверенности. Комбинируй
визуальные артефакты, аудио-анализ, частотные следы, метаданные и провенанс; оценивай
контекст (кто, когда, откуда получил файл). Детекторы помогают, но не выносят приговор.
Честная формулировка «есть признаки синтетики, уверенность средняя» полезнее громкого
«это фейк».""",
"tool-xways": r"""## Что важно помнить

X-Ways работает read-only поверх образа, поэтому оригинал остаётся неизменным. Сила
инструмента — в скорости, фильтрах и встроенных парсерах; слабость — в том, что он
требует понимания файловых систем и артефактов. Не путай «найдено» с «доказано»:
найденный файл — факт, его роль в инциденте — интерпретация, которую обосновывает
аналитик.""",
"web-mongodb-redis": r"""## Что важно помнить

Redis и MongoDB — не только цель, но и источник доказательств. Открытый доступ — сам по
себе находка; опасные команды (CONFIG/SAVE/MODULE/SLAVEOF) и операции drop/delete —
следы атаки. AOF-журнал Redis и oplog MongoDB дают историю изменений. И не забывай:
после доступа к базе исследуй и саму машину — компромисс сервиса часто означает
компромисс хоста.""",
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
