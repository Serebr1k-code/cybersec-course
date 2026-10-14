---
id: forensics-memory-extra
title: "Модуль: память — macOS, dyld-кэш и кусты реестра"
category: forensics
parent: forensics-memory-artifacts
difficulty: hard
order: 5
tags: [forensics, memory, macos, dyld, registry-hives, roadmap]
prerequisites: [forensics-memory-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ памяти"
estimated_minutes: 12
summary: "Этап ветки «память»: особенности macOS-памяти, разделяемый кэш dyld и восстановление кустов реестра из дампа."
---

Память Windows и Linux мы разбирали. Остались три особые темы: специфика macOS
(унифицированная память, сжатие), кэш **dyld** (разделяемая библиотека macOS) и
извлечение **кустов реестра** прямо из дампа. Разберём.

## Что покрывает этот модуль

- **macOS-память** — особенности сбора и анализа.
- **dyld-кэш** — где живёт код библиотек macOS.
- **Кусты реестра** — восстановление hives из дампа.

## Рекомендуемый порядок изучения

1. `mem-macos` — специфика macOS.
2. `mem-dyld-cache` — разделяемый кэш.
3. `mem-registry-hives` — реестр из памяти.

## Что вы будете уметь

- Собирать и анализировать память macOS.
- Работать с dyld-кэшем.
- Извлекать кусты реестра из дампа.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| macOS-дамп | что было в памяти | Volatility/osxpmem |
| dyld_shared_cache | где код библиотек | `dyld_extractor` |
| hive в дампе | состояние реестра | Volatility `hivelist` |

## Куда дальше

Открывай урок **«Память macOS»** — начнём со специфики.
