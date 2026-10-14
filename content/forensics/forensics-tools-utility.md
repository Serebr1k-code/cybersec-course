---
id: forensics-tools-utility
title: "Модуль: утилиты — конвертеры, файловые системы и карвинг"
category: forensics
parent: forensics-tooling
difficulty: medium
order: 3
tags: [forensics, tools, cyberchef, fiwalk, ntfs, regripper, dfir-orc, roadmap]
prerequisites: [forensics-tooling]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Работа с инструментами"
estimated_minutes: 13
summary: "Этап ветки «инструменты»: рабочие утилиты — конвертеры данных, разбор ФС, извлечение из образов и реестра."
---

Крупные платформы решают много, но иногда нужен один точный инструмент. Здесь —
утилиты, которые закрывают конкретные задачи: декодирование, разбор ФС, извлечение и
реестр.

## Что покрывает этот модуль

- **CyberChef** — «швейцарский нож» преобразований.
- **DFIR ORC** — извлечение артефактов из образов/систем.
- **fiwalk** — обход образов через Sleuth Kit.
- **NTFS-утилиты** — MFT, `$LogFile`, `$UsnJrnl`.
- **RegRipper** — разбор реестра.

## Рекомендуемый порядок изучения

1. `tool-cyberchef` — быстрые преобразования.
2. `tool-fiwalk` — обход образов.
3. `tool-ntfs-tools` — низкий уровень NTFS.
4. `tool-regripper` — реестр.
5. `tool-dfir-orc` — массовое извлечение.

## Что вы будете уметь

- Декодировать и преобразовывать данные (CyberChef).
- Обходить образы программно (fiwalk).
- Читать NTFS-структуры напрямую.
- Парсить реестр (RegRipper).
- Собирать артефакты массово (DFIR ORC).

## Артефакт → вопрос

| Задача | Инструмент |
|--------|-----------|
| декодирование | CyberChef |
| обход образа | fiwalk |
| NTFS-структуры | icat/mmls/analyzeMFT |
| реестр | RegRipper |
| массовый сбор | DFIR ORC |

## Куда дальше

Открывай урок **«CyberChef»** — начнём с универсального конвертера.
