---
id: forensics-doc-formats
title: "Модуль: форматы документов — OOXML, ODF, RTF, XPS"
category: forensics
parent: forensics-file-magic
difficulty: medium
order: 5
tags: [forensics, docx, ooxml, odf, rtf, xps, documents, roadmap]
prerequisites: [forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ документов"
estimated_minutes: 13
summary: "Этап ветки «форматы»: как устроены офисные документы — OOXML (docx/xlsx), ODF, RTF и XPS — и где в них следы и малварь."
---

Документы — самый частый вектор атак и источник метаданных. Современные форматы — это
ZIP-архивы (OOXML/ODF) или текстовые/бинарные форматы (RTF/XPS). Разберём их структуру.

## Что покрывает этот модуль

- **OOXML** — docx/xlsx/pptx (ZIP + XML).
- **ODF** — odt/ods (открытый аналог).
- **RTF** — текстовый формат с объектами.
- **XPS** — «PDF от Microsoft».

## Рекомендуемый порядок изучения

1. `doc-ooxml-internals` — структура OOXML.
2. `doc-odf` — ODF.
3. `doc-rtf` — RTF и его объекты.
4. `doc-xps` — XPS.

## Что вы будете уметь

- Разбирать OOXML/ODF как архивы.
- Находить метаданные, макросы, встроенные объекты.
- Читать RTF и находить в нём полезную нагрузку.
- Разбирать XPS.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| docx | кто создал/менял | `unzip`, XML |
| vbaProject.bin | есть ли макрос | `olevba` |
| .rtf | что внутри | текстовый разбор |
| .xps | структура | `unzip` |

## Куда дальше

Открывай урок **«OOXML изнутри»** — начнём с docx/xlsx.
