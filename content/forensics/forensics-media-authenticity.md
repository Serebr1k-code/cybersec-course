---
id: forensics-media-authenticity
title: "Модуль: подлинность медиа — deepfake, provenance, QR"
category: forensics
parent: forensics-file-magic
difficulty: medium
order: 7
tags: [forensics, deepfake, provenance, c2pa, qr, roadmap]
prerequisites: [forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ подлинности медиа"
estimated_minutes: 12
summary: "Этап ветки «форматы»: как проверять подлинность медиа — deepfake-детекция, метаданные происхождения (C2PA) и QR/штрихкоды."
---

В эпоху генеративного ИИ встаёт вопрос: файл настоящий? Этот модуль — про проверку
подлинности: синтетические медиа, метаданные происхождения и кодированные метки.

## Что покрывает этот модуль

- **Deepfake** — признаки синтетических медиа.
- **Provenance** — C2PA/Content Credentials.
- **QR/штрихкоды** — что в них закодировано.

## Рекомендуемый порядок изучения

1. `media-deepfake` — признаки подделки.
2. `media-provenance` — метаданные происхождения.
3. `media-qr-barcode` — кодированные метки.

## Что вы будете уметь

- Искать признаки deepfake.
- Читать C2PA/Content Credentials.
- Декодировать QR/штрихкоды.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| видео/аудио | синтетика? | анализ артефактов |
| C2PA-манифест | кто/чем создал | `c2patool` |
| QR | что закодировано | `zbarimg` |

## Куда дальше

Открывай урок **«Deepfake-форензика»** — начнём с признаков синтетики.
