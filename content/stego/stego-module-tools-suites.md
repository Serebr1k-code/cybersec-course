---
id: stego-module-tools-suites
title: "Модуль: Наборы инструментов для контейнеров"
category: stego
parent: stego-tooling-advanced
difficulty: medium
order: 5
tags: [stego, roadmap, stegoveritas, pngcheck, jpegtran, foremost, tools]
prerequisites: [stego-tooling-advanced]
useful_for:
  - "CTF Stego: рабочий арсенал инструментов"
  - "Форензика: разбор контейнеров"
  - "Blue team: анализ вложений"
estimated_minutes: 8
summary: "Навигационный модуль по инструментам контейнеров: Stegoveritas (автоматический прогон), pngcheck/optipng (структура PNG), jpegtran/jpegoptim (lossless JPEG), foremost/scalpel (карвинг)."
---

## Зачем этот модуль

Каждый формат требует своего инструмента. Этот модуль собирает рабочий арсенал:
чем разобрать структуру PNG, чем — JPEG без пересжатия, чем достать вложенный файл
из сырого потока.

## Что разберём

- **stego-tool-stegoveritas** — автоматический конвейер проверок изображения.
- **stego-tool-png-suite** — pngcheck/optipng/pngcrush/zopfli: структура PNG.
- **stego-tool-jpeg-suite** — jpegtran/jpegoptim: lossless-работа с JPEG.
- **stego-tool-foremost** — foremost/scalpel: карвинг по сигнатурам.

## Как проходить

По порядку: сначала «зонтик» (Stegoveritas), затем инструменты под конкретный
формат (PNG, JPEG) и карвинг. В каждом уроке — реальный файл и разбор.

## Что вы будете уметь

- Прогонять автоматический анализ и читать отчёт.
- Разбирать чанки PNG и ловить подделки по CRC.
- Работать с JPEG без пересжатия.
- Вырезать файлы из сырых данных.
