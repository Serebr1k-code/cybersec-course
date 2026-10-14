---
id: forensics-tl-corr
title: "Модуль: Корреляция и сущности"
category: forensics
parent: forensics-timeline-deep
difficulty: medium
order: 1
tags: [forensics, module, roadmap]
prerequisites: [forensics-timeline-deep]
useful_for:
- CTF Forensics.
- DFIR.
- Расследования.
estimated_minutes: 10
summary: "Cross-artifact корреляцию, разрешение сущностей и оценку уверенности улик"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Корреляция и сущности»: cross-artifact корреляцию, разрешение сущностей и оценку уверенности улик.

- **tl-cross-artifact** — Cross-artifact корреляция: собрать события в одну картину.
- **tl-entity-resolution** — Entity resolution: один человек под разными именами.
- **tl-provenance** — Provenance и уверенность: сколько стоит улика.

## Почему такой порядок

Разрозненные события нужно связать в одну картину, прежде чем её визуализировать.

## Что вы сможете после этапа

- Связывать события из разных артефактов.
- Оценивать provenance улик.

## Квиз

Проверь себя.

```quiz
- question: Зачем cross-artifact корреляция?
  options:
    - "Чтобы собрать единую картину из разных источников"
    - "Чтобы сжать логи"
    - "Чтобы шифровать"
    - "Чтобы ускорить диск"
  answer: 0
  explanation: Одно событие подтверждается несколькими артефактами.
- question: Что такое entity resolution?
  options:
    - "Сведение одного человека под разными именами к одной сущности"
    - "Сжатие данных"
    - "Шифрование"
    - "Сортировка логов"
  answer: 0
  explanation: Разные логины могут принадлежать одному человеку.
- question: Зачем оценивать provenance?
  options:
    - "Чтобы понять, сколько стоит улика"
    - "Чтобы ускорить поиск"
    - "Чтобы сжать данные"
    - "Чтобы сменить пояс"
  answer: 0
  explanation: Provenance говорит о достоверности источника.
```

## Где пригодится

- CTF Forensics.
- DFIR.
- Расследования.
