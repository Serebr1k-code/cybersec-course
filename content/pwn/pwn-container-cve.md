---
id: pwn-container-cve
title: "Модуль: Container escape CVE"
category: pwn
parent: pwn-cve-exploitation
difficulty: medium
order: 4
tags: [pwn, module, roadmap, cve]
prerequisites: [pwn-sandbox-escape]
useful_for:
  - "Эксплуатация реальных CVE"
  - "Red team: повышение привилегий"
estimated_minutes: 10
summary: "Навигационный модуль: побег из контейнеров и оркестраторов через известные уязвимости ядра и runtime."
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Container escape CVE»: побег из контейнеров и оркестраторов через известные уязвимости ядра и runtime.

- overlayfs (CVE-2021-3493 / CVE-2023-0386) — повышение привилегий и побег.
- runc/Docker escape CVE — обход изоляции runtime.
- Kubernetes escape CVE — от пода к ноде.

## Почему такой порядок

Контейнеры добавляют изоляцию namespaces/cgroups; их баги рассматриваются последними, опираясь на kernel-эксплуатацию.

## Что вы сможете после этапа

- Оценивать, ограничивает ли контейнер вектор.
- Планировать побег из пода к хосту.

## Квиз

Проверь себя.

```quiz
- question: Что эксплуатирует CVE-2021-3493?
  options:
    - "SMB"
    - "overlayfs в Ubuntu-ядре"
    - "Kerberos"
    - "DNS"
  answer: 1
  explanation: Баг в overlayfs-патче Ubuntu давал root.
- question: Побег из контейнера обычно ведёт...
  options:
    - "К хосту"
    - "К другому контейнеру"
    - "В интернет"
    - "К базе"
  answer: 0
  explanation: Цель побега — получить доступ к хосту-ноде.
- question: Что нужно проверить прежде всего для побега?
  options:
    - "Пароль"
    - "Возможности (capabilities) и общие mount'ы"
    - "Версию браузера"
    - "Логи"
  answer: 1
  explanation: Capabilities и shared mounts определяют доступные примитивы.
```

## Где пригодится

- Пентест контейнерных сред.
- Побег из пода Kubernetes.
- Оценка риска устаревшего ядра в контейнерах.
