---
id: misc-sandbox-containers-hub
title: "Модуль: Контейнеры и WASM"
category: misc
parent: misc-sandbox
difficulty: medium
order: 2
tags: [misc, module, roadmap]
prerequisites: [misc-sandbox]
useful_for:
- CTF Misc.
- Пентест контейнеров.
- Аудит WASM.
estimated_minutes: 10
summary: "Контейнерные песочницы и wasm sandbox escape"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Контейнеры и WASM»: контейнерные песочницы и WASM sandbox escape.

- **misc-sandbox-containers** — Модуль: контейнерные песочницы.
- **misc-sandbox-wasm** — WASM sandbox escape.

## Почему такой порядок

Контейнеры и WASM — популярные изоляторы, их баги разбирают после базовых песочниц.

## Что вы сможете после этапа

- Оценивать изоляцию контейнера.
- Искать escape в WASM-рантайме.

## Квиз

Проверь себя.

```quiz
- question: Что лежит в основе изоляции контейнера?
  options:
    - "Namespaces и cgroups"
    - "Шрифты"
    - "DNS"
    - "СУБД"
  answer: 0
  explanation: Namespaces/cgroups ограничивают процессы.
- question: Чем полезен WASM для изоляции?
  options:
    - "Модель памяти и capability-модель ограничивают код"
    - "Он быстрее C"
    - "Он шифрует"
    - "Он без сети"
  answer: 0
  explanation: WASM даёт ограниченную среду исполнения.
- question: Что ищут при побеге из контейнера?
  options:
    - "Путь к хосту через общие ресурсы"
    - "Больше памяти"
    - "Смену темы"
    - "Логи"
  answer: 0
  explanation: Цель — доступ к хосту-ноде.
```

## Где пригодится

- CTF Misc.
- Пентест контейнеров.
- Аудит WASM.
