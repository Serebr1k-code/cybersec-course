---
id: pwn-modern-houses
title: "Модуль: современные house-of-* (Roman, Corrosion, Water)"
category: pwn
parent: pwn-heap-basics
difficulty: hard
order: 4
tags: [heap, house-of-roman, house-of-corrosion, house-of-water, roadmap]
prerequisites: [pwn-heap-house]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 12
summary: "Отдельный этап: house-of-техники для modern glibc — Roman, Corrosion и Water, где классические приёмы уже не работают."
---

Классические house-of-* (Lore, Force, Einherjar) появились десятилетия назад и частично закрыты проверками glibc. Но куча развивается, и вместе с ней — атаки. House of Roman обходится без утечки libc, House of Corrosion эксплуатирует large bin в glibc 2.27–2.30, House of Water использует `_IO_list_all` и FSOP. Знание этих техник отличает «могу повторить writeup» от «могу решить новую задачу».

## Что покрывает этот модуль

- **House of Roman** — комбинация fastbin и unsorted bin для записи без утечки libc.
- **House of Corrosion** — атака на large bin, `bk_nextsize` и произвольная запись в glibc 2.27–2.30.
- **House of Water** — манипуляция `_IO_list_all` и связка с FSOP.
- **Контекст** — какие версии glibc уязвимы и какие проверки появились позже.

## Рекомендуемый порядок изучения

1. `pwn-house-roman` — Roman: fastbin + unsorted bin, запись без утечки libc.
2. `pwn-house-corrosion` — Corrosion: large bin, `bk_nextsize`, версии glibc.
3. `pwn-house-water` — Water: `_IO_list_all`, FSOP-цепочка.

Материал опирается на `pwn-heap-house` (базовые дома) и `pwn-heap-bin-attacks`, а также связан с `pwn-fsop` (House of Water использует `_IO_FILE`) и `pwn-modern-houses` продолжает `pwn-house-modern`.

## Что вы будете уметь

- Применять House of Roman, когда нет утечки libc.
- Использовать large-bin-примитивы House of Corrosion.
- Строить FSOP-цепочку House of Water.
- Выбирать технику под конкретную версию glibc.

## Квиз

```quiz
- question: "Чем House of Roman примечателен?"
  options:
    - "Работает без утечки libc"
    - "Требует прав root"
    - "Атакует только ядро"
    - "Не использует кучу"
  answer: 0
  explanation: "Roman комбинирует fastbin и unsorted bin, чтобы писать без libc-утечки."
- question: "Какую структуру задействует House of Corrosion?"
  options:
    - "large bin и поле bk_nextsize"
    - "стек"
    - "GOT"
    - "таблицу символов"
  answer: 0
  explanation: "Corrosion эксплуатирует large bin в определённых версиях glibc."
- question: "С чем связан House of Water?"
  options:
    - "С FSOP и _IO_list_all"
    - "С переполнением стека"
    - "С format string"
    - "С seccomp"
  answer: 0
  explanation: "Water манипулирует списком _IO_FILE и переходит в FSOP."
```

## Где пригодится

- **CTF:** задачи на modern glibc с минимумом утечек.
- **Bug bounty:** эксплуатация heap-багов на актуальных дистрибутивах.
- **Пентест:** обход современного hardening glibc.
- **Работа:** research актуальных heap-техник.
