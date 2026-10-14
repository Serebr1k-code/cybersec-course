---
id: pwn-allocators
title: "Модуль: не-glibc аллокаторы"
category: pwn
parent: pwn-heap-primitives
difficulty: hard
order: 4
tags: [pwn, module, roadmap, allocator, jemalloc, tcmalloc, scudo, partitionalloc, mimalloc]
prerequisites: [pwn-heap-basics, pwn-heap-primitives]
useful_for:
  - "Эксплуатация сервисов и приложений с собственным аллокатором"
  - "Android/Chrome/Windows heap-эксплуатация"
estimated_minutes: 14
summary: "Навигационный модуль: мир аллокаторов за пределами glibc — jemalloc, tcmalloc, Scudo, PartitionAlloc, mimalloc, hardened_malloc, dlmalloc и Segment Heap. Зачем они нужны, чем отличаются и как это меняет heap-эксплуатацию."
---

## Что покрывает этот этап

Весь предыдущий heap-материал был про **glibc malloc** (ptmalloc). Но огромная
часть реальных целей использует **другой аллокатор**: браузеры, серверы, мобильные
приложения и даже ядро. Если ты придёшь с tcache-техникой к процессу на jemalloc —
она не сработает: там другие структуры, размеры и правила.

- **Серверные и general-purpose** — jemalloc, tcmalloc, mimalloc, dlmalloc.
- **Мобильные и hardened** — Scudo (Android), hardened_malloc (GrapheneOS).
- **Браузерные** — PartitionAlloc (Chrome).
- **Windows** — Segment Heap (современный NT).
- **Ядро** — сравнение SLAB/SLUB/SLOB.

## Чем они отличаются от glibc malloc

Четыре ключевых отличия, из которых растёт вся специфика:

1. **Разделение по потокам и классам размеров.** jemalloc/tcmalloc держат
   per-thread кэши и «регионы» фиксированного размера — соседние chunk'и в
   одном регионе почти всегда одного класса.
2. **Другие метаданные.** В glibc метаданные chunk лежат рядом (size/fd/bk);
   в jemalloc/tcmalloc они часто вынесены в отдельные структуры (run/region,
   span/size-class), поэтому «перезапись метаданных» — это другой приём.
3. **Указатели-защиты.** Scudo/PartitionAlloc/hardened_malloc хранят
   закодированные или проверяемые указатели (checksum, cookie) и ловят порчу.
4. **Аренный отбор.** Один и тот же размер может попасть в разные регионы в
   зависимости от потока и CPU — это добавляет недетерминизм.

## Как устроены эти уроки

Для каждого аллокатора — один урок: где он применяется, как устроены его
структуры, какие примитивы даёт (переполнение, UAF, double-free) и какая
техника их эксплуатирует. Мы **не** переписываем glibc-техники, а показываем,
что меняется: имена структур, где искать метаданные и как обходить проверки.

Уроки разбиты на три подгруппы: legacy/general (dlmalloc, Segment Heap, slab),
мобильные hardened (macOS malloc, Scudo, hardened_malloc) и серверные/браузерные
(jemalloc, tcmalloc, PartitionAlloc, mimalloc).

## Что вы сможете после этапа

- Определять по бинарнику/процессу, какой аллокатор используется.
- Переносить общую идею (переполнение/UAF) на конкретный аллокатор.
- Понимать, почему на Scudo/PartitionAlloc классический unsafe-unlink невозможен.
- Знать, где искать метаданные, если они вынесены из chunk'а.

## Квиз

Проверь себя.

```quiz
- question: Почему tcache-техника не работает против jemalloc?
  options:
    - "jemalloc не выделяет память"
    - "У jemalloc другие структуры и классы размеров, нет tcache"
    - "jemalloc только для Windows"
    - "Он работает"
  answer: 1
  explanation: tcache — механизм glibc; у jemalloc свои per-thread кэши и регионы.
- question: Что делает Scudo/hardened_malloc с указателями?
  options:
    - "Ничего"
    - "Хранит проверяемые/закодированные указатели и ловит порчу"
    - "Шифрует диск"
    - "Ускоряет сеть"
  answer: 1
  explanation: Hardened-аллокаторы добавляют checksum/cookie и детект порчи метаданных.
- question: Где в jemalloc/tcmalloc часто лежат метаданные?
  options:
    - "Всегда в самом chunk'е рядом с данными"
    - "В отдельных структурах (run/span, size-class)"
    - "На диске"
    - "В регистре"
  answer: 1
  explanation: В отличие от glibc, метаданные вынесены, поэтому приёмы другие.
- question: Почему арена-отбор добавляет недетерминизм?
  options:
    - "Он замедляет CPU"
    - "Один размер может попасть в разные регионы в зависимости от потока"
    - "Он меняет архитектуру"
    - "Он удаляет память"
  answer: 1
  explanation: Аллокатор выбирает арену по потоку/CPU — соседство chunk'ов не гарантировано.
```

## Куда дальше

Начни с **dlmalloc** — это исторический предок ptmalloc, и на нём проще всего
увидеть, откуда взялись bin'ы. Затем **jemalloc/tcmalloc** (серверы) и
**PartitionAlloc/Scudo** (Chrome/Android). А пока главное запомни: **прежде чем
строить heap-эксплойт, выясни, какой аллокатор в процессе — техника зависит от него**.

## Где пригодится

- Эксплуатация серверов (Redis, Firefox, Chrome, Android-приложений).
- Понимание, почему один и тот же баг эксплуатируется по-разному на разных платформах.
- Выбор цели и техники под конкретный аллокатор.
