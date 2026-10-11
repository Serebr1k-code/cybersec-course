---
id: pwn-kernel-modern
title: "Модуль: современные kernel-техники (cross-cache, Dirty Pipe, DirtyCred)"
category: pwn
parent: pwn-kernel-core
difficulty: hard
order: 2
tags: [kernel, cross-cache, dirty-pipe, dirtycred, roadmap]
prerequisites: [pwn-kernel-heap]
useful_for:
  - "CTF Pwn категория"
  - "Kernel exploitation"
  - "Real-world CVE"
estimated_minutes: 12
summary: "Отдельный этап: современные kernel-техники — cross-cache attack, Dirty Pipe и DirtyCred, которые обходят стандартные митигации ядра."
---

Ядро Linux — самая защищённая цель в pwn: SMEP/SMAP, KASLR, KPTI, hardened usercopy, рандомизация slab. Классический ret2usr мёртв. Современная kernel-эксплуатация — это работа с аллокаторами (SLUB, cross-cache), логическими багами (Dirty Pipe) и манипуляцией credentials (DirtyCred). Эти техники переписали правила: иногда даже UAF не нужен.

## Что покрывает этот модуль

- **Cross-cache attack** — перенос страниц между кэшами SLUB для переиспользования освобождённой памяти.
- **Dirty Pipe (CVE-2022-0847)** — запись в read-only файлы через pipe_buffer.
- **DirtyCred (CVE-2022-2588/3913)** — подмена credentials без контроля над кодом.
- **Практику** — от PoC до повышения привилегий и побега из контейнера.

## Рекомендуемый порядок изучения

1. `pwn-kernel-cross-cache` — cross-cache: механика SLUB, освобождение страниц, переиспользование.
2. `pwn-dirty-pipe` — Dirty Pipe: pipe_buffer, запись в read-only, захват root.
3. `pwn-dirtycred` — DirtyCred: подмена credential-структур и контейнерный escape.

Материал опирается на `pwn-kernel-heap` (SLUB и UAF) и `pwn-kernel-smep-smap`, а также связан с `pwn-kernel-pipe-buffer` (та же структура, что в Dirty Pipe).

## Что вы будете уметь

- Понимать механику cross-cache и применять её к UAF.
- Эксплуатировать Dirty Pipe для записи в read-only файлы.
- Использовать DirtyCred для повышения привилегий и побега из контейнера.
- Выбирать технику под конкретное ядро и его митигации.

## Квиз

```quiz
- question: "Зачем нужна cross-cache attack?"
  options:
    - "Чтобы переиспользовать освобождённую страницу в другом slab-кэше"
    - "Чтобы отключить KASLR"
    - "Чтобы ускорить ядро"
    - "Чтобы зашифровать диск"
  answer: 0
  explanation: "Перенос страниц между кэшами даёт контроль над чужим объектом."
- question: "Что эксплуатирует Dirty Pipe?"
  options:
    - "Неинициализированные флаги pipe_buffer при записи в файл"
    - "Переполнение стека в ядре"
    - "Ошибку в DNS"
    - "Слабый пароль"
  answer: 0
  explanation: "Флаги pipe_buffer позволяют писать в page cache read-only файла."
- question: "В чём суть DirtyCred?"
  options:
    - "В подмене credential-структур ядра, а не кода"
    - "В переполнении кучи"
    - "В подборе пароля root"
    - "В отключении SELinux"
  answer: 0
  explanation: "Эксплуатация манипулирует объектами cred, а не потоком управления."
```

## Где пригодится

- **CTF:** kernel-задачи на современные CVE и slab.
- **Bug bounty:** kernel LPE в реальных продуктах.
- **Пентест:** повышение привилегий и escape из контейнера.
- **Работа:** research и оценка kernel-митигаций.
