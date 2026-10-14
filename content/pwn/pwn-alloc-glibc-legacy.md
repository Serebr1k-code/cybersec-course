---
id: pwn-alloc-glibc-legacy
title: "Модуль: legacy и системные аллокаторы (dlmalloc, Segment Heap, slab)"
category: pwn
parent: pwn-allocators
difficulty: hard
order: 1
tags: [pwn, module, roadmap, dlmalloc, ptmalloc, segment-heap, slab, slub, slob, kernel]
prerequisites: [pwn-allocators]
useful_for:
  - "Понимание корней glibc malloc и kernel slab"
  - "Эксплуатация Windows heap и ядра Linux"
estimated_minutes: 10
summary: "Навигационный модуль: исторический dlmalloc (предок ptmalloc), Windows Segment Heap и ядерные SLAB/SLUB/SLOB — три аллокатора, где метаданные устроены принципиально иначе."
---

## Что покрывает этот этап

Три аллокатора, которые стоит понять до или вместо экзотики:

- **dlmalloc** — исторический Doug Lea malloc, прямой предок glibc ptmalloc. На
  нём видно, откуда взялись bin'ы и почему unsafe-unlink вообще существует.
- **Windows Segment Heap** — современный heap NT (заменил NT Heap). Другая
  сегментация, другой набор техник для Windows-эксплуатации.
- **SLAB / SLUB / SLOB** — три аллокатора ядра Linux. От того, какой собран в
  ядре, зависит, какие структуры (freelist, slab-кэш) ты можешь перезаписать.

## Чем это отличается от ptmalloc

- **dlmalloc** — те же идеи (границы chunk, bin'ы, консолидация), но без tcache
  и современных проверок. Полезен как «минимальная модель».
- **Segment Heap** — выделяет память большими сегментами и делит их на
  subsegment'ы; метаданные вынесены в заголовок сегмента, а не в каждый chunk.
- **SLUB** — самый распространённый: freelist хранится *внутри* свободного
  объекта (как `next`), поэтому перезапись freelist-указателя — ключевой приём.
  **SLAB** — отдельный массив метаданных. **SLOB** — компактный для embedded.

## Как устроены эти уроки

Каждый урок разбирает один аллокатор: структуры, путь выделения/освобождения,
какие примитивы возможны и как их эксплуатируют. Для ядра — отдельно про то,
как выбор аллокатора меняет технику перезаписи (freelist hijack в SLUB против
freelist corruption в SLAB).

## Что вы сможете после этапа

- Объяснить, откуда в ptmalloc появились bin'ы и unsafe-unlink.
- Понимать устройство Segment Heap и уметь искать его заголовки.
- Различать SLAB/SLUB/SLOB и подбирать heap-технику под ядро.
- Осознанно читать код аллокатора, а не полагаться на готовые рецепты.

## Квиз

Проверь себя.

```quiz
- question: Чем dlmalloc связан с glibc malloc?
  options:
    - "Ничем"
    - "ptmalloc произошёл от dlmalloc"
    - "dlmalloc — это tcache"
    - "dlmalloc только для Windows"
  answer: 1
  explanation: glibc ptmalloc — наследник Doug Lea malloc, отсюда bin'ы и консолидация.
- question: Где в SLUB хранится freelist?
  options:
    - "В отдельном массиве"
    - "Внутри свободного объекта (next)"
    - "На диске"
    - "В регистре"
  answer: 1
  explanation: SLUB держит указатель следующего свободного объекта в самом объекте.
- question: Чем Segment Heap отличается от NT Heap?
  options:
    - "Ничем"
    - "Выделяет сегменты и делит на subsegment'ы, метаданные в заголовке сегмента"
    - "Работает без памяти"
    - "Это аллокатор Linux"
  answer: 1
  explanation: Segment Heap использует сегментную организацию вместо классических chunk'ов.
- question: Какой аллокатор ядра самый распространённый?
  options:
    - "SLOB"
    - "SLUB"
    - "dlmalloc"
    - "Scudo"
  answer: 1
  explanation: SLUB — дефолт большинства современных ядер Linux.
```

## Куда дальше

Начни с **dlmalloc** (минимальная модель), затем **Segment Heap** для Windows и
**SLAB/SLUB/SLOB** для ядра. А пока главное: **метаданные аллокатора могут лежать
вне chunk'а — сначала найди, где они, потом строй технику**.

## Где пригодится

- Windows heap-эксплуатация и kernel heap-эксплуатация.
- Понимание истории и устройства аллокаторов.
- Выбор техники под конкретную платформу.
