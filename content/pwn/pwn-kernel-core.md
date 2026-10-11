---
id: pwn-kernel-core
title: "Ядро: база эксплуатации (SMEP/SMAP, kernel ROP, kernel heap)"
category: pwn
parent: pwn-kernel-intro
difficulty: hard
order: 1
tags: [pwn, kernel, smep, smap, rop, heap]
prerequisites: [pwn-kernel-intro]
useful_for:
  - "CTF Pwn: kernel-задачи"
  - "Эксплуатация драйверов Linux"
estimated_minutes: 10
summary: "Первый kernel-этап: база эксплуатации ядра — SMEP/SMAP, kernel ROP и работа с kernel heap."
---
Первый из двух модулей по эксплуатации ядра Linux. После общего введения (pwn-kernel-intro) вы переходите к базовому набору техник: как обойти аппаратные защиты, как построить kernel ROP и как работать с кучей ядра.

## Что покрывает этап

**pwn-kernel-smep-smap** — SMEP/SMAP и способы их обхода при переходе из ядра в пользовательский код.
**pwn-kernel-rop** — kernel ROP: подготовка привилегий и возврат в userspace.
**pwn-kernel-heap** — куча ядра: slab/slub, объекты и типовые примитивы порчи.

## Почему такой порядок

Сначала SMEP/SMAP: без понимания этих защит нельзя выполнить ни одну примитивную технику вроде ret2usr. Затем kernel ROP — основной инструмент получения контроля в ядре. Kernel heap замыкает этап, потому что большинство современных багов ядра — именно heap-баги.

## Что вы сможете после этапа

- Обходить SMEP/SMAP через ROP-цепочку.
- Строить kernel ROP для повышения привилегий и возврата в userspace.
- Работать с объектами slab/slub и портить их.

## Квиз

```quiz
- question: "Почему SMEP/SMAP изучаются первыми?"
  options:
    - "Без их понимания не работает примитивный ret2usr"
    - "Они самые простые"
    - "Они относятся к userspace"
    - "Они не влияют на эксплойт"
  answer: 0
  explanation: "SMEP/SMAP блокируют выполнение и доступ к пользовательской памяти из ядра."
- question: "Какой инструмент является основным для получения контроля в ядре?"
  options:
    - "kernel ROP"
    - "format string"
    - "SQL-инъекция"
    - "XSS"
  answer: 0
  explanation: "Kernel ROP собирает цепочку из гаджетов ядра."
- question: "Почему kernel heap замыкает этап?"
  options:
    - "Большинство современных багов ядра — heap-баги"
    - "Он не связан с ядром"
    - "Он требует GPU"
    - "Он проще остальных"
  answer: 0
  explanation: "Slab/slub-баги — основной класс уязвимостей ядра."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
