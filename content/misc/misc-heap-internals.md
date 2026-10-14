---
id: misc-heap-internals
title: 'Модуль: аллокаторы и внутренности heap'
category: misc
parent: misc-binary-misc
difficulty: expert
order: 1
tags: [heap, allocator, glibc, musl, windows, tcache, roadmap]
prerequisites: [misc-binary-misc]
useful_for:
  - 'CTF pwn: heap'
  - 'Эксплуатация аллокаторов'
  - 'Понимать разницу libc/musl'
estimated_minutes: 16
summary: 'Аллокаторы изнутри: версии glibc (tcache, safe-linking, хуки), musl malloc, Windows LFH и House-of-техники.'
---

Аллокатор — это «невидимый» слой между вашим `malloc(16)` и реальной памятью. Пока вы не эксплуатируете heap, он неинтересен. Как только задача даёт переполнение или use-after-free, всё решает **конкретный аллокатор**: glibc, musl или Windows NT heap — у каждого свои структуры, проверки и техники. Этот модуль — про них.

## Что покрывает модуль

Четыре темы, объединённые одним вопросом «как устроен этот конкретный аллокатор и как его ломать»:

1. **Различия версий glibc** — tcache, safe-linking, удалённые хуки и почему один эксплойт не переносится между версиями.
2. **musl malloc** — минималистичный аллокатор из Alpine/musl-libc: другие бакеты, никакого tcache.
3. **Windows heap** — LFH, бэкенд NT heap и почему оффсеты Windows-кучи не похожи на glibc.
4. **House-of-техники** — классические приёмы (House of Force, Spirit, Einherjar) и когда они ещё работают.

## Почему такой порядок

Начинаем с glibc — это 90% CTF-задач на heap. Затем musl: та же задача, собранная под Alpine, ведёт себя иначе, и это ловушка для тех, кто заучил glibc-оффсеты. Windows-куча нужна для Windows-эксплуатации и pwn-задач с `ntdll`. И в конце — House-of-техники: они используют конкретные поля чанков и проверки, поэтому их место — после того, как вы поняли устройство чанка.

## Чему вы научитесь

- Определять версию libc и понимать, какие техники при этом доступны.
- Объяснять, чем musl malloc отличается от glibc и как это меняет эксплойт.
- Разбирать структуру Windows LFH и находить условия для переполнения.
- Применять House-of-техники и понимать их ограничения в новых версиях.

## Квиз

Проверь себя.

```quiz
- question: Что появилось в glibc 2.32 и ломает «записать адрес в fd»?
  options:
    - tcache
    - safe-linking
    - Удаление хуков
    - LFH
  answer: 1
  explanation: safe-linking хранит fd как (addr>>12) XOR ptr.
- question: Почему musl-эксплойт не совпадает с glibc-эксплойтом?
  options:
    - musl медленнее
    - Другая структура аллокатора и бакетов
    - musl не поддерживает free
    - У musl нет памяти
  answer: 1
  explanation: У musl своя реализация malloc, без tcache.
- question: Какая техника использует указатель top-чанка?
  options:
    - House of Force
    - House of Spirit
    - House of Einherjar
    - FSOP
  answer: 0
  explanation: House of Force перезаписывает top chunk для «отрицательного» malloc.
- question: Что проверяет Windows LFH?
  options:
    - Куки бакетов и размеры
    - ELF-заголовки
    - seccomp
    - ASLR
  answer: 0
  explanation: LFH хранит кодированные указатели и куки.
```

## Где пригодится

- **CTF pwn**: heap-задачи, где нужно точно знать аллокатор.
- **Эксплуатация**: перенос техник между glibc/musl/Windows.
- **Реверс**: понимание структур кучи в дизассемблере.
- **Разработка**: почему «работает локально, падает на сервере».
