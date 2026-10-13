---
id: pwn-tcache-mechanics
title: "Tcache: механика и атаки (glibc-защиты, stashing, calloc, house of botcake)"
category: pwn
parent: pwn-heap-tcache
difficulty: expert
order: 1
tags: [pwn, heap, tcache, glibc, stashing, calloc, botcake]
prerequisites: [pwn-heap-tcache]
useful_for:
  - "CTF Pwn: tcache-эксплойты"
  - "Разбор CVE в glibc tcache"
estimated_minutes: 10
summary: "Модуль tcache: эволюция защит glibc, tcache stashing, особенности calloc и house of botcake."
lab:
  kind: shell
  title: "Практика: safe-linking в tcache"
  toolset: [core, gdb]
  workdir: /home/student/task
  files: [task.md, tcache, tcache.gdb.txt]
  check: "grep -q 'next=0x405010' answer.txt"
  hints:
    - "После free двух чанков tcache хранит их в LIFO: `b` — голова, `b->fd` — следующий."
    - "С glibc 2.32 указатель замаскирован: `stored = next ^ (chunk_addr >> 12)`."
    - "`b = 0x405040`, `stored = 0x405415` → `next = 0x405415 ^ 0x405`."
---
Модуль посвящён tcache — кэшу небольших chunk в современном glibc, который стал центральным объектом heap-эксплуатации. Здесь вы разбираете эволюцию его защит и конкретные техники обхода.

## Что покрывает этап

**pwn-glibc-mitigations** — история и назначение защит tcache: safe-linking, проверки ключей, счётчики.
**pwn-tcache-stashing** — tcache stashing: перенос chunk в tcache при переполнении, дающий полезные примитивы.
**pwn-calloc** — особенности calloc и его взаимодействие с tcache при эксплуатации.
**pwn-house-botcake** — house of botcake: многошаговая техника через double-free и unsorted bin.

## Почему такой порядок

Сначала нужно понять, какие проверки вообще есть в tcache, — иначе техники бессмысленны. Tcache stashing — приём, появившийся как ответ на защиту и дающий нужные примитивы. Calloc важен, потому что он иначе взаимодействует с tcache. House of botcake замыкает модуль как самая сложная комбинированная техника.

## Что вы сможете после этапа

- Объяснять, от каких атак защищают safe-linking и проверки ключей.
- Применять tcache stashing для получения примитивов.
- Учитывать особенности calloc в эксплойте.
- Строить house of botcake через double-free и unsorted bin.

## Квиз

```quiz
- question: "Зачем изучать защиты tcache до атак на него?"
  options:
    - "Иначе техники бессмысленны — нужно знать, какие проверки обходить"
    - "Защиты проще"
    - "Атаки не связаны с защитами"
    - "Это требование компилятора"
  answer: 0
  explanation: "Атака всегда отвечает на конкретную проверку."
- question: "Чем calloc отличается в контексте tcache?"
  options:
    - "Он иначе взаимодействует с tcache, что меняет эксплойт"
    - "Он не выделяет память"
    - "Он работает только в ядре"
    - "Он всегда обнуляет указатели tcache"
  answer: 0
  explanation: "calloc не использует tcache так же, как malloc."
- question: "Какая техника замыкает модуль как самая сложная?"
  options:
    - "safe-linking"
    - "tcache stashing"
    - "house of botcake"
    - "calloc"
  answer: 2
  explanation: "House of botcake комбинирует double-free и unsorted bin."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
