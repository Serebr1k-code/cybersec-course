---
id: pwn-heap-bin-attacks
title: "Heap: атаки на bin-метаданные (fastbin, unsortedbin, largebin, mmap)"
category: pwn
parent: pwn-heap-basics
difficulty: hard
order: 2
tags: [pwn, heap, fastbin, unsortedbin, largebin, mmap]
prerequisites: [pwn-heap-basics, pwn-heap-corruption]
useful_for:
  - "CTF Pwn: продвинутый heap"
  - "Разбор CVE в glibc malloc"
estimated_minutes: 10
summary: "Второй этап heap-эксплуатации: атаки на bin-метаданные glibc — double-free в fastbin, утечка libc через unsorted bin, largebin и mmap-чанки."
lab:
  kind: shell
  title: "Практика: House of Spirit"
  toolset: [core, gdb]
  workdir: /home/student/task
  files: [task.md, spirit.c, spirit.gdb.txt]
  check: "grep -q 'fake=0x404050' answer.txt"
  hints:
    - "House of Spirit — подсовываем `free()` поддельный чанк с валидным size."
    - "Нужны корректные `prev_size`/`size` и правдоподобный size у «следующего» чанка."
    - "После `free(fake)` следующий `malloc` вернёт адрес поддельного чанка."
    - "`spirit.gdb.txt`: `P` — результат `malloc`, `&fake` — базовый адрес массива."
---
Продолжение heap-эксплуатации: атаки на сами структуры bin-метаданных glibc. Если предыдущий модуль давал примитивы (порча указателя, переполнение), то здесь вы учитесь превращать их в контролируемую запись и перекрытие через механизмы аллокатора.

## Что покрывает этап

**pwn-fastbin-dup** — двойное освобождение в fastbin и получение двух указателей на один chunk.
**pwn-unsortedbin-attack** — атака на unsorted bin: запись адреса libc в chunk и его последующее использование.
**pwn-largebin-attack** — манипуляция большими bin-ами и их связанными списками.
**pwn-mmap-exploitation** — эксплуатация chunk, выделенных через mmap, и их взаимодействие с остальной кучей.

## Почему такой порядок

Fastbin — самый простой bin и лучшая площадка для первого double-free, поэтому он открывает этап. Unsorted bin даёт утечку адреса libc — обязательный шаг при включённом ASLR. Largebin сложнее по структуре связей, поэтому идёт после. mmap-чанки — отдельный режим аллокатора для больших запросов, логично завершают этап.

## Что вы сможете после этапа

- Проводить double-free в fastbin и получать двойной указатель на chunk.
- Извлекать базовый адрес libc через unsorted bin и использовать его в цепочке.
- Портить связи largebin для произвольной записи.
- Понимать поведение mmap-чанков и их роль в эксплойте.

## Квиз

```quiz
- question: "Что даёт атака на unsorted bin в первую очередь?"
  options:
    - "Утечку адреса libc"
    - "Контроль над RIP"
    - "Обход seccomp"
    - "Расшифровку пароля"
  answer: 0
  explanation: "Unsorted bin позволяет записать указатель на libc_main_arena."
- question: "Какой bin удобнее всего для первого double-free?"
  options:
    - "largebin"
    - "unsorted bin"
    - "fastbin — у него простая односвязная структура"
    - "mmap-чанк"
  answer: 2
  explanation: "Fastbin использует односвязный список без сложных проверок."
- question: "Почему mmap-эксплуатация идёт последней?"
  options:
    - "Она не связана с кучей"
    - "Это отдельный режим аллокатора для больших запросов"
    - "Она требует root"
    - "Она работает только на Windows"
  answer: 1
  explanation: "Mmap-чанки обрабатываются отдельно от основной кучи."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
