---
id: pwn-heap-house
title: "Heap: техники house-of-* и кастомные аллокаторы"
category: pwn
parent: pwn-heap-basics
difficulty: hard
order: 3
tags: [pwn, heap, house-of-force, einherjar, lore, allocator]
prerequisites: [pwn-heap-basics, pwn-heap-bin-attacks]
useful_for:
  - "CTF Pwn: сложные многошаговые heap-эксплойты"
  - "Эксплуатация проприетарных аллокаторов"
estimated_minutes: 10
summary: "Третий этап heap-эксплуатации: семейство house-of-* (force, einherjar, lore) и эксплуатация кастомных аллокаторов."
lab:
  kind: shell
  title: "Практика: House of Force — top size = -1"
  toolset: [core, gdb]
  workdir: /home/student/task
  files: [task.md, force.c, force.gdb.txt]
  check: "grep -q 'top=0xffffffffffffffff' answer.txt"
  hints:
    - "House of Force начинается с перезаписи size top-чанка в максимальное значение."
    - "Тогда следующий `malloc` «отрежет» кусок от top в любом месте адресного пространства."
    - "`force.c` пишет `0xffffffffffffffff` сразу за первым чанком — в size top-чанка."
    - "`force.gdb.txt`: строка `0x405020`, второе qword — size top-чанка."
---
Завершающий этап heap-ветви: техники семейства house-of-* и эксплуатация кастомных аллокаторов. Здесь вы комбинируете все примитивы предыдущих модулей в сложные многошаговые эксплойты и учитесь атаковать нестандартные менеджеры памяти, которых нет в glibc.

## Что покрывает этап

**pwn-house-of-force** — техника через переполнение top chunk и манипуляцию указателем top.
**pwn-house-einherjar** — атака через fastbin и подмену fd для получения произвольной записи.
**pwn-house-lore** — манипуляция small/large bin при перераспределении chunk.
**pwn-custom-allocator** — эксплуатация самописных аллокаторов в прошивках и проприетарном ПО.

## Почему такой порядок

House-of-force, einherjar и lore развивались последовательно, каждый добавлял обход новых проверок glibc. Их стоит изучать в хронологическом порядке, чтобы понимать, от какой именно защиты уходит каждая техника. Кастомные аллокаторы идут последними: там нет готовых проверок glibc, зато нужно самому найти слабое место в логике.

## Что вы сможете после этапа

- Применять house of force через переполнение top chunk.
- Строить house of einherjar с подменой fd.
- Эксплуатировать house of lore на small/large bin.
- Искать и эксплуатировать слабости самописных аллокаторов.

## Квиз

```quiz
- question: "Почему техники house-of-* изучают в историческом порядке?"
  options:
    - "Так короче текст урока"
    - "Каждая следующая добавляет обход новых проверок glibc"
    - "Они не связаны между собой"
    - "Их нельзя запускать вместе"
  answer: 1
  explanation: "Каждая техника отвечает на очередную защиту аллокатора."
- question: "Чем эксплуатация кастомного аллокатора отличается от glibc?"
  options:
    - "Там нет готовых проверок glibc — нужно искать слабость в логике"
    - "Она всегда проще"
    - "Она невозможна"
    - "Она требует символьного исполнения"
  answer: 0
  explanation: "Кастомный аллокатор не защищён проверками glibc."
- question: "Какую технику относят к переполнению top chunk?"
  options:
    - "house of lore"
    - "house of einherjar"
    - "house of force"
    - "house of botcake"
  answer: 2
  explanation: "House of force манипулирует указателем top через переполнение."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
