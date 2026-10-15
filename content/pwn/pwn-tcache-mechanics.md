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

## Инструмент: gdb — отладчик

`gdb` управляет исполнением программы: точки останова, пошаговое выполнение, просмотр регистров и памяти. Основной динамический инструмент.

Ключи, которые пригодятся:
* `gdb ./prog` — открыть бинарник; `run` — запустить;
* `break <функция>` / `b *<адрес>` — точка останова;
* `info registers`, `x/16gx $rsp` — регистры и стек;
* `disassemble <функция>` — дизассемблер без выхода из отладчика.

### Рабочий пример (как в лаборатории)

```
$ gdb -batch -ex "b tcache.c:9" -ex run -ex "p/x a" -ex "p/x b" -ex "x/4gx b-0x10" tcache
Breakpoint 1 at 0x40117a: file tcache.c, line 9.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, run () at tcache.c:9
9	}
$1 = 0x405010
$2 = 0x405040
0x405030:	0x0000000000000000	0x0000000000000031
0x405040:	0x0000000000405415	0xfecc5ce0243c8c94
```

Подсказка из лаборатории: `gdb — отладчик (в лабе replay транскрипта для tcache)`.

## Tcache: структура и эволюция защит

**Tcache** (thread cache) — кэш небольших чанков (до 0x410) в glibc. На каждый размер есть LIFO-список (`tcache_perthread_struct`), содержащий до 7 чанков. При `free` чанк попадает в tcache, при `malloc` — забирается из него без обращения к основным bin. Это быстро, но и опасно: tcache стал центральным объектом heap-эксплуатации.

Эволюция защит: с glibc 2.29 добавлен **tcache key** (проверка double-free), с 2.32 — **safe-linking** (кодирование `fd`-указателя как `ptr ^ (chunk_addr >> 12)`), позже — проверки при `tcache_get`. Каждая защита закрыла конкретную технику и породила обходы. Знать версию glibc обязательно: техника, работающая на 2.27, не работает на 2.35.

## Safe-linking и обход

Safe-linking кодирует указатель `next` в tcache: хранимое значение = `next ^ (chunk_addr >> 12)`. Чтобы подделать `next`, нужно знать адрес чанка (или утечку закодированного указателя). Обходы: (1) утечка адреса чанка (например, через тот же UAF-чтение) и вычисление кодированного значения; (2) использование частичной перезаписи, если целевой адрес отличается от исходного только в младших 12 битах (кодирование по ним не влияет).

```text
stored = next ^ (chunk_addr >> 12)
next   = stored ^ (chunk_addr >> 12)
```

В лаборатории (`tcache` с `tcache.gdb.txt`) ты видишь два free-чанка: `b` — голова, `b->fd` — следующий, закодированный. Зная `b` и `stored`, восстанавливаешь `next`.

## Stashing, calloc и house of botcake

**Tcache stashing** — при переполнении tcache (больше 7 чанков) лишние уходят в fastbin/smallbin, а при последующих аллокациях «подкачиваются» обратно в tcache. Это даёт примитив: можно контролировать, какие чанки попадут в tcache и в каком порядке. **calloc** не использует tcache так же, как malloc (он обнуляет память и иначе берёт чанки), поэтому эксплойт, рассчитанный на malloc, может не сработать с calloc — это важно учитывать, если целевой объект аллоцируется calloc.

**House of botcake** — техника через double-free с использованием unsorted bin: освобождаешь чанк так, чтобы он попал в unsorted bin, затем через консолидацию и повторный free добиваешься двух ссылок на один чанк, что даёт overlap. Она сложнее простого tcache poisoning, но работает, когда tcache-путь закрыт (например, проверками key). Итог: tcache — не «одна техника», а арена, где защита и обход идут парами; понимание механики важнее заучивания готовых приёмов.

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
