---
id: pwn-musl
title: "Эксплуатация под musl libc"
category: pwn
parent: pwn-static-no-libc
difficulty: expert
order: 1
tags: [musl, static, mallocng, rop, iot, docker]
prerequisites: [pwn-static-no-libc, pwn-heap-basics, pwn-rop]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
  - "IoT/embedded"
estimated_minutes: 60
summary: "musl libc отличается аллокатором (mallocng), отсутствием некоторых гаджетов и другим layout — разбираем, как это меняет эксплуатацию статических бинарей и контейнеров на Alpine."
lab:
  kind: shell
  title: "Практика: статический бинарь без динамики"
  toolset: [core, bin]
  workdir: /home/student/task
  files: [task.md, chall]
  check: "grep -q 'needed=0' answer.txt"
  hints:
    - "`chall` — статически слинкованный бинарь (аналог статических сборок на musl)."
    - "`file chall` покажет `statically linked`."
    - "`readelf -d chall` печатает динамическую секцию — или сообщает, что её нет."
    - "Запишите `needed=<сколько NEEDED-библиотек>`."
---

## Вопрос, с которого всё начинается

Ты взял бинарь из Docker-образа на Alpine и попробовал применить знакомый tcache poisoning. Не работает: `__free_hook` не существует, а вместо tcache какой-то `mallocng`. Ты привык к glibc, а тут — **другая libc**.

Musl — компактная реализация стандартной библиотеки C, которую используют Alpine, Docker и embedded. Сегодня разберём, чем она отличается и как под неё адаптировать эксплуатацию.

## Наш пример: статический бинарь из Alpine

```bash
$ file ./chall
./chall: ELF 64-bit LSB pie executable, statically linked, ...
$ ldd ./chall
        not a dynamic executable
$ strings ./chall | grep -i musl
musl libc (x86_64)
Version 1.2.3
```

`not a dynamic executable` + строки musl — типичный статический musl-бинарь. Версия `1.2.3` важна: аллокатор зависит от неё.

## Шаг 1. Отличия от glibc

| Компонент | glibc | musl |
|---|---|---|
| аллокатор | malloc (tcache/bins) | mallocng |
| хуки | есть (<2.34) | нет |
| FILE | `_IO_FILE` | своя |
| линковка | динамическая | часто статическая |

Из-за этого **glibc-техники не переносятся**: tcache poisoning, FSOP через `_IO_2_1_stdout_` и перезапись `__free_hook` не работают. Нужен отдельный набор приёмов.

## Шаг 2. Аллокатор mallocng

С musl 1.2.0 используется **mallocng**. Он организует память в «группы» (`group`), каждая из которых содержит слоты фиксированного размера и метаданные (`meta`). Ключевые структуры:

| Структура | Роль |
|---|---|
| `group` | группа слотов |
| `meta` | метаданные группы |
| `malloc_context` | глобальный контекст |

В исходниках musl это `src/malloc/mallocng/` (`meta.h`, `malloc.c`). При освобождении слот помечается в маске (`freed_mask`); при необходимости группа переиспользуется. У `malloc_context` есть поле `secret` — аналог canary, используемый в проверках.

## Шаг 3. Heap-эксплуатация: подделка meta

Поскольку tcache/fastbin отсутствуют, эксплойты строятся вокруг `mallocng`:

```text
1) Определить версию musl (strings).
2) Изучить структуры group/meta/malloc_context.
3) Найти уязвимость (overflow в группу / UAF / double-free).
4) Перезаписать meta (mem или маски) -> аллокация по контролируемому адресу.
5) Через перекрытие перезаписать указатель/структуру приложения.
6) Вызвать ROP/syscall для shell.
```

Типовые сценарии: overflow в группу (перезапись `meta` соседа), UAF (переиспользование слота), double-free (проверок меньше, чем в glibc), манипуляция `meta` для произвольной аллокации. После получения произвольной записи атакуют `__malloc_context` или указатели приложения.

## Шаг 4. musl FILE — другая цель

FSOP в glibc опирается на `_IO_2_1_stdout_` и vtable. У musl **своя** реализация `FILE`, поэтому эти техники неприменимы напрямую. Другие цели: `__stdio_exit`, `atexit`-список musl, глобальные указатели. Можно атаковать `__malloc_context` для произвольной аллокации. Изучай исходники (`src/stdio/`, `src/malloc/`) и анализируй в gdb.

## Шаг 5. ROP под musl

musl-бинари часто статические, поэтому `syscall; ret`-гаджеты есть прямо в бинаре. ROP строится как для статических бинарей: ORW через syscall или SROP. `system` может присутствовать (musl её реализует), но для shell нужен `sh`. Ищи гаджеты через ROPgadget:

```bash
$ ROPgadget --binary ./chall | grep -E "pop rax|syscall"
0x00000000004011a9 : pop rax ; ret
0x00000000004011c2 : syscall ; ret
```

Для статических musl-бинарей характерны фиксированные адреса (если нет PIE) или PIE с утечкой. В CTF musl-задачи часто **проще в ROP, чем в heap** — начинай с ROP.

## Шаг 6. Отладка

Символы часто отсутствуют (stripped), поэтому используй `objdump -d`, Ghidra, IDA. В gdb, если символы есть, смотри `struct meta`/`struct group`; иначе анализируй вручную. Проверяй версию: `oldmalloc` в musl < 1.2.0, `mallocng` в ≥ 1.2.0. Практикуйся на Alpine:

```bash
$ docker run -it alpine
$ apk add build-base
```

## Сравнение musl и glibc heap

| Аспект | glibc | musl |
|---|---|---|
| Аллокатор | malloc (tcache/bins) | mallocng (groups) |
| Метаданные | chunk header | meta/group |
| Хуки | есть (<2.34) | нет |
| Safe-linking | да (2.32+) | нет (свои проверки) |

Различия означают, что glibc-эксплойты не переносятся. Публичных writeup'ов меньше, поэтому самостоятельный анализ и gdb — твои главные инструменты.

## Разбор mallocng в исходниках

`mallocng` состоит из нескольких файлов: `meta.h`, `malloc.c`, `realloc.c`, `free.c`. Ключевые структуры: `struct meta` (метаданные группы: `prev`, `next`, `mem`, `avail_mask`, `freed_mask`, `sizeclass`, `maplen`), `struct group` (группа слотов: `meta`, `active_idx`, слоты), `struct malloc_context` (глобальный контекст: `secret`, `init_done`, группы). Слоты распределяются по группам; при освобождении слот помечается в `freed_mask`; при необходимости группа переиспользуется.

Эксплуатация: перезапись `meta` (например, `mem` или масок) даёт произвольную аллокацию. Поле `secret` используется для проверок (аналог canary) — его нужно обойти или утечь. Изучай исходники (`git clone https://git.musl-libc.org/musl`) и структуры в gdb. Публичных writeup'ов меньше, чем для glibc, поэтому самостоятельный анализ особенно ценен.

## Практика: Alpine и mallocng

Запусти Alpine (`docker run -it alpine`), поставь `build-base` и собери тестовую программу. Изучи `mallocng` в исходниках. Для heap-задачи: определи версию, структуры, найди уязвимость, подделай `meta`. Для ROP — статические гаджеты. Веди заметки по структурам и смещениям: musl меняется между версиями, и то, что ты нашёл в 1.2.3, может отличаться в 1.2.5.

## Musl heap: практические сценарии

Типовые сценарии: overflow в группу (перезапись `meta` соседней группы); UAF (переиспользование слота); double-free (проверок меньше, чем в glibc); манипуляция `meta` (подделка `mem`/масок для аллокации по адресу). После получения произвольной аллокации/записи — перезапись `__malloc_context` или указателей приложения, затем ROP. Помни, что musl-бинари часто не имеют PIE или имеют, но с утечкой. Проверяй структуры в gdb (если символы есть) или анализируй вручную.

## На что смотреть дальше

- **Применение glibc-техник** — tcache/hooks/FSOP не работают.
- **Незнание mallocng** — структуры иные, изучай исходники.
- **Версия musl** — от неё зависит аллокатор (oldmalloc vs mallocng).
- **Статическая линковка** — libc вкомпилирована, гаджеты берутся из бинаря.
- **Мало writeup'ов** — анализируй самостоятельно.

## Что мы теперь знаем

- musl использует аллокатор `mallocng` (группы и `meta`), а не tcache/bins.
- Хуков `__free_hook`/`__malloc_hook` нет; `FILE` своя — glibc-FSOP неприменим.
- Heap-эксплуатация строится на подделке `meta`/`group`.
- ROP — статические гаджеты (`syscall; ret`), ORW/SROP.
- Версию musl определяют по строкам; от неё зависит аллокатор.

Musl используется в Docker/Alpine, поэтому навык востребован в контейнерной безопасности: контейнерные цели всё чаще собираются на musl, и умение работать с `mallocng` отличает специалиста, готового к реальным контейнерам, от того, кто знает только glibc.

## Квиз

Проверь себя.

```quiz
- question: "Какой аллокатор использует современный musl?"
  options:
    - "mallocng"
    - "tcache"
    - "jemalloc"
    - "SLUB"
  answer: 0
  explanation: "В новых musl применяется mallocng с иной структурой, отличной от glibc."
- question: "Почему в musl не работает FSOP через _IO_FILE?"
  options:
    - "У musl своя реализация stdio и иные структуры"
    - "FSOP только для Windows"
    - "У musl нет stdio"
    - "У musl нет файлов"
  answer: 0
  explanation: "Структуры FILE/vtable musl отличаются от glibc, поэтому glibc-FSOP неприменим."
- question: "На что целятся гаджеты в статическом musl-бинаре?"
  options:
    - "На сам бинарь (libc нет)"
    - "На libc"
    - "На tcache"
    - "На vDSO"
  answer: 0
  explanation: "В статике libc отсутствует; ROP строится из гаджетов бинаря."
- question: "Что часто делают при эксплуатации musl-бинаря вместо метаданных аллокатора?"
  options:
    - "Переполнение в соседний объект/логические баги"
    - "tcache poisoning"
    - "FSOP"
    - "house of force"
  answer: 0
  explanation: "mallocng не даёт glibc-примитивов, поэтому атакуют объекты приложения."
- question: "Как убедиться, что бинарь на musl и статический?"
  options:
    - "strings | grep musl и ldd (not a dynamic executable)"
    - "nm"
    - "readelf -n"
    - "strace"
  answer: 0
  explanation: "Строки musl + отсутствие динамических зависимостей указывают на статический musl."
```

## Куда дальше

Дальше — `pwn-canary-bypass`: разберём stack canary, его утечку и брутфорс, и вернёмся к привычному userland-миру. А пока главное: **musl — не glibc; забудь про tcache и хуки, изучай `mallocng`, а для ROP бери статические гаджеты.**

## Где пригодится

- **CTF:** Pwn — musl/Alpine/статичные задачи.
- **Bug bounty:** контейнеры на Alpine, IoT.
- **Пентест:** эксплуатация embedded-ПО.
- **Работа:** security research, container security.
