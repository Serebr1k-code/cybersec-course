---
id: linux-ebpf-forensics
title: 'eBPF-форензика: программы в ядре и их следы'
category: forensics
parent: forensics-linux-kernel
difficulty: hard
order: 2
tags: [linux, ebpf, bpf, rootkit, tracing, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Что такое eBPF, как программы живут в ядре, как их перечислять (bpftool) и почему это новый вектор руткитов.'
lab:
  kind: shell
  title: 'Практика: eBPF-форензика'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Раньше, чтобы влезть в ядро, нужен был модуль. Теперь есть **eBPF** — механизм, который
позволяет запускать код в ядре **без модуля**, легально и штатно. Беда в том, что тем же
механизмом пользуются руткиты: код живёт в ядре, но в списке модулей его нет. Как его
найти?

## Наш пример: программа, которой «не должно быть»

Начнём с того, что вообще загружено.

## Шаг 1: перечисляем eBPF-программы

```
$ sudo bpftool prog list
7: kprobe  name trace_sys_enter  tag a1b2c3d4  gpl
	loaded_at 2026-01-14T03:20:00+0000  uid 0
	...
15: tracepoint  name suspicious_recv  tag deadbeef  gpl
	loaded_at 2026-01-14T03:25:10+0000  uid 0
```

Каждая программа имеет id, тип (`kprobe`, `tracepoint`, `xdp`), имя, тег и — важно —
`loaded_at` и `uid`. Программа `suspicious_recv`, загруженная в 03:25, привлекает
внимание.

## Шаг 2: читаем детали

```
$ sudo bpftool prog show id 15
15: tracepoint  name suspicious_recv  tag deadbeef
	loaded_at 2026-01-14T03:25:10+0000  uid 0
	xlated 1024B  jited 700B  memlock 4096B
	btf_id 42
```

`xlated` — размер «скомпилированного» байткода, `jited` — после JIT. Программа
привязана к трассировочной точке (например, к приёму пакетов). Такой хук может
перехватывать данные в ядре.

## Шаг 3: куда привязана программа

```
$ sudo bpftool link list
5: tracepoint  prog 15  tp 'syscalls/sys_enter_recvfrom'
```

Ссылка (`link`) показывает, к какому событию привязана программа. `sys_enter_recvfrom`
означает перехват приёма данных — идеальное место, чтобы прятать трафик.

## Шаг 4: карты (maps) — где живут данные

eBPF-программы обмениваются данными через **карты**:

```
$ sudo bpftool map list
8: hash  name hidden_pkts  flags 0x0
	key 4B  value 512B  max_entries 1024  memlock 524288B
```

Карта `hidden_pkts` с 1024 записями — вероятно, накопитель «спрятанных» пакетов.

## Шаг 5: кто загрузил

Программа принадлежит какому-то процессу. Ищем в `/proc`:

```
$ for p in /proc/[0-9]*; do grep -l bpf "$p"/maps 2>/dev/null; done
/proc/991/maps
$ tr '\0' ' ' < /proc/991/cmdline
/opt/.hidden/bpf-loader
```

Загрузчик `bpf-loader` из скрытого каталога — вот источник.

## Что мы теперь знаем

- eBPF запускает код в ядре без модуля.
- `bpftool prog list` перечисляет программы с временем и uid.
- `bpftool link list` показывает, к чему привязана программа.
- Карты (maps) хранят данные, которыми обменивается программа.
- Загрузчик можно найти по `/proc/<pid>/maps` и `cmdline`.

## Если не сработало

- Нет bpftool? Читай `/sys/fs/bpf` и `/proc/*/maps`.
- Программа отсоединена, но карта осталась — смотри `bpftool map list`.
- Нужен дамп памяти? Volatility-плагины для eBPF ограничены — фиксируй живой вывод.

## Квиз

Проверь себя.

```quiz
- question: Чем eBPF-руткит отличается от модульного?
  options:
    - 'он не работает'
    - 'он живёт в ядре без загрузки модуля'
    - 'он требует перезагрузки'
    - 'он только на Windows'
  answer: 1
  explanation: 'eBPF-код исполняется в ядре штатным механизмом, без .ko-модуля.'
- question: Какая команда перечисляет eBPF-программы?
  options:
    - 'lsmod'
    - 'bpftool prog list'
    - 'ps aux'
    - 'netstat'
  answer: 1
  explanation: 'bpftool — штатная утилита для работы с eBPF-подсистемой.'
- question: Что показывает bpftool link list?
  options:
    - 'размер диска'
    - 'к какому событию привязана программа'
    - 'пароли'
    - 'маршруты сети'
  answer: 1
  explanation: 'links связывают программу с хуком (tracepoint, kprobe и т.д.).'
- question: Где eBPF-программа хранит данные?
  options:
    - 'в /tmp'
    - 'в картах (maps)'
    - 'в реестре'
    - 'в SWAP'
  answer: 1
  explanation: 'Обмен данными идёт через BPF-карты (hash/array и др.).'
```
