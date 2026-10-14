---
id: linux-network-artifacts
title: 'Сетевые артефакты Linux: сокеты, соединения и ARP'
category: forensics
parent: forensics-linux-runtime
difficulty: medium
order: 4
tags: [linux, network, sockets, conntrack, arp, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как по /proc/net, ss, conntrack и ARP восстановить сетевую активность хоста и связать её с процессами.'
lab:
  kind: shell
  title: 'Практика: Сетевые артефакты Linux'
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

Вредоносное ПО на Linux почти всегда «звонит домой» по сети. Но журналов может не
быть. Зато есть **текущее состояние** сети: сокеты, соединения, таблицы. Из них можно
восстановить, с кем хост общался. Разберём источники.

## Наш пример: подозрительное соединение

## Шаг 1: смотрим сокеты с процессами

```
$ sudo ss -tunap | grep ESTAB
tcp ESTAB 0 0 10.10.20.5:54322 203.0.113.5:443 users:(("x",pid=991,fd=4))
```

`ss` показывает активное соединение: локальный `10.10.20.5:54322` ↔ удалённый
`203.0.113.5:443`, и — главное — процесс `x` (PID 991). Это тот же процесс, что мы
нашли в `/proc`.

## Шаг 2: /proc/net — сырые данные

`ss` читает `/proc/net/*`. Полезно, когда `ss` недоступен:

```
$ cat /proc/net/tcp | head
  sl  local_address rem_address   st tx_queue rx_queue ...
   0: 0A0A1405: D426  CB007105: 01BB 01 ...
```

Адреса в hex и «перевёрнуты»: `0A0A1405` = `10.10.20.5`, `CB007105` = `203.0.113.5`,
порт `01BB` = 443. Уметь читать hex полезно, когда нет утилит.

## Шаг 3: conntrack — история соединений

Если включён firewall с conntrack, он помнит **все** соединения, включая закрытые:

```
$ sudo conntrack -L | grep 203.0.113.5
tcp 6 431999 ESTABLISHED src=10.10.20.5 dst=203.0.113.5 sport=54322 dport=443 ...
```

Это уже история, а не только текущее состояние — ценный источник для таймлайна.

## Шаг 4: ARP-таблица

Кто был в локальной сети:

```
$ ip neigh show
10.10.20.9 dev eth0 lladdr 02:42:0a:0a:14:09 REACHABLE
```

MAC-адрес `02:42:...` — типичный для виртуальных интерфейсов (Docker/VM). Сопоставляя
MAC и IP, понимаешь топологию и возможный источник атаки.

## Шаг 5: сопоставляем с процессами

Ключевая связка: сокет → inode → процесс. Inode сокета:

```
$ ls -l /proc/991/fd/4
lrwx------ 1 root root 64 ... 4 -> socket:[45678]
```

Затем ищем этот inode по всем `/proc`:

```
$ for p in /proc/[0-9]*; do grep -l 45678 "$p"/fdinfo/* 2>/dev/null; done
```

Так находишь **все** процессы, использующие соединение.

## Что мы теперь знаем

- `ss -tunap` показывает соединения с процессами.
- `/proc/net/tcp` — сырые hex-адреса (полезно без утилит).
- conntrack помнит закрытые соединения — история.
- `ip neigh` даёт ARP/MAC — локальная топология.
- Сокет ↔ inode ↔ процесс связывает сеть с файлами и процессами.

## Если не сработало

- Соединение закрыто? Смотри conntrack и логи firewall.
- Нет conntrack? Проверь `/var/log/` и eBPF-трассировку.
- Нужен трафик? Снимай дамп (`tcpdump`) до выключения хоста.

## Квиз

Проверь себя.

```quiz
- question: Какая команда показывает соединения с процессами?
  options:
    - 'ls -la'
    - 'ss -tunap'
    - 'cat /etc/hosts'
    - 'free -h'
  answer: 1
  explanation: 'ss с -p связывает сокеты с процессами, -a показывает все.'
- question: Где хранятся сырые сетевые таблицы?
  options:
    - 'в /proc/net/tcp'
    - 'в /etc/passwd'
    - 'в /boot'
    - 'в /tmp'
  answer: 0
  explanation: '/proc/net/* содержит таблицы сокетов в hex.'
- question: Что даёт conntrack?
  options:
    - 'только текущие соединения'
    - 'историю соединений, включая закрытые'
    - 'пароли'
    - 'файлы'
  answer: 1
  explanation: 'conntrack ведёт таблицу состояний соединений — история трафика.'
- question: Как связать сокет с процессом?
  options:
    - 'по имени файла'
    - 'через inode сокета в /proc/<pid>/fd'
    - 'по MAC'
    - 'по дате'
  answer: 1
  explanation: 'Симлинк socket:[inode] связывает дескриптор и соединение.'
```
