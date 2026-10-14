---
id: linux-kernel-modules
title: 'Модули ядра Linux: загрузка, подписи и руткиты'
category: forensics
parent: forensics-linux-kernel
difficulty: hard
order: 1
tags: [linux, kernel, modules, rootkit, lsmod, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как читать /proc/modules и lsmod, проверять подписи модулей и находить скрытые руткитом модули.'
lab:
  kind: shell
  title: 'Практика: Модули ядра Linux'
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

Ты анализируешь Linux-сервер, который «странно себя ведёт»: процессы не видны в `ps`,
файлы исчезают. Это признаки **руткита** — вредоносного кода внутри ядра. Ядро Linux
расширяется модулями, и именно там прячется самое опасное ПО. Разберёмся, как это
увидеть.

## Наш пример: подозрительный модуль

Начнём с самого простого источника — списка загруженных модулей.

## Шаг 1: список модулей

```
$ lsmod | head -5
Module                  Size  Used by
nf_tables             245760  0
xt_conntrack           16384  1
```

`lsmod` читает `/proc/modules`. Три колонки: имя, размер в байтах, сколько раз
используется. Список длинный — но он не полный, если ядро заражено.

## Шаг 2: что модуль умеет

Каждый модуль можно распросить:

```
$ modinfo xt_conntrack
filename:       /lib/modules/6.1.0/kernel/net/netfilter/xt_conntrack.ko
license:        GPL
srcversion:     A1B2C3D4E5F6
depends:        nf_conntrack
```

`modinfo` показывает путь, лицензию и зависимости. Если модуль лежит не в
`/lib/modules/` или не имеет `srcversion` — это подозрительно.

## Шаг 3: подписи модулей

Ядро может требовать подписанные модули:

```
$ modinfo -F signature /lib/modules/$(uname -r)/kernel/net/netfilter/xt_conntrack.ko
(пусто, если подписи нет)
```

Если в системе включён **secure boot** и запрет неподписанных модулей, загрузить
чужой модуль нельзя. Проверить режим:

```
$ cat /sys/kernel/security/lockdown
[none] integrity confidentiality
```

`none` означает, что ограничения сняты — руткит может загрузиться.

## Шаг 4: скрытые модули

Руткит часто **вырезает** себя из списка, который показывает ядро. Тогда `lsmod` его
не покажет. Способ найти — сравнить список с реальными файлами `.ko` и с адресами
в памяти:

```
$ grep -c '' /proc/modules
142
$ find /lib/modules/$(uname -r) -name '*.ko*' | wc -l
141
```

Разница в один модуль — зацепка. Но более надёжно — искать по адресам структур ядра
(это делают Volatility/`linux_check_modules` на дампе памяти).

## Шаг 5: следы загрузки

Модуль где-то был загружен. Смотрим `dmesg`:

```
$ dmesg | grep -i 'module\|taint'
[  10.2] xt_conntrack: loading out-of-tree module taints kernel
```

«taints kernel» — ядро помечено как «грязное»: загружен модуль вне дерева. Это
признак стороннего кода.

## Что мы теперь знаем

- `/proc/modules` / `lsmod` — список загруженных модулей.
- `modinfo` показывает путь, лицензию, зависимости.
- Подписи и lockdown ограничивают загрузку.
- Руткит может скрыть себя из списка — сравнивай с файлами и памятью.
- `dmesg` с «taints kernel» сигналит о стороннем модуле.

## Если не сработало

- Нет доступа к живому ядру? Анализируй дамп памяти (Volatility).
- Модуль удалён с диска? Ищи его в кэше и в памяти.
- Всё выглядит чисто? Сравни хеши модулей с эталонными из пакета.

## Квиз

Проверь себя.

```quiz
- question: Что читает lsmod?
  options:
    - 'файлы .ko'
    - '/proc/modules'
    - 'dmesg'
    - '/etc/modules'
  answer: 1
  explanation: 'lsmod — обёртка над /proc/modules (имя, размер, счётчик использования).'
- question: Что означает «taints kernel» в dmesg?
  options:
    - 'ядро обновилось'
    - 'загружен модуль вне дерева — ядро помечено как грязное'
    - 'диск переполнен'
    - 'включён secure boot'
  answer: 1
  explanation: 'Taint flag появляется при загрузке стороннего/неподписанного кода.'
- question: Почему руткит может не показываться в lsmod?
  options:
    - 'он слишком маленький'
    - 'он вырезает себя из списка ядра'
    - 'lsmod устарел'
    - 'так работает ядро'
  answer: 1
  explanation: 'Руткит перехватывает вывод и скрывает свою структуру из /proc/modules.'
- question: Как проверить, разрешена ли загрузка неподписанных модулей?
  options:
    - 'по размеру диска'
    - 'cat /sys/kernel/security/lockdown'
    - 'командой free'
    - 'через /etc/hosts'
  answer: 1
  explanation: 'lockdown=none снимает ограничения на неподписанный код.'
```
