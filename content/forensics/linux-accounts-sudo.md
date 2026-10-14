---
id: linux-accounts-sudo
title: 'Linux-аккаунты и sudo: кто есть в системе и кто может всё'
category: forensics
parent: forensics-linux-deep
difficulty: medium
order: 1
tags: [linux, accounts, sudo, shadow, groups, forensics]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ Linux-хостов'
estimated_minutes: 45
summary: 'Как читать /etc/passwd, /etc/shadow, группы и sudoers, находить свежесозданных пользователей и подозрительные правила повышения прав.'
lab:
  kind: shell
  title: 'Практика: Linux-аккаунты и sudo'
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

Ты подключился к расследуемому серверу. Первый вопрос — не «что случилось», а «кто
вообще здесь есть». Злоумышленник почти всегда заводит себе учётку или меняет права
существующей. Начнём с самого базового источника — списка пользователей.

## Наш пример: пользователь backdoor

Предположим, в системе найден пользователь `backdoor`. Нам надо понять, откуда он
взялся, что умеет и какие следы оставил.

## Шаг 1: список пользователей

Файл `/etc/passwd` хранит учётные записи. Формат — семь полей через двоеточие:

```
$ cat /etc/passwd | grep backdoor
backdoor:x:1002:1002::/home/backdoor:/bin/bash
```

Читаем: имя `backdoor`, пароль в отдельном файле (`x`), UID `1002`, GID `1002`,
комментарий пуст, домашний каталог `/home/backdoor`, оболочка `/bin/bash`.

UID ≥ 1000 обычно означает обычного пользователя. А вот UID `0` — это **root**.
Опасный признак: учётка с именем вроде `backdoor`, но с UID `0`.

## Шаг 2: пароли и хеши

Хеши паролей лежат в `/etc/shadow` (доступен только root):

```
$ sudo cat /etc/shadow | grep backdoor
backdoor:$6$abcd...:19500:0:99999:7:::
```

Поля: хеш, день последней смены пароля, минимальный/максимальный срок, срок
предупреждения. `$6$` — это SHA-512. Отсутствие пароля (`!` или `*`) означает, что
вход по паролю запрещён — но это не значит, что учётка не используется (по SSH-ключу
всё равно можно войти).

## Шаг 3: группы и привилегии

Права в Linux — это в первую очередь группы. Команда `id`:

```
$ id backdoor
uid=1002(backdoor) gid=1002(backdoor) groups=1002(backdoor),27(sudo)
```

Членство в группе `sudo` (или `wheel`) даёт право повышать права. Группа `docker` —
это фактически root: тот, кто может запускать контейнеры, может смонтировать хост.
Ищи такие «тихие» привилегированные группы.

## Шаг 4: правила sudoers

Смотрим, что именно разрешено:

```
$ sudo grep -rE 'backdoor|NOPASSWD' /etc/sudoers /etc/sudoers.d/
backdoor ALL=(ALL) NOPASSWD: ALL
```

`NOPASSWD: ALL` — злоумышленник может выполнить любую команду без пароля. Это
классический persistence-приём.

## Шаг 5: следы в логах

Проверим, когда учётка создавалась:

```
$ grep -i 'useradd\|new user' /var/log/auth.log | grep backdoor
Jan 14 03:12:44 host useradd[2211]: new user: name=backdoor, UID=1002, ...
```

И кто её использовал:

```
$ last -f /var/log/wtmp | grep backdoor
backdoor pts/0        10.10.20.9       Thu Jan 14 03:15   still logged in
```

Источник `10.10.20.9` — это уже зацепка для дальнейшего расследования.

## Что мы теперь знаем

- `/etc/passwd` даёт список учёток; UID 0 — это root.
- Хеши и сроки — в `/etc/shadow`.
- Права даёт группа (`sudo`, `wheel`, `docker`).
- `sudoers` может разрешать `NOPASSWD` — это опасно.
- `auth.log` и `wtmp` показывают создание и входы.

## Если не сработало

- Нет доступа к `/etc/shadow`? Смотри членство в группах и `sudoers` — их часто
  достаточно.
- Логи ротированы? Проверь `auth.log.1`, `.gz` и journald (`journalctl -u ssh`).
- Учётка удалена? Ищи её UID в файлах (`find / -uid 1002`).

## Квиз

Проверь себя.

```quiz
- question: Что означает UID 0 в /etc/passwd?
  options:
    - 'обычный пользователь'
    - 'root — суперпользователь'
    - 'системный сервис'
    - 'заблокированный аккаунт'
  answer: 1
  explanation: 'UID 0 зарезервирован за root; любая запись с UID 0 имеет полные права.'
- question: Где хранятся хеши паролей Linux?
  options:
    - 'в /etc/passwd'
    - 'в /etc/shadow'
    - 'в /etc/hosts'
    - 'в /var/log/auth.log'
  answer: 1
  explanation: '/etc/shadow доступен только root и содержит хеши и сроки пароля.'
- question: Чем опасно правило NOPASSWD: ALL в sudoers?
  options:
    - 'замедляет систему'
    - 'позволяет выполнять любые команды без пароля'
    - 'отключает сеть'
    - 'удаляет логи'
  answer: 1
  explanation: 'NOPASSWD: ALL снимает запрос пароля — это фактически постоянный root.'
- question: Где искать момент создания пользователя?
  options:
    - 'в /etc/hosts'
    - 'в /var/log/auth.log (useradd)'
    - 'в /proc/cpuinfo'
    - 'в /etc/fstab'
  answer: 1
  explanation: 'useradd пишет запись в auth.log, часто с точным временем и UID.'
```
