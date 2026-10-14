---
id: linux-package-logs
title: 'Логи менеджера пакетов: что устанавливали и когда'
category: forensics
parent: forensics-linux-deep
difficulty: medium
order: 4
tags: [linux, dpkg, apt, rpm, yum, packages, forensics]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ Linux-хостов'
estimated_minutes: 45
summary: 'Как по dpkg/apt и rpm/yum восстановить историю установки ПО, найти свежие и подозрительные пакеты.'
lab:
  kind: shell
  title: 'Практика: Логи менеджера пакетов'
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

На сервере обнаружен неизвестный инструмент. Откуда он? Установлен вручную, пришёл с
обновлением или его поставил злоумышленник? Менеджер пакетов ведёт журнал — и это
один из самых недооценённых форензик-артефактов Linux.

## Наш пример: неизвестный netcat-форк

Предположим, на хосте лежит бинарник `/usr/bin/nc.traditional` странного вида. Смотрим
историю пакетов Debian/Ubuntu.

## Шаг 1: основной журнал dpkg

```
$ grep -i 'netcat\|nc\.' /var/log/dpkg.log
2026-01-14 03:20:11 install netcat-traditional:amd64 <none> 1.10-47
```

Строка говорит: `install`, пакет `netcat-traditional`, версия `1.10-47`, время
`03:20` — ровно в те же минуты, что и подозрительный вход по SSH. Совпадение по
времени — сильный сигнал.

## Шаг 2: журнал apt

`apt` пишет отдельный лог с более человекочитаемыми записями:

```
$ grep -i netcat /var/log/apt/history.log
Start-Date: 2026-01-14  03:20:08
Commandline: apt-get install -y netcat-traditional
```

Здесь виден **Commandline** — как именно вызывалась установка. `-y` означает
«соглашаться автоматически» — типично для скрипта, а не человека.

## Шаг 3: rpm/yum (RHEL/CentOS)

На rpm-системах другой путь:

```
$ grep -i nmap /var/log/dnf.log
2026-01-14T03:22:10Z DDEBUG Installed: nmap-7.94-1.el9.x86_64
```

А полный список установленного — через базу rpm:

```
$ rpm -qa --last | head -5
nmap-7.94-1.el9.x86_64            Thu 14 Jan 2026 03:22:10 AM UTC
```

`--last` сортирует по времени установки — свежие пакеты сразу на виду.

## Шаг 4: что осталось от пакета

Даже если пакет удалили, dpkg хранит следы:

```
$ grep -i netcat /var/log/dpkg.log | grep -E 'remove|purge'
2026-01-14 03:40:02 remove netcat-traditional:amd64 1.10-47 <none>
```

Установили в `03:20`, удалили в `03:40` — короткое окно использования. Само удаление
тоже улика: злоумышленник заметает следы.

## Шаг 5: сопоставляем всё

Собираем таймлайн:

```
03:20:08  apt install netcat-traditional
03:20:11  dpkg install
03:22:10  dnf install nmap
03:40:02  dpkg remove netcat-traditional
```

Каждая строка — независимое подтверждение. Если менеджер пакетов не использовался
(бинарник просто скопирован), в логах ничего не будет — тогда смотрим `~/.bash_history`
и временные метки самого файла (`stat`).

## Что мы теперь знаем

- `/var/log/dpkg.log` — установки/удаления Debian/Ubuntu.
- `/var/log/apt/history.log` — команды apt, включая Commandline.
- `dnf.log` / `rpm -qa --last` — RHEL-семейство.
- Установка и удаление в коротком окне — признак заметания следов.
- Нет записи в пакетном менеджере = бинарник скопирован вручную.

## Если не сработало

- Логи ротированы? Проверь `dpkg.log.1`, `.gz`.
- Файл скопирован вручную? Смотри `stat`, `bash_history`, `auditd`.
- Контейнер? Пакеты могли ставиться в образ — тогда смотри Dockerfile/слой.

## Квиз

Проверь себя.

```quiz
- question: Какой файл хранит установки/удаления пакетов в Debian/Ubuntu?
  options:
    - '/etc/passwd'
    - '/var/log/dpkg.log'
    - '/var/log/kern.log'
    - '/etc/apt/sources.list'
  answer: 1
  explanation: 'dpkg.log фиксирует install/remove/purge с версиями и временем.'
- question: Что даёт /var/log/apt/history.log помимо dpkg.log?
  options:
    - 'ничего'
    - 'Commandline — как именно вызывалась установка'
    - 'пароли'
    - 'сетевые соединения'
  answer: 1
  explanation: 'apt history.log содержит точную командную строку установки.'
- question: Чем подозрительно «установил и через 20 минут удалил»?
  options:
    - 'это норма'
    - 'короткое окно использования и заметание следов'
    - 'диск перегреется'
    - 'обновление ядра'
  answer: 1
  explanation: 'Быстрая установка-удаление типична для одноразового инструмента.'
- question: Бинарника нет ни в dpkg.log, ни в apt — что вероятнее?
  options:
    - 'пакет установлен штатно'
    - 'файл скопирован вручную, в обход менеджера пакетов'
    - 'система не Linux'
    - 'лог повреждён'
  answer: 1
  explanation: 'Отсутствие записи означает ручную загрузку/копирование файла.'
```
