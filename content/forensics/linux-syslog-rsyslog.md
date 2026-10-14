---
id: linux-syslog-rsyslog
title: 'syslog и rsyslog: как читать классический системный журнал'
category: forensics
parent: forensics-linux-deep
difficulty: medium
order: 3
tags: [linux, syslog, rsyslog, journald, logs, forensics]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ Linux-хостов'
estimated_minutes: 45
summary: 'Формат syslog/rsyslog, приоритеты и facility, ротация и сопоставление с journald — как не потеряться в общем журнале.'
lab:
  kind: shell
  title: 'Практика: syslog и rsyslog'
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

Ты открываешь `/var/log/syslog` — и видишь тысячи строк без явной структуры. Где тут
полезное, а где шум? Классический syslog читается не «сверху вниз», а по колонкам и
приоритетам. Разберём его анатомию.

## Наш пример: строка syslog

Возьмём одну строку:

```
Jan 14 03:12:44 web01 cron[2211]: (root) CMD (cd /tmp && ./update.sh)
```

## Шаг 1: разбираем поля

Слева направо:

- `Jan 14 03:12:44` — время (без года!);
- `web01` — имя хоста (hostname);
- `cron[2211]` — процесс и его PID;
- `(root) CMD (...)` — само сообщение.

Отсутствие года — важная ловушка. Если логи охватывают новый год, придётся
восстанавливать год по дате файла или по другим источникам.

## Шаг 2: приоритеты и facility

В сыром syslog приоритет обычно уже отфильтрован в отдельные файлы:
`auth.log`, `kern.log`, `mail.log`. Но при централизованном сборе приходит и число:

```
<134>Jan 14 03:12:44 web01 cron[2211]: ...
```

`134 = 16*8 + 6`. Первая часть — **facility** (16 = local0), вторая — **severity**
(6 = info). Severity идут от `0` (emerg) до `7` (debug). Для расследования важны
`0–4` (emerg/alert/crit/err).

## Шаг 3: находим подозрительный cron

Наша строка показывает, что root-крон запускает скрипт из `/tmp`. Это классический
persistence-приём: `/tmp` доступен на запись, скрипт легко подменить. Проверим:

```
$ grep -i 'CMD' /var/log/syslog | grep '/tmp'
Jan 14 03:12:44 web01 cron[2211]: (root) CMD (cd /tmp && ./update.sh)
Jan 14 04:12:44 web01 cron[2400]: (root) CMD (cd /tmp && ./update.sh)
```

Повторяется каждый час — значит, запись в crontab устойчивая.

## Шаг 4: rsyslog и централизация

В крупных системах логи отправляются на центральный сервер. Конфигурация — в
`/etc/rsyslog.conf` и `/etc/rsyslog.d/`:

```
$ grep -rE '^\*\.\*|@@|@' /etc/rsyslog.d/
*.* @@logserver.internal:514
```

`@@` — это TCP, `@` — UDP. Если логи уходили на центральный сервер, локальный файл
мог быть очищен, но копия осталась на сервере — это важнейшая зацепка.

## Шаг 5: сопоставление с journald

Современный Linux пишет и в бинарный journald. Сопоставим:

```
$ journalctl -u cron --since "2026-01-14 03:00" --until "2026-01-14 04:00"
Jan 14 03:12:44 web01 cron[2211]: (root) CMD (cd /tmp && ./update.sh)
```

journald хранит структурированные поля и не теряет год. Если syslog подчищен, а
journald нет — восстановишь картину.

## Что мы теперь знаем

- Формат syslog: время, хост, процесс[PID], сообщение.
- Года нет — восстанавливай по контексту.
- Facility × 8 + severity = число приоритета; важны 0–4.
- `@@`/`@` в rsyslog = пересылка на центральный сервер.
- journald — второй, бинарный источник; сопоставляй оба.

## Если не сработало

- Файл пуст? Проверь ротацию и `/var/log/remote/` на центральном сервере.
- Только journald? Используй `journalctl --output=json`.
- Время не сходится? Учти часовой пояс и `timedatectl`.

## Квиз

Проверь себя.

```quiz
- question: Какого поля НЕТ в классической строке syslog?
  options:
    - 'времени'
    - 'года'
    - 'имени хоста'
    - 'PID процесса'
  answer: 1
  explanation: 'Классический syslog пишет месяц/день/время без года.'
- question: Что означает @@ в rsyslog.conf?
  options:
    - 'запись в файл'
    - 'пересылка на центральный сервер по TCP'
    - 'шифрование'
    - 'ротация'
  answer: 1
  explanation: '@@ — TCP, @ — UDP; так логи уходят на центральный сервер.'
- question: Как из числа приоритета получить severity?
  options:
    - 'умножить на 8'
    - 'взять остаток от деления на 8'
    - 'прибавить 8'
    - 'никак'
  answer: 1
  explanation: 'priority = facility*8 + severity, поэтому severity = priority % 8.'
- question: Почему запись cron с ./update.sh из /tmp подозрительна?
  options:
    - 'cron медленный'
    - '/tmp доступен на запись — скрипт легко подменить'
    - 'cron не работает ночью'
    - 'это норма'
  answer: 1
  explanation: 'Запуск root-скрипта из /tmp — классический persistence-приём.'
```
