---
id: linux-sshd-logs
title: 'SSH-логи: успешные входы, брутфорс и туннели'
category: forensics
parent: forensics-linux-deep
difficulty: medium
order: 2
tags: [linux, ssh, auth, brute-force, tunnel, forensics]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ Linux-хостов'
estimated_minutes: 45
summary: 'Как читать auth.log/journald по SSH: отличать успешные входы от брутфорса, находить ключи и туннели.'
lab:
  kind: shell
  title: 'Практика: SSH-логи'
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

Сервер взломан. Скорее всего, вошли по SSH. Но журнал полон строк `Failed password`
и `Accepted publickey` — как из этого месива понять, **был ли настоящий вход** и
**с какого адреса**? Разберём по шагам.

## Наш пример: подозрительный вход

У нас есть `/var/log/auth.log`. Начнём с фильтра по SSH:

```
$ grep -i sshd /var/log/auth.log | tail -20
Jan 14 02:10:11 host sshd[900]: Failed password for invalid user admin from 203.0.113.5 port 40122 ssh2
Jan 14 02:10:14 host sshd[901]: Failed password for invalid user admin from 203.0.113.5 port 40130 ssh2
Jan 14 02:11:02 host sshd[950]: Accepted password for root from 203.0.113.5 port 40200 ssh2
```

Видно три события: два провала и **успех** с того же адреса. Это типичная картина
подбора: сначала много неудач, потом попадание.

## Шаг 1: отделяем шум от сигнала

Тысячи `Failed password` — это фон интернета. Значение имеет `Accepted`. Считаем:

```
$ grep -c 'Failed password' /var/log/auth.log
18422
$ grep 'Accepted' /var/log/auth.log
Jan 14 02:11:02 host sshd[950]: Accepted password for root from 203.0.113.5 port 40200 ssh2
```

Один успех из 18 тысяч попыток — это и есть точка входа.

## Шаг 2: недействительные пользователи

`invalid user` означает, что такого пользователя нет — злоумышленник перебирает
имена:

```
$ grep 'invalid user' /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn | head
   500 admin
   320 test
   210 oracle
```

Список имён — это профиль атаки. Если среди них есть реальный пользователь, атака
была адресной.

## Шаг 3: вход по ключу, а не по паролю

Современный вход часто выглядит иначе:

```
$ grep 'Accepted publickey' /var/log/auth.log
Jan 14 03:00:01 host sshd[1200]: Accepted publickey for deploy from 10.10.20.7 port 51000 ssh2: RSA SHA256:AbCd...
```

`publickey` означает, что пароль не использовался — вошли по ключу. Значит, надо
искать, какой ключ добавлен в `~/.ssh/authorized_keys` и когда.

## Шаг 4: туннели и переброски портов

SSH умеет перенаправлять трафик. Признак — `session opened` с необычными запросами:

```
$ grep -E 'direct-tcpip|forwarded' /var/log/auth.log
Jan 14 03:05:00 host sshd[1300]: channel 2: open failed: administratively prohibited
```

Если видишь много `direct-tcpip` — кто-то использует сервер как прокси. Это признак
построения туннеля для дальнейшего доступа к внутренней сети.

## Шаг 5: сопоставляем с другими источниками

`auth.log` — не единственный источник. Проверим `last`:

```
$ last | head -5
root     pts/0        203.0.113.5      Thu Jan 14 02:11   still logged in
```

И journald, если rsyslog не пишет в файл:

```
$ journalctl _COMM=sshd --since "2026-01-14 02:00" | grep Accepted
```

## Что мы теперь знаем

- `Accepted` — реальный вход; `Failed` — фон.
- `invalid user` показывает список перебираемых имён.
- `publickey` = вход по ключу, надо искать ключ в `authorized_keys`.
- `direct-tcpip` = использование сервера как прокси/туннеля.
- Всегда сопоставляй `auth.log`, `last` и journald.

## Если не сработало

- Файла нет? Читай journald (`journalctl -u ssh`).
- Ротация? Проверь `.1` и `.gz`.
- Логи подчищены? Смотри `wtmp`/`btmp` (`last`, `lastb`) — их чистят реже.

## Квиз

Проверь себя.

```quiz
- question: Какая строка в auth.log означает реальный успешный вход?
  options:
    - 'Failed password'
    - 'Accepted password/publickey'
    - 'Connection closed'
    - 'Invalid user'
  answer: 1
  explanation: 'Только Accepted подтверждает вход; Failed — это неудачные попытки.'
- question: Что означает invalid user в логе sshd?
  options:
    - 'пользователь заблокирован'
    - 'такого пользователя нет — идёт перебор имён'
    - 'ошибка диска'
    - 'вход по ключу'
  answer: 1
  explanation: 'invalid user появляется, когда пытаются войти под несуществующим именем.'
- question: Признак использования SSH как туннеля?
  options:
    - 'много строк Failed password'
    - 'события direct-tcpip / forwarded'
    - 'перезагрузка'
    - 'смена пароля'
  answer: 1
  explanation: 'direct-tcpip и forwarded channels означают перенаправление трафика.'
- question: Где искать входы, если auth.log пуст?
  options:
    - 'в /etc/hosts'
    - 'в journalctl -u ssh и wtmp (last)'
    - 'в /proc/meminfo'
    - 'в /etc/fstab'
  answer: 1
  explanation: 'journald и wtmp дублируют события входа и часто сохраняются дольше.'
```
