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

## Полный разбор auth.log: поля и что они значат

Строка sshd имеет фиксированную структуру. Разберём её по полям, чтобы читать уверенно:

```
Jan 14 02:11:02 host sshd[950]: Accepted password for root from 203.0.113.5 port 40200 ssh2
└─дата─┘ └хост┘ └модуль,PID┘ └─событие─┘ └───кто───┘ └────источник────┘ └порт┘ └прото─┘
```

| Поле | Значение | На что смотреть |
|---|---|---|
| дата | локальное время хоста | часовой пояс и дрейф |
| `sshd[PID]` | PID процесса sshd | последовательность и правдоподобие |
| `Accepted` | успех | реальный вход |
| `Failed` | провал | фон или целенаправленный перебор |
| `password` / `publickey` | метод | пароль (слабый) или ключ (сильный) |
| `for USER` | учётка | `invalid user` = не существует |
| `from IP port N` | источник | сопоставление с фаерволом |
| `ssh2` | версия протокола | ssh1 — устаревшее |

## Геолокация и репутация адресов

Источник входа — ключевая зацепка. Быстрая обработка списка уникальных адресов:

```
$ grep 'Accepted' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
      3 10.10.20.7
      1 203.0.113.5
```

Дальше каждый адрес оценивают по контексту: `10.10.20.7` — внутренний (может быть легитимным админом), `203.0.113.5` — внешний (кандидат на атаку). Геолокация и репутация (ASN, `whois`) помогают, но помни: атакующий может использовать VPS, Tor или скомпрометированный промежуточный хост, поэтому «геолокация» — только ориентир, а не доказательство.

## Индикаторы компрометации SSH

| Индикатор | Что означает |
|---|---|
| Много `Failed password` → один `Accepted` | успешный подбор |
| `Accepted password for root` | вход под root по паролю (обычно запрещён политикой) |
| `Accepted publickey` с новым ключом | добавлен ключ атакующего |
| `invalid user` пачками | перебор имён |
| `maximum authentication attempts exceeded` | агрессивный перебор |
| `direct-tcpip` / `forwarded` | туннелирование |
| `Disconnected from ... preauth` | разрыв до аутентификации (сканер/бот) |
| `Connection closed by authenticating user` | частые обрывы — автоматизация |

## Туннели: local, remote и dynamic forwarding

SSH умеет три вида перенаправления, и следы у них разные:

- **Local (`-L`)** — клиент открывает локальный порт и шлёт трафик на сервер. На сервере видно `direct-tcpip` на целевой хост.
- **Remote (`-R`)** — сервер открывает порт и шлёт трафик клиенту. Это опасный случай: атакующий делает внутреннюю машину доступной наружу.
- **Dynamic (`-D`)** — SOCKS-прокси. Много разных `direct-tcpip` на разные порты.

```
$ grep -E 'direct-tcpip|forwarded|opened' /var/log/auth.log | head
Jan 14 03:05:00 host sshd[1300]: channel 1: open failed: administratively prohibited: open failed
```

`administratively prohibited` означает, что переброска запрещена конфигом (`AllowTcpForwarding no`) — но попытка уже зафиксирована. Много `direct-tcpip` на разные адреса — верный признак, что сервер используют как прокси вглубь сети.

## Крайние случаи и ограничения

- **Часовой пояс.** `auth.log` пишет локальное время; при сведении с сетевыми логами (UTC) нужен сдвиг, иначе таймлайн сломается.
- **Ротация и сжатие.** События могут быть в `auth.log.1`, `.2.gz`; `zgrep` ищет внутри.
- **journald вместо файла.** На systemd-системах `auth.log` может отсутствовать; тогда `journalctl -u ssh` или `_COMM=sshd`.
- **Логи подчищены.** Смотри `wtmp`/`btmp` (`last`, `lastb`), которые правят реже, и `auditd` (`/var/log/audit/`).
- **Подделка записей.** Аномальный PID или «висячее» событие без парного — сигнал инъекции (см. урок про запутывание следов).

## Сценарий: реконструкция вторжения

Задача — доказать факт и источник вторжения. Порядок:

```
# 1. Факт: есть ли успешный вход и когда
$ grep 'Accepted' /var/log/auth.log

# 2. Перебор до него: с каких адресов
$ grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head

# 3. Что делали после входа: команды, sudo, su
$ grep -E 'sudo|COMMAND' /var/log/auth.log

# 4. Постоянный доступ: новые ключи и учётки
$ grep -E 'useradd|new user' /var/log/auth.log
$ last -f /var/log/wtmp | head

# 5. Туннели: использовали ли как прокси
$ grep -E 'direct-tcpip|forwarded' /var/log/auth.log
```

Если успешный вход подтверждается и `wtmp` (сессия), и сетевым логом (трафик на 22) — вывод устойчив. Если только одна строка в `auth.log` без подтверждений — проверь подделку.

## Быстрые команды и разбор примера брутфорса

Однострочники, которыми удобно разбирать `auth.log` при инциденте:

```
# топ адресов по неудачным попыткам
$ grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head

# топ имён, которые перебирали
$ grep 'invalid user' /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn | head

# все успешные входы с временем и источником
$ grep 'Accepted' /var/log/auth.log

# попытки туннелирования
$ grep -E 'direct-tcpip|forwarded' /var/log/auth.log

# свести с wtmp
$ last -f /var/log/wtmp | head -20
```

Разберём типичный брутфорс целиком:

```
$ grep -c 'Failed password' /var/log/auth.log
18422
$ grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -3
  17000 203.0.113.5
    900 198.51.100.7
    500 10.10.20.9
$ grep 'Accepted' /var/log/auth.log | grep 203.0.113.5
Jan 14 02:11:02 host sshd[950]: Accepted password for root from 203.0.113.5 port 40200 ssh2
```

Читаем: 17000 неудач с одного адреса, затем **успешный вход под root** с него же. Это уже не фон — это целенаправленный подбор с результатом. Дальше обязательно проверяем, что происходило после входа: созданные учётки, новые ключи, `sudo`-команды, туннели. Успешный вход сам по себе — только начало картины; ценность имеет цепочка «вход → закрепление → действия».

Важно и обратное: тысячи `Failed` **без** единого `Accepted` — это просто интернет-шум, и тратить на него время не нужно. Сигнал — только успех и его окружение.

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
