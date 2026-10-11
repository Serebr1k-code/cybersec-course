---
id: web-nosql-dbms
title: "NoSQL и другие хранилища: карта атак и переход к разбору"
category: web
parent: web-nosql-injection
difficulty: medium
order: 1
tags: [nosql, mongodb, redis, elasticsearch, couchdb, cassandra, memcached, neo4j, datastore, fingerprint]
prerequisites: [web-nosql-injection]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
  - "Работа: AppSec, code review"
estimated_minutes: 25
summary: "Как определить тип NoSQL/иного хранилища по порту и отклику и выбрать вектор: инъекция операторов, анонимный доступ, RCE через конфиг, модули или репликацию."
---

NoSQL — это не одна база, а целое семейство с абсолютно разными моделями угроз. MongoDB принимает **JSON-операторы** и исполняет JavaScript, Redis — текстовый протокол команд без схемы и с записью файлов на диск, Elasticsearch отвечает HTTP/JSON и умеет скрипты, CouchDB хранит JSON-документы и имеет «admin party», Memcached вообще не имеет аутентификации, Neo4j говорит на Cypher. Общее у них одно: классический SQL-сканер их **не видит**, а тип хранилища определяет, дойдёте вы до RCE или нет. Этот урок — карта: как понять, с чем вы говорите, и куда идти за деталями. Четыре следующих урока — полные практические разборы.

## Зачем отдельный урок под каждое хранилище

«NoSQL-инъекция» в туториалах почти всегда сводится к `{"$ne": null}` в MongoDB. На реальном тесте вы чаще встречаете **открытый порт без пароля**, чем инъекцию в приложение. Разница критична, потому что от типа хранилища зависит:

- **какой вектор вообще применим** — операторная инъекция (Mongo), запись файла (Redis), скрипты (Elasticsearch), конфиг-инъекция (CouchDB);
- **есть ли анонимный доступ** — 27017/6379/9200/11211 исторически открыты без аутентификации;
- **дойдёте ли вы до RCE** — Redis/CouchDB/Elasticsearch(старый) да, Memcached/Cassandra — обычно нет;
- **какой клиентский инструмент использовать** — `mongosh`, `redis-cli`, `curl`, `cqlsh`, `cypher-shell`.

Практическое правило: **сначала тип хранилища, потом вектор**. Не пишите `$where` в Redis и не ждите `CONFIG SET` в MongoDB.

## Фингерпринт: что за хранилище перед нами

Быстрее всего определить тип по **баннеру и отклику на пробный запрос**. Три способа, все через одну команду:

```bash
# 1) Что вообще слушает порт (баннер)
nmap -sV -p 27017,6379,9200,5984,9042,11211,7474,8086,8087,9300 target

# 2) Прямой пробник по протоколу
curl -s http://target:9200/                 # Elasticsearch -> JSON с cluster_name/version
curl -s http://target:5984/                 # CouchDB -> {"couchdb":"Welcome",...}
curl -s http://target:7474/                 # Neo4j -> HTML/JSON об инстансе
redis-cli -h target -p 6379 PING            # Redis -> PONG
```

Признаки по тексту ответа:

| Отклик | Хранилище |
|--------|-----------|
| `{"couchdb":"Welcome","version":"3.x"}` | CouchDB |
| `{"name":"...","cluster_name":"...","version":{"number":"8.x"}}` | Elasticsearch |
| `You know, for search` (тег `<title>`) | Elasticsearch |
| `PONG` на `PING` | Redis |
| `-ERR unknown command` (любая команда) | Redis (защищён паролем или нет) |
| `It looks like you are trying to access MongoDB over HTTP` | MongoDB (HTTP-порт 28017) |
| `neo4j` / `Neo4j` в HTML | Neo4j |
| `{"results":...}` на `/query` | InfluxDB |

Для MongoDB фингерпринт делают самим протоколом: `mongosh` при подключении к 27017 без пароля покажет список БД.

## Порты и дефолтные доступы

Запомните таблицу — это первое, что проверяют при «открытом хранилище».

| Хранилище | Порт(ы) | Анонимно по умолчанию | Дефолтные креды |
|-----------|---------|:---------------------:|-----------------|
| MongoDB | 27017, 28017 (HTTP) | да (исторически) | нет |
| Redis | 6379 | да (без `requirepass`) | нет |
| Elasticsearch | 9200 (HTTP), 9300 (transport) | да (без security) | нет |
| CouchDB | 5984 | **admin party** (любой пароль) | нет |
| Cassandra | 9042 (CQL), 7000/7001 | нет | `cassandra:cassandra` |
| Memcached | 11211 | **да, всегда** | нет |
| Neo4j | 7474 (HTTP), 7687 (Bolt) | нет | `neo4j:neo4j` |
| InfluxDB | 8086 | да (v1 без auth) | нет |

`admin party` у CouchDB — это когда в `_users` нет ни одного администратора, и **любой** запрос считается админским: любой пароль подходит.

## Сводная таблица: инъекция, дамп, RCE

| Возможность | MongoDB | Redis | Elasticsearch | CouchDB | Neo4j |
|-------------|---------|-------|---------------|---------|-------|
| Инъекция в приложение | `$ne`/`$gt`/`$regex`/`$where` | CRLF-инъекция команд (редко) | Query DSL / painless | JSON-документ | Cypher |
| Анонимный дамп | `find()` по всем БД | `KEYS *` + `GET` | `_cat/indices` + `_search` | `_all_docs` | `MATCH (n) RETURN n` |
| Выполнение JS/скриптов | `$where`, `mapReduce` | Lua `EVAL` | painless/groovy | JS views | APOC / procedures |
| RCE | `mapReduce`->sh (старые) | CONFIG+SAVE, MODULE LOAD, репликация | Groovy (CVE-2015-1427), Kibana Timelion | `_config` query_server | через APOC/плагины |
| Запись файла | редко | да (webshell, keys, cron) | нет (обычно) | нет | нет |
| SSRF-дружелюбен | да (через приложение) | да (gopher) | да (script→HTTP) | да | да |

Ключевой вывод: **Redis — король RCE** через запись файла; **MongoDB — король инъекции** в приложение; **Elasticsearch/CouchDB** чаще ломаются как «открытый сервис», чем как точка инъекции.

## Анонимный доступ vs инъекция

Это два разных сценария, и путать их — главная ошибка.

- **Открытый сервис (network-facing).** Порт доступен извне, аутентификации нет. Вы просто подключаетесь клиентом и читаете/пишете данные. Это находка уровня critical сама по себе (утечка всей БД, часто с PII). Вектор — прямой доступ.
- **Инъекция (app-facing).** Сервис недоступен снаружи, но приложение передаёт в него пользовательский ввод. Вы подставляете оператор/запрос и меняете логику. Вектор — payload в параметре.

На багбаунти чаще встречается **второе** (порт закрыт файрволом), в CTF и внутреннем пентесте — **первое**. Проверяйте оба: сначала «достаю ли я до порта», потом «принимает ли приложение мой ввод».

```bash
# app-facing: приложение отдаёт JSON в MongoDB
curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":"x"}}'

# network-facing: порт открыт
mongosh "mongodb://target:27017" --eval 'db.getMongo().getDBNames()'
```

## Универсальный алгоритм триажа

Порядок, который не зависит от типа хранилища:

```bash
# 1. Скан портов хранилищ
nmap -sV -p 27017,6379,9200,5984,9042,11211,7474,8086 target

# 2. Для каждого открытого порта — анонимный пробник (см. таблицу портов)
curl -s http://target:9200/_cat/indices?v     # если пусто/401 -> идём дальше
redis-cli -h target PING
curl -s http://target:5984/_all_dbs

# 3. Если порт закрыт — ищем инъекцию в приложении (JSON/form/URL)
curl -s -X POST https://target/api -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":{"$ne":null}}'

# 4. Фиксируем доказательство: одна строка данных, которой не должно быть видно
```

Как только тип определён — открывайте соответствующий урок ниже.

## Переход к разборам: четыре хранилища

| Урок | Хранилище | Ключевые фишки | RCE |
|------|-----------|----------------|:---:|
| [`db-mongodb`](db-mongodb) | MongoDB | `$ne`/`$gt`/`$regex`/`$where`, `find()`, `mapReduce` | старые версии |
| [`db-redis`](db-redis) | Redis | CONFIG+SAVE webshell, authorized_keys, MODULE LOAD, репликация | да |
| [`db-elasticsearch`](db-elasticsearch) | Elasticsearch | `_cat`, `_search`, painless, Kibana CVEs | старые версии |
| [`db-other`](db-other) | CouchDB / Cassandra / Memcached / Neo4j / InfluxDB | admin party, дефолтные креды, `_config`, Cypher | CouchDB |

Начинайте с того хранилища, которое показал фингерпринт. Если портов не видно — работайте по MongoDB-диалекту: операторная инъекция в JSON встречается чаще всего.

## Частые ошибки

- **Искать SQL-синтаксис в NoSQL.** Кавычка `'` и `UNION SELECT` тут бесполезны — MongoDB ждёт **объект** с оператором, а не строку.
- **Забыть про `Content-Type`.** Операторная инъекция проходит только если приложение парсит тело как JSON (`application/json`); в `application/x-www-form-urlencoded` нужен `user[$ne]=x`.
- **Считать `redis-cli` безопасным.** `CONFIG SET` меняет живой сервер; на проде согласуйте, прежде чем перезаписывать `dbfilename`.
- **Путать «открытый порт» и «инъекцию».** Это разные находки с разной доказательной базой.
- **Игнорировать версию.** `db.eval` удалён с MongoDB 4.2, Groovy-скрипты в Elasticsearch — с 1.4.2+; без версии PoC не подобрать.
- **Забыть про аутентификацию по умолчанию.** Cassandra `cassandra:cassandra`, Neo4j `neo4j:neo4j` — их меняют не всегда.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой порт по умолчанию у MongoDB?"
  options:
    - "6379"
    - "27017"
    - "9200"
    - "5984"
  answer: 1
  explanation: "MongoDB слушает 27017; 6379 — Redis, 9200 — Elasticsearch, 5984 — CouchDB."
- question: "Какое хранилище исторически имеет режим admin party (любой пароль подходит)?"
  options:
    - "Memcached"
    - "Redis"
    - "CouchDB"
    - "Cassandra"
  answer: 2
  explanation: "Если в CouchDB нет администраторов, любой запрос считается админским."
- question: "Что означает режим admin party в CouchDB?"
  options:
    - "Сервер требует пароль администратора"
    - "Администраторов нет, и любой запрос выполняется с правами админа"
    - "База доступна только на чтение"
    - "Включён режим только для локальных подключений"
  answer: 1
  explanation: "Отсутствие записи администратора в _users делает все запросы админскими."
- question: "Какое хранилище чаще всего даёт RCE через запись файла на диск?"
  options:
    - "MongoDB"
    - "Memcached"
    - "Redis"
    - "Neo4j"
  answer: 2
  explanation: "Redis через CONFIG SET dir/dbfilename и SAVE пишет webshell, ключи SSH или cron."
- question: "Какая операторная инъекция в MongoDB обходит проверку пароля?"
  options:
    - "UNION SELECT NULL"
    - "password[$ne]=x"
    - "1 OR 1=1"
    - "SLEEP(5)"
  answer: 1
  explanation: "Оператор $ne (не равно) делает условие истинным для любого пароля."
```

## Где пригодится

- **CTF (Web):** NoSQL-задачи почти всегда сводятся к оператору `$ne` или открытому 27017/6379 — определять тип нужно за секунды.
- **Bug bounty:** открытые хранилища и NoSQL-инъекции в API — частый critical; умение отличить одно от другого экономит время отчёта.
- **Пентест:** внешний скан находит десятки портов; быстрый триаж решает, какой урок открыть и какой инструмент взять.
- **Работа (AppSec):** понимание, какие хранилища чем опасны, ложится в чек-лист ревью и hardening (auth, bind на localhost, файрвол).
