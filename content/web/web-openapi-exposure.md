---
id: web-openapi-exposure
title: "Утечки Swagger/OpenAPI и debug-страниц"
category: web
parent: web-recon-surface
difficulty: easy
order: 3
tags: [openapi, swagger, recon, debug, api-docs]
prerequisites: [web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 28
summary: "Как находить Swagger/OpenAPI-спецификации и debug-страницы: карта API, скрытые эндпоинты, параметры и схемы."
lab:
  kind: shell
  title: "Практика: утечка OpenAPI/Swagger"
  toolset: [core, curl, ffuf]
  workdir: /home/student/task
  files: [task.md, api_paths.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - Перебери типовые пути спецификации: `ffuf -w api_paths.txt -u http://api.lab.local/FUZZ -mc 200 -s`.
    - Найден путь `/v3/api-docs` — сохрани его: `curl -s http://api.lab.local/v3/api-docs -o api.json`.
    - Спека — одна строка. Ищи необычный маршрут: `grep -o '/internal/[a-z]*' api.json`.
    - Запроси найденный эндпоинт: `curl -s http://api.lab.local/internal/flag`. Флаг — в поле `debug_flag`.
    - Достань флаг: `curl -s http://api.lab.local/internal/flag | cut -d: -f3 > found.txt`, затем `check`.
---

## Вопрос, с которого всё начинается

Ты тестируешь API, но не знаешь ни одного эндпоинта — только домен `api.example`. Фаззить вслепую сотни путей можно часами. Но у команд, которые пишут API, есть привычка оставлять в проде **машинную документацию** — спецификацию OpenAPI.

Спецификация — это не «страница для людей», а файл, который описывает все маршруты, их параметры и схемы. Если он открыт, ты получаешь готовую карту API бесплатно. Сегодня мы найдём такую спеку, вытащим из неё «скрытый» эндпоинт и докажем, что он без авторизации.

## Наш пример

Есть бэкенд на `api.example`. Начнём с перебора типовых путей спецификации — не циклом `curl`, а нормальным фаззером:

```bash
$ printf 'swagger.json\nopenapi.json\napi-docs\nv3/api-docs\nswagger-ui.html\n' > /tmp/api_paths.txt
$ ffuf -w /tmp/api_paths.txt -u https://api.example/FUZZ -mc 200 -s
v3/api-docs
```

Путь `/v3/api-docs` отвечает `200`. Такое имя (с версией `v3`) типично для Spring Boot — значит, перед нами, скорее всего, Java-бэкенд. Забираем файл:

```bash
$ curl -s https://api.example/v3/api-docs -o api.json
$ head -c 120 api.json
{"openapi":"3.0.1","info":{"title":"Shop API","version":"1.4.0"},"paths":{
```

Это и есть **OpenAPI-спецификация** (раньше её называли Swagger) — JSON, описывающий весь API.

## Шаг 1: разбираем спеку в карту путей

Спецификация — это дерево, где ключ `paths` содержит все маршруты. Достаём их через `jq` (утилита для разбора JSON):

```bash
$ jq -r '.paths | keys[]' api.json
/api/v1/products
/api/v1/orders
/api/v1/users/{id}
/api/internal/config
/api/internal/debug/reset
```

Видишь два последних пути с `internal`? Их **нет ни в одном словаре** — они существуют только внутри спеки. Вот почему спека ценнее фаззинга: она показывает именно то, что написали разработчики, включая служебное.

Параметры и типы тоже описаны. Посмотрим на эндпоинт с параметром:

```bash
$ jq -r '.paths["/api/v1/users/{id}"] | keys[]' api.json
get
```

Каждый ключ внутри маршрута (`get`, `post`, `put`, `delete`) — это HTTP-метод, а `{id}` в фигурных скобках — параметр пути. Спека сообщает даже схему тела запроса и коды ответов, поэтому по ней можно заранее понять, какие поля принимает эндпоинт и что он возвращает. Это отличает её от простого списка URL: перед тобой полное описание контракта API.

## Шаг 2: проверяем авторизацию на «скрытом» эндпоинте

Самая частая ошибка разработчиков: «внутренний» путь не защищают, потому что «его же никто не знает». Проверим `/api/internal/config` без токена и с токеном обычного пользователя:

```bash
$ curl -s -o /dev/null -w 'noauth=%{http_code}\n' https://api.example/api/internal/config
noauth=200
$ curl -s https://api.example/api/internal/config
{"db_host":"127.0.0.1","db_user":"api","db_password":"Sup3rS3cret!"}
```

`200` без токена — и в ответе пароль от базы. Это **BFLA** (Broken Function Level Authorization): функция, доступная только администратору, открыта всем. Артефакт-доказательство — строка `db_password` в ответе.

Обрати внимание на разницу: если бы без токена было `401`, а с токеном обычного юзера `200` — это была бы тоже дыра (эскалация прав), просто другого класса.

## Шаг 3: Spring Actuator — если бэкенд на Java

Раз это Spring, проверим Actuator — набор служебных эндпоинтов для мониторинга:

```bash
$ curl -s https://api.example/actuator | jq -r '._links | keys[]'
env
health
heapdump
mappings
```

`env` отдаёт переменные окружения приложения, `mappings` — все маршруты (включая незадокументированные), а `heapdump` — дамп памяти, в котором лежат токены и пароли в открытом виде:

```bash
$ curl -s https://api.example/actuator/env | jq -r '.propertySources[].properties | keys[]' | grep -i pass
spring.datasource.password
```

Если бы приложение было на Spring Cloud Gateway старой версии, `/actuator/gateway/routes` позволял бы подсунуть SpEL-выражение и получить RCE (CVE-2022-22947) — но это уже отдельная история.

## Шаг 4: debug-страницы других фреймворков

Не только Java оставляет «чертежи». Три классики:

**Django** при `DEBUG=True` показывает на любой 404/500 полный стектрейс с настройками. Триггерим ошибку и грепаем:

```bash
$ curl -s "https://api.example/nonexistent'" | grep -iE 'SECRET_KEY|DATABASES'
SECRET_KEY = 'django-insecure-9x8y...'
```

`SECRET_KEY` — ключ подписи сессий; с ним можно подделать cookie пользователя.

**Laravel** с `APP_DEBUG=true` отдаёт страницу Ignition с `APP_KEY` и переменными окружения. **Werkzeug** (Flask) при включённом дебаге открывает **интерактивную консоль** прямо в браузере — это уже полноценное выполнение Python-кода, то есть RCE.

```bash
$ curl -s https://api.example/telescope/requests | head -c 80
<!DOCTYPE html><html ... <title>Laravel Telescope</title>
```

## Шаг 5: автоматизируем поиск

Перебирать пути и разбирать спеки руками быстро надоедает — на этом этапе помогают готовые инструменты.

**`nuclei`** — сканер с шаблонами под конкретные утечки. У него есть теги `exposure`, `swagger`, `actuator`:

```bash
$ nuclei -u https://api.example -tags exposure,swagger,actuator -j -silent | jq -r '.template-id'
swagger-api
spring-boot-actuator-env
```

Каждая строка — подтверждённая находка, которую nuclei уже проверил. Дальше её не нужно перепроверять вручную: достаточно открыть URL и забрать доказательство.

**`kiterunner`** — фаззер именно API-маршрутов: у него словарь не имён файлов, а типичных REST-путей (`/api/v1/users`, `/internal/health`), поэтому он находит эндпоинты там, где обычный `gobuster` молчит.

```bash
$ kr scan https://api.example -w routes.kite --fail-status-codes 404
GET 200 /api/internal/config
```

Наконец, найденную спеку удобно **импортировать** в Postman/Insomnia — они превратят её в коллекцию запросов, и ты сможешь пройти все эндпоинты по очереди, не выписывая каждый `curl` руками.

## Если не сработало

- Спека по типовым путям не нашлась — добавь в словарь `/redoc`, `/docs`, `/.well-known/openapi.json`, `/v2/api-docs`, `/swagger/v1/swagger.json`, `/api/swagger.json`.
- `/actuator` отвечает `401` — попробуй `/actuator/health` (часто открыт), а также `/actuator/env`, `/actuator/info`.
- Спека есть, но пустая или устаревшая — сверь её с реальностью: незадокументированные маршруты (`v1` рядом с `v2`) часто живут и без записи в файле.
- `401` на «внутреннем» пути — это не конец: проверь другие методы (PUT/DELETE), версии (`/api/v2/...`), а также с параметром `?format=json`.

## Что мы теперь знаем

- OpenAPI/Swagger-спецификация — это JSON-карта всех маршрутов, параметров и схем.
- Типовые пути: `/v3/api-docs`, `/openapi.json`, `/swagger.json`, `/api-docs`.
- В спеке бывают «скрытые» пути (`internal`, `admin`, `debug`), которых нет в словарях.
- Найденный эндпоинт проверяют на авторизацию: `200` без токена = BFLA/BOLA.
- Spring Actuator (`env`, `heapdump`, `mappings`) — отдельная золотая жила для Java.
- Debug-режим отдаёт секреты (`SECRET_KEY`, `APP_KEY`), а Werkzeug — прямой RCE.

## На что смотреть дальше

- Не фаззи вслепую, не проверив `/swagger.json` — спека экономит часы.
- `401` на `/actuator` — не тупик: пробуй `/actuator/env` и `/actuator/health`.
- Примеры в спеке (`example`, `default`) иногда содержат **живые токены** — проверяй их.
- Читай debug-стектрейсы: там версии, пути и секреты.
- Аккуратно с `heapdump` и `refresh` — они тяжёлые и могут «уронить» прод.

## Квиз

Проверь себя.

```quiz
- question: "Что даёт найденная OpenAPI/Swagger-спецификация?"
  options:
    - "Пароли администратора напрямую"
    - "Карту всех эндпоинтов, параметров и схем API"
    - "TLS-ключ сервера"
    - "Логи запросов"
  answer: 1
  explanation: "Спека описывает весь API — это готовый «чертёж»."
- question: "Какой путь типичен для Spring-спеки?"
  options:
    - "/swagger"
    - "/v3/api-docs"
    - "/api"
    - "/docs.json"
  answer: 1
  explanation: "Springdoc отдаёт /v3/api-docs."
- question: "Чем опасно `/actuator/env`?"
  options:
    - "Ничем, это мониторинг"
    - "Отдаёт переменные окружения с секретами (пароли БД, ключи)"
    - "Только CSS"
    - "Только картинки"
  answer: 1
  explanation: "Это конфигурация приложения, часто с секретами."
- question: "Найден эндпоинт `/api/internal/config`, он отвечает 200 без токена. Что это?"
  options:
    - "Норма"
    - "BFLA — доступ к административной функции без прав"
    - "XSS"
    - "Ошибка клиента"
  answer: 1
  explanation: "Функция открыта всем — сломанный контроль доступа."
- question: "Что делает `DEBUG=True` в Django на странице ошибки?"
  options:
    - "Ускоряет ответ"
    - "Показывает стектрейс с настройками и SECRET_KEY"
    - "Шифрует вывод"
    - "Кеширует"
  answer: 1
  explanation: "Отладочные страницы раскрывают конфигурацию."
```

## Куда дальше

В следующем уроке мы возьмём другую утечку разведки — **субдомены и их захват** (subdomain takeover): как найти брошенный поддомен, указывающий на несуществующий сервис, и занять его. А пока главное запомни: перед фаззингом всегда ищи спецификацию и debug — иногда весь API уже лежит в одном открытом JSON.

## Где пригодится

- **CTF (Web):** быстрое раскрытие API и секретов без эксплуатации.
- **Bug bounty:** открытые спеки/actuator/debug — частая валидная находка.
- **Пентест:** обязательный шаг разведки API (OWASP API9 — improper inventory).
- **Работа (AppSec/DevOps):** отключение спек, actuator и debug в проде.
