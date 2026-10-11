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
---

Спецификации API (Swagger/OpenAPI) и debug-страницы — это готовый «чертёж» приложения, случайно оставленный в проде. Через `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, `/actuator` можно узнать все эндпоинты, параметры, схемы и внутренние сервисы, а debug-режим (Django `DEBUG=True`, Laravel `APP_DEBUG=true`, Spring Actuator) выдаёт стектрейсы, переменные окружения и иногда секреты. Разведка этих поверхностей часто даёт больше, чем фаззинг wordlist'ом.

## Теория: где лежат спеки и debug

| Артефакт | Типичные пути |
|----------|---------------|
| OpenAPI/Swagger UI | `/swagger-ui.html`, `/swagger-ui/`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs` |
| ReDoc | `/redoc`, `/docs` |
| GraphQL | `/graphql`, `/graphiql`, `/v1/graphql` |
| Spring Actuator | `/actuator`, `/actuator/env`, `/actuator/health`, `/actuator/beans`, `/actuator/mappings` |
| Django debug | любой 404/500 при `DEBUG=True` |
| Laravel debug | `/.env`, ошибка `APP_DEBUG` → Ignition-страница |
| Rails | `/rails/info/routes`, `/rails/info/properties` |
| .NET | `/swagger`, `/swagger/v1/swagger.json` |
| Metrics | `/metrics`, `/prometheus`, `/debug/pprof` |

## Разобранный пример: Swagger → скрытые эндпоинты

Шаг 1 — ищем спеку:

```bash
printf 'swagger.json\nopenapi.json\napi-docs\nv2/api-docs\nv3/api-docs\nswagger-ui.html\n' > /tmp/api_paths.txt
ffuf -w /tmp/api_paths.txt -u https://app.example/FUZZ -mc 200 -s
```

Для широкого поиска берите `ffuf`/`gobuster` + `gobuster_parse` (см. `web-tool-ffuf`), а не цикл `curl`.

Шаг 2 — скачиваем и разбираем:

```bash
curl -s https://app.example/openapi.json -o api.json
jq -r '.paths | keys[]' api.json            # список путей
jq -r '.paths[] | keys[]' api.json | sort -u   # методы
jq -r '.. | .example? // empty' api.json        # примеры (иногда с токенами)
```

Шаг 3 — находим «скрытые» (admin/internal) эндпоинты и тестируем их напрямую: часто они не защищены, потому что «их же никто не знает».

## Разобранный пример: Spring Actuator

Actuator — золотая жила, если открыт:

```bash
curl -s https://app.example/actuator
curl -s https://app.example/actuator/env          # переменные окружения (креды, ключи)
curl -s https://app.example/actuator/beans        # все бины (иногда пароли в пропертях)
curl -s https://app.example/actuator/mappings     # карта эндпоинтов
curl -s https://app.example/actuator/heapdump -o heap.bin   # дамп памяти
curl -s https://app.example/actuator/threaddump
```

`/actuator/env` часто содержит `spring.datasource.password`, API-ключи, `secret_key_base`. В `/actuator/heapdump` ищите токены (можно прогнать `strings heap.bin | grep -i token`). В старых версиях Actuator уязвим к RCE через `/actuator/env` + `/actuator/refresh` (eureka/SpEL) — CVE-2022-22947 (Spring Cloud Gateway).

## Разобранный пример: Django/Laravel debug

Django при `DEBUG=True` показывает на 404/500 полную конфигурацию: `SECRET_KEY`, `DATABASES`, `ALLOWED_HOSTS`, установленные приложения, пути. Триггерим ошибку:

```bash
curl -s "https://app.example/nonexistent'" | grep -iE 'SECRET_KEY|DATABASES|Traceback'
```

Laravel с `APP_DEBUG=true` отдаёт Ignition-страницу с `APP_KEY`, env-переменными и (в старых версиях, CVE-2021-3129) RCE через логи/файлы. Ищем:

```bash
curl -s "https://app.example/nonexistent" | grep -iE 'APP_KEY|APP_ENV|Ignition'
```

## Инструменты

- **`curl` + `jq`** — вытягивание путей и примеров.
- **`ffuf`/`gobuster`** — поиск спекулятивных путей (`gobuster_parse`).
- **`nuclei`** — теги `swagger`, `actuator`, `exposure` (`nuclei_parse`).
- **`kiterunner`** — фаззинг API по «словарю» маршрутов.
- **`Postman`/`Insomnia`** — импорт OpenAPI и быстрый обход всех эндпоинтов.

## Что делать с найденным

- Пройтись по всем путям спеки: искать admin/internal/debug, IDOR, mass-assignment.
- Из примеров (`example`, `default`) вытащить токены/ключи и попробовать их.
- Из Actuator/env — креды к БД/облаку; из heapdump — сессии/токены.
- Из debug-страницы — `SECRET_KEY` (подделка сессий Django), `APP_KEY` (Laravel deser).
- Сопоставить спеки с реальностью: незадокументированные эндпоинты = частые дыры.

## Что дальше / decision

1. Нашли `openapi.json`/`swagger.json` → импортируйте, пройдите все пути.
2. Открыт Actuator → `/actuator/env`, `/heapdump`, `/mappings`.
3. Debug включён → вытащите `SECRET_KEY`/`APP_KEY` → подделка сессий/deser.
4. GraphQL открыт → introspection, затем batching/IDOR (см. `web-graphql-deep`).
5. Дальше — связать находки с другими векторами (JWT, deser, SSRF).

## Частые ошибки

- **Фаззить вслепую, не проверив `/swagger.json`.** Спека экономит часы.
- **Считать 401 на `/actuator` тупиком.** Пробуйте `/actuator/env`, `/actuator/health`.
- **Игнорировать примеры в спеке.** Там бывают живые токены.
- **Не читать debug-стектрейсы.** В них — пути, версии, секреты.
- **Ломать прод.** Actuator/refresh и heapdump — аккуратно.

## Полный список мест, где лежат спеки и дебаг

| Путь | Что отдаёт |
|------|-----------|
| `/swagger-ui.html`, `/swagger-ui/` | UI Swagger |
| `/v2/api-docs`, `/v3/api-docs` | OpenAPI JSON |
| `/swagger.json`, `/openapi.json` | спека |
| `/api-docs` | спека (NestJS и др.) |
| `/.well-known/openapi.json` | спека |
| `/graphql`, `/graphiql` | GraphQL + IDE |
| `/actuator`, `/actuator/env`, `/actuator/heapdump` | Spring Boot |
| `/debug`, `/__debug__` | отладка (Django/Flask) |
| `/telescope` | Laravel debug |
| `/server-status`, `/server-info` | Apache |
| `/.env`, `/config.json` | конфиги |

```bash
# перебор типовых путей
ffuf -u https://app.example/FUZZ -w api_paths.txt -mc 200,401,403
# проверка конкретных
for p in /swagger-ui/ /v2/api-docs /openapi.json /actuator/env; do
  printf '%-20s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' https://app.example$p)"
done
```

## Spring Actuator: что искать

| Endpoint | Риск |
|----------|------|
| `/actuator/env` | переменные окружения, креды |
| `/actuator/heapdump` | дамп памяти (токены, пароли) |
| `/actuator/health` | информация о БД |
| `/actuator/mappings` | все маршруты |
| `/actuator/configprops` | конфигурация |
| `/actuator/loggers` | смена уровня логов |
| `/actuator/threaddump` | состояние потоков |
| `/actuator/gateway/routes` | SSRF-риск (gateway) |

```bash
curl -s https://app.example/actuator/env | jq '.["propertySources"]'
curl -s https://app.example/actuator/heapdump -o heap.bin
strings heap.bin | grep -iE 'password|token|secret' | head
```

## Разобранный пример: Swagger → скрытые эндпоинты

```bash
# 1) находим спеку
curl -s https://app.example/v3/api-docs -o api.json
# 2) извлекаем все пути
jq -r '.paths | keys[]' api.json
# 3) ищем админские/отладочные
jq -r '.paths | keys[]' api.json | grep -iE 'admin|internal|debug|test'
# 4) вызываем найденный «скрытый» эндпоинт
curl -s https://app.example/api/internal/users
```

Спека — это карта API с параметрами и схемами; она экономит часы разведки.

## Разобранный пример: debug-страницы

```bash
# Django DEBUG=True -> traceback с настройками
curl -s 'https://app.example/trigger-error' | grep -iE 'SECRET_KEY|DATABASE'
# Laravel Telescope
curl -s https://app.example/telescope/requests
# Flask/Werkzeug debugger -> интерактивная консоль (RCE)
curl -s 'https://app.example/?__debugger__=yes&cmd=...'
```

Debug-консоль Werkzeug — прямой путь к RCE: она позволяет выполнять Python-код.

## Что делать с найденным

```text
1) собрать все пути из спеки
2) проверить авторизацию на каждом (BOLA/BFLA)
3) проверить «скрытые» параметры и версии API (v1/v2)
4) найти дефолтные креды в конфигах
5) извлечь секреты из heapdump/env
```

```bash
# проверка авторизации найденного эндпоинта
curl -s https://app.example/api/internal/users -o /dev/null -w '%{http_code}\n'   # без токена
curl -s https://app.example/api/internal/users -H 'Authorization: Bearer <user>' -o /dev/null -w '%{http_code}\n'
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `ffuf`/`gobuster` | перебор путей |
| `jq` | разбор спеки |
| `nuclei` | шаблоны exposure/actuator |
| `swagger-cli` | валидация/разбор |
| `kiterunner` | перебор API-маршрутов |

```bash
nuclei -u https://app.example -tags exposure,swagger,actuator -j | tee expo.json
kiterunner scan https://app.example -w routes.kite
```

## Что делать дальше / решение

1. **Переберите пути.** Спеки, actuator, debug.
2. **Разберите спеку.** Все маршруты и параметры.
3. **Проверьте авторизацию.** BOLA/BFLA на найденных эндпоинтах.
4. **Извлеките секреты.** env/heapdump/конфиги.
5. **Проверьте debug-консоль.** RCE через Werkzeug.
6. **Зафиксируйте PoC.** Доступ к данным/секретам/команде.

## Практика и справочники

- **HackTricks** — «Swagger», «Spring Actuator».
- **OWASP API Security Top 10** — API9 (improper inventory).
- **nuclei** — exposure-шаблоны.
- **kiterunner** — перебор API.

## Приоритеты при поиске exposure

Начните с перебора типовых путей (`/swagger-ui/`, `/v3/api-docs`, `/openapi.json`, `/actuator/env`). Затем разберите найденную спеку и извлеките все маршруты — это карта API. Проверьте авторизацию на каждом найденном эндпоинте (часто «внутренние» пути не защищены). Отдельно проверьте debug-страницы: Werkzeug-консоль даёт прямой RCE, Django DEBUG — утечку настроек и секретов, Laravel Telescope — историю запросов. Наконец, извлеките секреты из `env`/`heapdump`.

## Кратко

1. Перебор путей (спеки, actuator, debug).
2. Разбор спеки → все маршруты.
3. Проверка авторизации (BOLA/BFLA).
4. Извлечение секретов (env/heapdump).
5. Debug-консоль → RCE.
6. PoC — доступ к данным/секретам.

## Практика

- **HackTricks** — Swagger, Spring Actuator.
- **OWASP API Top 10** — API9.
- **kiterunner** — перебор API.

## Расширенный разбор: как использовать найденную спеку

Найденная OpenAPI-спека — это не «файл ради файла», а рабочая карта. Из неё извлекаются: список всех маршрутов (включая версии `v1`/`v2` и внутренние), схемы параметров (типы, обязательность, форматы), коды ответов и примеры. Дальше по каждому маршруту проверяется авторизация: часто «внутренние» пути (`/internal/`, `/admin/`, `/debug/`) вообще не защищены или проверяют только факт наличия токена, но не роль. Отдельно ищите параметры, помеченные как deprecated, и «скрытые» версии API, которые остались в проде.

```bash
# извлекаем маршруты и параметры
jq -r '.paths | to_entries[] | .key + " " + (.value|keys|join(","))' api.json
# ищем внутренние
jq -r '.paths | keys[]' api.json | grep -iE 'internal|admin|debug|v1'
# проверяем найденный эндпоинт без токена и с токеном обычного пользователя
curl -s -o /dev/null -w 'noauth=%{http_code}\n' https://app.example/api/internal/config
curl -s -H 'Authorization: Bearer <user>' -o /dev/null -w 'user=%{http_code}\n' https://app.example/api/internal/config
```

Разница в кодах (200 без токена или 200 с пользовательским токеном на админском маршруте) — прямое доказательство BFLA/BOLA.

## Квиз

```quiz
- question: "Что даёт OpenAPI/Swagger-спецификация?"
  options:
    - "Пароли"
    - "Карту всех эндпоинтов, параметров и схем API"
    - "TLS-ключ"
    - "Логи"
  answer: 1
  explanation: "Полная документация API."
- question: "Какой стандартный путь у Spring-спеки?"
  options:
    - "/swagger"
    - "/v3/api-docs"
    - "/api"
    - "/docs.json"
  answer: 1
  explanation: "Springdoc отдаёт /v3/api-docs."
- question: "Что опасного в /actuator/env?"
  options:
    - "Ничего"
    - "Переменные окружения с секретами (пароли БД, ключи)"
    - "CSS"
    - "Картинки"
  answer: 1
  explanation: "Раскрывает конфигурацию."
- question: "Что делает DEBUG=True в Django?"
  options:
    - "Ускоряет"
    - "Показывает трассировки с настройками и SECRET_KEY"
    - "Шифрует"
    - "Кеширует"
  answer: 1
  explanation: "Полные отладочные страницы."
- question: "Какой инструмент фаззит API по роутам?"
  options:
    - "sqlmap"
    - "kiterunner"
    - "hashcat"
    - "john"
  answer: 1
  explanation: "Kiterunner для API-роутов."
```

## Где пригодится

- **CTF (Web):** быстрое раскрытие API.
- **Bug bounty:** скрытые эндпоинты и утечки — частая находка.
- **Пентест:** первичная разведка API.
- **Работа (AppSec/DevOps):** отключение спек/debug/actuator в проде.
