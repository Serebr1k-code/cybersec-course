---
id: web-frameworks
title: "Серверные фреймворки как поверхность атаки: Laravel, Django, Rails, Spring"
category: web
parent: web-framework-cves
difficulty: hard
order: 5
tags: [framework, laravel, django, rails, spring, deserialization, ssti, cve]
prerequisites: [web-cms-platforms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 60
summary: "Серверные фреймворки (Laravel, Django, Rails, Spring) как цель: почему их баги критичны, типовые классы (deser, SSTI, debug) и методика атаки."
---

## Вопрос, с которого всё начинается

Когда компания пишет свой продукт, она берёт **фреймворк**: Laravel, Django, Rails, Spring. Фреймворк — это не «CMS», его код уникален для продукта, поэтому «готового эксплойта» обычно нет. Зато у фреймворков есть **типовые классы уязвимостей**, которые повторяются из проекта в проект: небезопасная десериализация, инъекция шаблонов, открытый debug-режим. Научившись их распознавать, ты ломаешь не «один сайт», а «класс сайтов». Разберём.

## Что общего у серверных фреймворков

Первое: **они предоставляют механизмы, которые опасны при неверном использовании**. Django сериализует сессии, Rails использует Marshal, Spring — SpEL, Laravel — unserialize. Каждый из этих механизмов при попадании пользовательских данных даёт RCE.

Второе: **они имеют debug-режимы**, которые в проде утекают всё: переменные окружения, SQL-запросы, секреты. Laravel Ignition, Django DEBUG, Rails `better_errors` — классика.

Третье: **у них есть критические CVE**, привязанные к версиям: Laravel Ignition RCE (CVE-2021-3129), Spring Cloud Gateway SpEL (CVE-2022-22947), Spring4Shell (CVE-2022-22965).

## Наш пример: находим Laravel

Цель — `https://app.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://app.target.example
https://app.target.example [200 OK] Laravel, X-Powered-By[PHP/8.1],
  Set-Cookie[laravel_session=...], PHPSESSID
```

Cookie `laravel_session` и `XSRF-TOKEN` — подписи Laravel. Версию определяем по заголовкам/статике или по характерным путям:

```
$ curl -s https://app.target.example/.env -o /dev/null -w '%{http_code}\n'
200
```

`.env` вернул `200` — это **прямая утечка конфига** (частая ошибка). В нём — `APP_KEY`, креды БД, ключи сервисов.

## Шаг 1: Laravel — APP_KEY и Ignition RCE

Два ключевых вектора. Первый — **утечка `APP_KEY`** (из `.env`, бэкапа, git): с ним можно расшифровать/подделать зашифрованные cookie и данные, а иногда — десериализовать payload. Второй — **Ignition RCE (CVE-2021-3129)**: при включённом debug-режиме эндпоинт `_ignition/execute-solution` позволял выполнить код.

```
POST /_ignition/execute-solution
{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
 "parameters":{"variableName":"x","viewFile":"phar://..."}}
```

## Шаг 2: Django — DEBUG, pickle-сессии, ORM

Django-векторы: (1) **DEBUG=True** в проде — утекают настройки, SQL, секреты на страницах ошибок; (2) **pickle-сессии** (если `SESSION_SERIALIZER` — pickle) — при утечке `SECRET_KEY` подделываются и десериализуются; (3) **ORM-инъекции** через `extra()`/raw SQL; (4) SSTI в шаблонах при `|safe`.

## Шаг 3: Rails — Marshal-сессии и secret_key_base

Rails-векторы: (1) **Marshal-сессии** — cookie сериализована через Ruby Marshal; при утечке `secret_key_base` подделывается объект → RCE (гаджеты Ruby); (2) **mass assignment** — передача лишних параметров (например, `admin=true`); (3) **`secret_key_base`** в конфиге/логах.

## Шаг 4: Spring — SpEL и Actuator

Spring-векторы: (1) **SpEL-инъекция** в Gateway/Cloud Function (CVE-2022-22947/22963) — RCE через выражение; (2) **Spring4Shell** (CVE-2022-22965) — RCE через data binding; (3) **Actuator** (`/actuator/env`, `/actuator/heapdump`, `/actuator/jolokia`) — утечка секретов и RCE через Jolokia.

## Шаг 5: методика атаки на фреймворк

1. **Фингерпринт** — фреймворк (cookie, заголовки, пути).
2. **Версия** — точная (заголовки, статика, `composer.json`, `Gemfile.lock`).
3. **Debug/env** — проверка `.env`, `/actuator`, страниц ошибок.
4. **CVE** — сопоставление.
5. **Механизмы** — сессии, десериализация, шаблоны.
6. **Эксплуатация** — при подтверждении.

## Шаг 6: как не навредить

Продуктовые приложения — это бизнес заказчика; их падение = ущерб. Десериализационные payload'ы могут быть деструктивны. Поэтому: сначала утечки (`.env`, debug), затем безопасные проверки, RCE — только при подтверждении и разрешении.

## Что мы теперь знаем

- Фреймворки дают типовые классы: десериализация, SSTI, debug-утечки.
- Laravel: APP_KEY + Ignition RCE; Django: DEBUG + pickle; Rails: Marshal + secret_key_base; Spring: SpEL + Actuator.
- Секреты (`APP_KEY`, `SECRET_KEY`, `secret_key_base`) = подделка/десериализация.
- Версия и механизмы — ключ к эксплуатации.

## Шаг 7: как определить фреймворк точно

Фреймворк выдают cookie, заголовки и служебные файлы. Признаки: Laravel — `laravel_session`, `XSRF-TOKEN`, `.env`; Django — `csrftoken`, `sessionid`, `/admin/`; Rails — `_app_session`, `X-Powered-By: Passenger`, `/assets/`; Spring Boot — `X-Application-Context`, `/actuator`. Проверяй эти маркеры пакетно через `httpx`, а версию уточняй по статике и служебным файлам (`composer.json`, `Gemfile.lock`, `/actuator/info`).

## Шаг 8: почему утечки важнее RCE

В продуктовых приложениях самая ценная находка — не RCE, а **секреты**: `.env`, `SECRET_KEY`, `secret_key_base`, `APP_KEY`, `actuator/env`. С ними можно подделать сессию, войти легитимно, расшифровать данные и часто дойти до RCE без эксплуатации уязвимости. Поэтому начинай с утечек — это дешевле, тише и часто результативнее.

## Шаг 9: как строить отчёт по фреймворку

Укажи: фреймворк и версию (с источником); найденные секреты (маскированно) и какие системы они открывают; применимые CVE; подтверждённые механизмы (debug, сериализация); импакт (данные, доступы). Отдельно — рекомендации: выключить debug, вынести `.env`, ротировать ключи, закрыть Actuator.

## Шаг 10: как расставить приоритеты

Приоритет выше, если приложение обрабатывает чувствительные данные и имеет утечку секретов или debug-режим. Ниже — если это внутренний сервис без данных. Не трать часы на десериализацию, когда рядом лежит открытый `.env`.

## Шаг 11: как связать фреймворк с инфраструктурой

Утечка `.env`/`SECRET_KEY` — это не только доступ к приложению, но и путь в инфраструктуру. В `.env` лежат: креды БД (прямой доступ к данным), SMTP (рассылки от имени компании), облачные ключи (S3, CDN), API-ключи сторонних сервисов. Поэтому после утечки **выпиши все ключи и определи, что каждый открывает** — это карта для дальнейших шагов.

## Шаг 12: почему фреймворковые баги ценнее CMS-багов

CMS-баг известен всем и часто пропатчен. Фреймворковый баг — в уникальном коде продукта, поэтому он «свежий» и менее защищённый. Плюс за продуктовым приложением обычно больше данных и денег. Это значит: фреймворковые цели приоритетнее, но требуют больше разведки (механизмы, секреты) и меньше готовых PoC.

## Шаг 13: как не раскрыться

Продуктовые приложения логируют всё (Sentry, Datadog, SIEM). Ошибки, десериализационные исключения и странные запросы к `.env`/`actuator` попадают в логи и алерты. Поэтому: точечные проверки, без массовых сканов, без очевидных payload'ов в популярных путях.

## Практика: как определить фреймворк за одну минуту

Серверные фреймворки выдают себя заголовками и cookie. Соберём набор признаков:

```
$ curl -sI https://app.target.example | grep -iE 'server|x-powered|set-cookie|x-frame'
Server: nginx
Set-Cookie: laravel_session=...; path=/; HttpOnly
X-Frame-Options: SAMEORIGIN
```

`laravel_session` → Laravel. `django`/`csrftoken` → Django. `_rails_session`/`_target_session` → Rails. `JSESSIONID` + `X-Application-Context` → Spring Boot. Один взгляд на cookie уже сужает круг. Дальше — уникальные пути: Laravel отдаёт `/.env`, Rails — `/rails/info/properties` (в dev), Spring — `/actuator`, Django — `/admin/`.

## Практика: Laravel `.env` и APP_KEY

Самая частая Laravel-находка — открытый `/.env`. Там лежат `APP_KEY`, `DB_PASSWORD`, `MAIL_*`, ключи AWS:

```
$ curl -s https://app.target.example/.env | grep -E 'APP_KEY|DB_'
APP_KEY=base64:xxxxxxxxxxxxxxxxxxxxxxxxxxxx
DB_PASSWORD=s3cr3t
```

`APP_KEY` — это ключ шифрования Laravel. С ним подделываются зашифрованные cookie и значение `remember_me`; в уязвимых версиях Ignition (CVE-2021-3129) — выполняется код. Всё, что нужно, — знать ключ. Поэтому `/.env` — цель номер один на любой Laravel-цели, и его обязательно проверяют первым запросом.

## Практика: Rails и Marshal-сессии

Rails исторически хранит сессию в cookie, сериализованной через `Marshal`, подписанной `secret_key_base`. Если ключ утёк (или слабый), можно сформировать `Marshal`-payload с gadget-цепочкой (`universal deserialization gadget`) и получить RCE. Признак Rails — cookie `_<app>_session` (обычно base64) и заголовок `X-Runtime` в ответе. Проверка `secret_key_base`: ищи в `/rails/info/properties` (dev), в `config/secrets.yml`, в открытом репозитории. Современные Rails (7+) перешли на `JSON`, и старый вектор закрыт — поэтому версию определяй до атаки.

## Практика: Spring Boot Actuator

Spring Boot отдаёт `/actuator` (если не закрыт). Это концентрат утечек:

```
$ curl -s https://app.target.example/actuator/env | head -c 200
{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment",...
```

`/actuator/env` — переменные окружения (пароли БД, токены), `/actuator/heapdump` — дамп памяти с кредами, `/actuator/mappings` — все эндпоинты, `/actuator/httptrace` — последние HTTP-запросы (иногда с токенами). Исторические CVE (Spring4Shell, CVE-2022-22965) дают RCE через `class.module.classLoader` при определённой конфигурации. Actuator — это первый путь, CVE — второй.

## Таблица: фреймворки и их «паспорта»

| Фреймворк | Cookie-признак | Путь-признак | Главная утечка |
|---|---|---|---|
| Laravel | `laravel_session` | `/.env`, `/telescope` | APP_KEY, креды БД |
| Django | `csrftoken`, `sessionid` | `/admin/`, трейсбек | SECRET_KEY |
| Rails | `_*_session`, `X-Runtime` | `/rails/info` | secret_key_base |
| Spring | `JSESSIONID` | `/actuator/*` | env, heapdump |
| Express | `connect.sid` | `/api/` | `.env`, proto-pollution |

## Почему фреймворковые баги ценнее CMS-багов

CMS — это конкретный сайт; фреймворк — это **весь парк приложений компании**, потому что на нём пишут внутренние сервисы, API, админки. Один утёкший `APP_KEY` или открытый `/actuator/env` может открыть не одно приложение, а десяток. Поэтому при аудите сначала смотри на фреймворк, а потом на CMS: ROI выше. И фиксируй в отчёте не «нашёл Laravel», а «`/.env` открыт и отдаёт APP_KEY и пароль БД — доступ к шифрованию cookie и базе».

## Шпаргалка: команды для фреймворков

Соберём быстрый чек-лист в одном месте. Laravel: `curl -s https://host/.env` и `curl -s https://host/telescope`. Django: `curl -s https://host/nonexistent-xyz` (ошибка с DEBUG), `curl -s https://host/admin/`. Rails: `curl -s https://host/rails/info/properties` и проверка cookie `_*_session`. Spring: `curl -s https://host/actuator`, `curl -s https://host/actuator/env`, `curl -s https://host/actuator/heapdump -o heap.bin`. Определение по cookie: `curl -sI https://host | grep -i set-cookie`. Каждую находку (например, открытый `/actuator/env`) фиксируй с точным выводом — это доказательство, а не «похоже, Spring».

## Квиз

Проверь себя.

```quiz
- question: "Что даёт утечка APP_KEY Laravel?"
  options:
    - "Ничего"
    - "Расшифровку/подделку данных и cookie"
    - "Только тему"
    - "Пароль почты"
  answer: 1
  explanation: "Ключ шифрования приложения."
- question: "Чем опасен DEBUG=True в Django?"
  options:
    - "Замедляет сайт"
    - "Утекают настройки, SQL и секреты на страницах ошибок"
    - "Меняет тему"
    - "Ничем"
  answer: 1
  explanation: "Подробные трассировки раскрывают внутренности."
- question: "Через что Rails-сессии могут привести к RCE?"
  options:
    - "Через Marshal и утечку secret_key_base"
    - "Через cookie"
    - "Через robots.txt"
    - "Через sitemap"
  answer: 0
  explanation: "Marshal-десериализация + гаджеты Ruby."
- question: "Что даёт Spring Actuator?"
  options:
    - "Только метрики"
    - "Утечку секретов (env/heapdump) и RCE (Jolokia)"
    - "Только логи"
    - "Ничего"
  answer: 1
  explanation: "Actuator-эндпоинты раскрывают конфиг."
- question: "С чего начинать атаку на фреймворк?"
  options:
    - "С запуска эксплойта"
    - "С фингерпринта и версии"
    - "С перезагрузки"
    - "С дампа БД"
  answer: 1
  explanation: "Фреймворк → версия → CVE."
```

## Куда дальше

Дальше — каждый фреймворк отдельно: Laravel, Django, Rails, Spring. А пока запомни: **фреймворк — это типовые классы; секреты и механизмы сериализации — ключ.**

## Где пригодится

- Bug bounty: продуктовые приложения на фреймворках.
- Пентест: аудит собственных разработок клиента.
- CTF: задания с deser/SSTI фреймворков.
