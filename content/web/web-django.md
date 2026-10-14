---
id: web-django
title: "Django: DEBUG-утечки, pickle-сессии и ORM-инъекции"
category: web
parent: web-frameworks
difficulty: medium
order: 2
tags: [django, python, debug, pickle, session, orm, ssti, secret-key]
prerequisites: [web-frameworks]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 65
summary: "Django как цель: утечки через DEBUG, подделка и десериализация pickle-сессий при утечке SECRET_KEY, ORM-инъекции и SSTI."
---

## Вопрос, с которого всё начинается

Django — главный Python-фреймворк: на нём пишут внутренние панели, API, дашборды. Django сам по себе безопаснее многих, но три вещи ломают его регулярно: **DEBUG=True в проде** (утечка всего), **pickle-сессии** (десериализация при утечке ключа) и **неаккуратный ORM/SQL**. Разберём.

## Наш пример: Django-приложение

Цель — `https://app.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://app.target.example
https://app.target.example [200 OK] Django, Python, Set-Cookie[csrftoken=...; sessionid=...]
```

Cookie `csrftoken` и `sessionid` — признаки Django. Проверяем debug-режим, вызвав ошибку:

```
$ curl -s https://app.target.example/nonexistent-page-xyz/ | grep -io 'DisallowedHost\|Traceback\|DEBUG = True'
DEBUG = True
```

Если видим `DEBUG = True` — Django в проде с включённым отладчиком. Это катастрофа: на страницах ошибок утекают настройки, SQL, пути и иногда секреты.

## Шаг 1: что утекает через DEBUG

При DEBUG=True Django показывает полную трассировку: SQL-запросы (с параметрами), настройки (включая `SECRET_KEY`, креды БД, API-ключи), список URL, версии библиотек. Этого достаточно, чтобы построить всю карту приложения и забрать секреты.

## Шаг 2: pickle-сессии и SECRET_KEY

По умолчанию Django сериализует сессии через JSON, но многие проекты включают `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'`. Тогда cookie `sessionid` — это подписанный **pickle**. Если утёк `SECRET_KEY` (из DEBUG или конфига), можно подписать свой pickle с гаджетом → **RCE** при десериализации.

Инструмент — `django-session-forge` / ручная сборка pickle.

## Шаг 3: ORM-инъекции и SSTI

Django ORM безопасен при использовании, но опасен при `extra()`, `raw()`, `RawSQL` с f-строками — там SQLi. Плюс шаблоны Django: если пользовательский ввод рендерится через `Template()` или помечен `|safe`, возможен **SSTI** (в Django-шаблонах ограничен, но через `{% debug %}`/`{% load %}` бывает полезен).

## Шаг 4: план атаки на Django

1. Фингерпринт (`csrftoken`, `sessionid`).
2. Проверка DEBUG (вызвать ошибку).
3. Утечка `SECRET_KEY` и настроек.
4. Проверка типа сессии (pickle?).
5. Подделка/десериализация сессии.
6. Пост-эксплуатация — БД, RCE.

## Шаг 5: как не навредить

Django-приложение — продукт. Подделка сессии меняет данные; десериализация может выполнить код. Поэтому: сначала утечки (DEBUG), потом безопасные проверки, эксплуатация — при подтверждении и разрешении.

## Шаг 6: чек-лист по Django

1. Cookie `csrftoken`/`sessionid`.
2. DEBUG-режим.
3. `SECRET_KEY` и настройки.
4. Тип сериализации сессии.
5. ORM/SQLi (`extra`, `raw`).
6. Сопоставление с CVE.

## Что мы теперь знаем

- Django узнаётся по `csrftoken`/`sessionid`.
- DEBUG=True утекает настройки, SQL и секреты.
- Pickle-сессии + утечка `SECRET_KEY` = RCE.
- ORM-инъекции — через `extra`/`raw`.
- Шаблоны опасны при `|safe`/`Template()`.

## Шаг 7: как использовать SECRET_KEY Django

С `SECRET_KEY` можно: (1) подписать произвольную сессию (если `SESSION_SERIALIZER` — pickle, то с гаджетом → RCE); (2) подделать подписанные cookie/токены; (3) обойти CSRF-проверки. Порядок: извлеки ключ из DEBUG-страницы/конфига, сформируй нужный сессионный объект, подпиши его тем же алгоритмом (`django.core.signing`), подставь cookie. Так утечка ключа = вход/повышение прав.

## Шаг 8: типовые ошибки при работе с Django

Ошибка первая — не проверить DEBUG (это первое, что стоит сделать). Вторая — считать сессию JSON по умолчанию (в проектах часто pickle). Третья — гнать SQLi там, где ORM параметризован. Четвёртая — забыть про `/admin/` (иногда открыт с дефолтными кредами).

## Шаг 9: как защититься от Django-атак

Защита: `DEBUG=False` в проде; `ALLOWED_HOSTS`; JSON-сериализация сессий; ротация `SECRET_KEY`; параметризованный ORM. Для атакующего: защищённый Django закрывает DEBUG и pickle, и остаются прикладные баги (SSTI, IDOR, SQLi в raw).

## Шаг 10: как связать Django с инфраструктурой

Настройки Django (видимые в DEBUG) содержат: `DATABASES` (креды БД), `CACHES` (Redis/Memcached), `EMAIL_*`, `AWS_*`, `STRIPE_*` и т.п. Плюс `SECRET_KEY`. С этими данными можно подключиться к БД напрямую (в обход приложения), читать кэш, слать письма, обращаться к платёжным API. Поэтому DEBUG-утечка — это не «ошибка конфигурации», а компрометация.

## Шаг 11: как безопасно проверить pickle-сессию

Сначала определи тип сериализации: возьми cookie `sessionid`, посмотри, начинается ли после base64-декодирования с `.` (подпись) и содержит ли pickle-маркеры (`\x80\x04`). Если да — сессия pickle. Проверяй подделку **только на своём пользователе** и с безобидным эффектом (например, смена имени), не создавая RCE без разрешения.

## Шаг 12: как искать Django-цели и оценивать их

Django-приложения выдают cookie `csrftoken`/`sessionid` и характерный `/admin/`. Оценивай: включён ли DEBUG (вызови ошибку), открыт ли `/admin/` с дефолтными кредами, какая версия. Если DEBUG включён — цель высокоприоритетная: утечка настроек почти гарантирована.

## Шаг 13: как оформить находку по Django

В отчёте: версия Django; факт DEBUG=True (с доказательством — трассировкой); утёкшие настройки (SECRET_KEY, креды БД, ключи); тип сессии (pickle?); подтверждение подделки (если применимо). Рекомендации: `DEBUG=False`, JSON-сессии, ротация SECRET_KEY, параметризованный ORM.

## Шаг 14: почему Django-админка — отдельная цель

`/admin/` Django по умолчанию доступна и часто остаётся с дефолтными кредами (`admin/admin`) или со слабым паролем. Это дешёвый путь: вход в админку даёт управление всеми моделями. Проверяй `/admin/` на каждой Django-цели — это первое, что стоит сделать после фингерпринта.

## Практика: вытаскиваем всё из DEBUG-страницы

Django с `DEBUG = True` на продакшене — это подарок. При любой ошибке отдаётся трейсбек с **настройками**: `SECRET_KEY`, `DATABASES` (пароль к БД), `ALLOWED_HOSTS`, `EMAIL_*`, переменные окружения. Спровоцируем ошибку и посмотрим:

```
$ curl -s "https://app.target.example/?id=1'" | grep -oE 'SECRET_KEY[^<]{0,120}'
SECRET_KEY = 'django-insecure-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
```

`django-insecure-` в префиксе — прямой признак, что ключ сгенерирован автоматически и никогда не менялся. Это значит: подпись сессий, CSRF-токенов и сброса пароля скомпрометирована.

## Практика: подписываем свою сессию

Django по умолчанию хранит сессию в cookie `sessionid`, подписанной `SECRET_KEY` (фреймворк `django.contrib.sessions`). Если ключ утёк, ты генерируешь валидную сессию любого пользователя:

```python
from django.core.signing import TimestampSigner, dumps
signer = TimestampSigner(key='django-insecure-xxxx')
# формируем значение сессии, где _auth_user_id = 1 (суперпользователь)
```

На практике проще использовать `django-session-forge` или `flask-unsign`-подобные утилиты для Django. Результат — cookie `sessionid`, с которой браузер заходит как `admin`, не зная пароля. Это тот же принцип, что подделка WordPress-cookie, и он показывает: **утечка ключа = полный захват аутентификации**.

## Практика: pickle-сессии

Если сессии хранятся в БД/кэше, но данные сериализуются через `pickle` (например, `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'`), то подделанная сессия может содержать pickle-payload. При `unserialize` он выполняет произвольный код. Это редкая, но смертельная конфигурация: достаточно доступа к записи сессии, чтобы получить RCE. Проверяется через `python3 -c "import django; ..."` — читаем настройку `SESSION_SERIALIZER` из утечки DEBUG.

## Практика: ORM-инъекции и SSTI в шаблонах

Django ORM защищает от SQLi, если использовать параметры. Но `extra()`, `raw()` и `RawSQL()` позволяют вставить непроверенный SQL. Шаблоны Django (`DTL`) в целом безопасны (нет выполнения Python), но `{{ ... }}` с пользовательскими фильтрами и сторонними тегами иногда даёт утечки (`{{ settings.SECRET_KEY }}`, если в контекст попадает `settings`). Проверяй `{{ 7*7 }}` — если увидишь `49`, значит шаблонизатор вычисляет выражения (это уже не DTL, а Jinja2 — типичная ошибка конфигурации).

## Таблица: где в Django искать дыру

| Признак | Где смотреть | Что даёт |
|---|---|---|
| `DEBUG=True` | страница ошибки | SECRET_KEY, креды БД |
| `PickleSerializer` | `SESSION_SERIALIZER` | RCE через сессию |
| `.raw()`/`extra()` | исходники вьюх | SQLi |
| Jinja2 вместо DTL | `{{ 7*7 }}` → 49 | SSTI → RCE |
| `django-insecure-` | утечка ключа | подделка сессии |
| открытый `/admin/` | админка | перебор/сброс |

## Как защититься (и что рекомендовать клиенту)

В отчёте по Django всегда давай конкретные рекомендации: `DEBUG = False` на проде; `SECRET_KEY` из переменных окружения и ротация после утечки; `SESSION_SERIALIZER` — только JSON; запрет `raw()`/`extra()` без параметризации; `ALLOWED_HOSTS` строго перечислен; админка за VPN или с MFA. Отдельно подчеркни: **если SECRET_KEY утёк, смена паролей не помогает** — нужно немедленно ротировать ключ и инвалидировать все сессии, иначе злоумышленник продолжит входить с подделанной cookie.

## Практика: GraphQL/DRF и утечка через API-схему

Современный Django почти всегда идёт с Django REST Framework (DRF) или Graphene. DRF отдаёт browsable API по умолчанию — `/api/` с формами и схемой. Если включён `DEFAULT_AUTHENTICATION_CLASSES` с `SessionAuthentication`, а `permission_classes` забыли, любой эндпоинт доступен анонимно. Проверяй так: `curl -s https://app.target.example/api/` — если видишь список маршрутов, это утечка. Graphene отдаёт интроспекцию (`{__schema{queryType{fields{name}}}}`) — полная карта API. Отдельно ищи `/api/schema/` и `/api/docs/` (drf-spectacular) — там описаны все поля и типы, включая внутренние ID. Это идеальная база для IDOR и mass-assignment: зная точные имена полей, ты отправляешь лишние (например, `is_staff: true`) и проверяешь, применит ли их сериализатор.

## Шпаргалка: команды для быстрой проверки Django

Быстрый чек-лист в одной таблице. Признак фреймворка: cookie `csrftoken` и `sessionid`, заголовок `X-Frame-Options: DENY`, ответ `Server: WSGIServer` (dev) или `gunicorn`. Ошибка с трейсбеком: `curl -s https://host/nonexistent-path-123` — если видишь страницу `DisallowedHost` или трейсбек, значит `DEBUG=True`. Ключ: `grep -oE "SECRET_KEY[^<]{0,120}"` по телу ошибки. Админка: `curl -s -o /dev/null -w '%{http_code}' https://host/admin/`. API: `curl -s https://host/api/` (DRF browsable) и `curl -s https://host/graphql -d '{"query":"{__schema{types{name}}}"}'`. Все результаты — в отчёт с точной командой. Если `DEBUG=True` подтверждён, это уже находка уровня high независимо от того, удалось ли подделать сессию.

## Квиз

Проверь себя.

```quiz
- question: "По каким cookie узнаётся Django?"
  options:
    - "csrftoken и sessionid"
    - "laravel_session"
    - "JSESSIONID"
    - "OCSESSID"
  answer: 0
  explanation: "Стандартные cookie Django."
- question: "Что утекает при DEBUG=True?"
  options:
    - "Только тема"
    - "Настройки, SQL, SECRET_KEY, версии"
    - "Ничего"
    - "Только логи"
  answer: 1
  explanation: "Полные трассировки на страницах ошибок."
- question: "Что даёт pickle-сессия + утечка SECRET_KEY?"
  options:
    - "XSS"
    - "RCE при десериализации"
    - "CSRF"
    - "Ничего"
  answer: 1
  explanation: "Можно подписать свой pickle с гаджетом."
- question: "Через что в Django возможна SQLi?"
  options:
    - "Через extra()/raw() с f-строками"
    - "Через cookie"
    - "Через robots.txt"
    - "Через sitemap"
  answer: 0
  explanation: "Сырой SQL без параметризации."
- question: "Когда Django-шаблоны опасны?"
  options:
    - "При |safe или Template() с вводом"
    - "Всегда"
    - "Никогда"
    - "Только в админке"
  answer: 0
  explanation: "Непроверенный ввод в шаблоне."
```

## Куда дальше

Дальше — Rails и его Marshal-сессии. А пока запомни: **в Django DEBUG — это катастрофа, а pickle + SECRET_KEY — это RCE.**

## Где пригодится

- Пентест внутренних панелей на Django.
- Bug bounty: Python-приложения.
- CTF: задания с pickle/DEBUG.
