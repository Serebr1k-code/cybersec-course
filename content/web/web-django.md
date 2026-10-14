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
estimated_minutes: 45
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
