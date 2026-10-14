---
id: web-rails
title: "Ruby on Rails: mass assignment, Marshal-сессии и secret_key_base"
category: web
parent: web-frameworks
difficulty: hard
order: 3
tags: [rails, ruby, marshal, deserialization, mass-assignment, secret-key-base, rce]
prerequisites: [web-frameworks]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 85
summary: "Rails как цель: mass assignment, Marshal-десериализация сессий при утечке secret_key_base и путь к RCE через Ruby-гаджеты."
---

## Вопрос, с которого всё начинается

Ruby on Rails — фреймворк, на котором построены GitHub, Shopify, Basecamp. Его безопасность опирается на **`secret_key_base`** — ключ, которым подписываются cookie и сессии. Если ключ утёк, а сессии сериализуются через **Marshal**, атакующий подписывает свой Ruby-объект и получает RCE. Плюс классика — **mass assignment**. Разберём.

## Наш пример: Rails-приложение

Цель — `https://app.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://app.target.example
https://app.target.example [200 OK] Ruby on Rails, Set-Cookie[_target_session=...], X-Powered-By[Phusion Passenger]
```

Cookie `_<app>_session` и заголовки `X-Powered-By: Phusion Passenger` — признаки Rails. Версию определяем по статике (`/assets/`, `Gemfile.lock` если доступен) или по эндпоинтам.

## Шаг 1: mass assignment

Rails позволяет создавать/обновлять модели из параметров. Если разработчик не ограничил поля (`permit`), клиент может прислать лишнее:

```
POST /users
user[name]=attacker&user[email]=a@b.c&user[admin]=true
```

Если `admin` не отфильтрован — пользователь становится админом. Это классический **mass assignment** (в старых Rails — до Strong Parameters).

## Шаг 2: Marshal-сессии и secret_key_base

Rails может сериализовать сессию через **Marshal** (cookie `_app_session`). Cookie подписана `secret_key_base`. Если ключ утёк (из конфига, `SECRET_KEY_BASE` в env, логов, git), можно подписать произвольный Marshal-объект. При десериализации сработает **Ruby gadget chain** — RCE.

Инструмент — `rails-secret-key-base` + публичные Ruby-гаджеты (например, через `Universal Deserialisation Gadget` для Rails).

## Шаг 3: где утекает secret_key_base

Ключ лежит в `config/secrets.yml`, `config/credentials.yml.enc` (зашифрован master key), переменной `SECRET_KEY_BASE`, иногда в `config/initializers/secret_token.rb` (старые версии). Утечка — через git-историю, бэкапы, `config/` при path traversal, логи.

## Шаг 4: план атаки на Rails

1. Фингерпринт (cookie `_app_session`, Passenger).
2. Версия Rails.
3. Проверка mass assignment.
4. Поиск `secret_key_base`.
5. Проверка типа сессии (Marshal?).
6. Подделка/десериализация → RCE.

## Шаг 5: как не навредить

Rails-приложение — продукт. Подделка сессии меняет данные; десериализация выполняет код. Поэтому: сначала масс-ассайнмент-проверки (безопасно), потом утечки, эксплуатация — при подтверждении и разрешении.

## Шаг 6: чек-лист по Rails

1. Cookie `_app_session`.
2. Версия Rails.
3. Mass assignment (`permit`).
4. `secret_key_base`.
5. Тип сериализации сессии (Marshal).
6. Сопоставление с CVE.

## Что мы теперь знаем

- Rails узнаётся по `_app_session` и Passenger.
- Mass assignment — передача лишних полей (`admin=true`).
- Marshal-сессия + утечка `secret_key_base` = RCE.
- Ключ утекает из конфига/env/git.
- Ruby-гаджеты превращают десериализацию в код.

## Шаг 7: как использовать secret_key_base

С `secret_key_base` можно подписать произвольный Marshal-объект (если сессия Marshal) и добиться RCE через Ruby-гаджет. Порядок: извлеки ключ, собери гаджет-цепочку (публичные Ruby-гаджеты для Rails), сформируй cookie, подпиши тем же алгоритмом и отправь. Так утечка ключа = RCE.

## Шаг 8: типовые ошибки при работе с Rails

Ошибка первая — не проверить mass assignment (это дешёвый и частый баг). Вторая — считать cookie безопасной (если Marshal + ключ утёк — нет). Третья — игнорировать `credentials.yml.enc` (там могут быть ключи). Четвёртая — забыть про историю git (ключи в старых коммитах).

## Шаг 9: как защититься от Rails-атак

Защита: Strong Parameters (только разрешённые поля); JSON-сериализация сессий вместо Marshal; ротация `secret_key_base`; защита `credentials`. Для атакующего: защищённый Rails закрывает mass assignment и Marshal-вектор, и остаются прикладные баги.

## Шаг 10: как связать Rails с инфраструктурой

Rails-конфиг (`config/database.yml`, `credentials.yml.enc`, env) содержит креды БД, Redis, облака и сторонних API. `secret_key_base` даёт подделку сессий, а креды БД — прямой доступ к данным. Поэтому после утечки конфига — перечисли всё и проверь, что открывает каждый ключ.

## Шаг 11: как безопасно проверить Marshal-сессию

Возьми cookie `_app_session`, base64-декодируй и посмотри на структуру (Marshal начинается с `\x04\x08`). Если это Marshal — можно подписать объект. Проверяй на **своём** пользователе и с безобидным эффектом (например, смена id), прежде чем строить RCE-гаджет. И только с разрешения — полноценную цепочку.

## Шаг 12: как искать Rails-цели и оценивать их

Rails-приложения выдают cookie `_app_session` и `X-Powered-By: Passenger`. Оценивай: версию, наличие mass assignment, доступность конфигов (`config/`), тип сессии. Если `secret_key_base` утёк — цель критическая: это RCE.

## Шаг 13: как оформить находку по Rails

В отчёте: версия Rails; подтверждение mass assignment (создание админа); утёкший `secret_key_base` (маскированно); тип сессии (Marshal?); подтверждение подделки. Рекомендации: Strong Parameters, JSON-сессии, ротация ключа, защита credentials.

## Шаг 14: почему Rails-цели редки, но ценны

Rails-приложений меньше, чем PHP/Python, но за ними часто крупные продукты (SaaS, маркетплейсы) с большим импактом. Плюс баги в Rails (Marshal, mass assignment) дают прямой путь к RCE/админу. Поэтому Rails-цель стоит времени, если она встретилась.

## Практика: фингерпринт Rails

Rails определяют по cookie и заголовкам:

```
$ curl -sI https://app.target.example | grep -iE 'set-cookie|x-runtime|server'
Set-Cookie: _app_session=...; path=/; HttpOnly
X-Runtime: 0.034512
```

`_<app>_session` и `X-Runtime` — признаки Rails. В dev-режиме открыт `/rails/info/properties` (версии, пути, конфиг), а `/rails/info/routes` показывает все маршруты. Версию Rails достаём из `/rails/info/properties` или из заголовка `X-Runtime` + `Server: Puma`. Точная версия критична: старые Rails (<5.2) уязвимы к `Marshal`-десериализации, новые (7+) используют JSON и от этого вектора защищены.

## Практика: Marshal-сессии и secret_key_base

Rails до 5.2 хранил сессию как `Marshal`-объект, подписанный `secret_key_base`. Если ключ утёк (из `/rails/info/properties`, `config/secrets.yml`, открытого репозитория или `.env`), можно сформировать `Marshal`-payload с gadget-цепочкой (`universal deserialization gadget` для Ruby) и получить RCE. Проверка: убедиться, что cookie декодируется в `Marshal`-структуру (начинается с `\x04\x08` после base64) и что версия Rails < 5.2. Только после этого — payload.

## Практика: сильные параметры и mass-assignment

Rails-контроллеры используют `params.require(...).permit(...)`. Ошибка в `permit` (например, разрешён `:admin` или `:role`) даёт mass-assignment: отправляешь лишнее поле и повышаешь себе права. Проверяется так: на форме регистрации/профиля отправь `user[role]=admin` или `user[is_admin]=1` и проверь результат. Это частая находка в Rails-приложениях и не требует ни CVE, ни специальных инструментов — только понимание модели.

## Практика: SSRF и открытые эндпоинты

Rails-приложения часто имеют функции импорта/вебхуков (как Ghost). Проверяй параметры, принимающие URL, — они дают SSRF. Также ищи `/rails/info` и `/rails/mailers` в dev-конфигурации: `/rails/mailers` показывает письма (иногда с токенами сброса пароля). Перебор: `ffuf -u https://app/FUZZ -w <rails-paths>` по списку `rails/info`, `rails/mailers`, `rails/conductor`.

## Таблица: Rails-векторы

| Вектор | Условие | Уязвимые версии | Что даёт |
|---|---|---|---|
| Marshal deserialization | утечка `secret_key_base` | <5.2 | RCE |
| Mass-assignment | ошибка `permit` | все | повышение прав |
| `/rails/info` открыт | dev-конфиг | все | утечка конфигов |
| `/rails/mailers` | dev-конфиг | все | письма, токены |
| SSRF | функции импорта | все | внутренняя сеть |

## Как выстроить работу и как оформить

Порядок: фингерпринт (cookie, `X-Runtime`) → проверка dev-путей (`/rails/info/properties`, `/rails/mailers`) → определение версии Rails → при <5.2 и утечке ключа — Marshal-вектор → параллельно проверка mass-assignment на формах. Rails-приложения часто «чистые» по CVE, поэтому основная ценность — в конфигурационных утечках и логике. В отчёте фиксируй версию, технику, артефакт и рекомендации: `config.force_ssl`, отключить dev-роуты на проде, ротация `secret_key_base`, строгий `permit`.

## Шпаргалка: команды для Rails

Быстрый набор. Признак: `curl -sI https://host | grep -iE '_session|x-runtime'`. Dev-пути: `/rails/info/properties`, `/rails/info/routes`, `/rails/mailers`. Версия Rails: из `/rails/info/properties` (строка `Rails version`). Проверка Marshal: декодировать cookie `_*_session` из base64 и посмотреть, начинается ли с `\x04\x08` (Marshal) или с `{` (JSON). Mass-assignment: отправить лишнее поле (`user[role]=admin`) в форму профиля. SSRF: параметры-URL в функциях импорта. Порт по умолчанию — 3000 (dev). Каждую проверку — с сохранением запроса и ответа.

## Почему Rails часто «чист» по CVE, но не по логике

Современные Rails-приложения редко падают от известных CVE: фреймворк дисциплинированно патчится, а `Marshal`-сессии заменены на JSON. Поэтому основная ценность работы на Rails — **конфигурация и логика**, а не готовые эксплойты. Смотри на: (1) dev-роуты (`/rails/info`, `/rails/mailers`), (2) ошибки в `permit` (mass-assignment), (3) SSRF в функциях импорта, (4) утечки через нестрогие шаблоны (Slim/ERB с `html_safe`). Эти баги не требуют версии и работают на любой современной сборке — зато их находят только чтением кода и логики. Поэтому на Rails-цели переключайся с «поиска CVE» на «понимание модели данных и прав».

## Практика: чтение `/rails/info/routes`

В dev-режиме Rails отдаёт полную карту маршрутов, что бесценно для разведки:

```
$ curl -s https://app.target.example/rails/info/routes | grep -oE '/[a-z0-9_/]+' | sort -u | head
/api/v1/users
/api/v1/admin/export
/internal/metrics
```

Так за один запрос ты получаешь список эндпоинтов, включая неочевидные (`/internal/metrics`, `/admin/export`). Дальше каждый эндпоинт проверяется на авторизацию: `curl -s -o /dev/null -w '%{http_code}' <url>`. Часто `admin`-эндпоинты забывают закрыть, и они отвечают `200` анонимно. Это классический Rails-баг: маршрут есть, `before_action :authenticate` забыли. Фиксируй каждый открытый эндпоинт отдельной находкой и проверяй, не отдаёт ли он данные.

## Замечание про dev-роуты на проде

Если `/rails/info` открыт на продакшене — это не «мелочь», а прямая утечка конфигурации: версии, пути, переменные окружения. Оформляй как отдельную находку уровня medium/high и рекомендуй отключить dev-роуты (`config.consider_all_requests_local = false`) и убрать gem'ы разработки из продакшен-бандла.

## Финальный чек-лист по Rails

Cookie-признак, `X-Runtime`, `/rails/info/properties`, `/rails/info/routes`, `/rails/mailers`, версия Rails, декодирование `_*_session`, mass-assignment на формах, SSRF в импортах — девять пунктов, которых достаточно для полного аудита Rails-приложения.

## Квиз

Проверь себя.

```quiz
- question: "Что такое mass assignment в Rails?"
  options:
    - "Загрузка файлов"
    - "Передача лишних параметров (например, admin=true)"
    - "SQLi"
    - "XSS"
  answer: 1
  explanation: "Модель обновляется из нефильтрованных параметров."
- question: "Чем подписаны Rails-сессии?"
  options:
    - "secret_key_base"
    - "APP_KEY"
    - "machineKey"
    - "SECRET_KEY (Django)"
  answer: 0
  explanation: "Ключ Rails для подписи."
- question: "Что даёт утечка secret_key_base + Marshal-сессия?"
  options:
    - "XSS"
    - "RCE через Ruby-гаджет"
    - "CSRF"
    - "Ничего"
  answer: 1
  explanation: "Подписывается произвольный Marshal-объект."
- question: "Где утекает secret_key_base?"
  options:
    - "Из конфига/env/git"
    - "Из cookie"
    - "Из robots.txt"
    - "Из sitemap"
  answer: 0
  explanation: "Ключ в secrets/credentials/env."
- question: "По какой cookie узнаётся Rails?"
  options:
    - "_app_session"
    - "laravel_session"
    - "JSESSIONID"
    - "csrftoken"
  answer: 0
  explanation: "Имя сессии Rails."
```

## Куда дальше

Дальше — Spring и его SpEL/Actuator. А пока запомни: **в Rails ищи mass assignment и secret_key_base; Marshal + ключ = RCE.**

## Где пригодится

- Пентест продуктовых команд на Rails.
- Bug bounty: Ruby-приложения.
- CTF: задания с Marshal/десериализацией.
