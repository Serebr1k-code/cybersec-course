---
id: web-laravel
title: "Laravel: CVE-2021-3129 (Ignition RCE), APP_KEY и утечка .env"
category: web
parent: web-frameworks
difficulty: hard
order: 1
tags: [laravel, php, ignition, deserialization, app-key, env, rce]
prerequisites: [web-frameworks]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Laravel как цель: определение версии, утечка .env с APP_KEY, RCE через Ignition (CVE-2021-3129) и десериализация."
---

## Вопрос, с которого всё начинается

Laravel — самый популярный PHP-фреймворк. На нём пишут SaaS, панели, API. У Laravel есть две родовые проблемы: **`.env` в webroot** (утечка всех секретов) и **Ignition** — debug-обработчик, который при неверной конфигурации выполняет код. Плюс **`APP_KEY`** — ключ шифрования, с которым связана вся безопасность приложения. Разберём.

## Наш пример: Laravel-приложение

Цель — `https://app.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://app.target.example
https://app.target.example [200 OK] Laravel, Set-Cookie[laravel_session=...; XSRF-TOKEN=...]
```

Cookie `laravel_session` и `XSRF-TOKEN` — признаки Laravel. Проверяем `.env`:

```
$ curl -s https://app.target.example/.env
APP_NAME=Target
APP_KEY=base64:Q2hhbmdlTWVQbGVhc2U9PQ==
DB_PASSWORD=supersecret
MAIL_PASSWORD=...
```

`.env` открыт — это **полная утечка конфига**: `APP_KEY`, креды БД и почты.

## Шаг 1: CVE-2021-3129 — Ignition RCE

Ignition — обработчик ошибок Laravel, доступный при `APP_DEBUG=true`. Эндпоинт `_ignition/execute-solution` позволял выполнить произвольный код через «решение» (solution). PoC:

```
POST /_ignition/execute-solution HTTP/1.1
Content-Type: application/json

{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
 "parameters":{"variableName":"x","viewFile":"phar:///tmp/exploit.phar/test"}}
```

Через цепочку PHAR-десериализации выполняется код. Требуется `APP_DEBUG=true` и уязвимая версия Ignition (< 2.5.2).

## Шаг 2: APP_KEY — что с ним можно

`APP_KEY` шифрует cookies, значения и иногда сессионные данные. С утёкшим ключом можно: (1) расшифровать зашифрованные cookie/поля; (2) подделать их (например, повысить роль); (3) в связке с десериализацией — выполнить код. Поэтому `APP_KEY` — цель номер один после утечки `.env`.

## Шаг 3: десериализация и другие векторы

Laravel использует `unserialize()` в нескольких местах (кэш, очередь, cookie). При наличии **gadget chain** (Laravel-гаджеты публикуются, например, в `phpggc`) это object injection → RCE. Плюс у Laravel бывают SSTI через Blade (`{!! !!}`) и SQLi через `whereRaw`.

## Шаг 4: план атаки на Laravel

1. Фингерпринт (cookie `laravel_session`).
2. Проверка `.env` (утечка секретов).
3. Версия Laravel/Ignition.
4. Проверка CVE-2021-3129 (debug-режим).
5. Работа с `APP_KEY` (расшифровка/подделка).
6. Пост-эксплуатация — БД, очереди, RCE.

## Шаг 5: как не навредить

Laravel-приложение — продукт; его падение = ущерб. Ignition-PoC может создавать файлы. Поэтому: сначала утечки, потом безопасные проверки, RCE — при подтверждении и разрешении.

## Шаг 6: чек-лист по Laravel

1. Cookie `laravel_session`/`XSRF-TOKEN`.
2. `.env` (утечка).
3. `APP_KEY`, креды БД.
4. Версия Ignition + CVE-2021-3129.
5. Точки десериализации.
6. Сопоставление с CVE.

## Что мы теперь знаем

- Laravel узнаётся по cookie `laravel_session`.
- `.env` в webroot — полная утечка секретов.
- CVE-2021-3129 — Ignition RCE при debug.
- `APP_KEY` позволяет расшифровать/подделать данные.
- Десериализация через Laravel-гаджеты даёт RCE.

## Шаг 7: как использовать APP_KEY на практике

С `APP_KEY` можно: (1) расшифровать зашифрованные cookie и значения (`Crypt::decrypt`); (2) подделать их, повысив роль или изменив id; (3) в связке с десериализацией — выполнить код. Порядок: возьми зашифрованное значение из cookie, расшифруй своим ключом (скрипт на PHP с `Crypt::decrypt`), измени, зашифруй обратно и подставь. Так «утечка ключа» превращается в повышение привилегий.

## Шаг 8: типовые ошибки при работе с Laravel

Ошибка первая — проверять Ignition на пропатченной версии (>= 2.5.2) и решать, что «не работает». Вторая — запускать деструктивный PoC вместо чтения. Третья — не проверять `.env` (это первое, что стоит сделать). Четвёртая — игнорировать очереди и кэш: там тоже бывает десериализация.

## Шаг 9: как защититься от Laravel-атак

Защита: `APP_DEBUG=false` в проде; `.env` вне webroot; ротация `APP_KEY`; обновление Ignition; проверка `unserialize` в коде. Для атакующего: защищённый Laravel закрывает Ignition и утечку `.env`, и остаются механизмы приложения (SSTI, SQLi, десериализация).

## Шаг 10: как связать Laravel с инфраструктурой

`.env` Laravel — это карта инфраструктуры: `DB_*` (база), `REDIS_*` (кэш/очереди), `MAIL_*` (почта), `AWS_*`/`S3_*` (облако), `*_SECRET`/`*_KEY` (сторонние API). С этими кредами можно подключиться к Redis (часто без пароля внутри), читать очереди, выгружать файлы из S3, слать письма. Поэтому после утечки `.env` — перечисли все переменные и проверь каждую.

## Шаг 11: как безопасно проверить CVE-2021-3129

Публичный PoC Ignition создаёт PHAR-файл и вызывает десериализацию. Безопасная проверка: сначала убедиться, что `_ignition/execute-solution` вообще отвечает (не 404) и `APP_DEBUG=true`. Только затем — запуск с **безобидной** командой (`id`) и очистка созданных файлов. Не запускай PoC, который пишет веб-шелл, без разрешения.

## Шаг 12: как искать Laravel-цели и оценивать их

Laravel-приложения ищут по cookie `laravel_session` и открытому `.env` (Shodan: `http.title:"Laravel"` или по характерным путям). Оценивай цель так: есть ли `.env`, включён ли debug, какая версия Ignition, какие ключи в конфиге. Если `.env` открыт — цель высокоприоритетная, даже без CVE: одни креды БД уже дают полный доступ к данным.

## Шаг 13: как оформить находку по Laravel

В отчёте: точная версия Laravel/Ignition; факт утечки `.env` (с перечислением типов секретов, но без их публикации); расшифрованные/подделанные данные; подтверждение Ignition (если применимо); список систем, к которым ведут ключи. Отдельно — рекомендации (debug off, `.env` вне webroot, ротация ключей).

## Шаг 14: почему Laravel — частый выбор для bug bounty

Laravel популярен в SaaS, а SaaS-программы щедро платят. Утечка `.env` — одна из самых частых находок и легко проверяется. Поэтому на любой PHP-цели первым делом проверяй `.env` и служебные файлы — это дешёвая разведка с высокой отдачей.

## Квиз

Проверь себя.

```quiz
- question: "По какой cookie узнаётся Laravel?"
  options:
    - "laravel_session"
    - "JSESSIONID"
    - "PHPSESSID"
    - "OCSESSID"
  answer: 0
  explanation: "Имя сессии Laravel."
- question: "Что даёт открытый .env?"
  options:
    - "Только тему"
    - "APP_KEY, креды БД и почты"
    - "Ничего"
    - "Пароль админа"
  answer: 1
  explanation: "Все секреты приложения."
- question: "Какая уязвимость у Ignition?"
  options:
    - "XSS"
    - "RCE через execute-solution (CVE-2021-3129)"
    - "CSRF"
    - "clickjacking"
  answer: 1
  explanation: "При APP_DEBUG=true выполняется код."
- question: "Что позволяет сделать APP_KEY?"
  options:
    - "Расшифровать/подделать данные и cookie"
    - "Только тему"
    - "Ничего"
    - "Пароль почты"
  answer: 0
  explanation: "Это ключ шифрования приложения."
- question: "Через что в Laravel возможна десериализация?"
  options:
    - "Через Laravel-гаджеты (phpggc)"
    - "Через ViewState"
    - "Через Marshal"
    - "Через Yii"
  answer: 0
  explanation: "PHP object injection с гаджетами Laravel."
```

## Куда дальше

Дальше — Django и его debug/pickle-векторы. А пока запомни: **в Laravel сначала `.env` и `APP_KEY`, потом Ignition RCE.**

## Где пригодится

- Bug bounty: SaaS и панели на Laravel.
- Пентест: аудит PHP-разработок.
- CTF: задания с Ignition/десериализацией.
