---
id: web-wordpress
title: "WordPress: xmlrpc, wp-json REST, wp-cron и подделка auth-cookie"
category: web
parent: web-cms-platforms
difficulty: medium
order: 1
tags: [wordpress, xmlrpc, rest-api, wp-json, cookie-forgery, nonce, cve]
prerequisites: [web-cms-platforms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 50
summary: "Полный разбор WordPress как цели: перечисление пользователей через REST, xmlrpc-брутфорс и SSRF, wp-cron, подделка сессионной cookie через секреты и nonce-слабости."
lab:
  kind: shell
  title: "Практика: перечисление пользователей и чтение секрета в WordPress"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, wp-json-users.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'REST-эндпоинт /wp-json/wp/v2/users отдаёт список пользователей без авторизации.'
    - 'Посмотри файл wp-json-users.json — это сохранённый ответ REST.'
    - 'Собери слаги пользователей и найди тот, у которого role=administrator.'
    - 'Флаг лежит в поле description администратора — сохрани его в found.txt.'
---

## Вопрос, с которого всё начинается

WordPress стоит на 40% сайтов интернета. Это значит, что если ты умеешь его ломать, ты умеешь ломать огромную часть веба. Но «ломать WordPress» — не про одну кнопку: это про набор служебных интерфейсов, которые есть на **каждой** установке и которые часто открыты. Сегодня мы пройдём их по порядку.

## Наш пример: блог на WordPress

Цель — `https://blog.target.example`. Мы уже знаем из фингерпринта, что это WordPress 6.4.2. Наша задача — не трогая базу, собрать максимум информации и найти путь к администратору.

## Шаг 1: REST-перечисление пользователей

Начиная с версии 4.7 у WordPress есть **REST API** по пути `/wp-json/`. Один из его эндпоинтов — `wp/v2/users` — по умолчанию отдаёт список авторов:

```
$ curl -s 'https://blog.target.example/wp-json/wp/v2/users'
[{"id":1,"name":"admin","slug":"admin","link":"...","description":"Founder"},
 {"id":2,"name":"editor","slug":"editor","description":""}]
```

Мы получили логины `admin` и `editor` без единого запроса на вход. В `description` иногда утекают заметки, а по `id` можно угадать, кто главный админ (обычно `id:1`).

Если эндпоинт закрыт (`rest_user_query` фильтром), есть запасной путь — `/wp-json/wp/v2/users?search=admin` или старый `/?author=1`, который редиректит на страницу автора и показывает его слаг в URL:

```
$ curl -sI 'https://blog.target.example/?author=1' | grep -i location
location: https://blog.target.example/author/admin/
```

## Шаг 2: xmlrpc.php — брутфорс и SSRF в одном файле

Файл `/xmlrpc.php` — реализация протокола XML-RPC. Он принимает POST с XML и умеет метод `wp.getUsersBlogs`, который проверяет логин/пароль. Проблема в методе `system.multicall`: он позволяет упаковать **сотни** попыток входа в один HTTP-запрос.

```
POST /xmlrpc.php HTTP/2
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password123</string></value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>
```

Одна такая пачка обходит лимит «N попыток в минуту», потому что защита считает **HTTP-запросы**, а не проверки пароля внутри. Именно поэтому `xmlrpc.php` — первое, что рекомендуют отключать.

Тот же файл даёт **pingback**: метод `pingback.ping` заставляет WordPress сходить по указанному URL, чтобы «проверить ссылку». Это готовый **SSRF** — сервер ходит во внутреннюю сеть за тебя:

```
<methodName>pingback.ping</methodName>
<params>
  <param><value><string>http://127.0.0.1:8080/</string></value></param>
  <param><value><string>https://blog.target.example/post/1</string></value></param>
</params>
```

## Шаг 3: wp-cron.php и неожиданные эффекты

`/wp-cron.php` запускает отложенные задачи при каждом визите. Если его дёргать в цикле, можно заставить сервер выполнять тяжёлые задачи (отправка почты, обновления) — это и DoS, и способ «подтолкнуть» выполнение кода, если есть задача, которую злоумышленник может подложить.

Проверяем, что он открыт:

```
$ curl -sI https://blog.target.example/wp-cron.php | head -1
HTTP/2 200
```

## Шаг 4: подделка auth-cookie — когда украли секрет

WordPress хранит сессию в cookie вида `wordpress_logged_in_<hash>=username|expiry|token|hmac`. Последняя часть — **HMAC**, подпись на секретном ключе `AUTH_KEY`/`SECRET_KEY` из `wp-config.php`.

Если эти ключи утекли (бэкап, `.env`, LFI, git-история), можно **сгенерировать валидную cookie** без пароля. Инструмент `wp-force-login` или скрипт на Python берут ключи и логин, считают HMAC и подставляют cookie. С этого момента ты — админ, не зная пароля.

Именно поэтому `wp-config.php` — самая ценная цель при LFI: там и доступ к БД, и четыре секретных ключа.

## Шаг 5: nonce — не защита от того, о чём ты думаешь

**Nonce** в WordPress («number used once») — не одноразовый токен, а HMAC от действия и времени пользователя. Он защищает от CSRF, но **не от утечки**: если nonce виден на странице, он действителен ~24 часа для твоего пользователя. Поэтому если удалось внедрить XSS, любой REST-запрос, требующий nonce, выполняется с ним же.

## Углублённый разбор: подделка auth-cookie

WordPress аутентифицирует по cookie `wordpress_logged_in_<hash>`, где `<hash>` — это хеш от пути сайта. Сама cookie — `username|expiration|token|hmac`, подписанная секретами из `wp-config.php` (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY` и соли). Если эти значения утекли (через LFI, бэкап, git), cookie можно подделать для любого пользователя, включая администратора:

```python
# псевдокод: подпись cookie admin|exp|token|hmac
sig = hmac_sha256(LOGGED_IN_KEY + LOGGED_IN_SALT, f"{user}|{exp}|{token}|{hmac_part}")
```

Вывод: `wp-config.php` — первоочередная цель после LFI, потому что оттуда получают и доступ к БД, и все соли. Защита — уникальные соли и запрет чтения конфига.

## wp-config и что оттуда достают

`wp-config.php` содержит: `DB_NAME/DB_USER/DB_PASSWORD/DB_HOST` (доступ к базе), все `*_KEY`/`*_SALT` (подделка cookie и nonce), `table_prefix`, иногда `WP_DEBUG` и пути. Даже без RCE чтение базы даёт хэши пользователей и секретный контент. Поэтому в чек-листе WordPress чтение конфига стоит сразу после определения версии и плагинов. Если `wp-config.php` недоступен, а БД открыта наружу (редко, но бывает), хэши достаются напрямую.

## REST API: перечисление и атаки

`/wp-json/wp/v2/users` часто открыт и отдаёт список пользователей с их slug — это готовые логины для брутфорса. Далее `/wp-json/wp/v2/posts?per_page=100` отдаёт черновики, если есть неверная настройка прав. `/wp-json/wp/v2/comments` может раскрывать e-mail. Проверяй:

```bash
curl -s http://T/wp-json/wp/v2/users | jq ".[].slug"
curl -s "http://T/wp-json/wp/v2/posts?status=draft" | jq ".[].title.rendered"
```

Если REST закрыт, но `xmlrpc.php` открыт — используй `system.multicall` для брутфорса сотен паролей одним запросом (обходит лимиты по запросам) и `pingback.ping` для SSRF. Защита — отключить xmlrpc и ограничить REST, но атакующему важно помнить: закрытие одного канала не закрывает другой.

## Что писать в отчёте по WordPress

Фиксируй: версию ядра, список плагинов/тем с версиями, найденные CVE, доступные эндпоинты (xmlrpc, REST), статус wp-config. Для каждой находки — минимальный воспроизводимый запрос и наблюдаемый результат. Указывай, что доступно анонимно, а что требует учётки. Рекомендации: обновить ядро и плагины, удалить неиспользуемые, отключить xmlrpc, ограничить REST, настроить WAF и мониторинг.

## Итог по WordPress

Ядро WordPress редко уязвимо само — риск в плагинах, темах и конфигурации (xmlrpc, REST, wp-config). Практический порядок: версия → плагины/темы → эндпоинты → конфиг. Ключевой актив — `wp-config.php`: оттуда и БД, и соли для подделки cookie. Если конфиг недоступен, работай через плагины и эндпоинты, но не выдумывай RCE без подтверждения.

## Мини-шпаргалка по WordPress

Версия → плагины/темы → `/wp-json/wp/v2/users` (логины) → `xmlrpc.php` (брут/SSRF) → `wp-config.php` (БД + соли). Ключевой актив — конфиг: оттуда и БД, и подделка auth-cookie.

## Финальные заметки по WordPress

Помни про связку уязвимостей: устаревший плагин может дать LFI, LFI — прочитать `wp-config.php`, а конфиг — доступ к БД и подделку auth-cookie для админа. Отдельные находки выглядят средне, но вместе дают полный контроль. Поэтому в отчёте показывай цепочку, а не только точки. И проверяй обе стороны: и плагины/темы, и конфигурацию (xmlrpc, REST, права на файлы).

## Что мы теперь знаем

- `/wp-json/wp/v2/users` и `/?author=1` перечисляют логины.
- `xmlrpc.php` даёт `system.multicall` (брутфорс в одном запросе) и `pingback.ping` (SSRF).
- `wp-cron.php` открыт почти всегда и запускает задачи.
- Секреты из `wp-config.php` позволяют подделать `wordpress_logged_in` cookie.
- nonce — защита от CSRF, но не от XSS-компрометации.

## Шаг 6: перечисление плагинов и тем вручную

`wpscan` может быть заблокирован или недоступен. Тогда плагины находят руками — по статике. Список плагинов часто утекает в HTML:

```
$ curl -s https://blog.target.example/ | grep -oE '/wp-content/(plugins|themes)/[a-z0-9-]+/' | sort -u
/wp-content/plugins/contact-form-7/
/wp-content/plugins/woocommerce/
/wp-content/themes/astra/
```

Каждое имя — это каталог. Теперь определим версии. У плагинов версия часто в `readme.txt`:

```
$ curl -s https://blog.target.example/wp-content/plugins/contact-form-7/readme.txt | grep -i 'stable tag'
Stable tag: 5.8.1
```

У темы версия лежит в `style.css`:

```
$ curl -s https://blog.target.example/wp-content/themes/astra/style.css | grep -i '^Version:'
Version: 4.5.0
```

Мы получили точные версии без единого сканера. Дальше — WPScan DB или CVE-поиск по `contact-form-7 5.8.1`.

## Шаг 7: реальный сценарий и что писать в отчёт

Соберём всё в одну историю. Цель — блог на WordPress 6.4.2. Шаги: `whatweb` дал версию; `/wp-json/wp/v2/users` выдал логины `admin` и `editor`; `/?author=1` подтвердил слаг; перечисление статики показало устаревший Contact Form 7 5.8.1. Итог: два независимых вектора — брутфорс `admin` через `xmlrpc.php` (multicall) и CVE для плагина.

Что писать в отчёт: **не «нашёл WordPress», а конкретику**. Хорошая запись выглядит так:

- цель: `blog.target.example`;
- стек: WordPress 6.4.2 / PHP 8.2 / nginx;
- находка: `/wp-json/wp/v2/users` перечисляет пользователей без авторизации (подтверждено выводом);
- находка: `xmlrpc.php` открыт и принимает `system.multicall` (подтверждено ответом 200);
- версия плагина Contact Form 7 5.8.1 устарела относительно 5.8.2+ (потенциальный CVE).

Каждое утверждение подкреплено **сохранённым запросом и ответом**. Это то, что отличает отчёт от «я что-то видел».

## Шаг 8: если xmlrpc закрыт — что дальше

Администраторы всё чаще отключают `xmlrpc.php`. Проверить это просто: POST на файл должен вернуть `405 Method Not Allowed` с заголовком `allow: POST` при включённом модуле, и `403`/пустоту при отключённом.

Если xmlrpc закрыт, брутфорс идёт по обычной форме входа `/wp-login.php`. Здесь работает **credential stuffing** (проверка украденных пар) и точечный подбор по известным логинам из REST. Лимиты обходятся сменой `X-Forwarded-For` (если сервер ему доверяет) и распределением попыток во времени.

Второй запасной вектор — **сброс пароля**. WordPress формирует ссылку с ключом; если ключ предсказуем или утекает в почтовый лог, аккаунт захватывается без пароля. Третий — плагины аутентификации: их баги дают вход в обход ядра.

## Квиз

Проверь себя.

```quiz
- question: "Что отдаёт /wp-json/wp/v2/users?"
  options:
    - "Пароли в открытом виде"
    - "Список пользователей с логинами и слагами"
    - "Дамп базы данных"
    - "Конфиг wp-config.php"
  answer: 1
  explanation: "REST-эндпоинт публично перечисляет авторов."
- question: "Почему xmlrpc.php удобен для брутфорса?"
  options:
    - "Он не требует логина"
    - "system.multicall упаковывает много попыток в один HTTP-запрос"
    - "Он отключает капчу"
    - "Он показывает пароль"
  answer: 1
  explanation: "Защита считает запросы, а не проверки внутри."
- question: "Что позволяет подделать cookie wordpress_logged_in?"
  options:
    - "Знание логина"
    - "Секретные ключи AUTH_KEY/SECRET_KEY из wp-config.php"
    - "IP админа"
    - "Версия PHP"
  answer: 1
  explanation: "Cookie подписана HMAC на этих ключах."
- question: "Чем pingback.ping опасен?"
  options:
    - "Удаляет посты"
    - "Заставляет сервер сходить по указанному URL — SSRF"
    - "Меняет пароль"
    - "Загружает плагины"
  answer: 1
  explanation: "Сервер делает запрос от своего имени."
- question: "Что не защищает nonce?"
  options:
    - "От CSRF"
    - "От повторного использования в течение суток"
    - "От XSS, который читает nonce со страницы"
    - "От прямых REST-запросов"
  answer: 2
  explanation: "XSS читает актуальный nonce и использует его."
```

## Куда дальше

Дальше — плагины и темы WordPress: там живёт большинство RCE и SQLi. А пока запомни: **четыре служебных файла (`/wp-json/`, `/xmlrpc.php`, `/wp-cron.php`, `/?author=`) — это твой первый чек-лист на любой WordPress-цели.**

## Где пригодится

- Bug bounty: WordPress-программы — самая массовая категория.
- CTF: задания с блогом и «найди админа».
- Пентест: аудит CMS у клиента начинается ровно с этого чек-листа.
