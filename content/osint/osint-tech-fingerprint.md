---
id: osint-tech-fingerprint
title: "Технологический фингерпринт сайта: Wappalyzer, BuiltWith, WhatWeb"
category: osint
parent: osint-web-surface
difficulty: medium
order: 1
tags: [osint, fingerprint, web, whatweb, wappalyzer, builtwith, headers]
prerequisites: [osint-infrastructure]
useful_for:
  - "CTF категория OSINT"
  - "Bug bounty и пентест"
  - "Разведка поверхности атаки"
estimated_minutes: 30
summary: "Как определить технологии сайта пассивно: HTTP-заголовки, WhatWeb, Wappalyzer, BuiltWith, фингерпринт по статике, CMS и версии, WAF."
---

## Вопрос, с которого всё начинается

Перед тобой сайт `shop.example.com`. Чтобы понять, какие уязвимости искать, нужно знать, **на чём он построен**: веб-сервер, язык, фреймворк, CMS. Как определить стек, не отправляя на цель ни одного агрессивного запроса?

Ответ — в **технологическом фингерпринте**: пассивном определении технологий по заголовкам, статике и публичным базам. Разберём его на одном домене.

## Наш пример: домен shop.example.com

Работаем с одним объектом — `shop.example.com`. Задача: определить стек и составить список конкретных векторов (CVE, пути, файлы). Всё делаем пассивно — только GET и HEAD.

## Шаг 1: заголовки HTTP — первый источник

Самый быстрый способ — посмотреть ответ сервера. Один запрос отдаёт массу информации.

```bash
curl -sSI https://shop.example.com
```

```
HTTP/2 200
server: nginx/1.24.0
x-powered-by: PHP/8.1.0
set-cookie: laravel_session=...; path=/
link: <https://shop.example.com/wp-json/>; rel="https://api.w.org/"
```

Читаем сразу: сервер nginx 1.24, бэкенд на PHP 8.1, cookie `laravel_session` — это фреймворк Laravel. Заголовок `link` с `wp-json` — характерный маркер WordPress (возможно, на другом хосте).

Полезные заголовки:

| Заголовок | Что выдаёт |
|-----------|-----------|
| `Server` | веб-сервер и версия |
| `X-Powered-By` | язык или фреймворк |
| `Set-Cookie` | `PHPSESSID`→PHP, `JSESSIONID`→Java, `laravel_session`→Laravel |
| `X-Generator` | CMS (WordPress, Drupal, Joomla) |
| `Via` / `X-Cache` | CDN |

## Шаг 2: WhatWeb — сигнатуры

`whatweb` — консольный инструмент с базой из тысяч сигнатур. Он сопоставляет ответ сайта с ними и выводит найденное.

```bash
whatweb -v https://shop.example.com
```

```
https://shop.example.com [200 OK] Cookies[laravel_session],
  HTTPServer[nginx/1.24.0], IP[93.184.216.34], PHP[8.1.0],
  PoweredBy[PHP], Country[UNITED STATES][US]
```

Флаг `-v` показывает, какие сигнатуры сработали. Уровни агрессии (`-a`): `1` — пассивно, один запрос; `3` — по умолчанию; `4` — агрессивно и шумно. Для OSINT всегда начинай с `-a 1`.

## Шаг 3: фингерпринт по статике

Заголовки легко подменить, поэтому смотрим на **статику** — пути к скриптам, стилям и шрифтам. Открываем исходный код страницы.

```bash
curl -s https://shop.example.com | grep -oiE '(wp-content|/build/assets/|/_next/|react|vue|bootstrap)[^"'\'' ]*' | sort -u
```

```
/build/assets/app-3f9a2c.js
/build/assets/app-3f9a2c.css
```

Маркеры по артефактам:

| Артефакт | Технология |
|----------|-----------|
| `/wp-content/`, `/wp-includes/` | WordPress |
| `/sites/default/files/` | Drupal |
| `/build/assets/<hash>.js` | Vite (часто с Laravel) |
| `__NEXT_DATA__`, `/_next/` | Next.js |
| `data-v-` атрибуты | Vue |

`/build/assets/` с хэшем — типичный Vite-фронт, что согласуется с Laravel-бэкендом.

## Шаг 4: определяем CMS и версии

Версия важна: она определяет, какие CVE применимы. Для WordPress версию выдают служебные файлы.

```bash
curl -s https://shop.example.com/wp-json/ | python3 -m json.tool | grep -i version
curl -s https://shop.example.com/readme.html | grep -i "Version"
```

Для Drupal смотрят `CHANGELOG.txt`, для Joomla — `administrator/manifests/files/joomla.xml`. Эти файлы часто забывают закрыть, и они дают точную версию. Помни: устаревшая версия — это **гипотеза**, а не доказательство уязвимости.

## Шаг 5: WAF и защитные технологии

Наличие WAF меняет тактику: сканирование будет блокироваться. Признаки:

| Признак | WAF или CDN |
|---------|-------------|
| `Server: cloudflare` | Cloudflare |
| `X-Sucuri-ID` | Sucuri |
| `Server: AkamaiGHost` | Akamai |
| `X-CDN: Imperva` | Imperva |

```bash
curl -sSI "https://shop.example.com/?q=<script>alert(1)</script>" | grep -iE 'server|cf-ray|x-sucuri'
```

Ответ `403` на явно вредоносный параметр — признак активной фильтрации.

## Шаг 6: сводим в карту и приоритизируем

Собираем наблюдения в таблицу «наблюдение → вывод → следующий шаг».

| Наблюдение | Вывод | Дальнейший шаг |
|-----------|-------|----------------|
| `X-Powered-By: PHP` | PHP-бэкенд | искать `.env`, phpinfo |
| `laravel_session` | Laravel | проверить `/storage/logs/laravel.log` |
| `wp-json` | WordPress | `wpscan`, версии плагинов |
| `cf-ray` | Cloudflare | искать origin (см. CDN-урок) |

Итог: Cloudflare → PHP 8.1 / Laravel / Vite-фронт. Дальше ищем известные CVE Laravel и публичные пути. Так из пары запросов получается список конкретных векторов.

## Wappalyzer и BuiltWith

**Wappalyzer** — расширение для браузера и CLI. Расширение показывает стек прямо в тулбаре, CLI запускается из npm:

```bash
npx wappalyzer-cli https://example.com
```

**BuiltWith** — крупная коммерческая база технологий. Публичная страница `builtwith.com/example.com` ценна **историческими данными**: видно, что сайт раньше был на другой CMS. Смотри разделы Analytics & Tracking (пиксели — это pivot-идентификаторы), Hosting (провайдер и CDN) и Relationship (аффилированные домены).

## Автоматизация: батч-фингерпринт

Когда поддоменов десятки, ручной `curl` не масштабируется. Собираем пассивный скрипт, который снимает заголовки и сводит результат в таблицу.

```bash
while read -r h; do
  HDR=$(curl -sS -m 10 -D - -o /dev/null "https://$h" 2>/dev/null)
  SRV=$(printf '%s' "$HDR" | grep -i '^server:' | cut -d: -f2- | xargs)
  PWR=$(printf '%s' "$HDR" | grep -i '^x-powered-by:' | cut -d: -f2- | xargs)
  printf '%s\t%s\t%s\n' "$h" "$SRV" "$PWR"
done < hosts.txt | column -t -s $'\t'
```

Фрагмент вывода:

```
shop.example.com    cloudflare    PHP/8.1.0
blog.example.com    nginx/1.24.0  -
app.example.com     gunicorn      -
```

Из одной таблицы видно три разных стека на трёх поддоменах — и три разных набора векторов.

## Определение CMS и версий

Версия важна, потому что определяет применимые CVE. Для WordPress:

```bash
curl -s https://example.com/readme.html | grep -i "Version"
curl -s https://example.com/wp-links-opml.php | grep -i generator
```

Для Drupal смотрят `CHANGELOG.txt`, для Joomla — `administrator/manifests/files/joomla.xml`. Эти файлы часто забывают закрыть, и они дают точную версию — но помни: версия это гипотеза, а не доказательство уязвимости.

## Что мы теперь знаем

По-простому:

1. Заголовки HTTP — самый быстрый источник стека.
2. WhatWeb сопоставляет ответ с базой сигнатур.
3. Статика (пути JS/CSS) подтверждает заголовки.
4. Версии CMS определяются по служебным файлам.
5. WAF определяется по заголовкам и реакции на полезную нагрузку.

## На что смотреть дальше

- **Не доверяй только заголовкам.** Их подменяют — перепроверяй статикой.
- **Не суди о бэкенде по `Server` за CDN.** Это версия CDN-прослойки.
- **Не завышай агрессию.** `whatweb -a 4` шумит и может активировать WAF.
- **Не путай технологии по одному cookie.** Нужен второй сигнал.
- **Не забывай про поддомены.** Стек `api.`, `admin.`, `dev.` может отличаться.

## Квиз

Проверь себя.

```quiz
- question: "Какой заголовок надёжнее всего выдаёт бэкенд-язык, даже если Server подменён?"
  options:
    - "`Date`"
    - "`Set-Cookie` (например, `laravel_session`, `PHPSESSID`, `JSESSIONID`)"
    - "`Content-Length`"
    - "`Accept-Ranges`"
  answer: 1
- question: "Почему при виде Server: cloudflare нельзя судить о версии бэкенда по этому заголовку?"
  options:
    - "Cloudflare всегда врёт"
    - "Это версия CDN-прослойки, а не приложения за ней"
    - "Заголовок не читается curl"
    - "Cloudflare отключает заголовки"
  answer: 1
- question: "С какого уровня агрессии WhatWeb стоит начинать пассивную разведку?"
  options:
    - "`-a 4`"
    - "`-a 3`"
    - "`-a 1`"
    - "У WhatWeb нет уровней"
  answer: 2
- question: "Какой артефакт в HTML указывает на WordPress?"
  options:
    - "`/sites/default/files/`"
    - "`/wp-content/` и `wp-json`"
    - "`__NEXT_DATA__`"
    - "`data-v-` атрибуты"
  answer: 1
- question: "Зачем определять точную версию CMS?"
  options:
    - "Чтобы выбрать цвет интерфейса"
    - "Чтобы сопоставить её с известными CVE"
    - "Чтобы ускорить curl"
    - "Чтобы узнать часовой пояс"
  answer: 1
```

## Куда дальше

В следующем уроке мы возьмём **файлы `.well-known`** и разберём, что они раскрывают о структуре приложения — от `security.txt` до `openid-configuration`. А пока запомни главное: фингерпринт собирается из нескольких слоёв, и уверенный вывод даёт только совпадение сигналов из независимых источников.

## Где пригодится

- **CTF (OSINT):** определить стек сайта и найти версию с известной уязвимостью.
- **Bug bounty:** приоритизировать цели по стеку (WordPress-плагины, Laravel-пути).
- **Пентест:** пассивно составить карту технологий до активного сканирования.
- **Blue team:** понять, что выдаёт ваш собственный периметр наружу.
