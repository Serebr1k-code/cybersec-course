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
Технологический фингерпринт — это определение того, **на чём построен сайт**: веб-сервер, язык, фреймворк, CMS, CDN, аналитика, WAF. Это первый шаг любой разведки веб-поверхности: зная стек, вы знаете, какие уязвимости искать, какие файлы проверять и как не выдать себя при сканировании. Всё в этом уроке можно делать пассивно — из заголовков, публичных баз и статики, не отправляя на цель ни одного «атакующего» запроса.

## Теория: из чего складывается фингерпринт

Фингерпринт собирается из нескольких слоёв, от самого надёжного к самому шумному:

| Слой | Источник | Надёжность |
|------|----------|-----------|
| Заголовки HTTP | `Server`, `X-Powered-By`, `Set-Cookie` | высокая |
| Тело ответа | мета-теги, комментарии, генератор | средняя |
| Статика | пути JS/CSS, шрифты, хэши | средняя |
| Cookies | имена и префиксы | высокая |
| DNS/CDN | CNAME, IP, ASN | высокая |
| Публичные базы | BuiltWith, Wappalyzer, Shodan | зависит от давности |

Правило: **совпадающие сигналы из двух независимых источников** дают уверенный вывод. Один сигнал — гипотеза.

## Заголовки HTTP: первый источник

Самый быстрый и надёжный способ — посмотреть ответ сервера. Один запрос:

```bash
curl -sSI https://example.com
```

Вывод:

```
HTTP/2 200
server: nginx/1.24.0
date: Sun, 11 Oct 2026 12:00:00 GMT
content-type: text/html; charset=UTF-8
x-powered-by: PHP/8.2.12
set-cookie: PHPSESSID=abc123; path=/
x-generator: WordPress 6.4
link: <https://example.com/wp-json/>; rel="https://api.w.org/"
```

Здесь сразу читается: nginx 1.24, PHP 8.2, WordPress 6.4. Заголовок `link` с `wp-json` — характерный признак WordPress. `x-generator` — распространённый маркер CMS.

Полезные заголовки и их смысл:

| Заголовок | Что выдаёт |
|-----------|-----------|
| `Server` | веб-сервер и версия |
| `X-Powered-By` | язык/фреймворк (PHP, ASP.NET, Express) |
| `X-AspNet-Version` | версия ASP.NET |
| `Set-Cookie` | `PHPSESSID`→PHP, `JSESSIONID`→Java, `ASP.NET_SessionId`→.NET, `csrftoken`→Django |
| `X-Generator` | CMS (WordPress, Drupal, Joomla) |
| `Via` / `X-Cache` | CDN (Cloudflare, Fastly, Varnish) |
| `X-Drupal-Cache` | Drupal |

```bash
curl -sSI https://target.example | grep -iE 'server|x-powered-by|set-cookie|x-generator|via|x-cache'
```

## WhatWeb: сигнатуры и уровни агрессии

`whatweb` — CLI-инструмент с базой из тысяч сигнатур. Базовый прогон:

```bash
whatweb -v https://example.com
```

`-v` показывает, какие именно сигнатуры сработали:

```
http://example.com [200 OK] Country[UNITED STATES][US],
  Cookies[PHPSESSID], HTML5, HTTPServer[nginx/1.24.0],
  IP[93.184.216.34], PHP[8.2.12], PoweredBy[PHP],
  WordPress[6.4]
```

Уровни агрессии (`-a`):

| Уровень | Поведение |
|---------|-----------|
| `-a 1` | пассивно, один запрос |
| `-a 3` | несколько запросов (по умолчанию) |
| `-a 4` | агрессивно, много запросов, шумно |

Для OSINT всегда начинайте с `-a 1` (пассивно), повышайте только при явном разрешении. Полезные флаги:

```bash
whatweb -a 1 --no-errors --color=never -i targets.txt   # батч из файла
whatweb --user-agent "Mozilla/5.0 ..." https://example.com  # подмена UA
whatweb --cookie "session=abc" https://example.com      # с сессией
```

## Wappalyzer и BuiltWith

**Wappalyzer** — браузерное расширение и CLI. Расширение показывает стек прямо в тулбаре, кликом по иконке. CLI (через npm):

```bash
npx wappalyzer-cli https://example.com
```

**BuiltWith** — крупнейшая коммерческая база технологий. Публичная страница `builtwith.com/example.com` показывает историю стека и «соседей» (домены с теми же tracking ID). Её ценность в **исторических данных**: видно, что сайт раньше был на другой CMS.

Что искать в BuiltWith:
- раздел **Analytics & Tracking** — Google Analytics, GTM, пиксели (pivot-идентификаторы);
- раздел **Hosting** — провайдер и CDN;
- раздел **Relationship** — аффилированные домены.

## Фингерпринт по статике: JS, CSS, шрифты, фреймворки

Заголовки врут (их легко подменить), поэтому смотрим на статику. Откройте исходный код страницы (`curl -s https://example.com`) и ищите:

```bash
curl -s https://example.com | grep -oiE '(wp-content|wp-includes|/static/|/assets/|react|vue|angular|jquery|bootstrap)[^"'\'' ]*' | sort -u
```

Маркеры:

| Артефакт | Технология |
|----------|-----------|
| `/wp-content/`, `/wp-includes/` | WordPress |
| `/sites/default/files/` | Drupal |
| `/media/jui/` | Joomla |
| `/static/js/main.<hash>.js` | React (CRA) |
| `__NEXT_DATA__`, `/_next/` | Next.js |
| `data-v-` атрибуты | Vue |
| `ng-version` | Angular |
| `wp-emoji-release.min.js` | WordPress |

```bash
curl -s https://example.com | grep -oE 'meta name="generator"[^>]*'
# <meta name="generator" content="WordPress 6.4" />
```

## Определение CMS и версий

Версия важна: она определяет, какие CVE применимы. Для WordPress:

```bash
curl -s https://example.com/wp-json/ | python3 -m json.tool | grep -i version
curl -s https://example.com/readme.html | grep -i "Version"
curl -s https://example.com/wp-links-opml.php | grep -i generator
```

Для Drupal — `CHANGELOG.txt`; для Joomla — `administrator/manifests/files/joomla.xml`. Эти файлы часто забывают закрыть, и они дают точную версию.

## Разобранный пример: пассивный фингерпринт домена

Цель: определить стек `shop.example.com`, ничего не ломая.

Шаг 1 — заголовки:

```bash
curl -sSI https://shop.example.com | grep -iE 'server|x-powered-by|set-cookie|x-generator'
# server: cloudflare
# set-cookie: laravel_session=...; path=/
# x-powered-by: PHP/8.1.0
```

Вывод: за Cloudflare, бэкенд — PHP + Laravel (`laravel_session`).

Шаг 2 — статика:

```bash
curl -s https://shop.example.com | grep -oiE '/build/assets/[^"]+' | sort -u | head
# /build/assets/app-3f9a2c.js
# /build/assets/app-3f9a2c.css
```

`/build/assets/` с хэшем — типичный Vite/Laravel-микс. Гипотеза подтверждена.

Шаг 3 — WAF/CDN и версии:

```bash
whatweb -a 1 https://shop.example.com
# Cloudflare, Laravel, PHP 8.1, Bootstrap, jQuery 3.6
```

Итог: Cloudflare → PHP 8.1 / Laravel / Vite-фронт / Bootstrap. Дальше ищем известные CVE Laravel для 8.1 и публичные пути (`/storage/logs/laravel.log`, `/.env`).

## WAF и защитные технологии

Наличие WAF меняет тактику: сканирование будет блокироваться. Признаки:

| Признак | WAF/CDN |
|---------|---------|
| `Server: cloudflare` | Cloudflare |
| `X-Sucuri-ID` | Sucuri |
| `Server: AkamaiGHost` | Akamai |
| `X-CDN: Imperva` | Imperva |
| Ответ 403 на `?id=1'` | есть фильтрация |

```bash
curl -sSI "https://example.com/?q=<script>alert(1)</script>" | grep -iE 'server|cf-ray|x-sucuri'
```

## Таблица артефактов и выводов

| Наблюдение | Вывод | Дальнейший шаг |
|-----------|-------|----------------|
| `X-Powered-By: PHP` | PHP-бэкенд | искать `.php`, `.env`, phpinfo |
| `laravel_session` | Laravel | проверить `/.env`, `storage/logs` |
| `wp-json`, `/wp-content/` | WordPress | `wpscan`, версии плагинов |
| `X-Nextjs-Cache` | Next.js | проверить `/_next/data/` |
| `cf-ray` | Cloudflare | искать origin (см. CDN-модуль) |
| `JSESSIONID` | Java | Tomcat/Spring-пути, `/actuator` |

## Ошибки и подводные камни

- **Доверять только заголовкам.** Их подменяют (`Server: nginx` на Apache) и скрывают. Всегда перепроверяйте статикой.
- **Игнорировать CDN.** Если видите Cloudflare, версия `Server` — это версия CDN, а не бэкенда. Не делайте вывод о бэкенде по ней.
- **Завышать агрессию.** `whatweb -a 4` шумит и может активировать WAF/бан. Начинайте с `-a 1`.
- **Путать технологии по одному `Set-Cookie`.** `csrf`-cookies есть у многих фреймворков; нужен второй сигнал.
- **Забывать про поддомены.** Стек может отличаться на `api.`, `admin.`, `dev.`. Фингерпринтите каждый хост.
- **Считать устаревшую версию уязвимой без CVE.** Версия — это гипотеза, а не доказательство.

## Что дальше / решение

Фингерпринт — основа для приоритизации. Дальше: **tracking-идентификаторы** (`osint-tracking-ids`) для поиска «соседних» доменов владельца, **`.well-known`-файлы** (`osint-wellknown-files`) за структурой приложения и **TLS-фингерпринт** (`osint-tls-fingerprint`) для корреляции хостов. Итог: из заголовков + статики + публичных баз вы получаете уверенный стек цели и список конкретных векторов (CVE, пути, файлы), не сделав ни одного агрессивного запроса.

## Автоматизация: батч-фингерпринт списка хостов

Когда поддоменов десятки, ручной `curl` не масштабируется. Собираем пассивный батч-скрипт, который по списку хостов снимает заголовки и статику и сводит результат в таблицу. Он не делает ничего агрессивного — только GET и HEAD.

```bash
#!/usr/bin/env bash
# passive-fingerprint.sh — пассивный фингерпринт списка хостов
OUT=fingerprint.tsv
printf 'host\tserver\tpowered_by\tcookie\tgenerator\n' > "$OUT"
while read -r h; do
  [ -z "$h" ] && continue
  HDR=$(curl -sS -m 10 -A 'Mozilla/5.0' -D - -o /dev/null "https://$h" 2>/dev/null)
  SRV=$(printf '%s' "$HDR" | grep -i '^server:' | head -1 | cut -d: -f2- | xargs)
  PWR=$(printf '%s' "$HDR" | grep -i '^x-powered-by:' | cut -d: -f2- | xargs)
  COO=$(printf '%s' "$HDR" | grep -i '^set-cookie:' | grep -oiE 'PHPSESSID|JSESSIONID|ASP.NET_SessionId|laravel_session|csrftoken|_rails' | head -1)
  GEN=$(curl -sS -m 10 "https://$h" 2>/dev/null | grep -oiE '<meta name="generator"[^>]*>' | head -1)
  printf '%s\t%s\t%s\t%s\t%s\n' "$h" "$SRV" "$PWR" "$COO" "$GEN" >> "$OUT"
done < hosts.txt
column -t -s $'\t' "$OUT"
```

Запуск:

```bash
chmod +x passive-fingerprint.sh
./passive-fingerprint.sh
```

Фрагмент вывода:

```
host                    server        powered_by   cookie            generator
shop.example.com        cloudflare    PHP/8.1.0    laravel_session   -
blog.example.com        nginx/1.24.0  -            PHPSESSID         WordPress 6.4
app.example.com         gunicorn      -            csrftoken         -
```

Из одной таблицы уже видно три разных стека на трёх поддоменах — и три разных набора векторов. Такой скрипт удобно складывать в пайплайн: результат `fingerprint.tsv` потом фильтруется (`grep wordpress`, `grep laravel`) и передаётся в соответствующие инструменты (`wpscan`, поиск `.env`).

## Квиз

```quiz
- question: "Какой заголовок НАИБОЛЕЕ надёжно выдаёт бэкенд-язык, даже если `Server` подменён?"
  options:
    - "`Date`"
    - "`Set-Cookie` (например, `laravel_session`, `PHPSESSID`, `JSESSIONID`)"
    - "`Content-Length`"
    - "`Accept-Ranges`"
  answer: 1
- question: "Почему при виде `Server: cloudflare` нельзя судить о версии бэкенда по этому заголовку?"
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
- question: "Зачем определять ТОЧНУЮ версию CMS?"
  options:
    - "Чтобы выбрать цвет интерфейса"
    - "Чтобы сопоставить её с известными CVE"
    - "Чтобы ускорить curl"
    - "Чтобы узнать часовой пояс"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** определить стек сайта-приложения и найти версию с известной уязвимостью.
- **Bug bounty:** приоритизировать цели по стеку (WordPress-плагины, Laravel-пути).
- **Пентест:** пассивно составить карту технологий до активного сканирования.
- **Blue team:** понять, что выдаёт ваш собственный периметр наружу.
- **Разведка поверхности атаки:** свести стек всех поддоменов в единую карту.
