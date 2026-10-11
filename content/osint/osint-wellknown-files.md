---
id: osint-wellknown-files
title: "robots.txt, sitemap.xml, security.txt и .well-known"
category: osint
parent: osint-web-surface
difficulty: easy
order: 3
tags: [osint, robots, sitemap, securitytxt, wellknown, paths, recon]
prerequisites: [osint-tech-fingerprint]
useful_for:
  - "CTF категория OSINT"
  - "Bug bounty и пентест"
  - "Картирование поверхности атаки"
estimated_minutes: 25
summary: "Стандартные файлы сайта как источник структуры: robots.txt, sitemap.xml, security.txt, .well-known, ads.txt и другие — что искать и как читать."
---
На любом сайте есть набор «служебных» файлов, которые владельцы создают не для посетителей, а для роботов и сервисов: `robots.txt`, `sitemap.xml`, `security.txt`, `ads.txt`, каталог `.well-known`. Для OSINT это маленькая золотая жила: они **намеренно раскрывают структуру** — какие пути есть, какие закрыты от индексации, кто отвечает за безопасность, какие вендоры используются. Эти файлы отдают почти все сайты, а читать их безопасно и быстро.

## Теория: зачем существуют эти файлы

Каждый служебный файл появился для решения конкретной задачи, и каждая задача раскрывает что-то полезное:

| Файл | Назначение | Что даёт разведке |
|------|-----------|-------------------|
| `robots.txt` | правила для поисковых ботов | список путей, в т.ч. «запретных» |
| `sitemap.xml` | карта сайта для индексации | все страницы и разделы |
| `security.txt` | контакты по безопасности | email, срок действия, политика |
| `ads.txt` | авторизованные рекламные системы | партнёры, monetization |
| `humans.txt` | команда сайта | имена, роли |
| `.well-known/` | стандартные сервисные данные | ACME, OIDC, MTA-STS и др. |

Парадокс: `robots.txt` с директивой `Disallow: /admin/` не защищает `/admin/` — он **сообщает всему миру**, что там что-то есть. Это классический источник находок.

## robots.txt: карта скрытого

Запрос:

```bash
curl -s https://example.com/robots.txt
```

Пример ответа:

```
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /private/
Disallow: /wp-admin/
Disallow: /*.pdf$
Allow: /public/

Sitemap: https://example.com/sitemap.xml
```

Читаем: есть `/admin/`, `/backup/`, `/private/`. Это прямые кандидаты для проверки (в рамках авторизации!). `Allow` и `Disallow` с wildcard (`/*.pdf$`) показывают паттерны.

Полезные запросы:

```bash
# все директивы Disallow/Allow
curl -s https://example.com/robots.txt | grep -iE '^(Disallow|Allow):'
# все Sitemap-ссылки
curl -s https://example.com/robots.txt | grep -i '^Sitemap:'
# user-agent-специфичные блоки (иногда раскрывают разных ботов)
curl -s https://example.com/robots.txt | grep -iA5 'User-agent'
```

Часто в `robots.txt` светят **staging/dev-поддомены** и **нестандартные порты**.

## sitemap.xml: полная структура

`Sitemap` указывает на XML-карту. Забираем:

```bash
curl -s https://example.com/sitemap.xml | head -40
```

Пример:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/products/</loc></url>
  <url><loc>https://example.com/blog/2026/10/release/</loc></url>
  <url><loc>https://example.com/downloads/manual-v3.pdf</loc></url>
</urlset>
```

Извлекаем все URL:

```bash
curl -s https://example.com/sitemap.xml | grep -oE '<loc>[^<]+' | sed 's/<loc>//'
```

Sitemap часто вложенный: `sitemap_index.xml` ссылается на подкарты (`sitemap-posts.xml`, `sitemap-products.xml`). Рекурсивно обходим их — так собирается полный список страниц, включая забытые разделы и документы.

## security.txt: контакты и политика

Стандарт RFC 9116. Живёт в двух местах:

```bash
curl -s https://example.com/.well-known/security.txt
curl -s https://example.com/security.txt
```

Пример:

```
Contact: mailto:security@example.com
Contact: https://example.com/security/report
Expires: 2027-01-01T00:00:00.000Z
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/security/hall-of-fame
Policy: https://example.com/security/policy
Preferred-Languages: en, ru
Canonical: https://example.com/.well-known/security.txt
```

Что даёт: email службы безопасности (для ответственного раскрытия), PGP-ключ, ссылку на политику и «доску благодарности» (там перечислены прошлые исследователи — иногда с описанием уязвимостей).

## .well-known: стандартные сервисы

Каталог `/.well-known/` содержит стандартизованные файлы:

| Путь | Что раскрывает |
|------|----------------|
| `/.well-known/security.txt` | контакты безопасности |
| `/.well-known/acme-challenge/` | домен на Let's Encrypt |
| `/.well-known/openid-configuration` | OIDC-эндпоинты, issuer |
| `/.well-known/mta-sts.txt` | почтовая политика |
| `/.well-known/change-password` | поддержка смены пароля |
| `/.well-known/assetlinks.json` | привязка Android-приложений |
| `/.well-known/apple-app-site-association` | deep links iOS |
| `/.well-known/webfinger` | федерация (Mastodon и др.) |

Пример проверки OIDC:

```bash
curl -s https://example.com/.well-known/openid-configuration | python3 -m json.tool
```

Вывод:

```json
{
  "issuer": "https://login.example.com/",
  "authorization_endpoint": "https://login.example.com/oauth2/authorize",
  "token_endpoint": "https://login.example.com/oauth2/token",
  "jwks_uri": "https://login.example.com/.well-known/jwks.json"
}
```

Это раскрывает внутренний IdP (`login.example.com`) — отдельный актив для разведки.

## Разобранный пример: полный сбор служебных файлов

Цель: `app.example.com`.

```bash
BASE=https://app.example.com
for p in /robots.txt /sitemap.xml /sitemap_index.xml /.well-known/security.txt \
         /security.txt /.well-known/openid-configuration /.well-known/assetlinks.json \
         /humans.txt /ads.txt; do
  code=$(curl -s -o /tmp/f -w '%{http_code}' -m 8 "$BASE$p")
  [ "$code" = 200 ] && echo "== $p ==" && head -5 /tmp/f
done
```

Фрагмент вывода:

```
== /robots.txt ==
User-agent: *
Disallow: /admin/
Disallow: /api/internal/

== /.well-known/security.txt ==
Contact: mailto:soc@example.com
Expires: 2027-03-01T00:00:00Z

== /humans.txt ==
/* TEAM */
Developer: Ivan Petrov
Contact: ivan@example.com
```

Итог: обнаружены `/api/internal/` (кандидат), SOC-почта и имя разработчика с личным email — два новых pivot-идентификатора (email → см. ветку email-разведки).

## Таблица: быстрый чек-лист

| Файл | Проверять | Что искать |
|------|-----------|-----------|
| `robots.txt` | всегда | Disallow-пути, Sitemap, dev-поддомены |
| `sitemap.xml` | всегда | полный список URL, документы |
| `security.txt` | всегда | контакты, PGP, политика |
| `humans.txt` | часто | имена, email команды |
| `ads.txt` | для рекламных сайтов | партнёры, publisher ID |
| `openid-configuration` | если есть логин | IdP, эндпоинты |
| `assetlinks.json` | мобильные | package name, отпечатки |
| `mta-sts.txt` | почта | режим, MX-политика |

## Ошибки и подводные камни

- **Считать `Disallow` защитой.** Это публичный файл; запрет в нём — не контроль доступа.
- **Не проверять оба пути security.txt.** Он может лежать в корне или в `.well-known/`.
- **Игнорировать вложенные sitemap.** `sitemap_index.xml` ведёт на подкарты — обходите рекурсивно.
- **Ходить на найденные пути без авторизации.** `robots.txt` даёт гипотезы, а не разрешение; проверять их можно только в рамках scope.
- **Забывать про регистр и слеши.** `.well-known` (не `.well_known`), `/security.txt` (не `/Security.txt`).
- **Не сохранять ответы.** Служебные файлы меняются — фиксируйте снимки для истории.

## Что дальше / решение

Служебные файлы — быстрый способ получить структуру и контакты. Дальше: **TLS-фингерпринт** (`osint-tls-fingerprint`) для корреляции хостов, **email-разведка** (`osint-email-enum`) по найденным адресам, и **картирование поверхности атаки** (`osint-attack-surface`). Итог: за пару минут вы получаете карту путей, контакты команды и кандидатов на проверку — всё легально и без шума.

## Продвинутые .well-known-файлы

Помимо security.txt и OIDC, каталог `.well-known/` содержит много полезного:

| Путь | Что раскрывает |
|------|----------------|
| `/.well-known/webfinger?resource=acct:user@host` | федеративные профили |
| `/.well-known/nodeinfo` | Fediverse-инстанс |
| `/.well-known/host-meta` | метаданные хоста |
| `/.well-known/security.txt` | контакты |
| `/.well-known/matrix/client` | Matrix-сервер |
| `/.well-known/did.json` | децентрализованные идентификаторы |
| `/.well-known/gpc.json` | Global Privacy Control |
| `/.well-known/est/` | PKI-регистрация |

Проверка набора:

```bash
BASE=https://example.com
for p in webfinger?resource=acct:test@example.com nodeinfo host-meta \
         matrix/client did.json gpc.json openid-configuration; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 6 "$BASE/.well-known/$p")
  echo "$code  $p"
done
```

Каждый `200` — новый факт об инфраструктуре.

## security.txt: разбор и «hall of fame»

В `security.txt` кроме контактов бывает ссылка на страницу благодарностей (Acknowledgment). Она перечисляет исследователей и иногда — суть находок:

```bash
curl -s https://example.com/.well-known/security.txt
curl -s https://example.com/security/hall-of-fame | grep -iE 'cve|vulnerability|by '
```

Это раскрывает: зрелость программы безопасности, типы найденных уязвимостей и активных исследователей (имена → pivot).

## Автоматизация массовой проверки

По списку хостов проверяем все служебные файлы и собираем сводку:

```bash
#!/usr/bin/env bash
# wellknown-scan.sh — сбор служебных файлов по списку хостов
PATHS="/robots.txt /sitemap.xml /.well-known/security.txt /security.txt \
       /.well-known/openid-configuration /.well-known/assetlinks.json /humans.txt /ads.txt"
while read -r h; do
  for p in $PATHS; do
    out=$(curl -s -m 8 -w '%{http_code}' -o /tmp/wk "$h$p")
    if [ "$out" = "200" ]; then
      echo "=== $h$p ==="
      head -3 /tmp/wk
    fi
  done
done < hosts.txt
```

Результат — сводка служебных файлов по всем поддоменам, готовая к анализу.

## Правовые и этические границы

- Служебные файлы **публичны** — их чтение легально.
- Но найденные в `robots.txt` пути **не разрешение** на их обход/эксплуатацию.
- Не используйте найденные email для спама/соц. инженерии.
- В CTF данные вымышлены — этика проще; в реальности — строго в рамках scope.

## Поиск служебных файлов через поисковики

Иногда файлы не в корне, а в подкаталогах. Дорки:

```
site:example.com ext:txt inurl:robots
site:example.com inurl:security.txt
site:example.com intitle:"index of" sitemap
site:example.com ext:xml sitemap
```

Также ищем утёкшие служебные файлы в архивах:

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/robots.txt&output=text&limit=5"
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/sitemap.xml&output=text&limit=5"
```

Исторические версии часто содержат пути, которых уже нет на живом сайте.

## Приоритизация находок из служебных файлов

Не все найденные пути равнозначны. Приоритет:

| Путь из robots/sitemap | Приоритет |
|------------------------|-----------|
| `/admin`, `/internal`, `/api` | высокий |
| `/backup`, `/old`, `/.git`, `/.env` | высокий |
| `/staging`, `/dev`, `/test` | средний |
| `/private`, `/tmp` | средний |
| `/public`, `/assets` | низкий |

Составьте список и проверяйте по приоритету — в рамках авторизации.

## Квиз

```quiz
- question: "Что означает `Disallow: /admin/` в robots.txt с точки зрения безопасности?"
  options:
    - "Директория защищена паролем"
    - "Файл публично сообщает о существовании пути"
    - "Директория удалена"
    - "Путь доступен только ботам"
  answer: 1
- question: "Где по стандарту RFC 9116 лежит security.txt?"
  options:
    - "Только в корне"
    - "В `/.well-known/security.txt` (и, для совместимости, в корне)"
    - "В `robots.txt`"
    - "В `sitemap.xml`"
  answer: 1
- question: "Что раскрывает `/.well-known/openid-configuration`?"
  options:
    - "Пароли пользователей"
    - "Issuer и эндпоинты OIDC-провайдера"
    - "Список портов"
    - "DNS-зону"
  answer: 1
- question: "Как обходить вложенные sitemap?"
  options:
    - "Игнорировать их"
    - "Рекурсивно: sitemap_index.xml ссылается на подкарты"
    - "Скачать один раз и остановиться"
    - "Только через Shodan"
  answer: 1
- question: "Что можно извлечь из `humans.txt`?"
  options:
    - "Список CVE"
    - "Имена и контакты команды сайта"
    - "Пароли БД"
    - "Карту сети"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** в robots.txt/sitemap спрятан путь к флагу.
- **Bug bounty:** быстрый список эндпоинтов и контактов для отчёта.
- **Пентест:** стартовая карта структуры приложения без агрессивного сканирования.
- **Расследования:** найти контакты SOC/разработчиков и связать с личностями.
- **Blue team:** проверить, что ваш собственный robots.txt не раскрывает лишнего.
