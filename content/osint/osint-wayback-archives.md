---
id: osint-wayback-archives
title: "Веб-архивы: Wayback Machine, archive.today и исторический DNS"
category: osint
parent: osint-search-dorking
difficulty: easy
order: 1
tags: [wayback, archive, historical, dns-history, cache]
prerequisites: [osint-search-operators]
useful_for:
  - "Поиск удалённого контента"
  - "CTF категория OSINT"
  - "Bug bounty recon"
estimated_minutes: 40
summary: "Как доставать удалённые страницы, старые версии сайтов, исторические DNS-записи и кэш; API Wayback и archive.today."
---

Сайт меняется: страницы удаляют, ссылки прячут, конфиги закрывают. Но интернет **помнит**. Веб-архивы хранят снимки страниц по датам, а исторический DNS — прошлые IP и поддомены. Это один из самых недооценённых источников OSINT.

## Wayback Machine

**web.archive.org** периодически снимает копии сайтов. Для OSINT это означает доступ к тому, что уже удалили.

Как использовать:

1. Введите URL в `web.archive.org`.
2. Откройте **календарь** — выберите дату снимка.
3. Сравните старую и текущую версию (diff).
4. Ищите **старые ссылки**, которые сейчас отдают 404.

Полезные фишки:

- Скачать **все** URL из архива домена: `http://web.archive.org/cdx/search/cdx?url=example.com&output=text&fl=original&collapse=urlkey`
- Фильтр по коду/типу: `&filter=statuscode:200&filter=mimetype:text/html`

```bash
# Все уникальные URL из архива
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&collapse=urlkey" | sort -u
```

Это даёт карту прошлых страниц: `/admin`, `/backup.zip`, `/api/v1/...` — часто уже закрытых, но дающих понимание структуры.

## archive.today

**archive.ph / archive.today** — второй крупный архив, снимает «на лету» и хранит снимки, которых нет в Wayback. Особенно полезен для новостных и динамических страниц. Поддерживает поиск по URL и полнотекстовый поиск.

## Google Cache и другие кэши

- **Google Cache** (`cache:` в поиске, часто недоступен) — свежая копия.
- **Bing Cache** — через `cc.bingj.com`.
- **Яндекс.Сохранённая копия** — в результатах поиска.

Кэш лучше архива тем, что показывает **недавнее** состояние (часы-дни), а архив — долгую историю.

## Исторический DNS и поддомены

Архивы страниц — не единственное. **Историю DNS** хранят:

| Сервис | Что даёт |
|---|---|
| SecurityTrails | исторические A/MX/NS/TXT, поддомены |
| ViewDNS.info | history, reverse IP, DNS report |
| DNSdumpster | карта поддоменов |
| crt.sh | поддомены из TLS-сертификатов |
| urlscan.io | что сканер видел на домене |

Старые A-записи показывают **прошлые хостинги**, а MX/TXT — смену почтовых провайдеров и SPF. Иногда «мертвый» поддомен в прошлом указывал на dev-сервер.

## Recon через архив: рабочий конвейер

```bash
# 1. Все URL из Wayback
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&fl=original&collapse=urlkey" \
  | sort -u > wayback_urls.txt

# 2. Отфильтровать интересное
grep -Ei 'admin|api|backup|\.zip|\.sql|config|\.env|token' wayback_urls.txt

# 3. Проверить, что живо сейчас
while read -r u; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$u")
  [ "$code" != "404" ] && echo "$code $u"
done < wayback_urls.txt | sort -u
```

> `waybackurls` и `gau` (getallurls) автоматизируют шаги 1–2.

## Сравнение версий

Если интересна **эволюция** сайта (когда добавили страницу, когда убрали), откройте два снимка разных дат и сделайте diff:

```bash
curl -s "http://web.archive.org/web/2020/https://example.com/robots.txt" > old.txt
curl -s "https://example.com/robots.txt" > new.txt
diff old.txt new.txt
```

`robots.txt` в архиве часто раскрывает пути, которые сейчас скрыты.

## Частые ошибки

- **Думать, что архив полный**: часть страниц никогда не снималась.
- **Забывать про `collapse=urlkey`** — получите тысячи дублей.
- **Игнорировать даты**: старый IP может быть чужим сейчас.
- **Путать кэш поисковика и Wayback** — это разные вещи.
- **Считать 404 в архиве недоступным** — сам снимок может быть жив по ссылке `/web/<timestamp>/`.

## Инструменты автоматизации архива

Ручной сбор URL не масштабируется. Используйте:

- **waybackurls** — все URL из Wayback для домена.
- **gau (getallurls)** — Wayback + Common Crawl + OTX + URLScan.
- **waymore** — более глубокий обход Wayback (с пагинацией).

```bash
# все URL из нескольких источников
gau example.com | sort -u > urls.txt
waybackurls example.com | sort -u >> urls.txt

# фильтр по интересному
grep -Ei 'admin|api|backup|\.zip|\.sql|config|\.env|token|swagger' urls.txt | sort -u
```

Дальше — проверка живости через `httpx` (см. osint-subdomain-tools).

## URLScan и Common Crawl

Помимо Wayback есть другие архивы веба:

- **urlscan.io** — хранит скриншоты, DOM и запросы сканированных страниц (см. osint-url-analysis).
- **Common Crawl** — огромный корпус веб-страниц; поиск по индексу даёт исторические URL и контент.
- **archive.today** — «на лету» сохраняет страницы, которых нет в Wayback.

```bash
# Common Crawl: индекс по домену (через коллаб-инструменты или CDX-подобный API)
# urlscan: поиск прошлых сканов
curl -s "https://urlscan.io/api/v1/search/?q=domain%3Aexample.com" | jq '.results[].page.url'
```

## Дифф контента во времени

Историю удобно превращать в **изменения**:

```bash
# robots.txt до/после — что скрыли
curl -s "http://web.archive.org/web/2021/https://example.com/robots.txt" > old_robots.txt
curl -s "https://example.com/robots.txt" > new_robots.txt
diff old_robots.txt new_robots.txt

# ключевые страницы: сравнить версии
diff <(curl -s "http://web.archive.org/web/2022/https://example.com/") \
     <(curl -s "https://example.com/")
```

Disallow-строки, исчезнувшие из robots.txt, часто указывают на закрытые разделы, которые всё ещё существуют.

## CDX API: машинный доступ к Wayback

`web.archive.org/cdx/search/cdx` — основной интерфейс для скриптов: отдаёт таблицу снимков (timestamp, original, mimetype, statuscode, digest).

```bash
# все снимки домена (JSON)
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=digest&limit=5000"
# параметры:
#   url=example.com*   — wildcard по поддоменам
#   matchType=domain   — только домен
#   from=2015 to=2020  — диапазон дат
#   filter=statuscode:200
#   collapse=urlkey    — по одному снимку на URL
#   output=json|text
```

`collapse=digest` убирает дубликаты по содержимому — остаются **уникальные** версии страниц.

## waybackurls и gau: массовый сбор URL

Из архива можно вытащить все когда-либо проиндексированные URL — это кладезь для поиска забытых эндпоинтов.

```bash
# waybackurls: все URL из Wayback для списка доменов
echo example.com | waybackurls | sort -u > urls.txt
# gau (GetAllUrls): Wayback + Common Crawl + AlienVault OTX
gau example.com --threads 5 --subs > gau_urls.txt
# фильтрация интересного
grep -Ei '\.(js|json|env|bak|sql|zip|config)$' urls.txt | sort -u
# поиск параметров для дальнейшего теста
grep -E '\?' urls.txt | cut -d'?' -f2 | tr '&' '\n' | cut -d= -f1 | sort -u
```

Особенно ценны **старые JS-файлы**: в них остаются внутренние API-пути, ключи и dev-эндпоинты.

## Исторический DNS и поддомены

DNS-история показывает IP и поддомены, которых уже нет в живых.

```bash
# SecurityTrails API: исторический DNS
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" -H "APIKEY: $ST_KEY" | jq
# поддомены
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" -H "APIKEY: $ST_KEY" | jq -r '.subdomains[]'
# ViewDNS / DNSdumpster — веб-аналоги; passive DNS (PassiveTotal, VirusTotal)
```

Исторический A-запись → старый IP → возможно, ещё живой сервер без CDN (origin-hunting, osint-cdn-origin).

## Дифф контента во времени

Сравнение версий вскрывает удалённую функциональность, тестовые страницы и утечки.

```bash
# скачать две версии
curl -s "http://web.archive.org/web/20180101000000id_/http://example.com/" > old.html
curl -s "http://web.archive.org/web/20240101000000id_/http://example.com/" > new.html
# diff (id_ отдаёт оригинал без обвязки Wayback)
diff -u old.html new.html | head -100
```

Ищите: удалённые ссылки на `staging`/`dev`, старые email, закомментированные ключи, изменённые эндпоинты. В старых JS — устаревшие API-ключи (проверяйте валидность в рамках авторизации).

## URLScan и Common Crawl

- **URLScan** — база сканов с DOM, скриншотами, запросами; API даёт поиск по домену и ресурсам.
- **Common Crawl** — петабайты веб-данных с открытым индексом.

```bash
# URLScan: поиск по домену
curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com" | jq -r '.results[].page.url'
# URLScan: получить DOM и запросы конкретного скана
curl -s "https://urlscan.io/api/v1/result/<uuid>/" | jq '.data.requests[].request.request.url'
# Common Crawl: индекс
curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=example.com/*&output=json" | head
```

URLScan часто хранит **скриншоты** страниц — удобно для визуального сравнения, когда оригинала уже нет.

## Скриншоты и визуальная история

```bash
# Wayback screenshot API (последний снимок страницы картинкой)
curl -s "https://archive.org/wayback/available?url=example.com" | jq
# URLScan даёт PNG для каждого скана
curl -s "https://urlscan.io/screenshots/<uuid>.png" -o shot.png
```

Сравнение скриншотов по годам показывает редизайны, смену логотипов, добавление новых сервисов — полезно для атрибуции и таймлайна.

## Частые ошибки и ограничения

- **Забыть `id_`** — без него Wayback отдаёт страницу с обвязкой архива и переписанными ссылками.
- **Игнорировать `collapse`** — тысячи дублей забивают выдачу.
- **Верить дате снимка как дате изменения** — Wayback мог сохранить старую версию позже.
- **Rate-limit**: CDX при больших запросах тормозит/429 — дробите по датам и делайте паузы.
- **robots/exclusions**: часть URL не архивируется — отсутствие снимка ≠ отсутствие страницы.
- **Юридически**: архивные секреты, найденные в JS, — всё ещё секреты; не эксплуатируйте без авторизации.

## Квиз

```quiz
- question: "Что хранит Wayback Machine?"
  options:
    - "Исторические снимки страниц по датам"
    - "Пароли сайтов"
    - "Только главную страницу"
    - "Будущие версии сайта"
  answer: 0
- question: "Какой параметр CDX API убирает дубликаты URL?"
  options:
    - "`collapse=urlkey`"
    - "`filter=statuscode`"
    - "`output=json`"
    - "`limit=100`"
  answer: 0
- question: "Зачем искать URL в Wayback для пентеста?"
  options:
    - "Найти старые/удалённые эндпоинты, которые могут быть всё ещё доступны"
    - "Получить пароль администратора"
    - "Ускорить сайт"
    - "Это бесполезно"
  answer: 0
- question: "Что даёт исторический DNS (SecurityTrails)?"
  options:
    - "Прошлые A/MX/NS-записи и поддомены"
    - "Пароли email"
    - "Содержимое страниц"
    - "Только текущий IP"
  answer: 0
- question: "Чем кэш поисковика отличается от архива?"
  options:
    - "Кэш показывает недавнее состояние, архив — долгую историю"
    - "Ничем"
    - "Кэш хранит только картинки"
    - "Архив обновляется каждую минуту"
  answer: 0
```

## Где пригодится

- **Bug bounty:** поиск забытых эндпоинтов и параметров через `waybackurls`/`gau`.
- **CTF (OSINT):** найти удалённую страницу с флагом.
- **Расследования:** восстановить изменённый контент.
- **Пентест:** восстановить структуру приложения до закрытия разделов.
