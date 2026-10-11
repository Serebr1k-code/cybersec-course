---
id: osint-shodan-dorks
title: "Мастерство Shodan/Censys: фильтры, дорки и API"
category: osint
parent: osint-infra-artifacts
difficulty: medium
order: 1
tags: [shodan, censys, fofa, zoomeye, filters, api]
prerequisites: [osint-infrastructure]
useful_for:
  - "Attack surface management"
  - "Bug bounty и пентест"
  - "CTF категория OSINT"
estimated_minutes: 45
summary: "Продвинутые фильтры Shodan и Censys, дорки по сервисам, работа с API и экспорт результатов для анализа."
---

Shodan — не «поиск сайтов», а **поисковик по баннерам сервисов**. Он уже просканировал интернет и проиндексировал ответы: HTTP-заголовки, TLS-сертификаты, баннеры БД, промышленные протоколы. Умение строить запросы = умение мгновенно находить чужую инфраструктуру, не отправляя ни одного пакета на цель.

## Как думать о Shodan

Каждое устройство в интернете Shodan периодически опрашивает и сохраняет **banner** — то, что оно ответило. Запрос в Shodan — это фильтр по полям баннера. Ничего не сканируется «вживую» — вы работаете по кэшу. Из этого следуют два практических правила:

- **Данные могут быть устаревшими** (от недель до месяцев) — критичную находку всегда верифицируйте вручную.
- **Пассивность** — запрос к Shodan не касается цели, значит не виден её IDS. Идеально для ранней разведки.

## Основные фильтры

| Фильтр | Значение | Пример |
|---|---|---|
| `net:` | CIDR / ASN | `net:203.0.113.0/24` |
| `hostname:` | имя хоста | `hostname:example.com` |
| `port:` | порт | `port:8080` |
| `country:` | страна | `country:RU` |
| `org:` | организация | `org:"Acme"` |
| `os:` | ОС | `os:Windows` |
| `product:` | продукт | `product:nginx` |
| `version:` | версия | `version:1.18` |
| `http.title:` | `<title>` | `http.title:"Grafana"` |
| `http.html:` | HTML-содержимое | `http.html:"dashboard"` |
| `http.status:` | код ответа | `http.status:200` |
| `http.component:` | JS-фреймворк | `http.component:"jQuery"` |
| `ssl:` / `ssl.cert.subject.cn:` | TLS | `ssl:"example.com"` |
| `vuln:` | известная уязвимость | `vuln:CVE-2021-44228` |
| `has_screenshot:` | есть скриншот | `has_screenshot:true` |
| `asn:` | номер AS | `asn:AS15169` |

Логика: **пробел = AND**, `|`/`OR` — альтернатива, `-` — исключение, `"..."` — точная фраза. Скобки задают приоритет: `(http.title:"Grafana" OR http.title:"Kibana") country:DE`.

## Классические дорки

```
# Открытые веб-камеры и IoT
http.title:"Network Camera"
server: SQ-WEBCAM
has_screenshot:true port:554

# Базы данных наружу
port:27017 -authentication   # MongoDB без авторизации
port:6379 -authentication    # Redis без пароля
port:9200 http.title:"Kibana"
port:5432 "PostgreSQL"

# DevOps и панели
http.title:"Grafana"
http.title:"Jenkins"
product:ElasticSearch
http.favicon.hash:-305179312  # Jenkins по хэшу иконки

# Утечки через директории
http.title:"Index of /"

# Инфраструктура конкретной организации
org:"Example Inc" port:22
ssl.cert.subject.cn:example.com
asn:AS15169 port:443
```

Фильтр `http.favicon.hash` особенно ценен: одинаковый favicon = одинаковая технология, даже если заголовки изменены. Хэш берётся из `https://www.shodan.io/search?query=http.favicon.hash:-305179312`.

## Censys, FOFA, ZoomEye

- **Censys** — сильнее в TLS-сертификатах и точных полях. Синтаксис: `services.http.response.html_title: "..."`, `services.tls.certificates.leaf_data.names: example.com`, `services.service_name: HTTP`.
- **FOFA** (`fofa.info`) — популярен в азиатском регионе, мощные фильтры `body=`, `cert=`, `domain=`, `title=`, `port=`, `icon_hash=`.
- **ZoomEye** — аналогично, хорош для IoT и устройств.
- **Shodan** — лучший обзор, Screenshots и Facets.

Комбинируйте: если в Shodan пусто, часто найдётся в FOFA/Censys из-за разного покрытия и частоты сканирования.

```text
# FOFA
cert="example.com"
title="Grafana" && country="RU"
icon_hash="-305179312"

# Censys
services.http.response.html_title: "Grafana"
services.tls.certificates.leaf_data.subject.common_name: example.com
```

## Работа с API

Без API большой объём не собрать. Shodan CLI:

```bash
shodan init <API_KEY>

# Поиск и выгрузка JSON
shodan search --fields ip_str,port,http.title 'org:"Example Inc" port:443' | head

# Разбор домена (поддомены + их IP)
shodan domain example.com

# Хосты организации + статистика по портам (facets)
shodan stats --facets port 'org:"Example Inc"'
shodan stats --facets product 'net:203.0.113.0/24'

# Информация о конкретном хосте
shodan host 93.184.216.34

# Количество результатов без выгрузки
shodan count 'product:nginx country:RU'
```

Censys API через `curl`:

```bash
curl -s https://search.censys.io/api/v2/hosts/search \
  -u "$CENSYS_ID:$CENSYS_SECRET" \
  --data-urlencode 'q=services.http.response.html_title: "Jenkins"' \
  -d per_page=50 | jq '.result.hits[].ip'
```

> Уважайте лимиты API. Сохраняйте результаты локально, чтобы не тратить квоту повторно. Для Shodan бесплатный план даёт ~1 запрос/сек и ограничение на `search`; `host`/`domain` дешевле.

## Конвейер анализа

1. **Собрать** — запрос по `net:`/`org:`/`ssl.cert`.
2. **Нормализовать** — `jq` в CSV: IP, порт, продукт, версия.
3. **Обогатить** — сматчить с CVE по продукту/версии.
4. **Верифицировать** — проверить критичные находки вручную (`curl -I`), не слепо доверять кэшу.
5. **Отчёт** — список хостов с пометкой, что подтверждено.

```bash
shodan search --fields ip_str,port,product,version \
  'org:"Example Inc"' --limit 1000 > raw.json
jq -r '.matches[] | [.ip_str,.port,.product,.version] | @tsv' raw.json \
  | sort -u > assets.tsv
```

## Разобранный пример

Задача: найти все серверы организации `Acme` с открытым SSH и их версии.

```
org:"Acme" port:22
```

Через API:

```bash
shodan search --fields ip_str,port,product,version 'org:"Acme" port:22' > acme_ssh.json
jq -r '.[] | "\(.ip_str)\t\(.product) \(.version)"' acme_ssh.json | sort -u
```

Далее — сопоставить версии с CVE (например, старый OpenSSH → известные уязвимости). Второй проход: по найденным IP запросить `shodan host` и вытащить все порты каждого хоста, а не только 22.

## Частые ошибки

- Считать Shodan живым сканером: данные могут быть **устаревшими** (месяцы).
- Не проверять находку вручную → ложные срабатывания.
- Превышать квоту API → блокировка.
- Путать `org:` (по баннеру/владельцу) с реальным владением.
- Забывать про Censys/FOFA → терять покрытие.
- Игнорировать `-` и `OR`: без них запрос слишком широкий и тонет в результатах.

## Что делать дальше / решение

- **Нужны все активы организации** → `shodan stats --facets port,product org:"..."`, затем `search` по каждому интересному порту.
- **Нужен конкретный сервис** → дорк по `http.title:`/`product:`/`favicon.hash`, затем ручная проверка.
- **Нужен охват TLS** → `ssl.cert.subject.cn:` и Censys `services.tls.certificates`.
- **Нужны свежие данные** → включите Shodan Monitor/Alert на нужный диапазон.
- **Нужна привязка к ASN** → `asn:ASxxxx` + урок `osint-bgp` для расширения на все префиксы.

## Screenshots и визуальная разведка

Shodan делает скриншоты HTTP-сервисов. Фильтр `has_screenshot:true` отсекает сервисы без картинки, а при доступе к скриншотам можно глазами опознать панели, принтеры, камеры и роутеры. Комбинируйте: `product:nginx has_screenshot:true http.title:"Login"` — это быстрее, чем открывать сотни хостов вручную. Censys отдаёт `services.http.response.favicons` и скриншоты в ответе API.

## Алерты и мониторинг

Shodan Monitor/Alert следит за диапазоном и шлёт уведомление при новом открытом порте или уязвимости. Для пентеста полезно и обратное: подписка на диапазон цели показывает, что её администраторы заметили и закрыли сервис. Дешёвая альтернатива без платного тарифа — периодически прогонять `shodan count '<запрос>'` и сравнивать число результатов между запусками.

## CVE и уязвимости в Shodan

Фильтр `vuln:` ищет хосты, помеченные известными CVE. Это не «подтверждённая уязвимость», а указание, что версия/конфигурация попадает под подозрение:

```
vuln:CVE-2021-44228              # Log4Shell
product:"Apache httpd" version:"2.4.49"   # путь-траверсал CVE-2021-41773
product:"OpenSSH" version:"7.4"
```

В Censys аналог — поля `services.software` и `labels`. Всегда сверяйте версию с официальным диапазоном CVE: баннер может врать (`Server:` подделывается), а патч мог быть уже применён.

## Интеграция с конвейером recon

Результаты Shodan удобно сливать с остальными источниками:

```bash
# активы организации -> IP -> живой веб
shodan search --fields ip_str,port --limit 1000 'org:"Acme"' \
  | awk '{print $1":"$2}' | sort -u > acme_ports.txt
cut -d: -f1 acme_ports.txt | sort -u | httpx -silent -title -tech-detect
```

Дальше: `nmap` по найденным портам (для подтверждения), `nuclei` по HTTP-хостам (для шаблонных проверок), сопоставление с `osint-bgp` (какие ASN) и `osint-cert-transparency` (какие имена). Так пассивные данные Shodan становятся картой поверхности до единого пакета на цель.

## Этика, закон и границы

Shodan показывает только **публично доступное**, но это не значит, что всё можно трогать:

- Просмотр баннера в кэше — пассивно и безопасно.
- **Подключение** к найденному сервису (особенно БД/панели) — уже активное действие и может быть нарушением.
- Не выгружайте и не публикуйте персональные данные из открытых баз.
- В bug bounty сверяйтесь с правилами программы: часть активов вне scope даже если они ваши «по баннеру».
- Фиксируйте время запроса: кэш Shodan быстро устаревает, и через неделю находка может не воспроизводиться.

## Шпаргалка по синтаксису

| Задача | Запрос |
|---|---|
| активы организации | `org:"Acme"` |
| диапазон | `net:203.0.113.0/24` |
| конкретный продукт+версия | `product:nginx version:1.18` |
| по TLS-имени | `ssl.cert.subject.cn:example.com` |
| по favicon | `http.favicon.hash:-305179312` |
| по уязвимости | `vuln:CVE-2021-44228` |
| только с картинкой | `has_screenshot:true` |
| исключить | `... -http.title:"404"` |

## Как читать баннер Shodan

Один результат — это JSON с полями `ip_str`, `port`, `product`, `version`, `os`, `hostnames`, `domains`, `http`, `ssl` и `data` (сырой баннер). Разбор:

```bash
shodan host 93.184.216.34 | sed -n '1,40p'
```

- `data` — сырой ответ; здесь видны заголовки, редиректы, подсказки о фреймворке.
- `http.components` — технологии (jQuery, PHP, nginx).
- `ssl.cert.subject.cn` — имя из сертификата; `ssl.cert.expired` — просрочка.
- `hostnames`/`domains` — обратные имена, найденные Shodan.

Умение читать эти поля отличает «нашёл IP» от «понял, что там за сервис».

## Квиз

```quiz
- question: "Что индексирует Shodan?"
  options:
    - "Баннеры сервисов, полученные при периодическом сканировании"
    - "Только HTML-страницы"
    - "Пароли пользователей"
    - "Только домены"
  answer: 0
- question: "Какой фильтр Shodan ищет по диапазону/ASN?"
  options:
    - "`net:`"
    - "`site:`"
    - "`ip:`"
    - "`range:`"
  answer: 0
- question: "Что означает запрос `port:27017 -authentication`?"
  options:
    - "MongoDB без включённой аутентификации"
    - "Открытый SSH"
    - "Веб-камера"
    - "Jenkins"
  answer: 0
- question: "Зачем нужен Shodan API?"
  options:
    - "Для массового поиска и выгрузки результатов в структурированном виде"
    - "Для взлома серверов"
    - "Для отправки email"
    - "Он не нужен"
  answer: 0
- question: "Что делать после находки критичного сервиса в Shodan?"
  options:
    - "Проверить его вручную (curl -I / баннер), не доверяя кэшу слепо"
    - "Сразу сообщать в отчёт как подтверждённое"
    - "Игнорировать"
    - "Публиковать в интернете"
  answer: 0
```

## Где пригодится

- **Bug bounty**: быстрый поиск активов организации, включая неочевидные порты.
- **Attack surface management**: инвентаризация внешних сервисов.
- **CTF (OSINT)**: найти «спрятанный» сервис по подсказке.
- **Пентест**: приоритизация целей до активного сканирования.
