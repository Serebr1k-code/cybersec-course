---
id: osint-url-analysis
title: "Анализ URL и доменов: urlscan.io, VirusTotal, MalwareBazaar"
category: osint
parent: osint-threat-intel
difficulty: medium
order: 2
tags: [urlscan, virustotal, malware, url, threat-intel]
prerequisites: [osint-threat-intel]
useful_for:
  - "Threat intel: анализ подозрительных ссылок"
  - "Blue team: triage инцидентов"
estimated_minutes: 45
summary: "Анализ URL без перехода по нему: urlscan.io, VirusTotal, MalwareBazaar, AbuseIPDB, WHOIS-корреляция и построение вердикта по домену."
---

Подозрительную ссылку не нужно открывать самому — это и опасно, и неинформативно. Вместо этого URL прогоняют через сервисы-«песочницы»: они сами заходят на страницу, рендерят её в изолированном браузере и отдают скриншот, DOM, список сетевых запросов, редиректы и вердикт антивирусов. Навык анализировать ссылку **не открывая её** — базовый для threat intel, SOC и triage фишинга.

## Анатомия подозрительного URL

Прежде чем что-то отправлять, разберите ссылку руками. Опасность часто видна ещё до сервисов:

- **Схема и юзер-инфо**: `http://user@evil.com` — часть до `@` может маскировать реальный хост; `http://example.com@evil.com/` ведёт на `evil.com`.
- **Омоглифы**: `аpple.com` (кириллическая `а`) ≠ `apple.com`. Проверяйте punycode (`xn--...`).
- **Поддомены-обманки**: `login.microsoft.com.evil.example` — реальный домен `evil.example`.
- **Длинные пути и параметры**: base64 в query, вложенные редиректы `?url=`, `?next=`, `?continue=`.
- **Расширения-двойники**: `invoice.pdf.exe`, `doc.docx.html`.
- **Нестандартные порты**: `https://example.com:8443/` — часто C2 или админка.

Быстрый разбор без запросов:

```bash
# структура URL, хост, схема, параметры
python3 - <<'PY'
from urllib.parse import urlsplit, parse_qs
u = "http://user@example.com.evil.example:8443/login?next=http%3A%2F%2Fevil.example"
p = urlsplit(u)
print("scheme:", p.scheme)
print("host  :", p.hostname)
print("port  :", p.port)
print("params:", parse_qs(p.query))
PY
```

## urlscan.io

urlscan запускает реальный браузер в песочнице и возвращает **скриншот**, **DOM**, **все сетевые запросы** (HTML/JS/CSS/шрифты/редиректы), связанные домены и IP, а также собственный вердикт по спискам.

```bash
# отправить URL на скан (нужен API-ключ, бесплатный тариф есть)
curl -s "https://urlscan.io/api/v1/scan/" -H "API-Key: $URLSCAN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://suspicious.example","visibility":"public"}'
# → {"message":"Submission successful","uuid":"...","api":"https://urlscan.io/api/v1/result/<uuid>/",...}

# получить результат по UUID (дайте 5–15 секунд)
curl -s "https://urlscan.io/api/v1/result/<uuid>/" | python3 -m json.tool

# вытащить только интересное: домены, IP, скриншот
curl -s "https://urlscan.io/api/v1/result/<uuid>/" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("verdicts:",d.get("verdicts")); print("screenshot:",d.get("task",{}).get("screenshotURL")); print("domains:",[r["domain"] for r in d.get("data",{}).get("requests",[])])'

# поиск уже сделанных сканов по домену (без ключа)
curl -s "https://urlscan.io/api/v1/search/?q=domain%3Aexample.com&size=100" \
  | python3 -c 'import sys,json;[print(r["page"]["url"]) for r in json.load(sys.stdin)["results"]]'
```

Что искать в результате: цепочку **редиректов** (куда реально ведёт ссылка), какие **сторонние скрипты** грузятся (фишинг-киты часто тянут JS с захваченных доменов), **favicon-хэш** и **TLS-сертификат** (совпадение с известным набором — сильный признак кампании).

## VirusTotal

Мультиантивирусный вердикт по URL, домену, IP, файлу и хэшу. Плюс passive DNS, история WHOIS, коммуникации (граф связей), сигнатуры и поведенческие отчёты.

```bash
# вердикт по URL: сначала получаем id (base64url без паддинга)
curl -s "https://www.virustotal.com/api/v3/urls" -H "x-apikey: $VT_KEY" \
  --data-urlencode "url=http://suspicious.example" | python3 -m json.tool

# вердикт по домену: детекты, WHOIS, DNS, связанные файлы
curl -s "https://www.virustotal.com/api/v3/domains/example.com" -H "x-apikey: $VT_KEY" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"]["attributes"];print("stats:",d["last_analysis_stats"]);print("whois:",d.get("whois","")[:400])'

# по хэшу файла — что это за малварь
curl -s "https://www.virustotal.com/api/v3/files/<sha256>" -H "x-apikey: $VT_KEY" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin)["data"]["attributes"];print(d["last_analysis_stats"]);print(d.get("popular_threat_classification"))'

# passive DNS: какие IP исторически были у домена
curl -s "https://www.virustotal.com/api/v3/domains/example.com/resolutions?limit=40" \
  -H "x-apikey: $VT_KEY" | python3 -c 'import sys,json;[print(r["attributes"]["ip_address"], r["attributes"]["date"]) for r in json.load(sys.stdin)["data"]]'
```

VT-«граф» (relationships: `communicating_files`, `referrer_files`, `resolutions`, `siblings`) — главный инструмент **пивотинга**: от одного URL к целой инфраструктуре кампании.

## MalwareBazaar, URLhaus и ThreatFox

Экосистема abuse.ch — бесплатные базы без ключей:

- **MalwareBazaar** (`bazaar.abuse.ch`) — образцы malware: семейство, теги, подписи, imphash, ssdeep.
- **URLhaus** — база вредоносных URL, привязанных к распространению малвари.
- **ThreatFox** — обмен IOC (IP/домен/URL/хэш) с контекстом кампании.
- **YARA**-правила (`yara.rules`) для детекта.

```bash
# MalwareBazaar: инфо по хэшу
curl -s "https://mb-api.abuse.ch/api/v1/" -d "query=get_info&hash=<sha256>" | python3 -m json.tool

# MalwareBazaar: образцы по тегу семейства
curl -s "https://mb-api.abuse.ch/api/v1/" -d "query=get_taginfo&tag=Emotet&limit=10"

# URLhaus: статус URL
curl -s "https://urlhaus-api.abuse.ch/v1/url/" -d "url=http://suspicious.example/payload"
```

## AbuseIPDB и репутация IP

Когда из urlscan/VT вы достали IP хостинга, проверьте его репутацию и «соседей»:

```bash
# AbuseIPDB: репутация IP (жалобы, счётчик abuse)
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90" \
  -H "Key: $ABUSE_KEY" -H "Accept: application/json" | python3 -m json.tool

# ASN и префикс IP — понять хостера (bulletproof hosting?)
curl -s "https://api.bgpview.io/ip/1.2.3.4" | python3 -m json.tool

# reverse IP: какие ещё домены на этом IP (пассивно, через VT)
curl -s "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/resolutions" -H "x-apikey: $VT_KEY" | head -c 2000
```

## WHOIS-корреляция и свежесть

Возраст домена — ключевой признак фишинга: свежая регистрация (дни/недели) + приватный WHOIS = сильное подозрение.

```bash
whois example.com | grep -iE 'creation|created|registrar|expiry|updated'
# Registrar Abuse Contact Email / Registrant Organization — ищите общий регистрант между доменами
```

Свяжите домены по **общему регистранту**, **общему email в WHOIS**, **общему TLS-сертификату**, **общему favicon-хэшу** — это выводит на всю кампанию.

## Автоматизация: скрипт построения вердикта

Соберите всё в один пайплайн, чтобы не бегать по веб-интерфейсам:

```bash
#!/usr/bin/env bash
# triage_url.sh — быстрый вердикт по домену
set -euo pipefail
D="$1"
echo "== DNS =="; dig +short "$D" A; dig +short "$D" NS; dig +short "$D" MX
echo "== WHOIS age =="; whois "$D" | grep -iE 'creation|created' | head -2
echo "== VT =="; curl -s "https://www.virustotal.com/api/v3/domains/$D" -H "x-apikey: $VT_KEY" \
  | python3 -c 'import sys,json;a=json.load(sys.stdin)["data"]["attributes"];print(a["last_analysis_stats"])'
echo "== urlscan =="; curl -s "https://urlscan.io/api/v1/search/?q=domain%3A$D" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["results"]),"scans")'
```

## Построение вердикта

Не полагайтесь на один источник — сводите сигналы в шкалу:

1. **urlscan** → скриншот, редиректы, загружаемые ресурсы.
2. **VirusTotal** → детекты URL/домена/файла + passive DNS.
3. **MalwareBazaar/URLhaus** → привязка к семейству малвари.
4. **AbuseIPDB** → репутация IP хостинга.
5. **WHOIS** → возраст и регистрант.
6. Итог: **malicious / phishing / suspicious / clean** — с перечислением доказательств и уровнем уверенности.

## Частые ошибки

- **Открывать ссылку в своём браузере** — риск компрометации; только песочница сервиса.
- **Доверять одному сервису** — детекты различаются; сверяйте VT + urlscan + AbuseIPDB.
- **Игнорировать дату вердикта** — старый отчёт не отражает текущее состояние домена (домен мог сменить владельца или «очиститься»).
- **Считать 0 детектов чистотой** — свежий вредонос ещё не попал в базы; смотрите поведение в urlscan.
- **Не смотреть редиректы** — чистый первый URL может вести на малварь через JS/мета-редирект.
- **Забыть про приватность скана** — `visibility:"public"` публикует ваш скан; для внутренних ссылок используйте `unlisted`/`private`.

## Продвинутый анализ редиректов и цепочек

Ссылка может вести на чистый первый домен, а малварь — за цепочкой редиректов. Отслеживайте **всю** цепочку:

```bash
# цепочка редиректов без выполнения JS
curl -sIL "http://suspicious.example" -o /dev/null -w '%{url_effective}\n'

# заголовки и Location каждого шага
curl -sI "http://suspicious.example" | grep -iE 'location|server|content-type'
```

JS-редиректы (`window.location`, мета-обновление) curl не выполнит — их видно в urlscan/DOM. Проверяйте **оба** типа.

## Хостинг, ASN и репутация инфраструктуры

```bash
# ASN и владелец хостинга
curl -s "https://api.bgpview.io/ip/1.2.3.4" | jq '.data.prefixes[0].asn'
# репутация IP
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4" -H "Key: $ABUSE_KEY" | jq '.data.abuseConfidenceScore'
```

**Bulletproof hosting** (ASN с массой жалоб) — сильный сигнал вредоносности. Сверяйте ASN с известными «плохими» провайдерами.

## Хэши файлов и pivot на образцы

Если urlscan/VT показывают скачанный файл — переходите к образцу:

```bash
# по хэшу: семейство, поведение, IOCs
curl -s "https://www.virustotal.com/api/v3/files/<sha256>" -H "x-apikey: $VT_KEY" \
  | jq '.data.attributes | {last_analysis_stats, popular_threat_classification, type_description}'
# MalwareBazaar: скачать образец (осторожно, в изолированной среде)
curl -s "https://mb-api.abuse.ch/api/v1/" -d "query=get_file&sha256_hash=<sha256>" -o sample.zip
```

## Квиз

```quiz
- question: "Что даёт urlscan.io?"
  options:
    - "Только вердикт антивирусов"
    - "Скриншот, DOM, сетевые запросы и связанные ресурсы страницы"
    - "Пароли сайта"
    - "Спутниковые снимки"
  answer: 1
- question: "Почему нельзя открывать подозрительную ссылку локально?"
  options:
    - "Это медленно"
    - "Риск компрометации — используйте песочницу сервиса"
    - "Ссылка не откроется"
    - "Так требует API"
  answer: 1
- question: "Что такое AbuseIPDB?"
  options:
    - "База malware-образцов"
    - "Репутация IP по жалобам"
    - "Реестр доменов"
    - "Сервис спутников"
  answer: 1
- question: "Почему 0 детектов не означает чистоту?"
  options:
    - "VirusTotal всегда врёт"
    - "Свежий вредонос может ещё не попасть в базы"
    - "Детекты не важны"
    - "Нужно заплатить"
  answer: 1
- question: "Какой признак домена усиливает подозрение?"
  options:
    - "Старая дата регистрации"
    - "Свежая регистрация и приватные WHOIS-данные"
    - "Наличие MX-записи"
    - "Высокий TTL"
  answer: 1
```

## Где пригодится

- **CTF:** анализ подозрительных ссылок в задачах threat intel.
- **Blue team:** triage фишинга и IOC без риска для рабочей станции.
- **Bug bounty:** оценка связанных доменов, зеркал и «теневой» инфраструктуры.
- **Работа SOC:** быстрое построение вердикта по URL и приоритизация алертов.
