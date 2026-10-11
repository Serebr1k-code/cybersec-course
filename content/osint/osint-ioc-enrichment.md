---
id: osint-ioc-enrichment
title: "Обогащение и пивотинг индикаторов (IOC)"
category: osint
parent: osint-threat-intel
difficulty: medium
order: 3
tags: [ioc, enrichment, pivoting, threat-intel, mitre]
prerequisites: [osint-threat-intel]
useful_for:
  - "Threat intel: обогащение индикаторов"
  - "Blue team: приоритизация алертов"
estimated_minutes: 52
summary: "Что такое IOC, как обогащать индикаторы (IP/домен/хэш/email) через сервисы, пивотинг на связанные сущности и оценка уверенности."
---

IOC (Indicator of Compromise) — наблюдаемый признак компрометации: IP, домен, URL, хэш файла, email, строка реестра. Сам по себе индикатор почти бесполезен — «1.2.3.4» ничего не говорит аналитику. Ценность даёт **обогащение** (добавление контекста) и **пивотинг** (переход к связанным сущностям). Это ядро ежедневной работы threat intel и SOC.

## Типы индикаторов

| Тип | Пример | Что обогащаем |
|---|---|---|
| IP | `1.2.3.4` | ASN, гео, репутация, passive DNS, открытые порты |
| Домен | `evil.example` | WHOIS, CT-логи, passive DNS, детекты, категория |
| URL | `http://.../payload` | urlscan, VT, категория, редиректы |
| Хэш | `sha256:...` | VT, MalwareBazaar, семейство, imphash |
| Email | `a@evil.example` | breach-базы, SPF, соцсети, регистрант |
| SSL/TLS | `sha1` сертификата | все домены с тем же cert (CT) |
| JARM/favicon | отпечаток | все C2 того же инструмента |

## Обогащение через API

Обогащение — это автоматический сбор контекста по каждому индикатору. Примеры бесплатных/условно-бесплатных API:

```bash
# IP → репутация и жалобы
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90" \
  -H "Key: $ABUSE_KEY" -H "Accept: application/json" | python3 -m json.tool

# IP → ASN, префикс, владелец сети
curl -s "https://api.bgpview.io/ip/1.2.3.4" | python3 -m json.tool

# домен → вердикт антивирусов + passive DNS + WHOIS
curl -s "https://www.virustotal.com/api/v3/domains/evil.example" -H "x-apikey: $VT_KEY" \
  | python3 -c 'import sys,json;a=json.load(sys.stdin)["data"]["attributes"];print(a["last_analysis_stats"])'

# хэш → семейство и контекст
curl -s "https://mb-api.abuse.ch/api/v1/" -d "query=get_info&hash=<sha256>" | python3 -m json.tool

# домен → категория и связанные индикаторы (OTX)
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/evil.example/general" | python3 -m json.tool
```

Агрегаторы и платформы: **MISP** (self-hosted sharing), **OpenCTI** (граф знаний), **AlienVault OTX**, **ThreatFox**, **Pulsedive**, **GreyNoise** (отсеивает «шумный» интернет-скан от целевого).

## Пивотинг

Пивотинг — это переход от одного индикатора к другим через **общие атрибуты**. Именно он превращает одну строку в карту инфраструктуры:

- **IP → все домены на нём** (passive DNS, reverse IP).
- **Домен → все IP, где он встречался** (passive DNS, история резолва).
- **Хэш → другие файлы того же семейства** (imphash, ssdeep, «похожие образцы»).
- **TLS-сертификат → все домены с тем же cert** (crt.sh / Censys по fingerprint).
- **JARM/favicon-хэш → все C2 того же инструмента** (Cobalt Strike, Metasploit).
- **Email → все домены регистранта** (reverse WHOIS).
- **WHOIS-регистрант → все его домены** (reverse WHOIS через DomainTools/Whoxy).

```bash
# passive DNS по домену (OTX)
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/evil.example/passive_dns" \
  | python3 -c 'import sys,json;[print(r["hostname"],r["address"]) for r in json.load(sys.stdin)["passive_dns"][:20]]'

# reverse WHOIS: другие домены того же владельца
curl -s "https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=$WX_KEY&searchType=current&mode=purchase&basicSearchTerms={\"include\":[\"evil.example\"]}"

# все домены с тем же TLS-сертификатом через crt.sh
curl -s "https://crt.sh/?q=<sha1-сертификата>&output=json" | python3 -c 'import sys,json;[print(x["name_value"]) for x in json.load(sys.stdin)]'
```

Практический пример цепочки: фишинговый email → домен `login-secure.example` → urlscan показывает редирект на IP `45.x.x.x` → AbuseIPDB: 200 жалоб → passive DNS находит ещё 12 доменов на том же IP → crt.sh по сертификату даёт ещё 5 поддоменов → всё это одна кампания. Один индикатор превратился в список из 18.

## Оценка уверенности

Не все индикаторы равны. Стройте шкалу:

- **Высокая**: подтверждено несколькими независимыми источниками, свежее, совпадает с известной кампанией/семейством.
- **Средняя**: один надёжный источник, есть контекст (ASN, семейство), но нет перекрёстного подтверждения.
- **Низкая**: единственный детект, возможен false positive.

Факторы понижения: индикатор старше 90 дней (**декай**), хостинг shared, попадание в списки «шумных» сканеров (GreyNoise), отсутствие контекста.

## MITRE ATT&CK

Обогащайте индикаторы связью с техниками ATT&CK: C2 (T1071 Application Layer Protocol), эксфильтрация (T1041), фишинг (T1566), загрузка инструментов (T1105). Это помогает приоритизировать алерты и писать понятные отчёты: не «вредоносный IP», а «C2-сервер кампании X, техника T1071».

## Автоматизация пайплайна

Соберите обогащение в один скрипт, чтобы не дёргать сервисы руками:

```bash
#!/usr/bin/env bash
# enrich.sh — обогащение домена
set -euo pipefail
D="$1"
echo "== VT =="; curl -s "https://www.virustotal.com/api/v3/domains/$D" -H "x-apikey: $VT_KEY" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["attributes"]["last_analysis_stats"])'
echo "== passive DNS =="; curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$D/passive_dns" \
  | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("passive_dns",[])),"records")'
echo "== WHOIS =="; whois "$D" | grep -iE 'creation|registrant org' | head -3
```

## Частые ошибки

- **Считать IOC истиной** — индикатор без контекста бесполезен и часто ложный.
- **Не проверять давность** — старый IP мог сменить владельца; декай обязателен.
- **Игнорировать ложные срабатывания** — shared hosting и CDN дают «шумные» IP.
- **Не пивотить** — вся ценность раскрывается при переходе к связанным сущностям.
- **Слепо доверять одному источнику** — разные базы видят разное; агрегируйте.
- **Хранить индикаторы без TTL** — у каждого IOC должен быть срок жизни и уровень уверенности.

## Инструменты обогащения

| Инструмент | Что даёт |
|---|---|
| VirusTotal | детекты, passive DNS, коммуникации |
| AbuseIPDB | репутация IP |
| GreyNoise | «шумные» vs целевые сканеры |
| AlienVault OTX | пульсы, passive DNS |
| Pulsedive | агрегация и скоринг |
| Shodan/Censys | открытые сервисы на IP |
| urlscan | что на странице домена |

```bash
# GreyNoise: отсеять интернет-шум от целевых атак
curl -s "https://api.greynoise.io/v3/community/1.2.3.4" -H "key: $GN_KEY" | jq '{classification, noise, riot}'
```

## Автоматизация и скоринг

```python
# простой скоринг индикатора
score = 0
score += 2 if vt_detections > 5 else 0
score += 1 if abuse_score > 50 else 0
score += 1 if domain_age_days < 30 else 0
score += 1 if has_mx else 0
verdict = "high" if score >= 4 else "medium" if score >= 2 else "low"
print(verdict, score)
```

Автоматизируйте сбор, но вердикт — за аналитиком. Храните доказательства (JSON-ответы) для проверяемости.

## Формат вывода обогащения

```json
{
  "ioc": "evil.example",
  "type": "domain",
  "enrichment": {
    "vt_detections": 7,
    "creation_date": "2024-05-01",
    "passive_dns": ["1.2.3.4", "5.6.7.8"],
    "nameservers": ["ns1.badhost.net"]
  },
  "confidence": "high",
  "sources": ["virustotal", "otx"]
}
```

## Практика: VirusTotal API глубоко

```bash
# базовый отчёт по домену
curl -s "https://www.virustotal.com/api/v3/domains/evil.example" -H "x-apikey: $VT_KEY" \
  | jq '.data.attributes | {reputation, last_analysis_stats, categories, whois_date}'
# связанные объекты — пивотинг
curl -s "https://www.virustotal.com/api/v3/domains/evil.example/resolutions" -H "x-apikey: $VT_KEY" \
  | jq -r '.data[].attributes.ip_address'
curl -s "https://www.virustotal.com/api/v3/domains/evil.example/subdomains" -H "x-apikey: $VT_KEY" \
  | jq -r '.data[]'
# коммуникации файла
curl -s "https://www.virustotal.com/api/v3/files/<sha256>/contacted_ips" -H "x-apikey: $VT_KEY" | jq '.data[].id'
```

Лимиты важны: бесплатный ключ даёт около 4 запросов в минуту и 500 в день. Кэшируйте ответы и не тратьте квоту на повторные запросы одного индикатора.

## Практика: passive DNS и reverse IP

```bash
# passive DNS через OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/evil.example/passive_dns" \
  | jq -r '.passive_dns[] | [.hostname,.address,.first,.last]|@tsv' | head -20
# reverse IP — все домены на одном IP
curl -s "https://api.hackertarget.com/reverseiplookup/?q=1.2.3.4"
# SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/evil.example" -H "APIKEY: $ST_KEY" | jq '.current_dns'
```

## Практика: MISP и OpenCTI

MISP — платформа обмена индикаторами; экспорт событий:

```bash
curl -s "https://misp.example/events/restSearch" -H "Authorization: $MISP_KEY" \
  -H "Accept: application/json" -d '{"type":"domain"}' | jq '.response[].Event.info'
```

OpenCTI — граф знаний: индикаторы связываются с кампаниями, техниками ATT&CK и отчётами. Экспорт в STIX 2.1 — стандартный способ обмена между платформами.

## Справочник: форматы обмена индикаторами

| Формат | Назначение |
|---|---|
| STIX 2.1 | структурированные объекты и связи между ними |
| MISP | платформенный обмен событиями |
| TAXII | транспорт для STIX |
| OpenIOC | устаревший формат IOC |

## Что дальше / решение

Автоматизируйте сбор обогащения, но итоговый вердикт всегда за аналитиком. Храните сырые ответы сервисов в JSON для проверяемости и ставьте каждому индикатору TTL и уровень уверенности — «вечный» IOC без срока жизни быстро превращается в источник ложных срабатываний. Для SOC логичный следующий шаг — превратить подтверждённые индикаторы в правила детекта, а для пентеста — понять, как ваша собственная инфраструктура выглядит в этих базах.

## Практика: пайплайн автоматизации обогащения

Ручное дёргание сервисов не масштабируется, поэтому соберите конвейер. Структура проста: очередь индикаторов, воркер на каждый тип, кэш ответов и хранилище результатов в JSON. Кэш обязателен — он экономит квоты API и делает повторный прогон воспроизводимым. Каждый индикатор проходит через несколько источников, результаты сводятся в один объект с полями `enrichment`, `confidence` и `sources`. Дедупликация по нормализованному значению (нижний регистр домена, развёрнутый IPv6) убирает повторные запросы. После сбора посчитайте скор и присвойте уровень уверенности: несколько независимых подтверждений и свежая дата поднимают вердикт, а попадание в списки шумных сканеров GreyNoise или возраст больше 90 дней его понижают. Храните сырые ответы, а не только вывод — это позволяет перепроверить решение спустя месяцы. Пайплайн удобно строить на Python с asyncio и ограничением параллелизма под лимиты конкретного API. Итог — воспроизводимый вердикт по каждому индикатору с доказательствами и понятным сроком жизни.

## Квиз

```quiz
- question: "Что такое обогащение IOC?"
  options:
    - "Удаление индикатора"
    - "Добавление контекста (ASN, WHOIS, репутация) к индикатору"
    - "Шифрование индикатора"
    - "Публикация индикатора"
  answer: 1
- question: "Что такое пивотинг?"
  options:
    - "Смена пароля"
    - "Переход к связанным сущностям через общие атрибуты"
    - "Удаление IOC"
    - "Построение отчёта"
  answer: 1
- question: "Какой атрибут помогает найти другие C2 того же инструмента?"
  options:
    - "TTL DNS"
    - "JARM/favicon-хэш"
    - "MX-запись"
    - "Дата регистрации"
  answer: 1
- question: "Почему IOC со shared hosting может быть ложным?"
  options:
    - "Он всегда зашифрован"
    - "На одном IP множество доменов, репутация размывается"
    - "Он не имеет ASN"
    - "Его нельзя обогатить"
  answer: 1
- question: "Что такое декай в контексте IOC?"
  options:
    - "Подтверждённый вредонос"
    - "Устаревшая/мёртвая инфраструктура"
    - "Тип хэша"
    - "Способ пивотинга"
  answer: 1
```

## Где пригодится

- **CTF:** обогащение индикаторов в задачах threat intel.
- **Blue team:** приоритизация алертов и triage инцидентов по контексту.
- **Пентест:** понимание, как ваша инфраструктура выглядит в threat-базах.
- **Работа SOC:** построение вердиктов, отчётов и правил детекта по IOC.
