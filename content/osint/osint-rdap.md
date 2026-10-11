---
id: osint-rdap
title: "WHOIS и RDAP: регистрационные данные домена и IP"
category: osint
parent: osint-whois-asn
difficulty: medium
order: 1
tags: [whois, rdap, registrar, domain, osint]
prerequisites: [osint-whois-asn]
useful_for:
  - "Атрибуция домена и владельца"
  - "Пентест: контакты и даты регистрации"
estimated_minutes: 55
summary: "Разница WHOIS и RDAP, разбор полей регистратора, исторические WHOIS, приватность/GDPR и практический сбор контактов и дат."
---

WHOIS — старейший протокол регистрационных данных о доменах и IP-адресах. RDAP (Registration Data Access Protocol) — его современная замена на базе HTTP/JSON с аутентификацией и структурированным ответом. Для разведки важны: кто владелец, когда создан, какие контакты, какие NS и статусы.

## WHOIS vs RDAP

| | WHOIS | RDAP |
|---|---|---|
| Транспорт | TCP/43, текст | HTTPS/JSON |
| Формат | свободный текст | структурированный JSON |
| Аутентификация | нет | есть (по токену/бутстрапу) |
| Будущее | устаревает | стандарт (RFC 7480-7484) |

```bash
whois example.com
whois 93.158.134.144
```

## Ключевые поля

- **Registrar / Registrar WHOIS Server** — через кого зарегистрирован домен; полезно для «соседей» и типовых админов.
- **Creation Date / Updated Date / Registry Expiry** — возраст домена; свежие домены (фишинг) и «забытые» (takeover).
- **Name Server** — DNS-провайдер (Cloudflare, Yandex, reg.ru).
- **Registrant/Admin/Tech** — контакты; часто скрыты из-за GDPR.
- **Status** — `clientHold`, `pendingDelete` (домен умирает), `ok`.
- **DNSSEC** — подписан ли домен.

## RDAP на практике

RDAP отдаёт JSON, удобный для скриптов:

```bash
# bootstrap: узнать RDAP-сервер для домена/IP
curl -s https://rdap.org/domain/example.com | python3 -m json.tool
curl -s https://rdap.org/ip/93.158.134.144 | python3 -m json.tool

# вытащить только события (даты) и NS
curl -s https://rdap.org/domain/example.com \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("events"));print([n["ldhName"] for n in d.get("nameservers",[])])'
```

Из ответа достаём `events` (registration/expiration), `entities` (роли registrar/registrant), `nameservers`, `status`. RDAP не имеет лимита на формат, поэтому парсится стабильнее WHOIS.

## RDAP-бутстрап и прямые запросы

`rdap.org` — редирект-сервис, но для надёжности можно обращаться к авторитетному RDAP-серверу напрямую. Бутстрап-файл IANA подсказывает сервер по TLD:

```bash
# список RDAP-серверов по TLD
curl -s https://data.iana.org/rdap/dns.json | jq -r '.services[] | select(.[0][]=="com") | .[1][]'

# прямой запрос к реестру .com (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/example.com | jq '{ldhName,status,events}'
```

Для IP-адресов бутстрап аналогичен (`rdap/ipv4.json`), а авторитетный сервер зависит от RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC).

## Разбор ответа RDAP

```bash
curl -s https://rdap.org/domain/example.com \
  | jq '{handle, ldhName, status, events, nameservers: [.nameservers[].ldhName],
         entities: [.entities[] | {roles, handle, vcard: .vcardArray[1]}]}'
```

- `events` — массив `{eventAction, eventDate}`: `registration`, `expiration`, `last changed`, `transfer`.
- `entities` — роли `registrar`, `registrant`, `administrative`, `technical`; внутри `vcardArray` — имя, email, телефон (если не отредактированы).
- `nameservers` — список NS; их домены указывают на DNS-провайдера.
- `secureDNS` — DNSSEC-статус.

## Приватность и GDPR

После введения GDPR большинство регистраторов скрывают персональные данные (`REDACTED FOR PRIVACY`, «Data Protected»). Что всё равно остаётся:

- Дата регистрации и NS.
- Email/телефон регистратора, а не владельца.
- **Исторические WHOIS** — до GDPR данные были открыты; сервисы вроде WhoisXML, DomainTools, ViewDNS хранят снимки. Это часто единственный способ найти настоящий контакт.

## Исторические WHOIS и обратный WHOIS

- **Historical WHOIS**: снимок `Registrant Email` до редактирования.
- **Reverse WHOIS**: поиск всех доменов с тем же email/именем/организацией — выявляет «портфели» владельца.

```bash
# пример через API (ключ в переменной)
curl -s "https://reverse-whois.whoisxmlapi.com/api/v1?apiKey=$WX_KEY&searchType=current&mode=preview&basicSearchTerms={\"include\":[\"example.com\"],\"voices\":[\"registrant\"]}"
```

## Статусы домена и их значение

Поле **Status** — важный сигнал о состоянии домена:

| Статус | Значение |
|---|---|
| `ok` / `active` | нормальное состояние |
| `clientHold` | регистратор приостановил (часто неоплата) |
| `serverHold` | реестр приостановил |
| `clientTransferProhibited` | запрет переноса (защита) |
| `pendingDelete` | домен скоро удалят (кандидат на перехват) |
| `redemptionPeriod` | период восстановления после удаления |

`pendingDelete`/`redemptionPeriod` — интересны: если домен бренда утекает, его может перехватить злоумышленник. Это класс находок для blue team.

## От WHOIS к ASN

Для IP-адреса WHOIS/RDAP возвращает не владельца, а **аллокацию**: диапазон, организацию, страну, ASN. Дальше вы переходите к карте маршрутизации (урок про BGP):

```bash
whois 93.158.134.144 | grep -iE 'netname|orgname|country|origin|route'
```

## Практический разбор вывода WHOIS

```bash
whois example.com
# ключевые строки:
#   Registrar: <посредник>
#   Creation Date: <возраст>
#   Registry Expiry Date: <когда истекает>
#   Name Server: <DNS-провайдер>
#   Registrant Organization: <если не скрыто>
#   Domain Status: <состояние>
```

Практика: свежесть домена + приватность + NS-сервис, не соответствующий компании = признак фишинга или «одноразовой» инфраструктуры. Для бренда проверяйте **все** близкие домены на предмет перехвата.

## Массовая проверка и мониторинг

```bash
# для списка доменов собрать ключевые поля
for d in $(cat domains.txt); do
  echo "== $d =="
  whois "$d" 2>/dev/null | grep -iE 'creation|registrar:|name server|status' | head -5
done
```

Сервисы (DomainTools, WhoisXML, ViewDNS) дают **API** для массового WHOIS и алертов на изменения. Для blue team настройте мониторинг: новые регистрации доменов, содержащих бренд (см. osint-typosquat).

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| `whois` | `whois example.com` | текст WHOIS |
| `rdap.org` | `curl https://rdap.org/domain/<d>` | JSON RDAP |
| IANA bootstrap | `data.iana.org/rdap/dns.json` | поиск RDAP-сервера |
| WhoisXML API | REST | исторический/reverse WHOIS |
| ViewDNS | веб | обратный WHOIS, история |
| `whois -h whois.cymru.com` | ` -v IP` | IP → ASN |

## Частые ошибки

- **Считать `REDACTED` тупиком**: смотрите исторические снимки и NS/registrar.
- **Путать registrar и registrant**: регистратор — посредник, не владелец.
- **Игнорировать даты**: возраст домена — сильный признак (фишинг/заброшенность).
- **Забыть про RDAP**: он структурный и не требует установки `whois`.
- **Не проверять статус**: `clientHold`/`pendingDelete` меняют интерпретацию.
- **Пропускать обратный WHOIS**: он вскрывает весь портфель владельца.

## Что делать дальше / решение

- **Атрибуция домена** → RDAP (`events`, `entities`) + исторический WHOIS.
- **Портфель владельца** → reverse WHOIS по email/организации.
- **Риск фишинга** → сравнить возраст домена, NS и регистратора с легитимным доменом.
- **Защита бренда** → мониторинг новых регистраций (см. osint-typosquat).

## RDAP для IP: RIR и аллокации

Для IP-адресов RDAP-ответ приходит от **регионального интернет-регистратора** (RIR), а не от регистратора домена. Пять RIR: ARIN (Северная Америка), RIPE (Европа/Ближний Восток), APNIC (Азия/Тихий океан), LACNIC (Латинская Америка), AFRINIC (Африка). В ответе важны:

- `handle` и `name` — объект аллокации (NET-блок).
- `startAddress` / `endAddress` — границы диапазона.
- `entities` с ролью `registrant` — организация-владелец.
- `events` — даты выделения и изменений.

```bash
curl -s https://rdap.org/ip/93.158.134.144 \
  | jq '{handle,name,startAddress,endAddress,country,entities:[.entities[].handle]}'
```

Дальше диапазон уходит в `osint-bgp` (ASN, префиксы) и `osint-reverse-dns` (свип PTR).

## Разбор кейса: домен-двойник бренда

Типовая находка blue team: свежий домен `examp1e.com` (единица вместо «l»), зарегистрированный неделю назад, с NS на бесплатном сервисе и приватными контактами. Разбор:

1. `whois`/RDAP → дата регистрации (свежая), регистратор (дешёвый), статус `clientTransferProhibited` (защита от переноса — часто ставит сам мошенник).
2. `dig` → NS указывают на хостинг с бесплатным SSL.
3. crt.sh → сертификат выдан на день-два позже регистрации.
4. Ad Library/поиск → пока нет контента, но домен уже в MX-настройке для фишинга.

Совокупность «свежий + приватный + бесплатный хостинг + несоответствие NS компании» — устойчивый признак фишинга. Вывод фиксируется как риск, домен ставится на мониторинг.

## Исторический WHOIS: практические сервисы и приёмы

Исторический WHOIS — ключ, когда текущие данные отредактированы. Приёмы:

- **Сервисы-архивы**: WhoisXMLAPI, DomainTools, ViewDNS, SecurityTrails хранят снимки.
- **Даты смены**: смотрите не только старые контакты, но и когда они были скрыты (обычно май 2018, GDPR).
- **Reverse по старым данным**: найденный email владельца → поиск всех доменов с ним.
- **NS-история**: смена DNS-провайдера выдаёт миграции и смену подрядчика.
- **Комбинируйте с CT**: сертификаты и WHOIS дополняют друг друга по датам.

```bash
# пример: сравнить текущий NS и исторический
whois example.com | grep -i 'name server'
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/ns" -H "APIKEY: $ST_KEY" | jq
```

Помните про лимиты API и легальность: обратный WHOIS по персональным данным требует правового основания в расследованиях.

## Сравнение WHOIS-сервисов

| Сервис | Сильная сторона |
|---|---|
| `whois` (системный) | быстро, бесплатно, текст |
| `rdap.org` | JSON, структура, бесплатно |
| SecurityTrails | история DNS/WHOIS, API |
| WhoisXMLAPI | historical + reverse WHOIS, API |
| DomainTools | глубокая история, платно |
| ViewDNS | обратный WHOIS, история, веб |
| `bgp.he.net` | WHOIS + ASN в одном окне |

Комбинируйте: бесплатные дают базу, платные API — историю и reverse. Для разовой задачи хватит `whois`+RDAP; для расследования — historical/reverse через API.

## Итог и типичные ошибки интерпретации

Сводка: WHOIS/RDAP даёт **даты, статусы, NS и (если повезёт) контакты**. Главные ошибки интерпретации: принимать `Registrar` за владельца; считать отсутствие `Registrant` тупиком (смотрите историю); игнорировать статус `pendingDelete` (перехват); не сверять NS-провайдера с реальностью компании; верить единственному источнику. Правило: домен описывается **набором** признаков (возраст + статус + NS + регистратор + история), а не одним полем.

## Квиз

```quiz
- question: "Чем RDAP отличается от WHOIS?"
  options:
    - "Он работает по TCP/43"
    - "Он основан на HTTPS и возвращает JSON"
    - "Он бесплатный, а WHOIS платный"
    - "Он не содержит дат"
  answer: 1
- question: "Какое поле WHOIS указывает на возраст домена?"
  options:
    - "Status"
    - "Creation Date"
    - "Name Server"
    - "DNSSEC"
  answer: 1
- question: "Почему исторические WHOIS-снимки ценны после GDPR?"
  options:
    - "Они быстрее"
    - "В них сохранились персональные данные до редактирования"
    - "Они содержат пароли"
    - "Они обязательны по закону"
  answer: 1
- question: "Что возвращает WHOIS/RDAP для IP-адреса?"
  options:
    - "Домашний адрес владельца"
    - "Информацию об аллокации: диапазон, организацию, ASN"
    - "Список портов"
    - "TLS-сертификат"
  answer: 1
- question: "Что такое reverse WHOIS?"
  options:
    - "Поиск доменов по общим email/организации владельца"
    - "Отмена регистрации домена"
    - "Запрос PTR"
    - "Перебор поддоменов"
  answer: 0
```

## Где пригодится

- **CTF:** определить владельца и связанные домены для следующего шага.
- **Bug bounty:** выявить «портфель» доменов одной организации.
- **Пентест:** контакты и даты для социальной инженерии и оценки риска.
- **Blue team:** мониторинг регистраций похожих доменов (бренд-защита).
