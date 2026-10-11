---
id: osint-whois-asn
title: "WHOIS, ASN и карта IP-инфраструктуры"
category: osint
parent: osint-collection
difficulty: medium
order: 2
tags: [whois, asn, ip, infrastructure, bgp, osint]
prerequisites: [osint-intro, osint-dns-recon]
useful_for:
  - "Атрибуция IP и домена"
  - "Пентест: карта инфраструктуры"
  - "CTF категория OSINT"
estimated_minutes: 55
summary: "WHOIS домена и IP, региональные реестры (RIR), ASN и BGP-префиксы — построение карты инфраструктуры и определение владельца адреса."
---

WHOIS — публичный реестр регистрантов: кто владеет доменом или диапазоном IP, когда это зарегистрировано, какие контакты и DNS. Вместе с ASN и BGP-данными он превращает отдельный адрес в часть карты инфраструктуры: владелец → провайдер → диапазон → соседние хосты. Это базовый навык атрибуции, на котором держатся почти все остальные ветки OSINT.

## WHOIS домена: что искать

```bash
whois example.com
```

Что искать в выводе:

- **Registrar** — через кого зарегистрирован домен.
- **Creation / Updated / Expiry Date** — возраст домена (свежие = подозрительные фишинг-домены).
- **Registrant Org / Country** — владелец (часто скрыт privacy-сервисом).
- **Name Server** — DNS-провайдер.
- **Status** — `clientHold`, `pendingDelete` (домен умирает), `ok`.

Если владелец скрыт (`REDACTED FOR PRIVACY`), смотрите на **NS-серверы** и **MX** — они часто выдают реальную компанию или хостера.

## WHOIS для IP

```bash
whois 93.158.134.144
```

Обратите внимание на:

- **netname** — имя сети (часто содержит аббревиатуру компании).
- **OrgName / OrgId** — организация-владелец.
- **CIDR / inetnum** — диапазон адресов.
- **country**, **descr**, **abuse-c** — контакт для жалоб.

Пример: если в netname стоит `YANDEX`, а в descr — `Yandex LLC`, вы знаете, что адрес в инфраструктуре Яндекса.

## Региональные реестры (RIR)

IP-адреса распределены между пятью региональными интернет-реестрами:

| RIR | Регион |
|---|---|
| ARIN | Северная Америка |
| RIPE NCC | Европа, Ближний Восток, Центральная Азия |
| APNIC | Азиатско-Тихоокеанский |
| LACNIC | Латинская Америка |
| AFRINIC | Африка |

Для России и СНГ актуален **RIPE**. WHOIS-сервер: `whois.ripe.net`. Для доменов .ru — `whois.tcinet.ru` (RU-CENTER).

```bash
whois -h whois.ripe.net 93.158.134.144
```

## ASN: автономные системы

**ASN (Autonomous System Number)** — номер сети, которой управляет один оператор (провайдер, облако, компания). Все IP внутри ASN маршрутизируются вместе.

Узнать ASN по IP:

```bash
# через whois (строка origin)
whois 93.158.134.144 | grep -i origin

# через внешний сервис (JSON)
curl -s "https://ipinfo.io/93.158.134.144/json"
```

Пример вывода `ipinfo.io`: `"org": "AS200350 Yandex.Cloud LLC"`. Это сразу говорит: адрес в облаке Яндекс.

## BGP-префиксы и расширение scope

BGP — протокол маршрутизации между ASN. Зная ASN, можно получить **все** префиксы оператора:

```bash
# все маршруты AS200350
curl -s "https://api.bgpview.io/asn/200350/prefixes" | head

# кто такой AS200350
curl -s "https://api.bgpview.io/asn/200350"
```

Это бесценно для расширения области разведки: если программа покрывает `*.example.ru`, а вы нашли, что домен хостится в облаке `Yandex.Cloud`, вы понимаете границы — но **не** автоматически расширяете scope (правила программы важнее технической связности!).

## RDAP как современная замена WHOIS

RDAP (RFC 7480-7484) — HTTP/JSON-версия WHOIS, удобная для скриптов:

```bash
curl -s https://rdap.org/domain/example.com | jq '{ldhName,status,events}'
curl -s https://rdap.org/ip/93.158.134.144 | jq '{handle,name,startAddress,endAddress}'
```

Преимущества: структурированный JSON, стабильный парсинг, бутстрап IANA для поиска сервера по TLD/IP. Для домена смотрите `events` (даты) и `entities` (роли), для IP — `handle`, `name`, границы диапазона. Подробнее — в уроке `osint-rdap`.

## Геолокация и хостинг по IP

Агрегаторы дают больше, чем просто ASN:

```bash
curl -s "https://ipinfo.io/93.158.134.144/json" | jq '{city,region,country,org,hostname,timezone}'
```

- **Город/регион** — приблизительная геолокация (не GPS, но полезно).
- **hostname** — PTR-запись, часто раскрывает роль.
- **org** — ASN + провайдер.
- **anycast** — один IP в разных местах; геолокация ненадёжна.

## Обратный WHOIS и связи доменов

Кроме IP, WHOIS даёт связи между **доменами**:

- **Reverse WHOIS**: все домены с тем же email/организацией/регистрантом → «портфель» владельца.
- **Общий NS**: домены с одним набором NS часто принадлежат одной организации.
- **Общий registrar**: слабый сигнал (массовые регистраторы), но полезен в комбинации.

```bash
# пример обратного WHOIS через API
curl -s "https://reverse-whois.whoisxmlapi.com/api/v1?apiKey=$WX_KEY&searchType=current&mode=preview&basicSearchTerms={\"include\":[\"example.com\"]}"
```

## Построение карты инфраструктуры

Соберите всё вместе в таблицу:

```
домен → A-запись → IP → WHOIS netname → ASN → провайдер → страна
```

Пример корреляции:

- `api.example.ru` → `93.158.134.144` → `Yandex` → `AS200350 Yandex.Cloud` → Россия.
- `cdn.example.ru` → `CNAME` на `cloudfront.net` → AWS → США.

Выводы: часть сервисов в собственном облаке, часть — за CDN. Это определяет, где искать origin (реальный сервер за CDN) и где вообще применимы техники атаки.

## Практика: быстрый «профиль» цели

```bash
DOMAIN=example.com
IP=$(dig +short $DOMAIN A | head -1)
echo "IP: $IP"
whois $IP | grep -iE 'netname|orgname|country|origin'
curl -s "https://ipinfo.io/$IP/json"
```

За несколько секунд вы получаете владельца, ASN и страну — основу для дальнейшей разведки.

## Автоматизация и обогащение

```bash
# скрипт: домен → IP → ASN → провайдер
D=example.com
IP=$(dig +short $D A | head -1)
ASN=$(curl -s "https://ipinfo.io/$IP/json" | jq -r .org)
echo "$D -> $IP -> $ASN"

# все домены/префиксы оператора
curl -s "https://api.bgpview.io/asn/$(echo $ASN | sed 's/AS//' | cut -d' ' -f1)/prefixes" \
  | jq -r '.data.ipv4_prefixes[].prefix'
```

Агрегаторы (ipinfo, bgpview, ipapi) отдают ASN, страну, город, хостинг-флаг одним запросом — это ускоряет построение карты.

## Практика: от IP к организации

Полный маршрут атрибуции:

1. **IP** → `whois` → netname/OrgName.
2. **ASN** → bgpview → владелец сети, страна.
3. **Префиксы** → диапазон адресов оператора.
4. **Reverse DNS** → имена в диапазоне (см. osint-reverse-dns).
5. **Passive DNS** → какие домены резолвились в этот IP.
6. **CT-логи** → имена на сертификатах.

Так один IP разворачивается в целую инфраструктуру с владельцем, доменами и хостами.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| `whois` | `whois <domain\|ip>` | регистрационные данные |
| `whois -h whois.ripe.net` | `... <ip>` | запрос к конкретному RIR |
| `whois -h whois.cymru.com` | `" -v <ip>"` | IP → ASN одной строкой |
| RDAP | `curl https://rdap.org/...` | JSON-версия WHOIS |
| ipinfo.io | `curl .../json` | ASN, гео, org |
| BGPView | `api.bgpview.io/asn/<n>/prefixes` | префиксы AS |
| `dig` | `dig +short <d> A` | текущий IP |

## Частые ошибки

- **Путать registrar и registrant** — регистратор посредник, не владелец.
- **Считать REDACTED тупиком** — смотрите NS/MX и историю.
- **Принимать гео-IP за точное** — anycast и VPN искажают.
- **Считать ASN владельцем адреса** — часто это провайдер/облако.
- **Забывать про IPv6** — у AS отдельные префиксы.
- **Расширять scope по технической связности** — правила программы важнее.

## Что делать дальше / решение

- **Атрибуция домена** → WHOIS/RDAP + исторический WHOIS (`osint-rdap`).
- **Атрибуция IP** → whois + ipinfo + `osint-bgp`.
- **Расширение периметра** → префиксы ASN → reverse DNS (`osint-reverse-dns`).
- **Поиск origin** → исторические A + CT + favicon (`osint-dns-history`).

## CIDR, диапазоны и как их читать

WHOIS/BGP оперируют **CIDR-нотацией**: `93.158.134.0/24` — это 256 адресов, `/16` — 65536, `/32` — один адрес. Понимание нотации нужно, чтобы правильно разворачивать диапазоны в списки IP для reverse DNS и сканирования:

```bash
# развернуть /24 в список адресов
python3 -c "import ipaddress;[print(ip) for ip in ipaddress.ip_network('93.158.134.0/24').hosts()]" | head
```

Практика: из ASN вы получаете **набор** префиксов; объединяйте их, чтобы получить полный диапазон оператора. Помните о границах scope — большой ASN (облако) содержит адреса множества клиентов, и сканировать их все нельзя.

## IRR и RPKI: подтверждение прав на префикс

Анонс в BGP не гарантирует, что оператор имеет право на префикс. Есть два механизма подтверждения:

- **IRR (Internet Routing Registry)** — база объектов `route:`/`route6:`, где владелец разрешает AS анонсировать префикс.
- **RPKI/ROA** — криптографически подписанное разрешение (Route Origin Authorization).

```bash
# RPKI-статус префикса
curl -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=AS200350&prefix=93.158.134.0/24" | jq '.data.status'
```

Статус `invalid` — анонс противоречит ROA (возможный hijack); `valid` — подтверждён; `not-found` — ROA нет. Для атрибуции это уточняет, «настоящий» ли оператор владеет префиксом. Подробнее — в уроке `osint-bgp`.

## Квиз

```quiz
- question: "Какой WHOIS-сервер обслуживает IP-адреса в России/Европе?"
  options:
    - "whois.arin.net"
    - "whois.ripe.net"
    - "whois.apnic.net"
    - "whois.lacnic.net"
  answer: 1
- question: "Что такое ASN?"
  options:
    - "Тип DNS-записи"
    - "Номер автономной системы (сети одного оператора)"
    - "Почтовый протокол"
    - "Формат сертификата"
  answer: 1
- question: "Что искать в WHOIS домена, если регистрант скрыт?"
  options:
    - "Ничего, данные недоступны"
    - "NS-серверы и MX — они выдают хостера/компанию"
    - "Только дату создания"
    - "Пароль администратора"
  answer: 1
- question: "Как получить все BGP-префиксы оператора?"
  options:
    - "`dig AS200350`"
    - "`curl api.bgpview.io/asn/200350/prefixes`"
    - "`whois example.com`"
    - "`nmap -sP`"
  answer: 1
- question: "Зачем определять провайдера по IP?"
  options:
    - "Чтобы узнать пароль"
    - "Чтобы понять, где искать origin/инфраструктуру и оценить границы"
    - "Чтобы ускорить сканирование"
    - "Это не нужно"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «кому принадлежит IP/домен».
- **Bug bounty:** определение облака/хостера, поиск origin за CDN.
- **Пентест:** расширение карты инфраструктуры, понимание границ.
- **Threat intel:** атрибуция IP-адресов атакующим группам.
