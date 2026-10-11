---
id: osint-cdn-origin
title: "CDN и WAF: определение и поиск origin-сервера"
category: osint
parent: osint-infra-network
difficulty: hard
order: 4
tags: [cdn, waf, origin, cloudflare, bypass]
prerequisites: [osint-infrastructure, osint-dns-history]
useful_for:
  - "Bug bounty: обход WAF и доступ к origin"
  - "Пентест: реальный периметр"
estimated_minutes: 62
summary: "Как определить CDN/WAF, найти настоящий origin через исторический DNS, CT, favicon, поддомены, прямые порты и утечки; проверка через Host-заголовок и риски."
---

CDN (Cloudflare, Akamai, Fastly, CloudFront) прячет реальный сервер и защищает WAF. Для пентеста/баг-баунти важно найти **origin** — настоящий IP, на котором крутится приложение, потому что WAF можно обойти, обратившись напрямую. Разведка origin — отдельный навык, который часто определяет успех всего тестирования.

## Как определить CDN/WAF

- **CNAME**: `dig +short www.example.com` → `*.cloudflare.net`, `*.akamaiedge.net`, `*.cloudfront.net`, `*.fastly.net`.
- **Заголовки ответа**: `Server: cloudflare`, `cf-ray`, `x-akamai-transformed`, `x-amz-cf-id`, `x-served-by: cache-...`.
- **ASN**: IP принадлежит AS13335 (Cloudflare), AS20940 (Akamai), AS16509 (Amazon), AS54113 (Fastly).
- **Cookie**: `__cfduid`/`__cf_bm` (Cloudflare), `ak_bmsc` (Akamai), `visid_incap` (Imperva).
- **Поведение**: при прямом запросе по IP без Host сайт не отдаётся (CDN-узлы отдают 403/redirect).

```bash
dig +short www.example.com
curl -sI https://www.example.com | grep -iE 'server|cf-ray|x-akamai|x-amz-cf|x-served-by|set-cookie'
whois $(dig +short www.example.com | head -1) | grep -iE 'netname|orgname|origin'
```

## Источники origin-IP

1. **Исторический DNS** (SecurityTrails, RiskIQ, ViewDNS DNS History): IP до переезда в CDN.
2. **Certificate Transparency** (crt.sh, Censys): сертификат мог быть выдан на прямой IP или внутреннее имя.
3. **Favicon-хэш**: поиск в Shodan/FOFA находит тот же сервер вне CDN (см. урок про favicon).
4. **Скан по сертификату**: Censys по имени в TLS-сертификате.
5. **Поддомены**: `dev`, `staging`, `mail`, `ftp`, `direct`, `origin`, `cpanel` часто **не** за CDN и указывают на тот же origin.
6. **SPF/MX**: почтовые серверы часто на том же хостинге, что и origin.
7. **Утечки**: конфиги, `.git`, CI-логи, paste-сайты с внутренним IP.
8. **Сторонние сервисы**: favicon через `shodan`, JARM-фингерпринт, анализ TLS-параметров.

```bash
# исторический DNS (SecurityTrails API)
curl -s "https://api.securitytrails.com/v1/history/www.example.com/dns/a" \
  -H "APIKEY: $ST_KEY" | python3 -m json.tool

# crt.sh: все имена с этим доменом (часто выдаёт внутренние хосты)
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | python3 -c 'import sys,json;print(sorted({n for r in json.load(sys.stdin) for n in r["name_value"].split("\n")}))'
```

## Проверка origin

Найденный IP не обязательно origin. Проверяйте через Host-заголовок:

```bash
# прямой запрос к IP с Host целевого домена
curl -skI https://<ip>/ -H 'Host: www.example.com'

# сравните с ответом через CDN
curl -skI https://www.example.com/

# если контент/заголовки совпадают — вероятный origin
```

Иногда origin отвечает только по HTTP или требует SNI — используйте `openssl s_client -servername`:

```bash
openssl s_client -connect <ip>:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

Некоторые origin настроены требовать **секретный заголовок** от CDN (Cloudflare Authenticated Origin Pulls, `X-Forwarded-For` проверка). Тогда прямой запрос вернёт 403 — это тоже сигнал, что вы нашли origin.

## Обход WAF и риски

- Прямой доступ к origin обходит WAF → инъекции/SQLi, которые «резал» WAF, могут сработать.
- Проверяйте, не блокирует ли origin запросы без Host/CDN-заголовка.
- **Юридически и этически**: доступ к origin в рамках scope разрешён; вне scope — нет. Не атакуйте инфраструктуру провайдера (CDN-узлы — собственность Cloudflare/Akamai).
- Если origin в другом ASN/у другого хостера, убедитесь, что он всё ещё в scope программы.

## Инструменты

- **CloudFlair** (`cloudflair.py`) — поиск origin через Shodan/Censys по сертификатам.
- **CloudPeler / CrimeFlare** — поиск по историческому DNS и сертификатам.
- **bypass-firewalls-by-DNS-history** — исторический DNS в один прогон.
- **SecurityTrails / ViewDNS** — история DNS.
- **Shodan/FOFA** — favicon и cert-поиск.

```bash
# пример: CloudFlair по домену
python3 cloudflair.py example.com
# пример: DNS history
python3 bypass-firewalls-by-DNS-history.py -d example.com
```

## Разбор кейса

Задача: обойти Cloudflare у `api.example.com`.

1. `dig` → CNAME на Cloudflare, AS13335.
2. crt.sh → находим `dev.api.example.com`, `origin.api.example.com`.
3. `dig origin.api.example.com` → IP `203.0.113.10` вне Cloudflare.
4. `curl -sk https://203.0.113.10/ -H 'Host: api.example.com'` → отдаёт API-ответ.
5. Проверяем исторический DNS → подтверждение. Origin найден.
6. Тестируем уязвимость (в рамках scope) напрямую, минуя WAF.

## Частые ошибки

- **Путать CDN-IP с origin**: сначала проверьте ASN и заголовки.
- **Останавливаться на одном источнике**: origin может быть найден только комбинацией.
- **Игнорировать поддомены**: `direct.example.com` — классика.
- **Слепо сканировать найденный IP**: убедитесь, что он в scope и принадлежит цели.
- **Забыть про IPv6**: origin может быть доступен только по IPv6.
- **Не проверять старые IP**: домен мог переехать; исторический IP может больше не быть origin.

## Инструменты автоматизации

- **CloudFlair** — поиск origin через Shodan/Censys по сертификатам.
- **CloudPeler/CrimeFlare** — исторический DNS + сертификаты.
- **bypass-firewalls-by-DNS-history** — история A-записей.
- **SecurityTrails/ViewDNS** — история DNS.
- **Shodan/FOFA** — favicon и cert-поиск.

```bash
python3 cloudflair.py example.com
python3 bypass-firewalls-by-DNS-history.py -d example.com
```

## Проверка и подтверждение origin

```bash
# прямой запрос к найденному IP с Host целевого домена
curl -skI "https://203.0.113.10/" -H 'Host: www.example.com'
# сравнить с ответом через CDN
curl -skI "https://www.example.com/"
# SNI-проверка сертификата
openssl s_client -connect 203.0.113.10:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject
```

Совпадение заголовков/контента → вероятный origin. Некоторые origin требуют секретный заголовок от CDN (Authenticated Origin Pulls) — тогда 403 тоже сигнал, что вы нашли сервер.

## Обход WAF и риски

- Прямой origin обходит WAF → инъекции, которые «резал» WAF, могут сработать.
- **Юридически**: origin в scope — можно; вне scope — нет; CDN-узлы — собственность провайдера, их не трогаем.
- Проверяйте, что найденный IP принадлежит цели (ASN, сертификат), а не случайному хосту.

## Определение CDN/WAF: подробный разбор

Заголовки и cookie, однозначно указывающие на провайдера:

| Заголовок или признак | Провайдер |
|---|---|
| `server: cloudflare`, `cf-ray`, `cf-cache-status` | Cloudflare |
| `server: AkamaiGHost`, `x-akamai-transformed` | Akamai |
| `x-amz-cf-id`, `x-amz-cf-pop`, `via: ...cloudfront.net` | CloudFront |
| `x-served-by: cache-*`, `x-fastly-request-id` | Fastly |
| `x-sucuri-id`, `server: Sucuri/Cloudproxy` | Sucuri |
| `x-iinfo`, `visid_incap`, `incap_ses` | Imperva |
| `x-azure-ref`, `x-msedge-ref` | Azure Front Door |

Определение по ASN и владельцу сети:

```bash
dig +short www.example.com
whois 104.16.x.x | grep -iE 'netname|orgname|origin|descr'
curl -s "https://api.bgpview.io/ip/104.16.x.x" | jq '.data.prefixes[].asn'
```

Соответствие ASN: Cloudflare — AS13335, Akamai — AS20940 и AS16625, CloudFront — AS16509, Fastly — AS54113, Imperva — AS19551.

## Источники origin — углублённо

- **Исторический DNS**: SecurityTrails, ViewDNS, DNSdumpster, RiskIQ. Ищите A-записи, сделанные до появления CNAME на CDN.
- **CT-логи**: сертификат мог быть выпущен на прямой IP или на внутреннее имя вида `internal.example.com`.
- **Favicon-хэш** (отдельный урок): поиск в Shodan и FOFA находит тот же сервер вне CDN.
- **SPF/MX/TXT**: `dig TXT example.com` — директивы `ip4:` в SPF часто указывают на хостинг почты, а он нередко совпадает с origin.
- **Поддомены**: `dev`, `staging`, `mail`, `ftp`, `direct`, `origin`, `cpanel`, `webmail` часто вне CDN.
- **Утечки**: `.git/config`, CI-логи, JS-бандлы с `sourceMappingURL`, paste-сайты с внутренними IP.
- **Сторонние сервисы**: JARM-фингерпринт, Censys по сертификату, Shodan `ssl:`.

```bash
# SPF с IP-диапазонами
dig +short TXT example.com | grep -oE 'ip4:[0-9./]+'
# MX-хосты
dig +short MX example.com
# исторический DNS (SecurityTrails)
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" -H "APIKEY: $ST_KEY" \
  | jq -r '.records[].values[].ip'
```

## Практика: инструменты origin discovery

```bash
# CloudFail — origin через исторические DNS и CT
git clone https://github.com/m0rtem/CloudFail
python3 cloudfail.py --target example.com

# CloudFlair — origin через Censys/Shodan по сертификатам
python3 cloudflair.py example.com -o out.txt

# bypass-firewalls-by-DNS-history
python3 bypass-firewalls-by-DNS-history.py -d example.com -o results.txt
```

## Валидация origin

Найденный IP не обязательно origin. Проверяйте его ответ с целевым Host:

```bash
# 1. прямой запрос с Host
curl -skI "https://203.0.113.10/" -H 'Host: www.example.com' | head -5
# 2. SNI-проверка сертификата
openssl s_client -connect 203.0.113.10:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
# 3. сравнение тела ответа с CDN-версией
curl -sk "https://203.0.113.10/" -H 'Host: www.example.com' | sha256sum
curl -sk "https://www.example.com/" | sha256sum
```

Совпадение заголовков и тела ответа — вероятный origin. Ответ 403 при прямом запросе тоже сигнал: значит, сервер настроен требовать секретный заголовок от CDN (Authenticated Origin Pulls).

## Справочник: провайдеры и диапазоны

| Провайдер | ASN | Типовой заголовок |
|---|---|---|
| Cloudflare | 13335 | `cf-ray` |
| Akamai | 20940 | `x-akamai-*` |
| CloudFront | 16509 | `x-amz-cf-id` |
| Fastly | 54113 | `x-served-by` |
| Imperva | 19551 | `x-iinfo` |

## Что дальше / решение

Найденный origin — это вход для прямого тестирования в рамках scope, но перед атакой убедитесь, что IP принадлежит цели (ASN, сертификат), а не случайному хосту на том же хостинге. Задокументируйте метод, IP и дату: при повторном тестировании CDN может переехать, и старый origin перестанет отвечать.

## Практика: origin через SSRF и утечки конфигурации

Когда пассивные источники молчат, origin иногда выдают сами приложения. Уязвимость SSRF в веб-приложении позволяет заставить сервер обратиться по внутреннему адресу и раскрыть IP, скрытый за CDN. Ещё один источник — метаданные облака: если на хосте есть SSRF, `http://169.254.169.254/latest/meta-data/` отдаёт внутренние данные инстанса. Ищите также утечки в статике: `sourceMappingURL` в JS-бандлах часто указывает на внутренние домены, `.git/config` раскрывает remote с IP или внутренним хостом, а `sitemap.xml` и `robots.txt` перечисляют пути, которые не проходят через CDN. Полезно просмотреть JS на предмет захардкоженных адресов бэкенда:

```bash
curl -s https://www.example.com/ | grep -oE 'src="[^"]+\.js"' | while read -r s; do
  url=$(echo "$s" | sed 's/src="//;s/"//'); curl -s "https://www.example.com/$url"
done | grep -oE 'https?://[a-z0-9.-]+' | sort -u
```

Так вы получаете список доменов и IP, которые приложение реально использует, — среди них часто и есть origin. Дальше каждый кандидат проверяется запросом с целевым Host-заголовком.

## Квиз

```quiz
- question: "Какой заголовок однозначно указывает на Cloudflare?"
  options:
    - "Content-Type"
    - "cf-ray"
    - "ETag"
    - "Date"
  answer: 1
- question: "Что такое origin-сервер?"
  options:
    - "CDN-узел"
    - "Настоящий сервер приложения за CDN"
    - "DNS-резолвер"
    - "WAF"
  answer: 1
- question: "Как проверить, что найденный IP — origin?"
  options:
    - "Пропинговать его"
    - "Запросить его с заголовком Host целевого домена и сравнить ответ"
    - "Сделать whois"
    - "Запросить PTR"
  answer: 1
- question: "Какой источник часто выдаёт origin после переезда в CDN?"
  options:
    - "Исторический DNS"
    - "robots.txt"
    - "TXT-запись SPF"
    - "MX-запись"
  answer: 0
- question: "Почему прямой доступ к origin опасен для защитника?"
  options:
    - "Он ускоряет сайт"
    - "Он обходит WAF, открывая уязвимости"
    - "Он меняет DNS"
    - "Он блокирует CDN"
  answer: 1
```

## Где пригодится

- **CTF:** обход фильтрации через прямой origin.
- **Bug bounty:** доступ к защищённому WAF функционалу и расширение impact.
- **Пентест:** определение реального периметра за CDN/WAF.
- **Blue team:** проверка, не утекает ли origin (закрытие прямых портов, firewall, Authenticated Origin Pulls).
