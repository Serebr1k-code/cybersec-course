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

## Вопрос, с которого всё начинается

Домен `api.example.com` отвечает, но за ним стоит Cloudflare. CDN прячет настоящий сервер и фильтрует атаки через WAF. Как найти **origin** — реальный IP, на котором крутится приложение?

Это важно, потому что WAF можно обойти, обратившись к origin напрямую. Поиск origin — отдельный навык, который часто определяет успех всего тестирования. Разберём его на одном домене.

## Наш пример: api.example.com за Cloudflare

Работаем с одним объектом — `api.example.com`. Задача: определить, что это действительно CDN, и найти настоящий сервер. Не трогаем инфраструктуру провайдера — CDN-узлы нам не принадлежат и вне scope.

## Шаг 1: определяем, что это CDN/WAF

Сначала убеждаемся, что за доменом стоит именно CDN. Смотрим DNS и заголовки ответа.

```bash
dig +short www.example.com
curl -sI https://api.example.com | grep -iE 'server|cf-ray|x-akamai|x-amz-cf|x-served-by'
```

```
104.16.132.229
server: cloudflare
cf-ray: 8f3a2b1c9d7e-LHR
```

Заголовок `cf-ray` однозначно указывает на Cloudflare. Другие признаки по провайдерам:

| Заголовок или признак | Провайдер |
|-----------------------|-----------|
| `server: cloudflare`, `cf-ray` | Cloudflare |
| `server: AkamaiGHost`, `x-akamai-transformed` | Akamai |
| `x-amz-cf-id`, `via: ...cloudfront.net` | CloudFront |
| `x-served-by: cache-*`, `x-fastly-request-id` | Fastly |
| `x-iinfo`, `visid_incap` | Imperva |

Дополнительно проверяем ASN: Cloudflare — AS13335, Akamai — AS20940, CloudFront — AS16509, Fastly — AS54113.

## Шаг 2: исторический DNS — первый источник origin

Раньше домен мог резолвиться напрямую, до переезда под CDN. Эти адреса остались в истории.

```bash
curl -s "https://api.securitytrails.com/v1/history/api.example.com/dns/a" \
  -H "APIKEY: $ST_KEY" | jq -r '.records[].values[].ip'
```

```
203.0.113.10
104.16.132.229
```

Отбрасываем адрес Cloudflare (`104.16.x.x`) и получаем кандидата `203.0.113.10` — адрес вне сети CDN.

## Шаг 3: CT-логи и поддомены — второй источник

Certificate Transparency хранит все имена, на которые выдавались сертификаты, включая внутренние.

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | tr '[:upper:]' '[:lower:]' | sort -u
```

```
dev.api.example.com
origin.api.example.com
api.example.com
```

Имя `origin.api.example.com` — почти прямая подсказка. Резолвим его:

```bash
dig +short origin.api.example.com
```

```
203.0.113.10
```

Совпало с историческим DNS — уверенность растёт. Поддомены `dev`, `staging`, `mail`, `direct`, `origin` часто **не** за CDN.

## Шаг 4: проверяем кандидата через заголовок Host

Найденный IP ещё не гарантированно origin. Проверяем, отвечает ли он на целевой домен: делаем запрос к IP, но в заголовке `Host` указываем имя.

```bash
curl -skI "https://203.0.113.10/" -H 'Host: api.example.com' | head -5
```

```
HTTP/2 200
server: nginx
x-api-version: v3
```

Ответ совпал с тем, что отдаёт домен через CDN, — origin найден. Проверить можно и по телу ответа:

```bash
curl -sk "https://203.0.113.10/" -H 'Host: api.example.com' | sha256sum
curl -sk "https://api.example.com/" | sha256sum
```

Иногда origin настроен требовать секретный заголовок от CDN (Authenticated Origin Pulls) — тогда прямой запрос вернёт `403`. Это тоже сигнал, что сервер найден.

## Шаг 5: другие источники origin

Если первые два не сработали, подключаем остальные:

- **Favicon-хэш:** поиск иконки в Shodan/FOFA находит сервер вне CDN.
- **SPF/MX:** `dig TXT example.com | grep ip4:` — почтовый сервер часто на том же хостинге.
- **Утечки:** `.git/config`, CI-логи, JS-бандлы с `sourceMappingURL`, paste-сайты.
- **Сторонние сервисы:** CloudFlair, CloudFail — автоматизируют поиск по сертификатам и истории.

```bash
dig +short TXT example.com | grep -oE 'ip4:[0-9./]+'
dig +short MX example.com
```

## Шаг 6: обход WAF и границы

Прямой доступ к origin обходит WAF, поэтому инъекции, которые «резал» фильтр, могут сработать. Но здесь важно держать рамки:

- **origin в scope — можно; вне scope — нет.**
- **CDN-узлы — собственность провайдера**, их не трогаем.
- Если origin в другом ASN, убедись, что он всё ещё в scope программы.

И задокументируй метод, IP и дату: при повторном тестировании CDN может переехать, и старый origin перестанет отвечать.

## Источники origin — углублённо

Если исторический DNS и CT молчат, подключаем остальные каналы:

- **Исторический DNS:** SecurityTrails, ViewDNS, RiskIQ. Ищи A-записи, сделанные до появления CNAME на CDN.
- **Favicon-хэш:** поиск иконки в Shodan/FOFA находит тот же сервер вне CDN.
- **SPF/MX:** директивы `ip4:` в SPF часто указывают на хостинг почты, а он нередко совпадает с origin.
- **Утечки:** `.git/config`, CI-логи, JS-бандлы с `sourceMappingURL`, paste-сайты.
- **Сторонние сервисы:** JARM-фингерпринт и Censys по сертификату.

```bash
dig +short TXT example.com | grep -oE 'ip4:[0-9./]+'
dig +short MX example.com
```

## Инструменты автоматизации

- **CloudFlair** — поиск origin через Shodan/Censys по сертификатам.
- **CloudFail** — origin через исторические DNS и CT.
- **bypass-firewalls-by-DNS-history** — история A-записей в один прогон.

```bash
python3 cloudflair.py example.com -o out.txt
python3 bypass-firewalls-by-DNS-history.py -d example.com
```

## Определение CDN: подробный разбор

Провайдера можно определить не только по `cf-ray`. Сводная таблица признаков:

| Провайдер | ASN | Типовой заголовок |
|-----------|-----|-------------------|
| Cloudflare | 13335 | `cf-ray` |
| Akamai | 20940 | `x-akamai-*` |
| CloudFront | 16509 | `x-amz-cf-id` |
| Fastly | 54113 | `x-served-by` |
| Imperva | 19551 | `x-iinfo` |

```bash
dig +short www.example.com
whois 104.16.x.x | grep -iE 'netname|orgname'
curl -s "https://api.bgpview.io/ip/104.16.x.x" | jq '.data.prefixes[].asn'
```

Если при прямом запросе по IP без Host сайт не отдаётся (403 или редирект) — это тоже признак CDN-узла.

## Почему это важный навык

Origin discovery часто определяет успех всего тестирования: пока ты бьёшь в CDN, WAF режет атаки, а прямой сервер остаётся нетронутым. Найденный origin меняет картину — ты видишь приложение без фильтра. Именно поэтому этот навык стоит отрабатывать отдельно и комбинировать источники, а не полагаться на один.

## Что мы теперь знаем

По-простому:

1. CDN определяется по заголовкам и ASN.
2. Исторический DNS даёт IP до переезда в CDN.
3. CT и поддомены (`origin`, `dev`) выдают настоящие хосты.
4. Кандидата проверяют запросом с заголовком `Host`.
5. `403` при прямом запросе — тоже сигнал, что origin найден.

## На что смотреть дальше

- **Не путай CDN-IP с origin.** Сначала проверь ASN и заголовки.
- **Не останавливайся на одном источнике.** Origin часто находится комбинацией.
- **Не игнорируй поддомены.** `direct.example.com` — классика.
- **Не сканируй слепо.** Убедись, что IP в scope и принадлежит цели.
- **Не забудь про IPv6.** Origin может быть доступен только по нему.

## Квиз

Проверь себя.

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

## Куда дальше

В следующем уроке мы займёмся **технологическим фингерпринтом** — определением стека сайта по заголовкам, статике и публичным базам. А пока запомни главное: origin ищут комбинацией источников, а найденный IP обязательно проверяют заголовком `Host`, прежде чем считать его настоящим сервером.

## Где пригодится

- **CTF:** обход фильтрации через прямой origin.
- **Bug bounty:** доступ к защищённому WAF функционалу и расширение impact.
- **Пентест:** определение реального периметра за CDN/WAF.
- **Blue team:** проверка, не утекает ли origin (закрытие прямых портов, firewall, Authenticated Origin Pulls).
