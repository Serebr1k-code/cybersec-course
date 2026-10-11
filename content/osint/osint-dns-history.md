---
id: osint-dns-history
title: "Исторические и пассивные DNS: SecurityTrails, PassiveTotal"
category: osint
parent: osint-dns-archive
difficulty: medium
order: 1
tags: [dns, passive-dns, securitytrails, historical, origin]
prerequisites: [osint-dns-recon]
useful_for:
  - "Поиск origin-IP за CDN"
  - "Bug bounty: subdomain takeover"
estimated_minutes: 55
summary: "Пассивные DNS-базы (SecurityTrails, PassiveTotal, ViewDNS), исторические A/CNAME-записи, поиск origin за CDN и признаков takeover."
---

Обычный DNS-запрос показывает **текущее** состояние. Но инфраструктура меняется: IP мигрируют в CDN, поддомены переезжают, старые записи остаются. Пассивные DNS-базы хранят историю и позволяют увидеть то, что уже скрыто.

## Что такое пассивный DNS

Пассивный DNS (passive DNS, pDNS) — это архив DNS-ответов, собранный сенсорами у рекурсивных резолверов и корневых серверов. Сервис отдаёт то, что **кто-то уже спрашивал раньше**, не посылая ни одного запроса к цели. Это полностью пассивная разведка.

Ключевые источники:

| Сервис | Особенность |
|---|---|
| SecurityTrails | богатая история A/CNAME/MX/TXT, API |
| PassiveTotal (RiskIQ) | история, WHOIS, хостинг-соседи |
| ViewDNS.info | бесплатные разовые запросы |
| DNSdumpster | визуальная карта, бесплатно |
| AlienVault OTX | passive DNS + IOC |
| RapidDNS | бесплатный, быстрый |

## История записей

```bash
# SecurityTrails: исторические A-записи
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" \
  -H "APIKEY: $ST_KEY" | python3 -m json.tool

# текущие поддомены (лимит 100 на бесплатном тарифе)
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
  -H "APIKEY: $ST_KEY"
```

Для каждой записи смотрите `first_seen` / `last_seen`. Запись, которая была активна год назад и исчезла, — кандидат на takeover, если CNAME остался указывать на сторонний сервис.

## Поиск origin-IP за CDN

CDN (Cloudflare, Akamai) скрывает настоящий сервер. Но раньше домен мог резолвиться напрямую. Историческая A-запись часто выдаёт origin:

1. Возьмите домен `shop.example.com`.
2. Посмотрите исторические A-записи в SecurityTrails.
3. Отфильтруйте IP, принадлежащие CDN (по ASN: Cloudflare AS13335, Akamai, Fastly).
4. Оставшиеся «серые» IP — вероятный origin.
5. Проверьте: `curl -sI https://<origin-ip> -H 'Host: shop.example.com'` — если отдаёт тот же контент, origin найден.

Дополнительные источники origin: сертификаты CT, старые MX/SPF, скан Shodan/Censys по favicon, утечки в GitHub.

## Поиск origin: полный чек-лист

- [ ] Исторические A-записи (SecurityTrails/RiskIQ) → IP вне ASN CDN.
- [ ] CNAME-цепочки: `dig +short <host> CNAME` → прямой хост провайдера.
- [ ] CT-логи: сертификат мог быть на прямой IP или внутреннее имя.
- [ ] Favicon-хэш в Shodan/FOFA (`osint-favicon`).
- [ ] Поддомены без CDN: `dev`, `staging`, `mail`, `direct`, `origin`.
- [ ] MX/SPF: почтовый сервер часто на том же хостинге, что и origin.
- [ ] Утечки: `.git`, CI-логи, конфиги с внутренним IP.
- [ ] Проверка: `curl -sI https://<ip> -H 'Host: <domain>'` — совпадает ли ответ.

## CNAME-цепочки и takeover

```bash
# ViewDNS / dig CNAME
dig +short shop.example.com CNAME
# если CNAME указывает на сторонний сервис, а сам хост отдаёт 404/NXDOMAIN — takeover
```

Типичные «висячие» CNAME: `*.s3.amazonaws.com`, `*.cloudfront.net`, `*.azurewebsites.net`, `*.github.io`, `*.herokuapp.com`, `*.zendesk.com`. Если ресурс на стороне провайдера уже удалён — атакующий может зарегистрировать его и перехватить имя.

## Соседи по хостингу

Passive DNS позволяет найти **другие домены на том же IP**:

```bash
# RiskIQ/ViewDNS reverse IP
curl -s "https://api.viewdns.info/reverseip/?host=93.158.134.144&apikey=$VD_KEY&output=json"
```

Общие соседи выдают: связанные проекты компании, инфраструктуру подрядчика, потенциальные цели для lateral-разведки.

## Продвинутый origin discovery

Помимо исторических A-записей, origin ищут так:

- **CT-логи**: сертификат мог быть выпущен на прямой IP/внутреннее имя.
- **Favicon-хэш**: поиск в Shodan/FOFA по иконке (см. osint-favicon).
- **Поддомены-«незащищённые»**: `dev`, `staging`, `mail`, `direct` часто не за CDN.
- **SPF/MX**: почтовые серверы часто на том же хостинге.
- **Утечки**: конфиги, `.git`, CI-логи с внутренним IP.
- **Сертификаты SAN**: сертификат на `example.com` может содержать внутренние имена.

## Subdomain takeover: проверка

```bash
# признаки «висячего» CNAME
dig +short sub.example.com CNAME
curl -s "http://sub.example.com" | grep -iE 'NoSuchBucket|No such app|GitHub Pages site|herokuapp'

# массовая проверка
subjack -w subs.txt -t 100 -timeout 30 -o takeovers.txt -ssl
```

Ресурс на стороне провайдера удалён, а CNAME остался → домен можно «занять». В bug bounty это награждается; эксплуатировать без scope нельзя.

## Мониторинг изменений DNS

Историю можно использовать не только для разового разбора, но и для мониторинга:

- Регулярно выгружайте A/CNAME/MX через API и сравнивайте с прошлым снимком.
- Новый CNAME на сторонний сервис — потенциальный takeover-риск.
- Исчезнувшая A-запись у важного хоста — сигнал сбоя или миграции.
- Изменение NS — смена DNS-провайдера (иногда захват домена).

```bash
# сохранить и сравнить
curl -s ".../domain/example.com/subdomains" -H "APIKEY: $ST_KEY" > today.json
diff <(jq -r '.subdomains[]' prev.json) <(jq -r '.subdomains[]' today.json)
```

## Разбор кейса

Задача: найти origin `shop.example.com` за Cloudflare.

1. SecurityTrails → исторические A: `203.0.113.10`, `198.51.100.7`.
2. `203.0.113.10` — ASN Cloudflare (CDN); `198.51.100.7` — хостинг вне CDN.
3. `curl -sI https://198.51.100.7 -H 'Host: shop.example.com'` → отдаёт тот же заголовок `X-Shop: v2`.
4. Origin найден. Дополнительно: reverse IP → ещё 3 домена компании на этом сервере.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| SecurityTrails API | `/history/<d>/dns/a` | история A-записей |
| RiskIQ/PassiveTotal | веб/API | история + соседи |
| ViewDNS | `/reverseip/` | обратный IP |
| DNSdumpster | веб | карта поддоменов |
| subjack | `-w subs.txt -ssl` | takeover |
| nuclei | `-t http/takeovers/` | takeover-шаблоны |

## Частые ошибки

- **Доверять одной базе**: разные pDNS-провайдеры видят разное; сверяйте SecurityTrails + RiskIQ + ViewDNS.
- **Путать passive DNS с активным**: `dig` к найденному имени уже активен; сама база — нет.
- **Игнорировать даты**: старая запись может быть полностью мёртвой; важна последняя активность.
- **Считать CDN-IP origin-ом**: сначала проверьте ASN и наличие заголовков CDN.
- **Пропускать CNAME**: висячие CNAME — отдельный класс уязвимостей.

## Что делать дальше / решение

- **Нужен origin** → исторические A + проверка `Host:` + favicon/CT.
- **Нужны takeover-кандидаты** → висячие CNAME + subjack/nuclei.
- **Нужны соседи** → reverse IP → связанные домены.
- **Нужен мониторинг** → периодический diff поддоменов и записей.

## Как работает сбор passive DNS

Понимание механики помогает интерпретировать данные и их пробелы. Passive DNS-провайдеры ставят **сенсоры** в точках, где виден трафик DNS: у крупных рекурсивных резолверов, в корневых и TLD-узлах, у провайдеров. Сенсор логирует пары «запрос → ответ» и складывает их в базу с метками времени. Отсюда следуют важные свойства: (1) база видит только то, что **кто-то спрашивал**, поэтому редкие имена могут отсутствовать; (2) покрытие зависит от расположения сенсоров — разные провайдеры дают разные срезы; (3) данные обновляются с задержкой; (4) ответы кэшируются, и записи с высоким TTL выглядят «долгоживущими». Именно поэтому одну и ту же цель смотрят в SecurityTrails, RiskIQ и ViewDNS и объединяют результаты, а не доверяют единственной базе. Для CTF, где важна каждая деталь, дополнительно подключают OTX и RapidDNS — они часто содержат имена, которых нет у «крупных» сервисов.

## Проверка origin через favicon и CT: пример

Дополним кейс с `shop.example.com`. Если исторические A-записи не дали чистого origin, подключаем favicon и сертификаты. Сначала берём хэш иконки сайта: `curl -s https://shop.example.com/favicon.ico | python3 -c 'import sys,mmh3,codecs,base64;print(mmh3.hash(codecs.encode(sys.stdin.buffer.read(),"base64")))'`. Затем ищем этот хэш в Shodan/FOFA (`http.favicon.hash:<hash>`) — найдутся все серверы с той же иконкой, включая прямой origin вне CDN. Параллельно смотрим CT: сертификат на `shop.example.com` мог быть выпущен до включения CDN и содержать внутренние имена (`internal-shop`, `shop-prod`) в SAN. Сопоставив оба следа, проверяем кандидата запросом с заголовком `Host:`. Так favicon и CT дополняют исторические A-записи, когда последние «затёрты» миграцией в CDN.

## Пассивный DNS для MX, TXT и IPv6

Историю смотрят не только по A/CNAME. Полезные типы:

- **MX**: старые почтовые серверы выдают прежних провайдеров и связанные хосты; почтовый origin часто не за CDN.
- **TXT/SPF**: включают сторонние сервисы (`include:`), которые перечисляют используемые SaaS и подрядчиков.
- **NS**: смена DNS-провайдера видна в истории и выдаёт миграции/смену подрядчика.
- **AAAA (IPv6)**: у домена может быть отдельная история IPv6, где CDN включён позже, и старый адрес остаётся «голым».

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/mx" -H "APIKEY: $ST_KEY" | jq
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/txt" -H "APIKEY: $ST_KEY" | jq
```

Совокупность MX + SPF + исторических A часто быстрее выводит на origin, чем один только A-историк.

## Быстрая шпаргалка

| Задача | Команда/сервис |
|---|---|
| история A | SecurityTrails `/history/<d>/dns/a` |
| поддомены | SecurityTrails `/domain/<d>/subdomains` |
| обратный IP | ViewDNS `/reverseip/?host=<ip>` |
| takeover | `subjack -w subs.txt -ssl` |
| origin-проверка | `curl -sI https://<ip> -H 'Host: <d>'` |
| мониторинг | diff поддоменов между запусками |

Ключевое: passive DNS — пассивно (не касается цели), но неполно (зависит от сенсоров); всегда сверяйте 2–3 базы.

## Квиз

```quiz
- question: "Чем пассивный DNS отличается от обычного запроса?"
  options:
    - "Он быстрее"
    - "Он отдаёт историю ответов, не посылая запросов к цели"
    - "Он работает только по IPv6"
    - "Он требует прав администратора"
  answer: 1
- question: "Зачем смотреть исторические A-записи домена за CDN?"
  options:
    - "Чтобы найти пароль"
    - "Чтобы обнаружить origin-IP, на который домен указывал до CDN"
    - "Чтобы узнать TTL"
    - "Чтобы сменить DNS-сервер"
  answer: 1
- question: "Что указывает на потенциальный subdomain takeover?"
  options:
    - "CNAME на сторонний сервис, который уже не обслуживает этот хост"
    - "Наличие MX-записи"
    - "Запись TXT с SPF"
    - "Высокий TTL"
  answer: 0
- question: "Какое поле помогает понять, актуальна ли историческая запись?"
  options:
    - "ASN"
    - "first_seen / last_seen"
    - "TTL"
    - "serial в SOA"
  answer: 1
- question: "Почему стоит сверять несколько passive DNS-провайдеров?"
  options:
    - "Они бесплатны"
    - "Разные сенсоры видят разные запросы, покрытие различается"
    - "Один из них всегда врёт"
    - "Так требует закон"
  answer: 1
```

## Где пригодится

- **CTF:** восстановление скрытой истории домена, поиск флага на забытом хосте.
- **Bug bounty:** origin discovery за CDN и поиск takeover-уязвимостей.
- **Пентест:** карта инфраструктуры и связанных доменов для расширения периметра.
- **Blue team:** мониторинг собственных висячих CNAME и устаревших записей.
