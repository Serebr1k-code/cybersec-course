---
id: osint-dns-recon
title: "DNS-разведка и пассивный поиск поддоменов"
category: osint
parent: osint-search-identifiers
difficulty: easy
order: 2
tags: [dns, subdomain, recon, dig, passive]
prerequisites: [osint-search-operators]
useful_for:
  - "Картирование внешней инфраструктуры домена"
  - "CTF-задачи с поддоменами и записями"
estimated_minutes: 45
summary: "Типы DNS-записей, пассивный и активный сбор поддоменов, разбор dig/host/nslookup, реверс DNS."
---

DNS — это «телефонная книга» интернета и одна из самых информативных поверхностей разведки. Прежде чем что-то сканировать, разберитесь, **какие имена и адреса вообще существуют**.

## Типы DNS-записей и что они выдают

| Запись | Значение для разведки |
|---|---|
| `A` / `AAAA` | IPv4/IPv6 адреса — куда указывает имя |
| `CNAME` | псевдоним — выдаёт облако/CDN/SaaS |
| `MX` | почтовые серверы — провайдер почты, кандидаты на фишинг |
| `TXT` | SPF, DKIM, DMARC, верификации сервисов |
| `NS` | серверы имён — DNS-провайдер, зона делегирования |
| `SOA` | первичный сервер зоны, контакт админа |
| `SRV` | сервисы (часто внутренние) |
| `PTR` | обратная запись IP → имя |

Особое внимание — **TXT**: там живут `v=spf1 include:...` (какие сервисы могут слать почту), верификации Google/Microsoft/Atlassian (какие SaaS используют), и иногда остатки ключей.

## Инструменты: dig, host, nslookup

```bash
# все основные записи
dig example.com ANY +noall +answer
dig example.com A +short
dig example.com MX +short
dig example.com TXT +short
dig example.com NS +short

# обратный DNS по IP
dig -x 93.184.216.34 +short

# указать конкретный резолвер (например, публичный)
dig @1.1.1.1 example.com A +short
```

`host` и `nslookup` делают то же самое короче:

```bash
host -t mx example.com
nslookup -type=txt example.com
```

## SPF, DKIM, DMARC

- **SPF** (`TXT` с `v=spf1`) — перечисляет хосты, которым разрешено слать почту от домена. Плохо настроенный SPF (`+all`) = можно подделать отправителя.
- **DKIM** — подпись писем; публичный ключ в `selector._domainkey.example.com` (TXT).
- **DMARC** (`_dmarc.example.com`) — политика обработки писем, проваливших проверку (`p=none` → письма не блокируются).

```bash
dig _dmarc.example.com TXT +short
dig google._domainkey.example.com TXT +short
```

## Пассивный сбор поддоменов

Пассивный метод **не трогает** целевой DNS — вы читаете чужие логи и базы. Это безопасно и незаметно.

- **Certificate Transparency** (см. отдельный урок): `crt.sh` — самый богатый источник.
- **Passive DNS**: `dnsdumpster.com`, `securitytrails.com`, `viewdns.info`.
- **Поисковики**: `site:*.example.com -www`.
- **Wayback Machine**: исторические снимки поддоменов.
- **RapidDNS**: `rapiddns.io/subdomain/example.com`.
- **Утечки CT-логов и публичные датасеты**.

Быстрый пассивный прогон через crt.sh без инструментов:

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | python3 -c 'import sys,json;print("\n".join(sorted({n for e in json.load(sys.stdin) for n in e["name_value"].split(chr(10))})))'
```

## Активный сбор: брутфорс DNS

Активный метод посылает запросы к DNS — это уже заметно. Используйте **только** когда политика позволяет и с малой нагрузкой.

```bash
# перебор словарём (пример с dnsx, аналогично: gobuster dns, ffuf, puredns)
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent

# массовая проверка списка имён
while read h; do dig +short "$h.example.com"; done < names.txt
```

Обнаружили **wildcard** (`*.example.com` резолвится в один IP)? Сначала проверьте случайное имя `dig random123.example.com` — если резолвится, брутфорс будет тонуть в шуме.

## Разбор результатов и корреляция

1. Соберите все имена в один файл.
2. Сгруппируйте по IP: `dig +short name | sort | uniq -c | sort -rn`.
3. Помечайте CDN/облака по CNAME и ASN: `cdn`, `akamai`, `cloudfront`, `yandexcloud`.
4. Ищите **интересные** имена: `admin`, `dev`, `staging`, `internal`, `jenkins`, `git`, `vpn`.
5. Сохраняйте всё в лог с датой.

## Реверс DNS и ASN

Реверс DNS по IP-диапазону помогает найти «соседей» по хостингу:

```bash
dig -x 93.158.134.144 +short
whois 93.158.134.144 | grep -iE 'netname|origin|country'
```

Дальше — переход к ASN и карте инфраструктуры (следующий урок).

## Приоритизация и обогащение результатов

Сырой список имён нужно превратить в приоритеты:

```bash
# сгруппировать по IP (много имён на один IP = shared/один сервер)
for h in $(cat names.txt); do
  ip=$(dig +short "$h" A | head -1)
  [ -n "$ip" ] && echo "$ip $h"
done | sort | tee ip_names.txt

# интересные имена
grep -iE 'admin|dev|staging|test|internal|jenkins|git|vpn|api|db|jira|grafana' names.txt
```

Дальше — HTTP-проверка (`httpx`) и определение технологий (см. osint-subdomain-tools).

## DNS как источник уязвимостей

Помимо карты, DNS даёт векторы:

- **Subdomain takeover**: «висячие» CNAME на удалённые сервисы.
- **Zone transfer (AXFR)**: открытый трансфер = полная зона (см. osint-zone-transfer).
- **Wildcard**: мешает брутфорсу, но создаёт ложные срабатывания.
- **DNS rebinding**: смена ответа для обхода same-origin.
- **Открытый резолвер**: amplification.

## Мониторинг изменений

DNS меняется — настройте мониторинг:

```bash
# сохранить срез и диффить при следующем прогоне
dig +short example.com A > snapshot_$(date +%F).txt
diff snapshot_2024-01-01.txt snapshot_2024-06-01.txt
```

Новые записи (особенно TXT-верификации, новые поддомены) сигналят о развёртывании новых сервисов — повод для повторной разведки.

## dig: справочник флагов и приёмов

`dig` — основной инструмент DNS-разведки; знание флагов ускоряет работу.

```bash
dig example.com A +short                 # только ответ
dig +noall +answer example.com MX        # только секция answer
dig +trace example.com                   # показать делегирование от корня
dig @8.8.8.8 example.com A               # через конкретный резолвер
dig +short example.com NS
dig +short TXT example.com
dig +dnssec example.com A                # запросить RRSIG
dig CH TXT version.bind @ns.example.com  # версия BIND (если раскрыта)
dig +short ANY example.com               # часто урезан (RFC 8482), но пробуем
dig -x 203.0.113.10 +short               # PTR
dig axfr example.com @ns.example.com     # попытка трансфера зоны
```

`+noall +answer` — лучший способ получить чистый вывод в скриптах. `version.bind`/`hostname.bind` (CHAOS-класс) иногда раскрывают версию и хост DNS-сервера.

## Трансфер зоны и wildcard

AXFR отдаёт всю зону — идеальный результат, если разрешён. Если нет — проверьте **wildcard** и брутфорс.

```bash
# AXFR по всем NS зоны
for ns in $(dig +short example.com NS); do
  echo "== $ns =="; dig axfr example.com @$ns | head -50
done
# wildcard: случайные имена, которые «резолвятся», означают wildcard
for i in 1 2 3; do dig +short "$(head -c8 /dev/urandom | base64 | tr -dc a-z)example.com"; done
```

Если случайные имена дают ответ — включён wildcard; брутфорс тогда бесполезен (все имена «существуют»). Различайте настоящие поддомены от wildcard-ответа по содержимому/коду.

## Пассивный сбор поддоменов

```bash
subfinder -d example.com -silent | sort -u > subs.txt
# источники и вывод
subfinder -d example.com -all -recursive -o subs.txt
# amass passive
amass enum -passive -d example.com -o amass.txt
# crt.sh без subfinder (curl-фолбэк)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | tr '\n' '\n' | sort -u
```

Пассивные источники: CT-логи, passive DNS, поисковики, ASN-дампы. Они не касаются цели напрямую — безопасно.

## Перестановки и мутации имён

К найденным поддоменам применяют генераторы вариаций — так находят `dev-`, `-staging`, `api2` и т.п.

```bash
# dnsgen: из известных имён делает варианты
cat subs.txt | dnsgen - | sort -u > permutations.txt
# gotator: комбинации слов
gotator -sub subs.txt -perm permutations.txt -depth 1 -numbers 3 > combos.txt
# резолвим только живые (массово и быстро)
dnsx -l combos.txt -silent -a -resp | tee resolved.txt
massdns -r resolvers.txt -t A -o S combos.txt | grep -v 'NXDOMAIN' > massdns.txt
```

`dnsx` и `massdns` позволяют проверить десятки тысяч имён быстро за счёт пула резолверов.

## Реверс DNS, ASN и BGP

```bash
# PTR для диапазона
for ip in 203.0.113.{1..254}; do dig -x $ip +short; done
# ASN по IP (Team Cymru)
whois -h whois.cymru.com " -v 203.0.113.10"
# префиксы ASN (BGP)
curl -s "https://api.bgpview.io/asn/13335/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'
# все домены на IP (reverse IP)
curl -s "https://api.hackertarget.com/reverseiplookup/?q=203.0.113.10"
```

ASN-префиксы дают **весь** диапазон организации — сканирование по префиксу находит хосты, не попавшие в DNS (osint-bgp).

## DNS как источник уязвимостей

| Запись | Что выдаёт / риск |
|--------|-------------------|
| TXT | верификации, ключи, `google-site-verification`, утечки |
| CNAME | висячие записи → takeover (см. ниже) |
| SPF/DMARC | спуфинг-поверхность (osint-spf-dkim) |
| MX | почтовые провайдеры, внешние сервисы |
| NS | DNS-провайдер, зона ответственности |
| CAA | какие CA разрешены — и что можно выпросить |

```bash
# поиск висячих CNAME (кандидаты на takeover)
while read h; do
  cname=$(dig +short CNAME "$h")
  [ -n "$cname" ] && echo "$h -> $cname"
done < subs.txt | tee cnames.txt
# проверка на takeover-сервисы
grep -Ei 'herokudns|s3|azure|github.io|cloudfront|fastly' cnames.txt
```

## Мониторинг изменений DNS

```bash
# ежедневный снимок и дифф
dig +short example.com A > /tmp/now.txt
diff /tmp/prev.txt /tmp/now.txt && echo "no change" || echo "CHANGED!"
cp /tmp/now.txt /tmp/prev.txt
# dnsx массовый мониторинг
dnsx -l subs.txt -a -resp-only | sort > all_ips.txt
```

Смена A-записи, появление новых поддоменов, изменения TXT — сигналы изменений инфраструктуры (новый деплой, переезд, компрометация).

## Частые ошибки

- **Игнорировать wildcard** — брутфорс «находит» миллионы имён.
- **Забыть указать резолвер** — кэш локального резолвера искажает картину; сверяйте с 8.8.8.8/1.1.1.1.
- **Путать CNAME-цепочку** — `+short` показывает только конечный A; для цепочки используйте `+trace`.
- **Считать отсутствие AXFR безопасностью** — закрытый AXFR при незакрытом брутфорсе/CT ничего не спасает.
- **Не проверять историю** — старые записи (SecurityTrails) дают серверы, которых уже нет в живых DNS.

## Квиз

```quiz
- question: "Какая запись выдаёт почтовый провайдер домена?"
  options:
    - "A"
    - "MX"
    - "PTR"
    - "SRV"
  answer: 1
- question: "Где хранится политика DMARC?"
  options:
    - "В записи A"
    - "В `_dmarc.example.com` (TXT)"
    - "В файле robots.txt"
    - "В NS-записи"
  answer: 1
- question: "Почему пассивный сбор поддоменов безопаснее активного?"
  options:
    - "Он быстрее"
    - "Он не посылает запросов к целевой инфраструктуре"
    - "Он даёт больше результатов"
    - "Он не требует интернета"
  answer: 1
- question: "Что означает `CNAME` для разведки?"
  options:
    - "Прямой IP-адрес"
    - "Псевдоним, раскрывающий облако/CDN/SaaS"
    - "Почтовый сервер"
    - "Обратную запись"
  answer: 1
- question: "Как проверить наличие wildcard DNS?"
  options:
    - "`dig example.com MX`"
    - "`dig random123.example.com`"
    - "`whois example.com`"
    - "`curl example.com`"
  answer: 1
```

## Где пригодится

- **CTF:** расшифровка записей, поиск поддомена с флагом.
- **Bug bounty:** полный охват scope (поддомены часто входят в программу).
- **Пентест:** поиск dev/staging-сред с ослабленной защитой.
- **Blue team:** инвентаризация собственной внешней поверхности.
