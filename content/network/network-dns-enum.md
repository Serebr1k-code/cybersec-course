---
id: network-dns-enum
title: "Перечисление DNS: zone transfer, брутфорс и DNS-разведка"
category: network
parent: network-module-dns
difficulty: medium
order: 2
tags: [network, dns, enumeration, axfr, subdomain, brute, recon]
prerequisites: [network-module-dns, network-dns-records]
useful_for:
  - "CTF Network (DNS-перечисление)"
  - "Пентест: карта поддоменов и зон"
  - "Работа (SOC): детект перечисления"
estimated_minutes: 55
summary: "Как перечислять DNS: zone transfer (AXFR), брутфорс поддоменов, обратный брутфорс, типовые SRV/поддомены и инструменты (dig, dnsx, gobuster, dnsrecon) — с командами и разбором."
---

Перечисление DNS — первый шаг разведки: пока другие сканируют порты, вы получаете список имён, которые указывают на внутренние сервисы, staging-среды и забытые поддомены. Урок продолжает [`network-module-dns`](network-module-dns) и опирается на [`network-dns-records`](network-dns-records).

## Zone transfer: один запрос — вся зона

Если авторитетный сервер разрешает **AXFR**, вы получаете всю зону: все A, MX, TXT, внутренние имена. Это самая ценная ошибка конфигурации.

```bash
# Найти авторитетные серверы
dig example.com NS +short
# Попробовать transfer с каждого
for ns in $(dig +short example.com NS); do
  echo "== $ns"; dig AXFR example.com @$ns | head -50
done
# dnsrecon автоматизирует
dnsrecon -d example.com -t axfr
```

Частая защита: AXFR разрешён только «своим» (вторичным серверам), но иногда его открывают всем.

## Брутфорс поддоменов

Когда AXFR закрыт, имена подбирают по словарю:

```bash
# gobuster dns
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -q
# dnsx — массовый резолвинг списка имён
dnsx -l names.txt -a -resp -o resolved.txt
# puredns — с валидацией wildcard
puredns bruteforce words.txt example.com -r resolvers.txt
```

Важно отличать реальные записи от **wildcard** (`*.example.com` резолвится на всё). Проверка: запросить случайное имя (`dig random123.example.com`).

```bash
# Проверка wildcard
dig +short doesnotexist-$(date +%s).example.com
# Если что-то вернулось — есть wildcard, брутфорс шумный
```

## Обратный брутфорс (PTR)

Иногда быстрее пройтись по диапазону IP и посмотреть PTR-имена:

```bash
# Обратный брутфорс подсети
for i in $(seq 1 254); do dig -x 10.0.0.$i +short; done
# Инструментом
dnsrecon -r 10.0.0.0/24
```

## Типовые SRV и «интересные» имена

```bash
D=example.com
# Active Directory
dig _ldap._tcp.$D SRV +short
dig _kerberos._tcp.$D SRV +short
dig _gc._tcp.$D SRV +short
# Прочее
dig _sip._tcp.$D SRV +short
dig _xmpp-server._tcp.$D SRV +short
```

Словарь «интересных» префиксов: `dev`, `staging`, `test`, `admin`, `vpn`, `mail`, `git`, `jenkins`, `api`, `internal`, `intranet`, `old`, `backup`.

## Инструменты перечисления

| Инструмент | Роль |
|---|---|
| `dig`/`host` | точечные запросы, AXFR |
| `dnsrecon` | AXFR, брутфорс, обратка |
| `dnsenum` | комплексное перечисление |
| `gobuster dns` | брутфорс поддоменов |
| `dnsx` | массовый резолвинг |
| `puredns` | брутфорс + валидация wildcard |
| `amass` | пассивная агрегация (OSINT) |

```bash
# Комплексный прогон
dnsrecon -d example.com -t std,brt,axfr
dnsenum example.com
```

## Пассивные источники

Кроме активных запросов, имена собирают пассивно: certificate transparency (crt.sh), DNS-архивы (SecurityTrails, VirusTotal), web-архивы. Это не создаёт трафика к цели.

```bash
# Certificate Transparency (пассивно)
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
```

Подробнее — в OSINT-ветке.

## Практика: полный цикл перечисления

```bash
D=example.com
# 1. Авторитетные серверы и AXFR
dig $D NS +short
for ns in $(dig +short $D NS); do dig AXFR $D @$ns 2>/dev/null; done | tee axfr.txt
# 2. Пассивно из crt.sh
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u > ct.txt
# 3. Брутфорс словарём
gobuster dns -d $D -w subdomains.txt -t 50 -q -o brute.txt
# 4. Резолвинг и дедупликация
cat ct.txt brute.txt | sort -u | dnsx -a -resp -o resolved.txt
wc -l resolved.txt
```

## Детект перечисления (для SOC)

- **всплеск NXDOMAIN** с одного источника — брутфорс;
- **много запросов разных имён** за короткое время;
- **AXFR-запрос** от неожидаемого клиента;
- **обратный брутфорс** PTR по диапазону.

```bash
# Топ источников по числу NXDOMAIN
tshark -r cap.pcap -Y 'dns.flags.rcode==3' -T fields -e ip.src | sort | uniq -c | sort -rn | head
```

## Частые ошибки

- **Игнорировать wildcard** — брутфорс выдаёт мусор.
- **Доверять одному источнику** — crt.sh не полон.
- **Забывать про SRV** — сервисы не находятся.
- **Пропускать обратку** — PTR раскрывает имена.
- **Брутить без rate-limit** — получите блокировку/бан.
- **Не дедуплицировать** — дубли мешают анализу.
- **Забывать про DNSSEC-поддомены** — они тоже видны.

## Что дальше / решение

После перечисления переходите к [`network-dns-attacks`](network-dns-attacks) (спуфинг, rebinding) и [`network-dnssec`](network-dnssec). Для туннелей — [`network-dns-tunnel`](network-dns-tunnel).

## Словари и стратегии перечисления

| Словарь | Размер | Когда |
|---|---|---|
| subdomains-top1million-5000 | 5000 | быстрый старт |
| subdomains-top1million-110000 | 110k | глубже |
| dns-Jhaddix | ~2M | полный |
| кастомный | свои префиксы | целевой |

Правильная стратегия: сначала пассивные источники (crt.sh, архивы), затем быстрый брутфорс топ-5000, затем — расширение словаря по найденным паттернам.

```bash
# Паттерны из уже найденных имён
grep -Eo '^[a-z]+' resolved.txt | sort | uniq -c | sort -rn | head
# Сгенерировать кандидатов по шаблону
for env in dev staging test uat; do for app in api web git; do echo "$env-$app"; done; done
```

## Лаборатория: перечисление end-to-end

```bash
D=example.com
# 1. Пассивно
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' \
  | sed 's/\*\.//' | sort -u > ct.txt
# 2. Быстрый брутфорс
gobuster dns -d $D -w subdomains-top1million-5000.txt -t 50 -q -o brute.txt
# 3. Резолвинг
cat ct.txt brute.txt | sort -u | dnsx -a -resp -o resolved.txt
# 4. Проверить wildcard заранее
dig +short no-such-$(date +%s).$D
wc -l resolved.txt
```

## Чек-лист перечисления

1. Проверен ли **wildcard** (`dig random...`)?
2. Использованы ли **пассивные** источники (crt.sh, архивы)?
3. Найден ли **AXFR**?
4. Прошлись ли по **SRV** и обратке?
5. Настроен ли **rate-limit**, чтобы не забанили?
6. **Дедуплицированы** ли результаты?
7. Проверены ли найденные имена на **takeover**?

```bash
# Сводка по найденным именам
wc -l resolved.txt
cut -d. -f1 resolved.txt | sort | uniq -c | sort -rn | head
```

## Вывод

Перечисление — итеративный процесс: пассивные источники дают старт, брутфорс расширяет, обратка добавляет внутренние имена, а SRV раскрывает сервисы. Ключ — валидация wildcard и дедупликация, иначе результат утонет в мусоре.

## Продвинутые техники перечисления

```bash
# Перестановки и мутации известных имён
dnsgen resolved.txt | dnsx -a -resp
# Использование нескольких резолверов (устойчивость к rate-limit)
puredns bruteforce words.txt example.com -r resolvers.txt
# Проверка takeover по CNAME
while read host; do
  c=$(dig +short CNAME $host); [ -n "$c" ] && echo "$host -> $c -> $(dig +short $c)"
done < resolved.txt | grep -E '\-> $'
```

**Мутации** (dnsgen, altdns) расширяют словарь, комбинируя найденные паттерны: `api-dev`, `dev-api`, `api2`. Это ловит имена, которых нет в словаре.

## Детект и защита

| Признак | Что означает |
|---|---|
| Всплеск NXDOMAIN | брутфорс |
| AXFR от чужого IP | попытка transfer |
| Много типов запросов | разведка |
| Обратный брутфорс PTR | сканирование диапазона |
| Запросы к wildcard | проверка на wildcard |

```bash
# Мониторинг: топ источников NXDOMAIN
tshark -r cap.pcap -Y 'dns.flags.rcode==3' -T fields -e ip.src \
  | sort | uniq -c | sort -rn | head
# Детект AXFR
tshark -r cap.pcap -Y 'dns.opcode==0 && dns.qry.type==252' -T fields -e ip.src
```

## Защита на стороне цели

```text
# Cisco/BIND: ограничить AXFR только вторичным серверам
allow-transfer { 10.0.0.2; };
# Включить rate-limiting (RRL) в BIND
rate-limit { responses-per-second 10; };
# Отключить wildcard, если он не нужен
```

## Вывод

Перечисление эффективно, когда сочетает пассивные источники, брутфорс, мутации и обратку — и всегда валидирует wildcard. Защита симметрична: закрыть AXFR, ограничить rate, убрать лишний wildcard, мониторить NXDOMAIN и AXFR-запросы.

## Квиз

```quiz
- question: "Что даёт успешный AXFR?"
  options:
    - "Полную зону DNS"
    - "Только A-записи"
    - "Сертификаты"
    - "Пароли"
  answer: 0
  explanation: "Zone transfer отдаёт все записи зоны."
- question: "Зачем проверять wildcard перед брутфорсом?"
  options:
    - "Чтобы отличить реальные имена от мусорных совпадений"
    - "Чтобы ускорить резолвинг"
    - "Чтобы включить DNSSEC"
    - "Чтобы сменить TTL"
  answer: 0
  explanation: "Wildcard резолвит любое имя и искажает результаты."
- question: "Какой пассивный источник имён не создаёт трафика к цели?"
  options:
    - "Certificate Transparency (crt.sh)"
    - "dig AXFR"
    - "gobuster dns"
    - "Обратный брутфорс"
  answer: 0
  explanation: "crt.sh — публичный лог сертификатов, запросы идут к нему."
- question: "Какой SRV-префикс указывает на Active Directory LDAP?"
  options:
    - "_ldap._tcp"
    - "_sip._tcp"
    - "_xmpp-server._tcp"
    - "_http._tcp"
  answer: 0
  explanation: "_ldap._tcp находит контроллеры домена."
- question: "Какой признак перечисления в дампе?"
  options:
    - "Всплеск NXDOMAIN с одного источника"
    - "Ровный поток HTTPS"
    - "Один ARP-запрос"
    - "Стабильный TTL"
  answer: 0
  explanation: "Много несуществующих имён — типичный брутфорс."
```

## Где пригодится

- **CTF:** задачи с DNS-перечислением и скрытыми записями.
- **Пентест:** карта поддоменов и внутренних сервисов.
- **SOC:** детект брутфорса и AXFR-запросов.
- **Инженерия:** контроль AXFR, wildcard, rate-limit.
