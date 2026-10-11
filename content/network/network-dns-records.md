---
id: network-dns-records
title: "DNS-записи глубоко: A, CNAME, MX, TXT, SRV и SOA"
category: network
parent: network-module-dns
difficulty: easy
order: 1
tags: [network, dns, records, a, cname, mx, txt, srv, soa]
prerequisites: [network-module-dns]
useful_for:
  - "CTF Network (разбор DNS-ответов)"
  - "Пентест: разведка по записям"
  - "Работа (SOC/IR): анализ DNS-артефактов"
estimated_minutes: 50
summary: "Подробный разбор типов DNS-записей: как читать A/AAAA/CNAME/MX/TXT/SRV/SOA/PTR, что каждая раскрывает о инфраструктуре и как использовать это в разведке."
---

DNS-записи — это структурированная карта домена. A/AAAA дают адреса, MX — почту, TXT — политики и верификации, SRV — сервисы, SOA — параметры зоны. Умение читать их превращает простой `dig` в полноценную разведку. Урок продолжает [`network-module-dns`](network-module-dns).

## A и AAAA: адреса

**A** — IPv4-адрес, **AAAA** — IPv6. По ним видно, за каким хостингом/провайдером стоит домен, есть ли CDN.

```bash
dig example.com A +short
dig example.com AAAA +short
# Сравнить с ASN/провайдером
whois $(dig +short example.com A | head -1) | grep -i org
```

Несколько A-записей — балансировка; разные подсети — возможный multi-region.

## CNAME: псевдонимы и опасность dangling

**CNAME** — алиас на другое имя. Часто используется для CDN и внешних сервисов. Опасность — **dangling CNAME**: запись указывает на освободившийся ресурс (например, удалённый S3-bucket), и его можно **захватить** (subdomain takeover).

```bash
dig www.example.com CNAME +short
# Проверить, резолвится ли цель
dig $(dig +short www.example.com CNAME) +short
# Если цель не резолвится (NXDOMAIN) — возможен takeover
```

## MX: почтовая инфраструктура

**MX** указывает почтовые серверы с приоритетом. Раскрывает провайдера почты (Google, Microsoft, свой Postfix) и помогает в фишинге/спуфинге.

```bash
dig example.com MX +short
# Определить провайдера
dig example.com MX +short | awk '{print $2}'
```

## TXT: политики и верификации

TXT-записи несут **SPF** (кто может слать почту), **DKIM** (подпись), **DMARC** (политика), а также верификации (Google, Microsoft, домены), ключи и многое другое. Часто там утекает информация о SaaS-сервисах.

```bash
dig example.com TXT +short
# SPF-запись
dig example.com TXT | grep -i spf
# DMARC
dig _dmarc.example.com TXT +short
# DKIM (селектор угадывается)
dig default._domainkey.example.com TXT +short
```

Подробнее — в [`network-arp`](network-arp) (спуфинг) и в разделе про email в OSINT.

## SRV: сервисы и порты

**SRV** описывает сервис: приоритет, вес, порт, целевой хост. Классика — `_sip._tcp`, `_ldap._tcp`, `_kerberos._tcp`. Из SRV видно, какие сервисы есть в домене (Active Directory, SIP, XMPP).

```bash
dig _ldap._tcp.example.com SRV +short
dig _kerberos._tcp.example.com SRV +short
dig _sip._tcp.example.com SRV +short
# Массовый поиск типовых SRV
for s in _ldap._tcp _kerberos._tcp _gc._tcp _sip._tcp _xmpp-server._tcp; do
  echo "== $s"; dig $s.example.com SRV +short
done
```

## SOA: параметры зоны

**SOA** содержит: primary NS, email администратора, **serial**, refresh, retry, expire, **minimum TTL** (для negative caching). Serial растёт при изменениях — по нему отслеживают обновления зоны.

```bash
dig example.com SOA +noall +answer
# Отследить serial
dig +short example.com SOA | awk '{print $3}'
```

## PTR и обратные зоны

**PTR** — обратное разрешение (IP→имя), живёт в `in-addr.arpa` (IPv4) и `ip6.arpa` (IPv6). Раскрывает имена хостов по диапазону и часто выдаёт внутренние названия.

```bash
dig -x 8.8.8.8 +short
# Обратный брутфорс подсети
for i in $(seq 1 20); do dig -x 10.0.0.$i +short; done
```

## CAA: кто может выдавать сертификаты

**CAA** ограничивает, какие CA вправе выпускать сертификаты для домена. Из записи видно, каких CA использует организация.

```bash
dig example.com CAA +short
```

## Практика: собрать профиль домена

```bash
D=example.com
echo "== A/AAAA"; dig $D A +short; dig $D AAAA +short
echo "== MX";     dig $D MX +short
echo "== NS";     dig $D NS +short
echo "== TXT";    dig $D TXT +short
echo "== SOA";    dig $D SOA +short
echo "== CAA";    dig $D CAA +short
echo "== SRV";    dig _ldap._tcp.$D SRV +short
```

Такой профиль — основа разведки: хостинг, почта, сервисы, политики, ограничения.

## Частые ошибки

- **Забывать про AAAA** — IPv6-адрес утекает.
- **Игнорировать TXT** — там SPF/DKIM/DMARC и верификации.
- **Путать NS и SOA** — NS список серверов, SOA — параметры зоны.
- **Не проверять CNAME-цели** — dangling → takeover.
- **Считать PTR обязательным** — часто его нет.
- **Не смотреть SRV** — сервисы остаются незамеченными.
- **Доверять одному резолверу** — кэш искажает картину.

## Что дальше / решение

После записей переходите к [`network-dns-enum`](network-dns-enum) (перечисление зон и поддоменов). Для атак — [`network-dns-attacks`](network-dns-attacks) и [`network-dns-tunnel`](network-dns-tunnel).

## DNSSEC-записи кратко

| Запись | Роль |
|---|---|
| DNSKEY | публичный ключ зоны |
| RRSIG | подпись набора записей |
| DS | хэш ключа дочерней зоны (в родителе) |
| NSEC/NSEC3 | доказательство отсутствия имени |

Цепочка доверия: root → TLD → зона. Проверка подписи защищает от спуфинга, но не от rebinding и не от утечек через TXT.

```bash
# Проверить DNSSEC-валидность
dig +dnssec example.com
delv example.com
# Найти DS-запись
dig example.com DS +short
```

## Практика: профиль поддомена

```bash
S=dev.example.com
echo "== A/AAAA"; dig $S A +short; dig $S AAAA +short
echo "== CNAME";  dig $S CNAME +short
echo "== TXT";    dig $S TXT +short
echo "== SOA";    dig $S SOA +short
# Проверить, не dangling ли CNAME
C=$(dig +short $S CNAME); echo "target=$C"; dig $C +short
```

Если цель CNAME не резолвится — возможен **subdomain takeover**: ресурс освободился, но запись осталась.

## Чек-лист по записям

1. Все ли **A/AAAA** актуальны (нет «мёртвых» IP)?
2. Нет ли **dangling CNAME**?
3. Корректен ли **SPF** (`-all` vs `~all`)?
4. Есть ли **DMARC** (`_dmarc`)?
5. Настроен ли **DKIM** (селекторы)?
6. Ограничен ли выпуск сертификатов (**CAA**)?
7. Ведётся ли **PTR** для почтовых IP?

```bash
# Быстрый аудит почтовых записей
dig example.com MX +short
dig example.com TXT | grep -i spf
dig _dmarc.example.com TXT +short
dig example.com CAA +short
```

## Итог

Каждая запись — фрагмент карты: адреса, почта, сервисы, политики, ограничения. Собирая их вместе, вы получаете профиль домена, который подсказывает и векторы атаки (dangling CNAME, слабый SPF), и точки защиты (DNSSEC, CAA, DMARC).

## Продвинутые сценарии

```bash
# Динамическое разрешение имён через конкретный NS
dig @ns1.example.com www.example.com A
# Проверить сплит-DNS (внутренний vs внешний резолвер)
dig www.example.com +short
dig @8.8.8.8 www.example.com +short
# Найти все CNAME-цепочки
dig +noall +answer www.example.com CNAME
# Проверить ANY (осторожно, часто отключён)
dig example.com ANY
```

Сплит-DNS — норма для организаций: внутренний резолвер отдаёт приватные адреса, внешний — публичные. Для пентеста это означает, что «снаружи» видна лишь часть карты.

## Сравнение типов записей

| Запись | Что раскрывает |
|---|---|
| A/AAAA | адреса, хостинг, CDN |
| CNAME | алиасы, внешние сервисы, takeover |
| MX | почтовый провайдер |
| TXT | SPF/DKIM/DMARC, верификации |
| NS | авторитетные серверы, провайдер DNS |
| SRV | сервисы (AD, SIP, XMPP) |
| SOA | serial, таймеры, админ |
| PTR | обратные имена |
| CAA | разрешённые CA |

## Чек-лист аудита записей

```bash
D=example.com
dig $D A +short
dig $D AAAA +short
dig $D MX +short
dig $D NS +short
dig $D TXT +short
dig $D SOA +short
dig $D CAA +short
dig _dmarc.$D TXT +short
# Проверить каждый CNAME на dangling
dig +short $D CNAME | while read t; do echo "$t -> $(dig +short $t)"; done
```

## Вывод

Записи — самый дешёвый источник разведки и самый частый источник уязвимостей (dangling CNAME, слабый SPF, отсутствие CAA). Регулярный аудит записей и автоматическая проверка целей CNAME закрывают класс subdomain takeover.

## Квиз

```quiz
- question: "Какой тип записи задаёт почтовый сервер?"
  options:
    - "MX"
    - "A"
    - "PTR"
    - "CAA"
  answer: 0
  explanation: "MX указывает почтовые серверы с приоритетом."
- question: "Что хранит TXT-запись домена?"
  options:
    - "Произвольный текст: SPF, DKIM, верификации"
    - "IPv4-адрес"
    - "Почтовый сервер"
    - "Обратное имя"
  answer: 0
  explanation: "TXT несёт политики и токены верификации."
- question: "Чем опасен dangling CNAME?"
  options:
    - "Освободившийся ресурс можно захватить (subdomain takeover)"
    - "Он ускоряет резолвинг"
    - "Он шифрует DNS"
    - "Он меняет TTL"
  answer: 0
  explanation: "Цель алиаса можно занять и обслуживать поддомен."
- question: "Что описывает SRV-запись?"
  options:
    - "Сервис, порт и целевой хост"
    - "Почту"
    - "Адрес"
    - "Сертификат"
  answer: 0
  explanation: "SRV задаёт приоритет, вес, порт и хост для сервиса."
- question: "Что содержит SOA-запись?"
  options:
    - "Параметры зоны: serial, TTL, primary NS"
    - "IPv4-адрес"
    - "Список почтовых серверов"
    - "Обратное имя"
  answer: 0
  explanation: "SOA описывает зону и её таймеры."
```

## Где пригодится

- **CTF:** разбор DNS-ответов и поиск утечек.
- **Пентест:** разведка хостинга, почты, сервисов.
- **SOC/IR:** анализ DNS-артефактов в инцидентах.
- **Инженерия:** корректные записи, SPF/DKIM/DMARC.
