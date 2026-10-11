---
id: osint-tls-fingerprint
title: "TLS-фингерпринт: JA3/JA4, сертификаты и шифры"
category: osint
parent: osint-web-surface
difficulty: hard
order: 4
tags: [osint, tls, ja3, ja4, certificate, ssl, fingerprint, cdn]
prerequisites: [osint-tech-fingerprint]
useful_for:
  - "CTF категория OSINT"
  - "Bug bounty и пентест"
  - "Threat intelligence и атрибуция"
estimated_minutes: 30
summary: "TLS как источник разведданных: разбор сертификатов и цепочек, JA3/JA4-отпечатки, поиск origin за CDN и корреляция хостов по стеку TLS."
---
TLS (Transport Layer Security) — это слой, который почти каждый сайт обязан иметь. Но TLS не только шифрует трафик: он **раскрывает данные о хосте и о клиенте**. Сертификат говорит, на какие имена выдан, кто выдал и когда. Набор поддерживаемых шифров и расширений (JA3/JA4) образует отпечаток, по которому можно отличать стеки и находить аффилированные хосты. Для OSINT это надёжный, часто недооценённый источник.

## Теория: что такое отпечаток TLS

Когда клиент устанавливает TLS-соединение, он в `ClientHello` сообщает: версию, список шифров (cipher suites), расширения (SNI, ALPN и др.), поддерживаемые группы. Порядок и состав этих полей **зависят от библиотеки** (OpenSSL, BoringSSL, NSS, Go crypto, SChannel) и её версии. Хэш от этой комбинации — это **JA3** (у клиента) и аналогично для сервера. **JA4** — модернизированная версия, учитывающая больше полей и ALPN.

Ключевые идеи:
- **JA3/JA4 клиента** — отпечаток ПО клиента. Все боты, парсеры и малварь имеют характерные JA3.
- **JA3/JA4 сервера** — отпечаток серверного стека. Позволяет найти «близнецов» по TLS.
- **Сертификат** — имена (SAN), издатель, срок, отпечатки ключа.

## Разбор сертификата

Базовый просмотр:

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Вывод:

```
subject=CN = example.com
issuer=C = US, O = Let's Encrypt, CN = R3
notBefore=Sep 10 00:00:00 2026 GMT
notAfter=Dec  9 23:59:59 2026 GMT
X509v3 Subject Alternative Name:
    DNS:example.com, DNS:www.example.com, DNS:api.example.com
```

Из сертификата сразу извлекаются **все SAN** — список имён, на которые он выдан. Это прямой источник поддоменов, как и Certificate Transparency, но «живой» — то, что сервер отдаёт прямо сейчас.

Полный дамп:

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -text
```

Смотрим на:
- **Issuer** — Let's Encrypt, DigiCert, Sectigo, внутренний CA (последнее — признак корпоративного периметра).
- **SAN** — список имён (может включать внутренние поддомены).
- **Key Usage / Extended Key Usage** — для чего ключ.
- **Public-Key** — алгоритм и размер (RSA 2048 vs ECDSA).
- **Serial** — уникален для сертификата.

## Цепочка сертификатов

Сервер отдаёт не один сертификат, а цепочку. Она показывает используемый CA и промежуточные звенья:

```bash
echo | openssl s_client -connect example.com:443 -servername example.com -showcerts 2>/dev/null | grep -E 's:|i:'
```

```
 0 s:CN = example.com
   i:C = US, O = Let's Encrypt, CN = R3
 1 s:C = US, O = Let's Encrypt, CN = R3
   i:C = US, O = Internet Security Research Group, CN = ISRG Root X1
```

Цепочка на Let's Encrypt → сайт автоматизирован (certbot/acme.sh), вероятно, на обычном хостинге. Цепочка на внутренний CA (например, `CN=Corp-Enterprise-CA`) → корпоративная инфраструктура, что само по себе — находка.

## JA3/JA4: отпечаток стека

Получить серверный JA3 можно утилитой `ja3` или через `nmap`/`tshark`. Для серверной стороны удобен `ja3`-скрипт, для клиентской — `tshark`:

```bash
# клиентский JA3 из pcap (запись TLS-хендшейка)
tshark -r capture.pcap -T fields -e tls.handshake.ja3 -Y 'tls.handshake.type==1'
```

Инструмент `ja3` по домену:

```bash
ja3 example.com 443
# ja3: 771,4865-4866-4867-49195-...,0-11-10-35-...,29-23-24,0
# ja3_hash: cd08e31494f9531f560d64c695473da9
```

Что делать с отпечатком:
- **Искать в базах.** TLS-фингерпринты серверов индексируются (например, Shodan показывает `ssl.ja3s`). Один и тот же серверный JA3 связывает хосты одного стека.
- **Определять ПО.** Клиентский JA3 известных ботов (curl, python-requests, малвари) опубликован — это база для детекта.
- **Находить origin за CDN.** Origin часто имеет «голый» TLS-стек, отличный от CDN-прослойки.

## Разобранный пример: origin за Cloudflare

Цель: `www.example.com` за Cloudflare. Ищем настоящий сервер.

Шаг 1 — подтверждаем CDN:

```bash
curl -sSI https://www.example.com | grep -i 'server\|cf-ray'
# server: cloudflare
# cf-ray: 8a1b... 
```

Шаг 2 — берём SAN и исторические сертификаты:

```bash
echo | openssl s_client -connect www.example.com:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
# DNS:www.example.com, DNS:example.com, DNS:origin.example.com
```

`origin.example.com` — прямой кандидат. Шаг 3 — проверяем его:

```bash
dig +short origin.example.com
# 203.0.113.42   ← не Cloudflare-диапазон
curl -sSI https://origin.example.com -H 'Host: www.example.com' | head -1
# HTTP/1.1 200 OK
```

Origin найден: IP не в диапазоне Cloudflare и отвечает на запрос с Host цели. Классический обход CDN через утечку в SAN.

## Корреляция хостов по TLS

Один серверный JA3/JA4 + одинаковый набор шифров + похожие сертификаты = одна инфраструктура. Это позволяет связать хосты, которые формально на разных доменах:

```bash
for h in a.example.com b.example.net c.example.org; do
  echo "== $h =="
  echo | openssl s_client -connect $h:443 -servername $h 2>/dev/null \
    | openssl x509 -noout -issuer -serial 2>/dev/null
done
```

Если serial/issuer совпадают — вероятно, один и тот же сервер (или один шаблон выпуска). Совпадение отпечатка публичного ключа (`pubkey hash`) — сильное доказательство.

## Таблица: что даёт TLS

| Данные | Источник | Применение |
|--------|----------|-----------|
| SAN-имена | `x509 -ext subjectAltName` | поддомены, origin |
| Issuer | `x509 -issuer` | CA, автоматизация, корп-периметр |
| Serial | `x509 -serial` | связь сертификатов |
| JA3/JA4 клиента | `tshark` по pcap | идентификация ПО/ботов |
| JA3/JA4 сервера | `ja3`, Shodan | корреляция хостов |
| Cipher suites | `s_client -cipher` | версия/тип стека |
| Срок | `x509 -dates` | гигиена, автопродление |

## Ошибки и подводные камни

- **Забывать `-servername` (SNI).** Без SNI сервер может отдать дефолтный сертификат — неверный вывод.
- **Считать SAN исчерпывающим.** Wildcard `*.example.com` скрывает конкретные имена; смотрите CT-логи.
- **Путать серверный и клиентский JA3.** Это разные отпечатки; для детекта клиента нужен pcap.
- **Игнорировать срок действия.** Просроченный сертификат — сигнал заброшенного/теневого хоста.
- **Доверять самоподписанным как «цели».** Самоподписанный сертификат на публичном IP — часто админка, но может быть и honeypot.
- **Не проверять исторические сертификаты.** Текущий SAN может не содержать старых имён; CT-логи содержат.

## Что дальше / решение

TLS-фингерпринт замыкает модуль веб-поверхности: вы знаете стек, ID владельца, структуру и TLS-отпечаток. Дальше: **сертификаты через CT** (ветка инфраструктуры) для исторических имён, **картирование поверхности атаки** (`osint-attack-surface`) и **CDN/origin** (`osint-cdn-origin`). Итог: TLS даёт вам имена, издателя, стек и способ найти origin — всё из одного соединения.

## JA4 и современные отпечатки

JA4 — развитие JA3: учитывает больше полей, версию TLS, ALPN и порядок расширений. Формат:

```
ja4 = t13d1516h2_8daaf6152771_02713d6af862
      │  │      │    │
      │  │      │    └─ хэш расширений
      │  │      └────── хэш шифров
      │  └───────────── кол-во шифров/расширений, ALPN
      └──────────────── протокол (t=TCP, q=QUIC), версия TLS
```

Преимущество: JA4 устойчивее к рандомизации порядка (GREASE) и лучше различает клиентов. Инструменты: `ja4` (FoxIO), `tshark` (поле `tls.handshake.ja4`).

```bash
tshark -r capture.pcap -T fields -e tls.handshake.ja4 -Y 'tls.handshake.type==1'
```

## Поиск origin за CDN: дополнительные методы

Помимо SAN, origin находят:
- **Исторический DNS** (см. `osint-dns-history`) — IP до включения CDN.
- **Почтовые заголовки** — `Received` иногда показывает origin-IP.
- **Поддомены без CDN** — `direct.`, `origin.`, `ftp.` часто вне CDN.
- **SSL-сертификаты по IP** — сканирование диапазона на сертификат с именем цели.
- **Favicon/уникальные пути** — поиск в Shodan/Censys по фингерпринту.

```bash
# сканирование диапазона на сертификат цели (в рамках авторизации)
nmap -p443 --script ssl-cert 203.0.113.0/24 | grep -B2 'example.com'
```

## Проверка TLS-конфигурации

Полный аудит TLS:

```bash
testssl.sh --quiet --color 0 https://example.com | head -40
```

Смотрим: поддерживаемые протоколы (TLS 1.0/1.1 — плохо), слабые шифры (RC4, 3DES), HSTS, OCSP stapling. Это оценка гигиены (см. `osint-dnssec-caa`).

## Резюме: TLS как разведданные

TLS — недооценённый источник. Из одного соединения извлекается: список имён (SAN), CA и его тип, срок, стек (JA3/JA4), а через историю — origin за CDN. Всё это пассивно и легально.

## OCSP, CRL и прозрачность

- **OCSP** — проверка отзыва сертификата. `openssl ocsp` показывает статус.
- **CRL** — списки отозванных.
- **Certificate Transparency** — публичный лог всех выданных сертификатов (см. `osint-cert-transparency`).

```bash
echo | openssl s_client -connect example.com:443 -servername example.com -status 2>/dev/null \
  | grep -A2 'OCSP Response Status'
```

Отозванный сертификат на живом сайте — сигнал инцидента/компрометации, ценный для threat intelligence.

## Квиз

```quiz
- question: "Что содержит поле Subject Alternative Name (SAN) сертификата?"
  options:
    - "Список портов"
    - "Список имён (доменов), на которые выдан сертификат"
    - "Пароль сервера"
    - "DNS-зону"
  answer: 1
- question: "Почему без флага `-servername` вывод openssl может быть неверным?"
  options:
    - "openssl не работает без него"
    - "Без SNI сервер может отдать дефолтный сертификат"
    - "Флаг ускоряет соединение"
    - "Он меняет порт"
  answer: 1
- question: "Что такое JA3?"
  options:
    - "Тип сертификата"
    - "Хэш-отпечаток параметров TLS-хендшейка (шифры, расширения)"
    - "Протокол DNS"
    - "Формат pcap"
  answer: 1
- question: "Как SAN помогает найти origin за CDN?"
  options:
    - "Он шифрует трафик"
    - "В нём может светиться имя вроде origin.example.com с реальным IP"
    - "Он блокирует Cloudflare"
    - "Он меняет Host-заголовок"
  answer: 1
- question: "О чём говорит issuer вида `CN=Corp-Enterprise-CA`?"
  options:
    - "Публичный CA Let's Encrypt"
    - "Внутренний корпоративный CA — вероятно, корп-периметр"
    - "Сертификат просрочен"
    - "Это самоподписанный тест"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** в SAN/истории сертификата спрятан нужный поддомен.
- **Bug bounty:** обход CDN и поиск origin для теста защиты.
- **Threat intelligence:** идентификация клиентского ПО по JA3, поиск C2.
- **Пентест:** корреляция хостов одной инфраструктуры по TLS-стеку.
- **Blue team:** инвентаризация сертификатов и поиск теневых/просроченных.
