---
id: network-tls-fingerprint
title: "TLS-фингерпринт: JA3/JA4, SNI и отпечатки клиентов"
category: network
parent: network-module-appprotos
difficulty: hard
order: 3
tags: [network, tls, ja3, ja4, sni, fingerprint, ech, clienthello]
prerequisites: [network-module-appprotos, network-tls-inspection]
useful_for:
  - "CTF Network (TLS-фингерпринт)"
  - "Пентест: маскировка под легитимный клиент"
  - "Работа (SOC): детект малвари и аномалий"
estimated_minutes: 55
summary: "TLS-фингерпринтинг: ClientHello, SNI, JA3/JA4, сертификаты и ECH — как различать клиентов без расшифровки, как это помогает SOC и как маскироваться под легитимный трафик."
---

Даже полностью зашифрованный TLS оставляет «отпечаток»: набор параметров ClientHello. **JA3/JA4** превращают его в хэш, по которому различают браузер, библиотеку и малварь — без расшифровки. Это ключевой инструмент современного детекта и одновременно цель для маскировки. Урок продолжает [`network-module-appprotos`](network-module-appprotos) и опирается на [`network-tls-inspection`](network-tls-inspection).

## Что видно в TLS-рукопожатии

В открытом виде (до шифрования сессии) видны:

- **ClientHello** — версии TLS, список cipher suites, расширения, supported groups;
- **SNI** — имя сервера, к которому идёт подключение;
- **сертификат сервера** — CN/SAN, издатель, срок;
- **параметры** — ALPN (h2/http/1.1), elliptic curves.

Полезная нагрузка зашифрована, но этих метаданных достаточно для fingerprint.

## SNI: имя без расшифровки

**SNI** (Server Name Indication) — имя хоста в ClientHello. Это то, по чему фильтруют домены и что скрывают через **ECH** (Encrypted Client Hello).

```bash
# SNI из дампа
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u
# ALPN
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_alpn_str | sort -u
```

## JA3: отпечаток ClientHello

**JA3** — MD5 от строки: `TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats`. Одинаковые библиотеки дают одинаковый JA3.

```text
JA3 string: 771,4865-4866-4867-...,0-11-10-35-...,29-23-24,0
JA3 hash:   MD5(строка)
```

```bash
# JA3 из pcap (tshark)
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 | sort | uniq -c | sort -rn
# JA3 для конкретного SNI
tshark -r cap.pcap -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja3 | head
```

## JA4: современный отпечаток

**JA4** (и JA4+) — эволюция JA3: кодирует версию, SNI-наличие, ALPN, шифры, расширения в человекочитаемую строку, устойчивее к порядку. Различает клиентов ещё точнее.

```bash
# JA4 в свежем tshark/zeek
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja4 2>/dev/null | sort | uniq -c
```

## Сертификаты как источник

```bash
# Сертификат сервера: CN/SAN, издатель
tshark -r cap.pcap -Y 'tls.handshake.type==11' -T fields \
  -e x509sat.uTF8String -e x509ce.dNSName | head
# Или через openssl
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
```

SAN раскрывает связанные домены, издатель — вендора (Let's Encrypt, внутренний CA).

## ECH и слепые зоны

**ECH** (Encrypted Client Hello) шифрует SNI, оставляя видимым только «внешний» домен (обычно CDN). Это закрывает фильтрацию по SNI, но JA3/JA4 и тайминги остаются. **DoH/DoT** аналогично скрывают DNS.

```bash
# Признак ECH — внешний SNI провайдера, отсутствие реального имени
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name contains "cloudflare"' | head
```

## Применение в SOC

- **малварь с уникальным JA3** — отличается от браузеров;
- **аномальный JA3 на популярный SNI** — подозрительно;
- **самоподписанные сертификаты** — C2;
- **редкие ALPN/версии** — нестандартные клиенты;
- **корреляция JA3+SNI+тайминги** — профиль клиента.

```bash
# Топ JA3 в сети (найти «нестандартные»)
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 | sort | uniq -c | sort -rn | head
```

## Пентест: маскировка

Чтобы не выделяться, инструмент должен использовать **легитимный JA3** (например, браузера) и корректный SNI/ALPN. Инструменты с нестандартным TLS-стеком (сканеры, C2) легко отличаются по отпечатку.

```bash
# Пример: curl с браузерными параметрами (JA3-подмена — отдельные инструменты)
curl --tls-max 1.3 -H 'User-Agent: Mozilla/5.0' https://example.com
# Инструменты: ja3transport, utls (Go) для кастомного ClientHello
```

## Защита

| Мера | Против чего |
|---|---|
| Мониторинг JA3/JA4 | малварь/аномалии |
| Детект self-signed/редких сертификатов | C2 |
| ECH для приватности | фильтрация по SNI |
| Корреляция с NetFlow/DNS | контекст |
| Обновление инструментов детекта | JA4 |

## Частые ошибки

- **Считать TLS «невидимым»** — метаданные есть.
- **Путать JA3 и SNI** — клиент vs сервер.
- **Игнорировать ECH** — SNI скрыт.
- **Не мониторить сертификаты** — C2 невидим.
- **Не учитывать JA4** — JA3 устаревает.
- **Маскировать только User-Agent** — JA3 выдаёт.
- **Забывать про ALPN** — h2/http1.1 — часть профиля.

## Что дальше / решение

После TLS-фингерпринта вернитесь к [`network-module-appprotos`](network-module-appprotos). Для TLS-атак — [`network-tls-attacks`](network-tls-attacks); для инспекции — [`network-tls-inspection`](network-tls-inspection).

## Практика: анализ JA3/JA4

```bash
# 1. Топ JA3 в трафике
tshark -r cap.pcap -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.ja3 | sort | uniq -c | sort -rn | head
# 2. JA3 для конкретного SNI
tshark -r cap.pcap -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja3 | sort -u | head
# 3. Сертификаты (self-signed?)
tshark -r cap.pcap -Y 'tls.handshake.type==11' \
  -T fields -e x509sat.uTF8String -e x509ce.dNSName | head
# 4. JA4 (свежий tshark)
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja4 2>/dev/null | sort | uniq -c
# 5. Zeek: ssl.log с отпечатками
zeek -r cap.pcap && cat ssl.log | zeek-cut server_name ja3 | head
```

## Сравнение методов фингерпринта

| Метод | Что кодирует | Устойчивость |
|---|---|---|
| SNI | имя сервера | скрывается ECH |
| JA3 | ClientHello (MD5) | средняя |
| JA4/JA4+ | ClientHello (структурно) | высокая |
| Сертификат | издатель/CN/SAN | зависит |
| ALPN | h2/http1.1 | часть профиля |
| Тайминги | поведение | слабая |

## Итог по TLS-фингерпринту

TLS-фингерпринт позволяет различать клиентов без расшифровки — по SNI, JA3/JA4, сертификату, ALPN и таймингам. Для SOC это мощный детект (малварь с уникальным JA3, self-signed C2), для пентеста — цель маскировки (использовать легитимный отпечаток). ECH и DoH/DoT скрывают часть метаданных, но отпечаток клиента и поведение остаются. Комбинируйте фингерпринт с NetFlow и DNS для полного профиля.

## Практическая польза фингерпринта

Разберём реальный сценарий SOC. В сети появляется трафик на «обычный» популярный домен (CDN), но с необычным JA3. Проверяем:

```bash
# 1. Все JA3 на этот SNI
tshark -r cap.pcap -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja3 \
  | grep 'cdn.example' | sort | uniq -c
# 2. Сравнить с известными браузерными JA3
# 3. Проверить тайминги и объём (NetFlow)
nfdump -r nfcapd.20261011* 'host <ip>' -s dstip/bytes -n 10
# 4. Проверить сертификат
tshark -r cap.pcap -Y 'tls.handshake.type==11' -T fields -e x509sat.uTF8String | head
```

Если JA3 не совпадает с браузером, а соединения регулярны и небольшие — это признак C2, маскирующегося под веб. Такое сочетание (SNI популярный, JA3 нестандартный, beaconing) — классический профиль.

## Итоговый вывод

TLS-фингерпринт превращает «невидимый» шифрованный трафик в наблюдаемый: SNI, JA3/JA4, сертификаты и ALPN дают профиль клиента. Для SOC это детект малвари и аномалий, для пентеста — цель маскировки. ECH/DoH/DoT скрывают часть метаданных, но отпечаток клиента и поведение остаются; комбинируйте их с NetFlow и DNS-логами для полной картины.

## Квиз

```quiz
- question: "Что такое SNI?"
  options:
    - "Имя сервера в ClientHello"
    - "Отпечаток клиента"
    - "Пароль TLS"
    - "Алгоритм шифрования"
  answer: 0
  explanation: "SNI указывает серверу запрашиваемое имя хоста."
- question: "Из чего строится JA3?"
  options:
    - "Версия, шифры, расширения, кривые, point formats"
    - "Сертификат сервера"
    - "DNS-запрос"
    - "Пароль"
  answer: 0
  explanation: "JA3 — хэш параметров ClientHello."
- question: "Зачем нужен JA4?"
  options:
    - "Современный, устойчивый отпечаток клиента"
    - "Шифрование DNS"
    - "Замена сертификата"
    - "Сжатие трафика"
  answer: 0
  explanation: "JA4 точнее и устойчивее JA3."
- question: "Что скрывает ECH?"
  options:
    - "SNI (имя сервера)"
    - "Сертификат"
    - "JA3"
    - "Порт"
  answer: 0
  explanation: "Encrypted Client Hello шифрует SNI."
- question: "Почему малварь видна по JA3?"
  options:
    - "Её TLS-стек отличается от браузерного"
    - "Она не шифрует"
    - "Она использует DNS"
    - "Она работает по UDP"
  answer: 0
  explanation: "Нестандартный ClientHello выдаёт клиент."
```

## Где пригодится

- **CTF:** задачи с TLS-дампами и отпечатками.
- **Пентест:** маскировка под легитимный клиент.
- **SOC:** детект малвари и аномальных клиентов.
- **Инженерия:** мониторинг и корреляция TLS-метаданных.
