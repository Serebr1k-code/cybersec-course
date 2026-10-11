---
id: network-module-appprotos
title: "Прикладные протоколы глубоко: HTTP/2, HTTP/3, БД и TLS-fingerprint"
category: network
parent: network-quic
difficulty: easy
order: 1
tags: [network, http2, http3, quic, database, tls, ja3, fingerprint]
prerequisites: [network-quic, network-tls-inspection]
useful_for:
  - "CTF Network (прикладные протоколы)"
  - "Пентест: анализ и атаки на транспорт и БД"
  - "Работа (SOC): фингерпринт и детект"
estimated_minutes: 55
summary: "Модуль по прикладным протоколам: HTTP/2 и HTTP/3/QUIC, протоколы баз данных (MySQL/PostgreSQL/MSSQL) и TLS-фингерпринтинг (JA3/JA4/SNI) — что видно на проводе и какие атаки возможны."
---

Поверх транспорта живут прикладные протоколы: HTTP/2 и HTTP/3, протоколы баз данных, а также TLS с его «отпечатками». Их разбор нужен и для атаки (request smuggling, перехват БД-кред), и для защиты (фингерпринт клиентов, детект аномалий). Этот модуль — база для [`network-http2-attacks`](network-http2-attacks), [`network-db-protocols`](network-db-protocols) и [`network-tls-fingerprint`](network-tls-fingerprint), опирается на [`network-quic`](network-quic) и [`network-tls-inspection`](network-tls-inspection).

## Зачем отдельный модуль

Транспорт и приложение — там, где происходят реальные атаки:

- **HTTP/2** — мультиплексирование и HPACK дают новые классы атак (smuggling, rapid reset);
- **HTTP/3 (QUIC)** — зашифрован даже заголовок, ломая классический DPI;
- **БД-протоколы** — аутентификация часто без шифрования, а ошибки раскрывают версии;
- **TLS-фингерпринт** — позволяет различать клиентов без расшифровки (JA3/JA4).

## HTTP/2 и его атаки

HTTP/2 — бинарный протокол с **фреймами**, **мультиплексированием** потоков и сжатием заголовков **HPACK**. Новые классы атак: **request smuggling** (CL.TE/TE.TE через разные представления длины), **HPACK-бомбы**, **rapid reset** (CVE-2023-44487), **frame-уровневые аномалии**.

```bash
# Определить HTTP/2 в дампе
tshark -r cap.pcap -Y 'http2' -T fields -e http2.header.name -e http2.header.value | head
# Проверить поддержку HTTP/2
curl -sI --http2 https://example.com | head
```

Подробно — в [`network-http2-attacks`](network-http2-attacks).

## HTTP/3 и QUIC

**QUIC** работает поверх UDP и шифрует почти всё, включая большую часть заголовка. Это ломает классический DPI, но остаются метаданные: версия, длины, тайминги. Блокировка HTTP/3 часто вынуждает клиента откатиться на HTTP/2 по TCP.

```bash
# HTTP/3 через curl
curl --http3 -sI https://example.com | head
# Захват QUIC
sudo tcpdump -i eth0 -nn 'udp port 443'
tshark -r cap.pcap -Y 'quic' -T fields -e quic.version | head
```

## Протоколы баз данных

- **MySQL/MariaDB** (3306) — handshake с версией и capabilities; пароль (mysql_native) — challenge/response;
- **PostgreSQL** (5432) — StartupMessage, затем auth; пароль зависит от метода (md5, scram);
- **MSSQL** (1433) — TDS-протокол; pre-login раскрывает версию/инстанс.

Часто БД слушают на внешнем интерфейсе без TLS — тогда креды и данные видны на проводе.

```bash
# Идентификация
nmap -sV -p 3306,5432,1433 10.0.0.1
# MSSQL pre-login
nmap -p 1433 --script ms-sql-info 10.0.0.1
```

Подробно — в [`network-db-protocols`](network-db-protocols).

## TLS-фингерпринт: JA3/JA4

**JA3/JA4** — отпечатки TLS-клиента по набору параметров ClientHello (версии, шифры, расширения). Они позволяют различать клиентов (браузер, библиотека, малварь) **без расшифровки**. Это ценно для SOC и для маскировки под легитимный клиент.

```bash
# JA3 из дампа
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 | sort -u
# SNI
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u
```

Подробно — в [`network-tls-fingerprint`](network-tls-fingerprint).

## Что видно на проводе

| Протокол | Видно | Скрыто |
|---|---|---|
| HTTP/1.1 (без TLS) | всё | — |
| HTTP/2 (h2c/h2) | фреймы (если без TLS) | внутри TLS — нет |
| HTTP/3 (QUIC) | метаданные, версия | заголовки/данные |
| MySQL/Postgres | handshake/креды (без TLS) | внутри TLS |
| TLS | SNI, JA3, сертификат | содержимое |

## Инструменты

| Инструмент | Назначение |
|---|---|
| `curl --http2/--http3` | проверка протоколов |
| `nghttp2`/`h2spec` | HTTP/2-клиент/тесты |
| `tshark` | разбор фреймов, JA3, SNI |
| `nmap ms-sql-info` | MSSQL |
| `mysql`/`psql` | БД-клиенты |

## Типовые ошибки

- **Игнорировать HTTP/2-специфику** — smuggling невидим в HTTP/1.1-инструментах.
- **Считать QUIC «невидимым»** — метаданные остаются.
- **Не проверять БД наружу** — креды/данные в открытом виде.
- **Путать JA3 и SNI** — отпечаток клиента vs имя сервера.
- **Не учитывать ECH** — скрывает SNI.
- **Забывать про downgrade** — HTTP/3 → HTTP/2 → HTTP/1.1.
- **Не логировать фингерпринты** — малварь не отличается от браузера.

## Что дальше / решение

Пройдите [`network-http2-attacks`](network-http2-attacks), [`network-db-protocols`](network-db-protocols), [`network-tls-fingerprint`](network-tls-fingerprint). Для QUIC — [`network-quic`](network-quic); для TLS — [`network-tls-attacks`](network-tls-attacks).

## Практика: разбор прикладных протоколов

```bash
# HTTP/2
tshark -r cap.pcap -Y 'http2' -T fields -e http2.type | sort | uniq -c
# QUIC
tshark -r cap.pcap -Y 'quic' -T fields -e quic.version | sort | uniq -c
# БД
tshark -r cap.pcap -Y 'mysql' -T fields -e mysql.user | head
tshark -r cap.pcap -Y 'pgsql' -T fields -e pgsql.query | head
# TLS-метаданные
tshark -r cap.pcap -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja3 | head
```

## Сравнение прикладных протоколов

| Протокол | Транспорт | Шифрование | Что видно |
|---|---|---|---|
| HTTP/1.1 | TCP | опц. TLS | всё без TLS |
| HTTP/2 | TCP | опц. TLS | фреймы без TLS |
| HTTP/3 | QUIC/UDP | да | метаданные |
| MySQL | TCP | опц. TLS | handshake/креды |
| PostgreSQL | TCP | опц. TLS | auth/запросы |
| MSSQL | TCP (TDS) | опц. TLS | pre-login |
| TLS | TCP | да | SNI/JA3/сертификат |

## Итог по прикладным протоколам

Прикладной уровень — там, где данные и атаки. Транспорт (HTTP/2/3) даёт новые классы атак (smuggling, rapid reset), БД-протоколы раскрывают версии и креды без TLS, а TLS-фингерпринт (JA3/JA4/SNI) позволяет различать клиентов без расшифровки. Практический вывод: для каждого протокола знайте, **что видно на проводе**, **что защищено TLS**, и **какие метаданные остаются** — это основа и для атаки, и для защиты.

## Как выбирать инструмент разбора

Для каждого прикладного протокола нужен свой инструмент. HTTP/2/3 удобно смотреть `nghttp2`/`curl --http2/--http3` и `tshark` с фильтрами `http2`/`quic`. БД-протоколы — родными клиентами (`mysql`, `psql`, `sqlcmd`) и NSE-скриптами. TLS — `tshark` с полями `tls.handshake.*` и `openssl s_client`.

```bash
# Универсальный старт: что вообще в дампе
tshark -r cap.pcap -q -z io,phs
# Топ протоколов
tshark -r cap.pcap -T fields -e frame.protocols | tr ':' '\n' | sort | uniq -c | sort -rn | head
```

Первым делом определите «фазовый состав» трафика (`-z io,phs`), затем переходите к конкретным протоколам. Это экономит время: вы сразу видите, есть ли HTTP/2, QUIC или БД-трафик.

## Итоговый вывод

Прикладные протоколы — финальный слой, где видно реальные данные. Знание их формата позволяет разбирать дампы, находить креды и аномалии, а TLS-фингерпринт — различать клиентов без расшифровки. Практический подход: определите протоколы → разберите метаданные → найдите слабые места (нет TLS, trust-auth, smuggling) → защитите.

## Заметка о едином подходе к разбору

Независимо от протокола, схема разбора одна: **определить протокол** → **разобрать метаданные** → **найти то, что не защищено** → **оценить экспозицию**. Для HTTP/2/3 это фреймы и потоки, для БД — handshake и auth, для TLS — отпечаток. Держите под рукой `tshark -z io,phs` для «карты» дампа и профильные фильтры (`http2`, `mysql`, `tls.handshake`) для деталей. Это универсальный навык, применимый к любому прикладному протоколу, даже незнакомому.

## Квиз

```quiz
- question: "Чем HTTP/2 отличается от HTTP/1.1?"
  options:
    - "Бинарные фреймы и мультиплексирование потоков"
    - "Только текстовый формат"
    - "Работает по UDP"
    - "Не использует заголовки"
  answer: 0
  explanation: "HTTP/2 — бинарный, с потоками и HPACK."
- question: "Поверх чего работает HTTP/3?"
  options:
    - "QUIC (UDP)"
    - "TCP"
    - "ICMP"
    - "SCTP"
  answer: 0
  explanation: "HTTP/3 = HTTP поверх QUIC/UDP."
- question: "Какой порт у PostgreSQL по умолчанию?"
  options:
    - "5432"
    - "3306"
    - "1433"
    - "1521"
  answer: 0
  explanation: "PostgreSQL — 5432, MySQL — 3306, MSSQL — 1433."
- question: "Что описывает JA3/JA4?"
  options:
    - "Отпечаток TLS-клиента по ClientHello"
    - "Сертификат сервера"
    - "Имя сервера (SNI)"
    - "Пароль"
  answer: 0
  explanation: "JA3/JA4 различают клиентов без расшифровки."
- question: "Почему QUIC усложняет DPI?"
  options:
    - "Он шифрует почти весь заголовок"
    - "Он медленный"
    - "Он не использует порты"
    - "Он работает по TCP"
  answer: 0
  explanation: "QUIC шифрует заголовки, оставляя лишь метаданные."
```

## Где пригодится

- **CTF:** задачи с HTTP/2/3, БД-дампами, TLS.
- **Пентест:** smuggling, перехват БД, маскировка под клиента.
- **SOC:** фингерпринт клиентов, детект аномалий.
- **Инженерия:** настройка HTTP/2/3, TLS для БД.
