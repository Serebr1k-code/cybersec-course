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
lab:
  kind: shell
  title: "Практика: разбор чужого дампа по протоколам"
  toolset: [core, tshark]
  workdir: /home/student/task
  files: [task.md, cap.pcap]
  check: "grep -q 'nto{pr0t0c0l_h13r4rchy_0dd_p0rt}' answer.txt"
  hints:
    - "Сначала «фазовый состав»: `tshark -r cap.pcap -q -z io,phs`."
    - "TLS-метаданные видны даже при шифровании: `tshark -r cap.pcap -T fields -e tls.handshake.extensions_server_name`."
    - "Прикладной слой на нестандартном порту: `tshark -r cap.pcap -Y http.request -T fields -e tcp.dstport -e http.host -e http.request.uri`."
    - "Метка в URI запроса: `nto{pr0t0c0l_h13r4rchy_0dd_p0rt}`."
---

## Вопрос, с которого всё начинается

Ты открыл чужой дамп `cap.pcap` и видишь мешанину трафика: что-то по TCP, что-то по UDP, где-то TLS. Вопрос простой: **что здесь за протоколы и что из них реально видно?** От ответа зависит, найдёшь ли ты учётные данные, заметишь ли аномалию и поймёшь ли, где спрятано содержимое.

Этот модуль — про прикладной слой: HTTP/2 и HTTP/3/QUIC, протоколы баз данных и TLS-«отпечатки». Он опирается на [`network-quic`](network-quic) и [`network-tls-inspection`](network-tls-inspection) и ведёт к [`network-http2-attacks`](network-http2-attacks), [`network-db-protocols`](network-db-protocols) и [`network-tls-fingerprint`](network-tls-fingerprint).

## Наш пример: карта чужого дампа

Прежде чем разбирать конкретный протокол, посмотрим «фазовый состав» трафика:

```
$ tshark -r cap.pcap -q -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter:
eth   frames:4210 bytes:3120456
  ip
    tcp
      tls    frames:1800
      http2  frames:410
    udp
      quic   frames:900
      mysql  frames:120
```

Теперь видно, из чего состоит дамп: TLS, HTTP/2, QUIC и немного MySQL. Разберём каждый.

## Шаг 1: HTTP/2 — бинарные фреймы

**HTTP/2** — бинарный протокол. Вместо текстовых строк он передаёт **фреймы** (заголовки, данные, настройки), умеет **мультиплексировать** несколько потоков в одном соединении и сжимает заголовки алгоритмом **HPACK**. Бинарность и мультиплексирование породили новые атаки — **request smuggling** (разное представление длины), **HPACK-бомбы** и **rapid reset** (CVE-2023-44487).

```
$ tshark -r cap.pcap -Y 'http2' -T fields -e http2.type | sort | uniq -c
     12 0
    310 1
     88 4
```

Тип `1` — фрейм HEADERS, `0` — DATA, `4` — SETTINGS. Если HTTP/2 идёт поверх TLS, содержимое скрыто, и видны только сами факты фреймов.

## Шаг 2: HTTP/3 и QUIC — зашифрованный транспорт

**QUIC** работает поверх UDP и шифрует почти всё, включая большую часть заголовка. Это ломает классический **DPI** (глубокую инспекцию пакетов), но метаданные остаются: версия, длины, тайминги.

```
$ curl --http3 -sI https://example.com | head -3
HTTP/3 200
server: cloudflare
content-type: text/html
```

```
$ tshark -r cap.pcap -Y 'quic' -T fields -e quic.version | sort | uniq -c
    900 0x00000001
```

`0x00000001` — версия QUIC v1. Частая практика — блокировать HTTP/3 на периметре, чтобы клиент откатился на HTTP/2 по TCP, где видно больше.

## Шаг 3: протоколы баз данных

У каждой СУБД свой формат на проводе:

- **MySQL/MariaDB** (3306) — приветствие с версией и capabilities; пароль в старом методе передаётся как challenge/response;
- **PostgreSQL** (5432) — `StartupMessage`, затем аутентификация (md5 или scram);
- **MSSQL** (1433) — протокол **TDS**; pre-login раскрывает версию и имя инстанса.

Часто БД слушают наружу **без TLS** — тогда видны и логин, и данные:

```
$ nmap -p 1433 --script ms-sql-info 10.0.0.1
PORT     STATE SERVICE
1433/tcp open  ms-sql-s
| ms-sql-info:
|   10.0.0.1:1433:
|     Instance name: MSSQLSERVER
|_    Version: Microsoft SQL Server 2019
```

```
$ tshark -r cap.pcap -Y 'mysql' -T fields -e mysql.user | head -3
app_user
app_user
```

Строка `app_user` в поле `mysql.user` — это логин, отправленный в открытом виде.

## Шаг 4: TLS-фингерпринт — JA3/JA4

**JA3/JA4** — отпечатки TLS-клиента, собранные из параметров его ClientHello (версии, набор шифров, расширения). Они позволяют различать клиентов — браузер, библиотеку, вредоносное ПО — **не расшифровывая трафик**.

```
$ tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 | sort -u
5d41402abc4b2a76b9719d911017c592
$ tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u
example.com
cdn.example.net
```

Поле `tls.handshake.ja3` даёт отпечаток клиента, а `extensions_server_name` — **SNI**, имя запрашиваемого сайта. Для SOC это способ отличить малварь от браузера; для атакующего — понять, под какой клиент маскироваться.

## Шаг 5: с чего начинать разбор дампа

Универсальный порядок для любого незнакомого дампа — от «карты» к деталям. Сначала смотрим фазовый состав, затем применяем профильный фильтр под каждый протокол:

```
$ tshark -r cap.pcap -T fields -e frame.protocols | tr ':' '\n' | sort | uniq -c | sort -rn | head
   4210 eth
   3120 ip
   1800 tcp
    900 udp
```

Дальше — точечно: `-Y 'http2'` для фреймов HTTP/2, `-Y 'quic'` для QUIC, `-Y 'mysql'` для БД, `-Y 'tls.handshake.type==1'` для ClientHello (JA3/SNI). Такой порядок экономит время: ты сразу видишь, есть ли в дампе нужный протокол, и не тратишь запросы на заведомо пустые фильтры.

## Что мы теперь знаем

- Сначала смотрят «фазовый состав» дампа (`tshark -z io,phs`), потом — конкретные протоколы.
- HTTP/2 — бинарный, с фреймами и HPACK; даёт smuggling и rapid reset.
- HTTP/3 (QUIC/UDP) шифрует заголовки — остаются метаданные.
- БД-протоколы без TLS раскрывают версии и учётные данные.
- JA3/JA4 различают TLS-клиентов, SNI показывает имя сервера — без расшифровки.
- Разбор всегда идёт от «карты» дампа к профильным фильтрам, а не наоборот.
- Бинарность HTTP/2 и шифрование QUIC — главные причины, почему классический DPI слепнет.

| Протокол | Транспорт | Шифрование | Что видно |
|---|---|---|---|
| HTTP/1.1 | TCP | опц. TLS | всё без TLS |
| HTTP/2 | TCP | опц. TLS | фреймы без TLS |
| HTTP/3 | QUIC/UDP | да | метаданные |
| MySQL | TCP | опц. TLS | handshake/креды |
| PostgreSQL | TCP | опц. TLS | auth/запросы |
| MSSQL | TCP (TDS) | опц. TLS | pre-login |
| TLS | TCP | да | SNI/JA3/сертификат |

## Если защита мешает

- **ECH (Encrypted Client Hello).** Скрывает SNI — остаётся JA3 и сертификат, если виден.
- **QUIC блокируется.** Клиент откатывается на HTTP/2 по TCP — смотри оба транспорта.
- **TLS на БД.** Если включён, креды не видны — тогда работай по метаданным и версиям.
- **HTTP/2 без TLS (h2c) не виден в HTTP/1.1-инструментах.** Используй `nghttp2` и фильтр `http2` в tshark.

<!-- lab -->

## Практика: разбор по протоколам

```
$ tshark -r cap.pcap -q -z io,phs
$ tshark -r cap.pcap -Y 'http2' -T fields -e http2.type | sort | uniq -c
$ tshark -r cap.pcap -Y 'quic' -T fields -e quic.version | sort | uniq -c
$ tshark -r cap.pcap -Y 'mysql' -T fields -e mysql.user | head
$ tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 -e tls.handshake.extensions_server_name | sort -u
```

Порядок один: определить протоколы → разобрать метаданные → найти то, что не защищено → оценить экспозицию.

## Квиз

Проверь себя.

```quiz
- question: 'Чем HTTP/2 отличается от HTTP/1.1?'
  options:
    - 'Бинарные фреймы и мультиплексирование потоков'
    - 'Только текстовый формат'
    - 'Работает по UDP'
    - 'Не использует заголовки'
  answer: 0
  explanation: 'HTTP/2 — бинарный, с потоками и HPACK.'
- question: 'Поверх чего работает HTTP/3?'
  options:
    - 'QUIC (UDP)'
    - 'TCP'
    - 'ICMP'
    - 'SCTP'
  answer: 0
  explanation: 'HTTP/3 = HTTP поверх QUIC/UDP.'
- question: 'Какой порт у PostgreSQL по умолчанию?'
  options:
    - '5432'
    - '3306'
    - '1433'
    - '1521'
  answer: 0
  explanation: 'PostgreSQL — 5432, MySQL — 3306, MSSQL — 1433.'
- question: 'Что описывает JA3/JA4?'
  options:
    - 'Отпечаток TLS-клиента по ClientHello'
    - 'Сертификат сервера'
    - 'Имя сервера (SNI)'
    - 'Пароль'
  answer: 0
  explanation: 'JA3/JA4 различают клиентов без расшифровки.'
- question: 'Почему QUIC усложняет DPI?'
  options:
    - 'Он шифрует почти весь заголовок'
    - 'Он медленный'
    - 'Он не использует порты'
    - 'Он работает по TCP'
  answer: 0
  explanation: 'QUIC шифрует заголовки, оставляя лишь метаданные.'
```

## Куда дальше

Мы научились разбирать прикладной слой. Дальше — вглубь: [`network-http2-attacks`](network-http2-attacks) разберёт smuggling и rapid reset, [`network-db-protocols`](network-db-protocols) — протоколы БД на проводе, [`network-tls-fingerprint`](network-tls-fingerprint) — JA3/JA4 в деталях. А пока запомни: **для каждого протокола знай, что видно на проводе, что защищено TLS и какие метаданные остаются.**

## Где пригодится

- **CTF:** задачи с HTTP/2/3, БД-дампами, TLS.
- **Пентест:** smuggling, перехват БД, маскировка под клиента.
- **SOC:** фингерпринт клиентов, детект аномалий.
- **Инженерия:** настройка HTTP/2/3, TLS для БД.
