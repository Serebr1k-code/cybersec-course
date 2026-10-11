---
id: network-http2-attacks
title: "HTTP/2 и HTTP/3: атаки на современный транспорт"
category: network
parent: network-module-appprotos
difficulty: hard
order: 2
tags: [network, http2, http3, quic, smuggling, hpack, rapid-reset]
prerequisites: [network-module-appprotos, network-quic]
useful_for:
  - "CTF Network (HTTP/2/3)"
  - "Пентест: request smuggling, DoS"
  - "Работа (SOC): детект HTTP/2-аномалий"
estimated_minutes: 55
summary: "HTTP/2 и HTTP/3: фреймы, потоки, HPACK, request smuggling (CL.TE/TE.TE), HPACK-бомбы, rapid reset и HTTP/3-специфика — с командами и разбором защиты."
---

HTTP/2 и HTTP/3 принесли скорость и мультиплексирование, но и новые классы атак. Различия в разборе длины и потоков между прокси и backend открывают request smuggling, а управление потоками — DoS (rapid reset). Урок продолжает [`network-module-appprotos`](network-module-appprotos) и опирается на [`network-quic`](network-quic).

## HTTP/2: фреймы и потоки

HTTP/2 — бинарный протокол: соединение состоит из **фреймов** (HEADERS, DATA, SETTINGS, RST_STREAM, WINDOW_UPDATE, PING, GOAWAY), а запросы/ответы идут в **потоках** (streams) с числовыми ID. Одно TCP-соединение несёт много параллельных запросов. Заголовки сжимаются **HPACK** с динамической таблицей.

```text
FRAME: length(24) | type(8) | flags(8) | stream_id(31) | payload
types: 0x0 DATA, 0x1 HEADERS, 0x4 SETTINGS, 0x3 RST_STREAM, 0x6 PING, 0x7 GOAWAY
```

```bash
# Разбор HTTP/2 в дампе
tshark -r cap.pcap -Y 'http2' -T fields -e http2.type -e http2.streamid | sort | uniq -c
# Клиент HTTP/2
nghttp -nv https://example.com/
```

## Request smuggling в HTTP/2

**Smuggling** возникает, когда frontend (прокси) и backend по-разному определяют границы запроса. В HTTP/2-контексте это проявляется через:

- **h2c smuggling** — переход HTTP/1.1 → HTTP/2 на frontend;
- **CL.TE / TE.TE** — расхождение в `Content-Length` vs `Transfer-Encoding`;
- **header injection** — CRLF в заголовках (HTTP/2 запрещает, но при downgrade — возможен).

```bash
# Проверить расхождение (лаборатория)
curl --http2 -H 'Transfer-Encoding: chunked' -H 'Content-Length: 6' \
  --data-binary $'0\r\n\r\nG' https://target/
# Инструменты: smuggler, h2csmuggler
python3 smuggler.py -u https://target/
```

Подробно о smuggling — в web-ветке (`web-request-smuggling`).

## HPACK-бомбы

**HPACK** использует динамическую таблицу: повторяющиеся заголовки ссылаются на уже переданные. Атакующий может «наполнить» таблицу так, что её размер исчерпает память backend (HPACK bomb) — это DoS.

```bash
# Концептуально: повторяющиеся большие заголовки
# (не запускать против чужих сервисов)
```

## Rapid Reset (CVE-2023-44487)

**Rapid Reset** эксплуатирует управление потоками: клиент открывает поток и сразу сбрасывает его (RST_STREAM), тысячи раз. Сервер тратит ресурсы на обработку, что приводит к DoS при малом объёме трафика. Патчится лимитами на число сбросов.

```bash
# Детект: много RST_STREAM в дампе
tshark -r cap.pcap -Y 'http2.type==3' -T fields -e http2.streamid | wc -l
```

## HTTP/3 и QUIC-специфика

HTTP/3 работает поверх QUIC (UDP). Особенности:

- **шифрование заголовков** — DPI видит мало;
- **0-RTT** — повторное соединение без полного рукопожатия (риск replay);
- **миграция соединений** — смена IP без разрыва (полезно и для атакующего);
- **QUIC-специфичные DoS** — amplification, version negotiation.

```bash
# HTTP/3-запрос
curl --http3 -sI https://example.com | head
# Захват QUIC
sudo tcpdump -i eth0 -nn 'udp port 443'
tshark -r cap.pcap -Y 'quic' -T fields -e quic.version -e quic.long.packet_type | head
```

## Практика: разбор HTTP/2-сессии

```bash
# 1. Захват
sudo tcpdump -i eth0 -nn -w h2.pcap 'tcp port 443'
# 2. Типы фреймов
tshark -r h2.pcap -Y 'http2' -T fields -e http2.type | sort | uniq -c | sort -rn
# 3. Заголовки
tshark -r h2.pcap -Y 'http2.header' -T fields -e http2.header.name -e http2.header.value | head
# 4. Аномалии: много RST_STREAM
tshark -r h2.pcap -Y 'http2.type==3' | wc -l
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `nghttp2`/`nghttp` | HTTP/2-клиент/сервер |
| `h2spec` | тесты соответствия |
| `h2csmuggler` | h2c smuggling |
| `smuggler` | request smuggling |
| `curl --http3` | HTTP/3 |

## Защита

| Мера | Против чего |
|---|---|
| Единый разбор длины на всех узлах | smuggling |
| Лимит RST_STREAM / потоков | rapid reset |
| Лимит размера HPACK-таблицы | HPACK-бомба |
| Обновления HTTP/2-стека | CVE |
| Единый протокол frontend/backend | расхождения |
| Мониторинг фреймов | детект аномалий |

## Частые ошибки

- **Тестировать HTTP/2 HTTP/1.1-инструментами** — smuggling невидим.
- **Игнорировать downgrade** — h2c на frontend.
- **Не лимитировать потоки** — rapid reset.
- **Считать QUIC «невидимым»** — метаданные есть.
- **Забывать про HPACK** — динамическая таблица = вектор.
- **Разные парсеры на узлах** — основа smuggling.
- **Не мониторить RST_STREAM** — DoS незамечен.

## Что дальше / решение

После HTTP/2/3 переходите к [`network-db-protocols`](network-db-protocols) и [`network-tls-fingerprint`](network-tls-fingerprint). Для smuggling — web-ветка.

## Практика: детект HTTP/2-аномалий

```bash
# 1. Захват h2
sudo tcpdump -i eth0 -nn -w h2.pcap 'tcp port 443'
# 2. Типы фреймов
tshark -r h2.pcap -Y 'http2' -T fields -e http2.type | sort | uniq -c | sort -rn
# 3. Аномалия: всплеск RST_STREAM (rapid reset)
tshark -r h2.pcap -Y 'http2.type==3' | wc -l
# 4. Проверка расхождения длины (smuggling) — на живом стенде
curl --http2 -H 'Transfer-Encoding: chunked' -H 'Content-Length: 6' \
  --data-binary $'0\r\n\r\nG' https://target/ -o /dev/null -w '%{http_code}\n'
# 5. Инструмент smuggler
python3 smuggler.py -u https://target/ -q
```

## Сравнение версий HTTP

| Версия | Транспорт | Формат | Мультиплексирование | Классы атак |
|---|---|---|---|---|
| HTTP/1.1 | TCP | текст | нет (pipelining) | smuggling, desync |
| HTTP/2 | TCP | бинарный | да (потоки) | h2c, HPACK, rapid reset |
| HTTP/3 | QUIC/UDP | бинарный | да | 0-RTT, amplification |

## Итог по HTTP/2 и HTTP/3

Современный HTTP быстрее и сложнее — и это создаёт новые векторы. **Request smuggling** опирается на расхождение парсеров frontend/backend, **rapid reset** — на управление потоками, **HPACK** — на сжатие заголовков. HTTP/3 добавляет QUIC-специфику и шифрует заголовки, ломая DPI. Защита: единый разбор длины, лимиты потоков и таблиц, обновления и мониторинг фреймов.

## Модель атак HTTP/2 на практике

Разберём типичный сценарий request smuggling в HTTP/2-инфраструктуре. Клиент подключается к frontend по HTTP/2 (или h2c), frontend преобразует запрос в HTTP/1.1 и отправляет backend. Если frontend и backend по-разному трактуют `Content-Length` и `Transfer-Encoding`, часть запроса «протекает» в следующий — так можно обойти аутентификацию или отравить кэш.

```bash
# 1. Проверить, что frontend поддерживает h2c
curl --http2-prior-knowledge http://target/ -o /dev/null -w '%{http_version}\n'
# 2. Проверить расхождение CL/TE (лаборатория)
curl --http2 -H 'Transfer-Encoding: chunked' -H 'Content-Length: 6' \
  --data-binary $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n' https://target/
# 3. Инструмент smuggler
python3 smuggler.py -u https://target/
```

Для rapid reset смотрите долю RST_STREAM: сервер, не лимитирующий сбросы, уязвим. Для HPACK-бомбы — размер динамической таблицы и повторяемость заголовков.

## Итоговый вывод

HTTP/2 и HTTP/3 дают производительность ценой сложности. Основные векторы — smuggling (расхождение парсеров), rapid reset (DoS потоками) и HPACK (ресурсы). Защита строится на единообразии разбора, лимитах и обновлениях. Понимание фреймов и потоков — обязательная база для тестирования современного веба.

## Квиз

```quiz
- question: "Что такое поток (stream) в HTTP/2?"
  options:
    - "Логический канал для запроса/ответа внутри соединения"
    - "TCP-соединение"
    - "UDP-датаграмма"
    - "Заголовок"
  answer: 0
  explanation: "Мультиплексирование: много потоков в одном соединении."
- question: "На чём основан request smuggling?"
  options:
    - "Разный разбор длины frontend и backend"
    - "Слабый пароль"
    - "Отсутствие TLS"
    - "Старый DNS"
  answer: 0
  explanation: "Расхождение CL/TE позволяет спрятать запрос."
- question: "Что эксплуатирует rapid reset?"
  options:
    - "Быстрое открытие и сброс потоков (RST_STREAM)"
    - "HPACK-сжатие"
    - "0-RTT"
    - "SNI"
  answer: 0
  explanation: "Массовые RST_STREAM вызывают DoS."
- question: "Почему QUIC усложняет DPI?"
  options:
    - "Шифрует почти весь заголовок"
    - "Работает по TCP"
    - "Не использует порты"
    - "Он медленный"
  answer: 0
  explanation: "Остаются только метаданные и версия."
- question: "Какая мера против HPACK-бомбы?"
  options:
    - "Лимит размера HPACK-таблицы"
    - "Отключить TLS"
    - "Включить HTTP/1.1"
    - "Отключить потоки"
  answer: 0
  explanation: "Ограничение таблицы не даёт исчерпать память."
```

## Где пригодится

- **CTF:** задачи с HTTP/2/3-фреймами.
- **Пентест:** smuggling, DoS, h2c.
- **SOC:** детект аномалий фреймов и RST_STREAM.
- **Инженерия:** корректная настройка HTTP/2/3.
