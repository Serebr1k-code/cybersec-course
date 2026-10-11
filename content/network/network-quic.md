---
id: network-quic
title: "QUIC и HTTP/3: анализ зашифрованного транспорта нового поколения"
category: network
parent: network-tls-inspection
difficulty: hard
order: 3
tags: [network, quic, http3, udp, tls13, analysis]
prerequisites: [network-tls-inspection, network-tcpip]
useful_for:
  - "CTF Network (разбор QUIC)"
  - "Пентест: анализ современного трафика"
  - "Работа (SOC): видимость и инспекция QUIC"
estimated_minutes: 50
summary: "Как устроен QUIC поверх UDP, что видно без расшифровки и как инспектировать и блокировать его в корпоративной сети."
---
QUIC — транспорт поверх **UDP**, несущий HTTP/3. Он объединяет TLS 1.3 в сам протокол, убирает head-of-line blocking и шифрует почти всё, включая часть транспортных метаданных. Для анализа это вызов: классические TCP-инструменты и middlebox'ы «слепы». Урок опирается на [`network-tls-inspection`](network-tls-inspection).

## Почему QUIC — вызов для анализа

- Работает по **UDP/443**, который часто разрешён и плохо инспектируется.
- **TLS 1.3 встроен**: handshake и данные в одном потоке.
- Шифруются не только данные, но и заголовки (защита от ossification).
- Соединение живёт по **connection ID**, а не по 5-tuple — сложно отслеживать при смене сети.
- Ретрай/версия-негоциация добавляют неочевидные ветки поведения.

## Что видно на проводе

- **Initial-пакет** несёт **ClientHello открыто**: SNI, ALPN (`h3`), поддерживаемые версии, иногда ClientHello-фрагменты.
- После handshake всё зашифровано; видны лишь размеры/тайминги пакетов.
- **Version Negotiation**, **Retry**-пакеты — тоже частично открыты.
- **SNI** можно использовать для фильтрации/логирования (если не ECH).

```bash
# Захват
tcpdump -i eth0 -n udp port 443 -w quic.pcap
# Разбор в Wireshark (поддерживает QUIC/TLS 1.3)
tshark -r quic.pcap -Y quic -V | head -80
# Только ClientHello/SNI
tshark -r quic.pcap -Y 'quic.tls.handshake.type==1' -T fields -e quic.tls.server_name -e quic.tls.alpn
# Статистика по протоколам
tshark -r quic.pcap -q -z io,phs
# Версии
tshark -r quic.pcap -Y 'quic.version' -T fields -e quic.version | sort | uniq -c
```

## Handshake QUIC по шагам

1. **Initial (client)** — ClientHello в открытом виде, ключи выведены из фиксированной соли.
2. **Initial (server)** — ServerHello + ключи; дальше заголовки защищены.
3. **Handshake** — сертификат сервера, проверка, Finished (зашифровано).
4. **1-RTT / 0-RTT** — данные приложения.
5. **Retry** — если сервер хочет проверить адрес клиента (anti-amplification), шлёт Retry с новым token.

```bash
# Посмотреть типы пакетов и стадии
tshark -r quic.pcap -Y 'quic' -T fields -e quic.packet_type | sort | uniq -c
# Retry-пакеты
tshark -r quic.pcap -Y 'quic.retry' -V | head -40
```

## Version Negotiation и совместимость

- **QUIC v1** (RFC 9000) — стандарт; **v2** (RFC 9369) — новая соль, обратная совместимость не гарантирована.
- **Version Negotiation** — сервер сообщает поддерживаемые версии; клиент выбирает.
- **Greasing** — зарезервированные значения версий/фреймов, чтобы middlebox'ы не «затвердевали».

```bash
tshark -r quic.pcap -Y 'quic.version' -T fields -e quic.version | sort | uniq -c
tshark -r quic.pcap -Y 'quic.connection.id' -T fields -e quic.connection.id | head
```

## 0-RTT и replay

QUIC поддерживает **0-RTT** (early data): клиент отправляет данные до завершения handshake, используя сохранённый ticket. Это создаёт риск **replay** для неидемпотентных запросов. Сервер должен ограничивать 0-RTT по методу/пути.

```bash
tshark -r quic.pcap -Y 'quic.tls.early_data' -T fields -e frame.number
```

Для анализа: если видите 0-RTT и сервер не ограничивает — потенциальный вектор replay-атак.

## ECH и потеря видимости

**Encrypted ClientHello (ECH)** шифрует SNI, поэтому фильтрация/логирование по имени сайта перестаёт работать. Признак: в Initial нет читаемого `server_name`. Тогда остаются только IP, размеры и тайминги.

```bash
# Есть ли SNI?
tshark -r quic.pcap -Y 'quic.tls.handshake.type==1' -T fields -e quic.tls.server_name
# Пусто + ALPN h3 => возможно ECH
```

## Расшифровка QUIC

QUIC использует TLS 1.3, поэтому ключи можно получить через **SSLKEYLOGFILE** (как и для TLS):

```bash
export SSLKEYLOGFILE=/tmp/keys.log
# запустить браузер/curl с этой переменной
tshark -r quic.pcap -o tls.keylog_file:/tmp/keys.log -Y http3 -T fields -e http3.headers
```

Без ключей расшифровка невозможна — только метаданные (SNI, размеры, тайминги). Для `curl`/`nghttp3` можно также писать **qlog** и разбирать его.

## Разобранный пример: разбор QUIC-handshake

```bash
# 1. Захват трафика браузера к сайту
sudo tcpdump -i any -n udp port 443 -c 200 -w q.pcap
# 2. SNI/ALPN из Initial
tshark -r q.pcap -Y 'quic.tls.handshake.type==1' -T fields -e ip.dst -e quic.tls.server_name -e quic.tls.alpn
# -> 93.184.216.34  example.com  h3
# 3. Проверяем версии
tshark -r q.pcap -Y quic -T fields -e quic.version | sort | uniq -c
# 4. Если есть ключи — расшифровка
tshark -r q.pcap -o tls.keylog_file:/tmp/keys.log -Y http3 -T fields -e http3.headers | head
# 5. Проверить поддержку h3 у сервиса
curl --http3-only -sI https://cloudflare-quic.com/
```

## Connection migration и балансировка

- **Connection ID (CID)**: длинный/короткий; по нему отслеживают соединение при смене IP/порта.
- **Connection migration**: клиент меняет сеть (Wi-Fi→LTE) без разрыва — 5-tuple меняется, CID остаётся.
- **Load balancer** маршрутизирует по CID, а не по 5-tuple.
- **Spin bit** — открытый бит для измерения RTT.

```bash
tshark -r q.pcap -Y 'quic.spin_bit' -T fields -e quic.spin_bit | head
tshark -r q.pcap -Y 'quic.connection.id' -T fields -e quic.connection.id | sort -u | head
```

## Корпоративная инспекция и защита

- **Блокировка UDP/443** заставляет браузеры откатиться на **TCP/HTTP2** (инспектируемо).
- **Firewall-правила** по SNI (`example.com`) в Initial.
- **DNS-фильтрация** + блокировка `Alt-Svc` (браузер узнаёт о QUIC из заголовка `Alt-Svc: h3=...`).
- **Прокси** с поддержкой HTTP/3 (или отключение QUIC на клиентах через политику).

```bash
# Клиентский fallback: Alt-Svc
curl -sI https://example.com/ | grep -i alt-svc
# Блокировка QUIC -> браузер пойдёт по TCP
iptables -A FORWARD -p udp --dport 443 -j DROP
```

## Частые ошибки

- **Сканировать QUIC как TCP** — QUIC только UDP.
- **Ожидать полный HTTP-запрос без ключей** — виден только ClientHello.
- **Путать ALPN `h3` и `h2`** — `h2` = HTTP/2 (TCP), `h3` = HTTP/3 (QUIC).
- **Забывать про ECH** — тогда фильтрация по SNI не работает.
- **Не учитывать connection ID** — при смене сети 5-tuple меняется.
- **Блокировать UDP целиком** — сломаете DNS/другие сервисы; блокируйте именно UDP/443.
- **Игнорировать 0-RTT** — риск replay.

## Сравнение TCP+TLS и QUIC

| Свойство | TCP + TLS 1.3 | QUIC |
|----------|---------------|------|
| Транспорт | TCP | UDP |
| Handshake | отдельно от TCP | встроен, 1-RTT/0-RTT |
| HoL blocking | на уровне TCP | устранён (per-stream) |
| Шифрование заголовков | нет | да (частично) |
| Идентификация соединения | 5-tuple | connection ID |
| Инспектируемость | выше (TCP/443) | ниже |

## Что дальше / решение

- Нужен **разбор метаданных** без ключей → SNI/ALPN/версии через `tshark` (Initial).
- Нужна **полная расшифровка** → SSLKEYLOGFILE (браузер/curl) + `tshark -o tls.keylog_file`.
- Нужна **корпоративная видимость** → блокировка/ограничение UDP/443 + DNS/Alt-Svc политика, TLS-инспекция → `network-tls-inspection`.
- Смежные темы → `network-tls-attacks` (атаки на TLS), `network-doh-dot` (шифрованный DNS), `network-pcap-analysis`.

Решение (алгоритм): 1) захватить UDP/443; 2) вытащить Initial (SNI/ALPN/версия); 3) проверить ECH (пусто = скрыто); 4) при необходимости получить ключи и расшифровать; 5) для защиты — управлять fallback (Alt-Svc, блокировка UDP/443).

## qlog и отладка клиентов

Многие QUIC-клиенты (Chromium, `curl`/`ngtcp2`, `quiche`) умеют писать **qlog** — структурированный JSON-лог событий соединения (пакеты, фреймы, тайминги). Это удобнее PCAP, когда нужны детали состояния.

```bash
# curl с qlog (сборка с ngtcp2/quiche)
curl --http3 --qlog-file qlog.json https://example.com/
# Chromium: --quic-log=/tmp/quiclog
# Разбор: qvis / quicvis (веб-визуализация qlog)
```

События qlog показывают, какие фреймы (STREAM, ACK, CRYPTO, RETRY) и когда отправлены — полезно при отладке падений handshake и при анализе 0-RTT.

## Retry, amplification и антиспуфинг

QUIC-сервер, получив большой Initial, не может сразу ответить больше, чем втрое (защита от **amplification**). Если адрес клиента не подтверждён, сервер шлёт **Retry** с token. Это важный признак при анализе:

```bash
# Retry-пакеты в захвате
tshark -r q.pcap -Y 'quic.retry' -V | head -40
# Сравнить размеры Initial и ответа (amplification)
tshark -r q.pcap -Y 'quic' -T fields -e quic.packet_length | head
```

Отсутствие Retry при подозрительном трафике может говорить о том, что сервер уже доверяет клиенту (сохранённый ticket).

## HTTP/3 в библиотеках и прокси

- **nginx** с `listen 443 quic` — терминирует HTTP/3, требует `Alt-Svc`.
- **HAProxy** — QUIC-фронтенд с маршрутизацией по CID.
- **Cloudflare/edge** — поддержка h3 из коробки.
- **curl/nghttp3/quiche** — клиентские реализации для тестов.

```bash
# Проверить, отдаёт ли сервис h3
curl --http3-only -sI https://cloudflare-quic.com/
# Alt-Svc сообщает клиенту о поддержке h3
curl -sI https://example.com/ | grep -i alt-svc
```

## Что дальше по QUIC

- Нужна **глубокая отладка** соединения → qlog + qvis.
- Нужна **расшифровка** → SSLKEYLOGFILE (см. выше).
- Нужна **защита периметра** → блокировка/ограничение UDP/443 и политика Alt-Svc, а также TLS-инспекция (`network-tls-inspection`).
- Смежные темы → `network-tls-attacks`, `network-doh-dot` (шифрованный DNS/DoH), `network-pcap-analysis`.

## Ключевые выводы

QUIC совмещает транспорт и криптографию, поэтому «классический» per-protocol анализ работает лишь частично: без ключей вы видите Initial (SNI/ALPN/версия) и метаданные (размеры/тайминги/спин-бит). Всё остальное — зашифровано. Для SOC это означает: политику строят на **Initial** и **Alt-Svc/DNS**, а не на содержимом. Для пентеста — помните, что блокировка UDP/443 переводит клиентов на инспектируемый TCP/HTTP2.

## Квиз

```quiz
- question: "Поверх какого транспорта работает QUIC?"
  options:
    - "UDP"
    - "TCP"
    - "SCTP"
    - "ICMP"
  answer: 0
  explanation: "QUIC работает поверх UDP (обычно 443) и включает TLS 1.3 внутри."
- question: "Что можно увидеть в QUIC Initial-пакете без расшифровки?"
  options:
    - "ClientHello: SNI и ALPN (например, h3)"
    - "Полный HTTP-запрос"
    - "Пароли"
    - "Содержимое ответа"
  answer: 0
  explanation: "Initial несёт ClientHello открыто; дальше всё зашифровано."
- question: "Как чаще всего заставляют клиента отказаться от QUIC в корпоративной сети?"
  options:
    - "Заблокировать UDP/443, чтобы браузер откатился на TCP/HTTP2"
    - "Отключить DNS"
    - "Включить IPv6"
    - "Сменить MAC"
  answer: 0
  explanation: "Блокировка UDP/443 вынуждает fallback на инспектируемый TCP."
- question: "Какой ALPN-идентификатор означает HTTP/3?"
  options:
    - "h3"
    - "h2"
    - "http/1.1"
    - "spdy/3"
  answer: 0
  explanation: "HTTP/3 использует ALPN h3."
- question: "Что нужно для расшифровки QUIC в Wireshark?"
  options:
    - "Файл ключей TLS (SSLKEYLOGFILE)"
    - "Пароль Wi-Fi"
    - "MAC-адрес"
    - "Сертификат сервера"
  answer: 0
  explanation: "QUIC использует TLS 1.3, поэтому ключи берутся из SSLKEYLOGFILE."
```

## Где пригодится

- **CTF:** разбор QUIC-трафика, поиск SNI/метаданных.
- **Пентест:** анализ современного шифрованного транспорта.
- **SOC:** видимость и инспекция QUIC, политика блокировки.
- **Работа:** настройка firewall/прокси для HTTP/3.
- **Сетевая инженерия:** понимание миграции с TCP на QUIC.
