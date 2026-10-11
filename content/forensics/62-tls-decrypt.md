---
id: forensics-tls-decrypt
title: "Расшифровка TLS: SSLKEYLOGFILE и keylog"
category: forensics
parent: forensics-network-deep
difficulty: hard
order: 1
tags: [tls, sslkeylogfile, wireshark, pcap, network, forensics, decryption]
prerequisites: [forensics-network-deep, forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ сетевого трафика"
estimated_minutes: 40
summary: "Как расшифровать TLS-трафик в Wireshark: SSLKEYLOGFILE, извлечение сессионных ключей из памяти/дампа, RSA-ключ, и почему forward secrecy усложняет задачу."
---
Современный трафик почти весь зашифрован TLS, что делает анализ PCAP без ключей малоинформативным. Однако TLS можно расшифровать, если получить сессионные ключи (SSLKEYLOGFILE), приватный RSA-ключ или ключи из памяти. Этот урок — про методы расшифровки, почему forward secrecy усложняет задачу, и как настроить Wireshark.

## Основы TLS и ключи

TLS-сессия устанавливает симметричный ключ через рукопожатие:
- **RSA key exchange** (устаревший): сессионный ключ шифруется публичным RSA-ключом сервера → зная приватный RSA-ключ, можно расшифровать.
- **ECDHE/DHE (forward secrecy)**: эфемерные ключи; приватный RSA-ключ НЕ поможет. Нужны сами сессионные ключи (из `SSLKEYLOGFILE` или памяти).

Поэтому стратегия: (1) RSA-ключ, если нет FS; (2) keylog-файл, если он есть; (3) извлечение ключей из памяти.

## SSLKEYLOGFILE

Браузеры и некоторые приложения по переменной окружения `SSLKEYLOGFILE` пишут сессионные ключи в файл (формат NSS Key Log).

```bash
# Linux: запустить браузер с keylog
$ SSLKEYLOGFILE=/tmp/keys.log firefox &
$ SSLKEYLOGFILE=/tmp/keys.log chromium &
# Windows: переменная окружения через setx
# затем Wireshark: Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
```

Формат файла:

```
CLIENT_RANDOM <32-байтный client_random> <48-байтный master_secret>
CLIENT_HANDSHAKE_TRAFFIC_SECRET ...
SERVER_HANDSHAKE_TRAFFIC_SECRET ...
```

Wireshark подхватывает его и расшифровывает трафик. В командной строке:

```bash
$ tshark -r capture.pcap -o tls.keylog_file:/tmp/keys.log -Y 'http' -T fields -e http.request.uri | head
```

## RSA-ключ

Если используется RSA key exchange (без FS), достаточно приватного ключа сервера.

```bash
# извлечь ключ из .pfx/.p12
$ openssl pkcs12 -in server.p12 -nocerts -nodes -out server.key
# Wireshark: TLS -> RSA keys list -> добавить IP:port + key
$ tshark -r capture.pcap -o tls.keys_list:"10.0.0.5,443,http,server.key" -Y http
```

Проверить, поддерживает ли сервер FS:

```bash
$ openssl s_client -connect host:443 -cipher 'DEFAULT' </dev/null 2>/dev/null | grep -i 'Cipher is'
# если ECDHE — FS включён, RSA-ключ не поможет
```

## Извлечение ключей из памяти

Для FS-сессий ключи живут только в памяти. Их извлекают из дампа.

```bash
# Volatility: извлечь TLS/SSL ключи (Windows)
$ vol -f mem.raw windows.ssl_keyscan
# Linux: ключи в процессах (OpenSSL), извлекаются через Volatility linux
$ vol -f mem.raw linux.pslist
# инструменты: tls_key_extract, ssldump (для старых), openssl-дампы
```

Формат найденных ключей конвертируют в NSS keylog и подают в Wireshark.

```bash
# пример: найти master secrets в дампе
$ strings -a mem.raw | grep -E '^CLIENT_RANDOM'
```

## Настройка Wireshark

1. **Preferences → Protocols → TLS**:
   - `(Pre)-Master-Secret log filename` — путь к keylog.
   - `RSA keys list` — приватные ключи (для не-FS).
2. После — фильтры `http`, `http2`, `tls` покажут расшифрованное содержимое.
3. Экспорт объектов: `File → Export Objects → HTTP`.

```bash
$ tshark -r capture.pcap -o tls.keylog_file:keys.log -Y 'http.request' -T fields -e http.host -e http.request.uri
```

## Практический разбор

```bash
# 1. Определить, есть ли FS
$ openssl s_client -connect evil.tld:443 -cipher DEFAULT </dev/null 2>/dev/null | grep -i cipher
# 2. Если FS — искать keylog
$ find / -name 'sslkeylog*' 2>/dev/null
$ grep -a 'SSLKEYLOGFILE' /proc/*/environ 2>/dev/null
# 3. Расшифровать
$ tshark -r capture.pcap -o tls.keylog_file:keys.log -Y 'http' -T fields -e http.request.full_uri | head
# 4. Извлечь объекты
$ tshark -r capture.pcap -o tls.keylog_file:keys.log --export-objects http,out/
```

## Разобранный пример

Дан PCAP с HTTPS-сессией и keylog-файл.

```bash
# 1. Расшифровать
$ tshark -r https.pcap -o tls.keylog_file:keys.log -Y 'http.request' -T fields -e http.host -e http.request.uri
evil.tld /gate.php
# 2. Тело запроса (данные эксфильтрации)
$ tshark -r https.pcap -o tls.keylog_file:keys.log -Y 'http.request.method=="POST"' -T fields -e http.file_data | head
# 3. Извлечь файлы
$ tshark -r https.pcap -o tls.keylog_file:keys.log --export-objects http,http_obj/
$ file http_obj/*
```

Итог: расшифрованный трафик показал C2-запросы и тело эксфильтрации.

## Справочная таблица

| Метод | Когда работает |
|-------|----------------|
| SSLKEYLOGFILE | есть keylog |
| RSA private key | нет forward secrecy |
| Ключи из памяти | FS, есть дамп |
| MITM-прокси | контроль над клиентом |
| Session hijack | украденные ключи |

## Частые ошибки

- **Пытаться расшифровать FS-трафик RSA-ключом** — не выйдет.
- **Не проверить наличие FS** перед попыткой.
- **Игнорировать keylog** — самый простой путь.
- **Забывать про TLS 1.3** — использует разные секреты (`*_TRAFFIC_SECRET`).
- **Не дампить память** — ключи исчезнут.
- **Путать ключ сервера и клиента** — в `keys_list` указывается нужный.

## Что дальше / решение

Конвейер: `openssl s_client` (FS?) → поиск keylog/RSA-ключа → извлечение ключей из памяти → `tshark -o tls.keylog_file`/Wireshark → анализ расшифрованного. Связка: `forensics-network-deep` (сеть), `forensics-pcap` (основы), `forensics-memory-keys` (память), `forensics-exfil` (данные).

## TLS 1.3 и QUIC

TLS 1.3 усилил forward secrecy: даже RSA-ключ сервера бесполезен, нужны `*_TRAFFIC_SECRET` из keylog. Формат NSS keylog для TLS 1.3:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
```

Wireshark (≥3.0) понимает TLS 1.3 в keylog. **QUIC** (HTTP/3) — TLS поверх UDP; Wireshark расшифровывает его тем же keylog (`QUIC` dissector, начиная с определённых версий).

```bash
# определить версию TLS
$ openssl s_client -connect host:443 -tls1_3 </dev/null 2>/dev/null | grep -i 'Protocol'
# keylog для TLS 1.3 всё равно работает
$ tshark -r capture.pcap -o tls.keylog_file:keys.log -Y http
```

## Прокси-перехват и MITM

Если контролируете клиента (корпоративная сеть, тестовый стенд), можно перехватить TLS через MITM-прокси (`mitmproxy`, `Burp`, `Charles`), который выдаёт собственный сертификат. Это не «расшифровка задним числом», а активный перехват — применимо для расследования в реальном времени и для анализа мобильных приложений.

```bash
# mitmproxy
$ mitmproxy --mode transparent --showhost
# установить корневой сертификат на клиента, направить трафик
```

Помните: MITM меняет трафик и требует установки корневого сертификата на целевой системе — это изменяет её состояние.

## Целостность и фиксация

Ключи — чувствительные данные; фиксируйте их источник (файл keylog, дамп памяти, экспорт) и хеши. Для отчёта: как получены ключи, какая сессия расшифрована, что извлечено. Храните оригинальный PCAP и ключи отдельно, документируйте цепочку.

## Ограничения

- **Нет ключей и есть FS** — расшифровка невозможна без активного перехвата.
- **TLS 1.3 keylog** требует, чтобы клиент его писал (не все приложения поддерживают).
- **QUIC/HTTP3** может не расшифроваться в старых версиях Wireshark.
- **Пиннинг сертификатов** (mobile) ломает MITM.
- **Клиентские сертификаты** (mTLS) усложняют перехват.

## Краткое резюме

Расшифровка TLS в форензике зависит от того, какой обмен ключами использовался. При RSA key exchange достаточно приватного ключа сервера; при forward secrecy (ECDHE/DHE, TLS 1.3) нужны сессионные ключи — из `SSLKEYLOGFILE` или из памяти. Wireshark/`tshark` принимают NSS keylog (`tls.keylog_file`) и RSA-ключи (`tls.keys_list`). Если ключей нет и FS включён, пассивная расшифровка невозможна — остаётся активный MITM-перехват. Всегда проверяйте наличие FS перед попыткой и фиксируйте источник ключей.

## Квиз

```quiz
- question: "Что содержит SSLKEYLOGFILE?"
  options:
    - "пароли сервера"
    - "строки CLIENT_RANDOM <hex> <master_secret>"
    - "сертификаты"
    - "список DNS"
  answer: 1
- question: "Почему приватный RSA-ключ сервера не расшифрует современный TLS?"
  options:
    - "ключ слишком короткий"
    - "из-за forward secrecy (ECDHE/DHE) ключ сервера не выводит сессионные ключи"
    - "TLS не использует RSA"
    - "ключ зашифрован"
  answer: 1
- question: "Где можно взять ключи сессии, если нет SSLKEYLOGFILE?"
  options:
    - "в дампе памяти процесса"
    - "в EVTX"
    - "в prefetch"
    - "в реестре"
  answer: 0
- question: "Что видно в TLS-трафике даже без ключей?"
  options:
    - "тела HTTP-ответов"
    - "SNI (имя хоста), сертификаты, JA3, тайминги"
    - "пароли"
    - "cookies"
  answer: 1
- question: "Как подключить keylog к Wireshark?"
  options:
    - "Preferences → Protocols → TLS → (Pre)-Master-Secret log filename"
    - "через фильтр tls.key"
    - "переименовать pcap"
    - "никак"
  answer: 0
```

## Где пригодится

- **CTF:** задачи, где флаг передаётся по HTTPS и есть keylog/дамп.
- **DFIR:** анализ C2 и утечек по зашифрованному каналу.
- **Анализ малвари:** расшифровка TLS-трафика бота (при наличии дампа).
- **Red team awareness:** понимание, что forward secrecy защищает прошлый трафик.
- **Сетевая форензика:** метаданные TLS как источник при невозможности расшифровки.
