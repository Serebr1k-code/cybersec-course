---
id: forensics-pcap
title: "Введение в анализ PCAP: сетевой дамп"
category: forensics
parent: forensics-img-captures
difficulty: medium
order: 1
tags: [pcap, tshark, wireshark, network, streams, ctf]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Network Security Monitoring"
  - "Incident Response"
estimated_minutes: 40
summary: "Как читать захваты трафика: tshark, фильтры, follow stream, извлечение файлов, анализ протоколов и credentials."
---

## Что такое PCAP

PCAP (packet capture) — файл с записанными сетевыми пакетами. Формат: `libpcap` (`.pcap`, `.cap`) или `pcapng` (`.pcapng`). Используется для отладки, мониторинга и форензики. Внутри — кадры с timestamp, длина и сырые байты (Ethernet → IP → TCP/UDP → приложение).

## Инструменты

- **Wireshark** — GUI, мощные фильтры, follow stream, извлечение объектов.
- **tshark** — CLI-версия Wireshark (для скриптов).
- **tcpdump** — захват и быстрый просмотр.
- **tcpflow/ngrep** — реконструкция потоков.
- **NetworkMiner** — извлечение файлов/credentials.
- **Zeek** — структурированные логи (см. `forensics-zeek`).

```bash
tshark -r capture.pcap                     # сводка пакетов
tshark -r capture.pcap -q -z io,phs        # статистика протоколов
capinfos capture.pcap                      # информация о дампе
```

## Фильтры tshark/Wireshark

**Display filters** (Wireshark-синтаксис):

```
ip.addr == 10.0.0.5
tcp.port == 443
http.request.method == "POST"
dns.qry.name contains "evil"
tls.handshake.extensions_server_name == "example.com"
frame contains "password"
```

```bash
# Примеры tshark
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
tshark -r cap.pcap -Y 'dns' -T fields -e dns.qry.name | sort -u
tshark -r cap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst
```

**BPF-фильтры** (для tcpdump): `tcp port 80`, `host 10.0.0.5`, `not arp`.

## Follow stream

Реконструкция TCP-сессии — ключевой приём.

```bash
# tshark: follow TCP stream (номер потока)
tshark -r cap.pcap -q -z follow,tcp,ascii,0
# список потоков
tshark -r cap.pcap -T fields -e tcp.stream | sort -un
```

В Wireshark: правый клик → Follow → TCP Stream.

## Извлечение файлов

```bash
# Экспорт объектов HTTP (Wireshark: File -> Export Objects -> HTTP)
tshark -r cap.pcap --export-objects http,./exported
# Извлечь все потоки как данные
tshark -r cap.pcap -Y 'http' -T fields -e http.file_data | xxd -r -p
# tcpflow
tcpflow -r cap.pcap -o out/
# NetworkMiner (GUI)
```

Полезно: HTTP-объекты (файлы), SMB-файлы, FTP-передачи, TLS (если ключи).

## Credentials в трафике

Многие протоколы передают учётные данные **в открытом виде**:

- **HTTP Basic Auth** (`Authorization: Basic base64`).
- **FTP** (`USER`/`PASS`).
- **Telnet.**
- **SMTP/POP3/IMAP.**
- **SNMP community.**
- **NTLM/Kerberos** (хэши, для Kerberoast/relay).

```bash
# HTTP Basic
tshark -r cap.pcap -Y 'http.authorization' -T fields -e http.authorization | \
  cut -d' ' -f2 | base64 -d
# FTP
tshark -r cap.pcap -Y 'ftp.request.command=="USER" || ftp.request.command=="PASS"' \
  -T fields -e ftp.request.arg
# Kerberos (для извлечения хэшей)
tshark -r cap.pcap -Y 'kerberos' -T fields -e kerberos.CNameString
```

## Практический пример: CTF-разбор

```bash
# 1. Обзор
capinfos capture.pcap
# 2. Протоколы
tshark -r capture.pcap -q -z io,phs
# 3. HTTP-объекты
tshark -r capture.pcap --export-objects http,./files
ls files/
# 4. Credentials
tshark -r capture.pcap -Y 'http.authorization || ftp || telnet'
# 5. Follow интересного потока
tshark -r capture.pcap -q -z follow,tcp,ascii,3
```

## TLS-трафик: что можно и что нельзя

TLS-трафик зашифрован, но метаданные видны: **SNI** (имя сервера), **сертификаты**, **JA3/JA3S**, размеры/тайминги. Расшифровка возможна при наличии:

- **SSLKEYLOGFILE** (клиентский лог ключей) — Wireshark: Preferences → Protocols → TLS → (Pre)-Master-Secret log.
- **Приватный RSA-ключ сервера** (если не ECDHE — forward secrecy мешает).
- **Извлечённые сессионные ключи** из памяти.

```bash
tshark -r cap.pcap -o tls.keylog_file:keys.log -Y 'http2' -T fields -e http2.header.value
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name
```

## SMB, FTP, SMB2 и передача файлов

```bash
# SMB-файлы (Wireshark: Export Objects -> SMB)
tshark -r cap.pcap --export-objects smb,./smb_files
# SMB-операции
tshark -r cap.pcap -Y 'smb2.cmd' -T fields -e smb2.filename
# FTP data
tshark -r cap.pcap -Y 'ftp-data' -T fields -e ftp-data
```

SMB часто содержит передачу malware/ransomware, доступ к шарам, NTLM-аутентификацию (для relay/кражи хэшей).

## Статистика и аномалии

```bash
# Топ-разговаривающие (по объёму)
tshark -r cap.pcap -q -z conv,ip | sort -k3 -n | tail
# Экспертные сообщения (аномалии)
tshark -r cap.pcap -q -z expert
# Протокольная иерархия
tshark -r cap.pcap -q -z io,phs
```

## Инструменты и команды

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
tshark -r capture.pcap --export-objects http,./exported
tshark -r capture.pcap -q -z follow,tcp,ascii,0
tshark -r capture.pcap -Y 'http.authorization' -T fields -e http.authorization
tshark -r capture.pcap -o tls.keylog_file:keys.log -Y 'tls'
tcpdump -r capture.pcap -nn 'tcp port 80'
tcpflow -r capture.pcap -o out/
# Wireshark: Statistics -> Protocol Hierarchy, Conversations, Expert Info
```

## Захват трафика

```bash
# tcpdump
tcpdump -i eth0 -w capture.pcap -s 0
tcpdump -i eth0 -nn 'tcp port 443 or udp port 53'
# С ротацией
tcpdump -i eth0 -w cap-%Y%m%d-%H%M.pcap -G 3600 -s 0
# dumpcap (Wireshark)
dumpcap -i eth0 -w out.pcapng -b filesize:100000 -b files:10
# Снятие с удалённого хоста
ssh user@host 'tcpdump -U -w - -s 0' > capture.pcap
```

Для больших объёмов используйте **ring buffer** (ротация) и фильтры BPF, чтобы не переполнить диск. Для TLS — добавьте `SSLKEYLOGFILE` в клиент.

## Протоколы, оставляющие следы

- **DNS** — домены (C2, DGA).
- **HTTP** — URI, User-Agent, тела, загруженные файлы.
- **SMB** — файлы, NTLM, имена шар.
- **Kerberos** — аутентификация, SPN (Kerberoast).
- **LDAP** — запросы к каталогу.
- **FTP/Telnet** — credentials в открытом виде.
- **SMTP/IMAP** — почта.
- **SMB2/NetBIOS** — латеральное движение.

Для каждого — свой фильтр tshark; combine с Zeek-логами для масштаба.

## Итог

PCAP-анализ: начните с `capinfos` и статистики протоколов, затем фильтруйте, реконструируйте потоки (follow stream), извлекайте файлы (export objects), ищите credentials. TLS зашифрован, но метаданные (SNI, JA3) видны; расшифровка возможна с SSLKEYLOGFILE. Zeek дополняет масштабом. Credentials в HTTP Basic/FTP/Telnet — быстрый выигрыш.

## Резюме

`capinfos` → статистика → фильтры → follow stream → export objects → credentials → TLS (SSLKEYLOGFILE). Zeek дополняет масштабом, а NetworkMiner удобен для быстрого извлечения файлов и кредов. Начинайте с обзора и протокольной иерархии, затем сужайте фильтрами и всегда извлекайте переданные файлы — флаг часто именно в них.

## Частые ошибки

- **Смотреть пакеты вместо потоков.** Follow stream эффективнее.
- **Забыть извлечь файлы.** Флаг часто в переданном файле.
- **Игнорировать DNS.** Указывает на C2/домены.
- **Не проверить credentials.** Часто в открытом виде.
- **Не фильтровать.** Большой дамп без фильтров нечитаем.
- **Путать display и capture фильтры.**

## Как не застрять

- **`capinfos`** — обзор.
- **`-z io,phs`** — протоколы.
- **Follow stream** — сессии.
- **Export objects** — файлы.
- **Фильтр по credentials.**
- **DNS** — домены/C2.

## Квиз

```quiz
- question: "Какая утилита — CLI-версия Wireshark?"
  options:
    - "tshark"
    - "nmap"
    - "john"
    - "zeek"
  answer: 0
- question: "Как реконструировать TCP-сессию в tshark?"
  options:
    - "follow stream (-z follow,tcp)"
    - "nmap -sV"
    - "sqlmap"
    - "hashcat"
  answer: 0
- question: "Как извлечь переданные по HTTP файлы?"
  options:
    - "export-objects http"
    - "rm -rf"
    - "mount"
    - "cat"
  answer: 0
- question: "Где чаще всего видны credentials в PCAP?"
  options:
    - "в TLS"
    - "в HTTP Basic / FTP / Telnet"
    - "в ICMP"
    - "в ARP"
  answer: 1
- question: "Что показывает `-z io,phs`?"
  options:
    - "статистику протоколов"
    - "пароли"
    - "файлы"
    - "ничего"
  answer: 0
```

## Где пригодится

- **CTF Forensics** — задачи с PCAP.
- **NSM** — мониторинг сети.
- **DFIR** — восстановление сетевой картины.
- **Пентест** — анализ перехваченного трафика.
- **Malware analysis** — C2-трафик.
