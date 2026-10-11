---
id: forensics-tshark-deep
title: "tshark и Wireshark: глубокие фильтры и извлечение объектов"
category: forensics
parent: forensics-net-ndr
difficulty: hard
order: 3
tags: [tshark, wireshark, pcap, display-filter, extraction, network-forensics]
prerequisites: [forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "Network Forensics"
  - "Анализ трафика"
estimated_minutes: 55
summary: "Глубокий разбор пакетов: фильтры захвата и отображения, статистика (-z), экспорт полей, извлечение объектов и реконструкция потоков через tshark и Wireshark."
---

`tshark` — консольная версия Wireshark, и для форензика это основной инструмент пакетного анализа. Он позволяет искать по байтам, извлекать поля, строить статистику и вытаскивать объекты (файлы, сертификаты, credentials) без ручного просмотра. Wireshark добавляет визуализацию и follow-stream. Здесь — приёмы, которые чаще всего решают CTF-задачи и реальные инциденты.

## Фильтры: два разных языка

Ключевое различие:

- **Capture filter (BPF)** — применяется ДО захвата, синтаксис `tcp port 80`. Используется в `-f`.
- **Display filter** — применяется ПОСЛЕ, синтаксис `http.request.method == "GET"`. Используется в `-Y` (или в поле Wireshark).

```bash
# Захват только нужного (BPF)
tshark -i eth0 -f "tcp port 443"
# Чтение PCAP с display-фильтром
tshark -r capture.pcap -Y 'http.request.method == "POST"'
# Комбинированные условия
tshark -r capture.pcap -Y 'ip.src==10.0.0.5 && tcp.flags.syn==1 && tcp.flags.ack==0'
```

## Полезные display-фильтры

| Цель | Фильтр |
|------|--------|
| HTTP POST | `http.request.method == "POST"` |
| DNS-запросы | `dns.flags.response == 0` |
| TLS SNI | `tls.handshake.extensions_server_name` |
| Ретрансмиссии | `tcp.analysis.retransmission` |
| Сбросы | `tcp.flags.reset == 1` |
| Credentials HTTP | `http.authorization` |
| FTP-логин | `ftp.request.command == "USER"` |
| ICMP-туннель | `icmp && data.len > 64` |
| Файлы | `http.content_type contains "application"` |

```bash
tshark -r capture.pcap -Y 'http.authorization' -T fields -e http.authorization
tshark -r capture.pcap -Y 'ftp.request.command=="PASS"' -T fields -e ftp.request.arg
tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort -u
```

## Извлечение полей и объектов

```bash
# Экспорт полей в CSV-подобный вид
tshark -r capture.pcap -T fields -E header=y -E separator=, \
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri

# Извлечь HTTP-объекты в каталог
tshark -r capture.pcap --export-objects http,./http_objs
ls ./http_objs

# Извлечь SMB-файлы
tshark -r capture.pcap --export-objects smb,./smb_objs
# DICOM, TFTP, IMF — по аналогии

# Выгрузить сертификаты X.509
tshark -r capture.pcap -Y 'tls.handshake.type==11' -T fields -e tls.handshake.certificate
```

## Статистика -z

Флаг `-z` включает встроенные отчёты; это самый быстрый способ получить обзор:

```bash
tshark -r capture.pcap -q -z io,phs        # иерархия протоколов
tshark -r capture.pcap -q -z conv,ip       # разговоры по IP
tshark -r capture.pcap -q -z endpoints,ip  # эндпоинты
tshark -r capture.pcap -q -z expert        # аномалии/ошибки
tshark -r capture.pcap -q -z http,tree     # статистика HTTP
tshark -r capture.pcap -q -z dns,tree
```

`-z io,phs` показывает, какие протоколы вообще есть в захвате; `-z conv,ip` — кто с кем и сколько; `-z expert` — на что Wireshark «ругается».

## Реконструкция потоков

```bash
# Follow TCP stream (вывод в ASCII)
tshark -r capture.pcap -q -z follow,tcp,ascii,0
# Follow HTTP/2
tshark -r capture.pcap -q -z follow,http2,ascii,0
# Список потоков
tshark -r capture.pcap -q -z follow,tcp,ascii
```

В Wireshark: правый клик по пакету → Follow → TCP/HTTP Stream. `tcpflow` даёт альтернативу на диске:

```bash
tcpflow -r capture.pcap -o ./flows
ls ./flows
```

## Разобранный пример

```bash
$ tshark -r attack.pcap -q -z conv,tcp | head
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |
10.0.0.5:51234 <-> 203.0.113.9:443              |  1200 | 90 kB | 3 | 400 B | 1203 | 90 kB |
$ tshark -r attack.pcap -Y 'http.request.method=="POST"' -T fields -e http.host -e http.request.uri -e http.user_agent
evil.example  /upload  Mozilla/5.0 (compatible; MSIE 9.0)
$ tshark -r attack.pcap --export-objects http,./objs
$ ls ./objs
%2Fupload  index.html
$ file './objs/%2Fupload'
./objs/%2Fupload: Zip archive data, at least v2.0 to extract
```

Вывод: атакующий отправил ZIP через POST на `evil.example/upload`; объект извлечён и распознан.

## Краевые случаи и подводные камни

- **BPF vs display filter.** Синтаксис разный; `-f` — до, `-Y` — после. Частая ошибка новичков.
- **Большие PCAP.** Читайте потоково, задайте `-c N` (первые N пакетов) или разбейте `editcap -c`.
- **Обрезанные пакеты (snaplen).** Если захват с малым snaplen, payload может отсутствовать — объекты не извлекутся.
- **Фрагментация.** tshark обычно собирает фрагменты; при `--no-reassembly` картина меняется.
- **TLS.** Без ключей — только метаданные; для расшифровки нужен `SSLKEYLOGFILE` или приватный ключ.
- **Экспорт объектов.** Имена файлов санитизируются; коллизии переименовываются.
- **Порядок пакетов.** Многопоточный захват может дать переупорядочивание; Wireshark сортирует, но `-T fields` — нет.
- **`-z expert`.** Это не «все ошибки», а эвристика Wireshark — не единственный источник.

## Продвинутые display-фильтры

Display-фильтры — сердце анализа. Ниже набор приёмов, которые экономят часы:

| Задача | Фильтр |
|--------|--------|
| Только новые соединения | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| RST-флуд | `tcp.flags.reset==1` |
| Повторные передачи | `tcp.analysis.retransmission` |
| Нулевое окно | `tcp.analysis.zero_window` |
| HTTP 4xx/5xx | `http.response.code >= 400` |
| Загрузка файлов | `http.request.method=="GET" && http.content_type contains "application"` |
| Большие DNS-ответы | `dns.flags.response==1 && dns.resp.len > 200` |
| Kerberos | `kerberos` |
| SMB-операции | `smb2.cmd == 5` |
| Скрытый ICMP | `icmp.type==8 && data.len > 100` |

```bash
# Все RST с указанием сторон
tshark -r capture.pcap -Y 'tcp.flags.reset==1' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
# HTTP-ответы с кодами
tshark -r capture.pcap -Y 'http.response' -T fields -e http.response.code | sort | uniq -c
```

## Экспорт и конвертация

```bash
# Разбить большой PCAP на части по 100000 пакетов
editcap -c 100000 big.pcap part.pcap
# Извлечь диапазон времени
editcap -A "2024-03-01 22:00:00" -B "2024-03-01 23:00:00" big.pcap window.pcap
# Конвертировать формат
editcap -F pcapng capture.pcap capture.pcapng
# Убрать дубликаты
editcap -d -w 1 capture.pcap nodup.pcap
# Слить несколько файлов
mergecap -w merged.pcap a.pcap b.pcap c.pcap
```

`editcap`/`mergecap` входят в тот же пакет, что и Wireshark/tshark, и незаменимы для подготовки больших захватов.

## Реконструкция TLS при наличии ключей

Если есть `SSLKEYLOGFILE` (из браузера) или приватный RSA-ключ сервера, tshark расшифрует трафик:

```bash
# Через SSLKEYLOGFILE
tshark -r tls.pcap -o tls.keylog_file:sslkeys.log -Y 'http2' -T fields -e http2.headers.path
# Через приватный ключ (RSA, устаревшие шифры)
tshark -r tls.pcap -o tls.keys_list:"0.0.0.0,443,http,server.key" -Y 'http'
```

Без ключей доступны только SNI/сертификаты/JA3. Подробнее — в `forensics-tls-decrypt`.

## Извлечение по протоколам

```bash
# Объекты разных протоколов
tshark -r cap.pcap --export-objects http,./o_http
tshark -r cap.pcap --export-objects smb,./o_smb
tshark -r cap.pcap --export-objects tftp,./o_tftp
tshark -r cap.pcap --export-objects imf,./o_mail    # почта
tshark -r cap.pcap --export-objects dicom,./o_dicom
# Сертификаты
tshark -r cap.pcap -Y 'tls.handshake.type==11' -T fields -e tls.handshake.certificate | head
# Credentials в открытых протоколах
tshark -r cap.pcap -Y 'ftp.request.command=="USER" || ftp.request.command=="PASS"' -T fields -e ftp.request.command -e ftp.request.arg
```

## Статистика для быстрого обзора

```bash
# Иерархия протоколов — что вообще есть в захвате
tshark -r cap.pcap -q -z io,phs
# Экспертные сообщения (аномалии)
tshark -r cap.pcap -q -z expert
# HTTP-статистика
tshark -r cap.pcap -q -z http,tree
# Время ответа
tshark -r cap.pcap -q -z io,stat,1,"COUNT(frame)frame"
```

`-z expert` — хорошая отправная точка: Wireshark сам указывает на подозрительные места (checksum errors, retransmissions, malformed).

## Чек-лист пакетного анализа

1. `-z io,phs` и `-z conv,ip` — обзор.
2. `-z expert` — аномалии.
3. `-Y` — сузить по протоколу/адресу/методу.
4. `-T fields` — выгрузить нужные поля.
5. `--export-objects` — вытащить файлы.
6. `follow`/`tcpflow` — восстановить сессию.
7. При наличии ключей — расшифровать TLS.

## Сложные случаи: фрагментация, туннели, обфускация

- **IP-фрагментация.** `tshark -Y 'ip.flags.mf==1 || ip.frag_offset>0'` покажет фрагменты; атакующие дробят пакеты, чтобы обойти IDS.
- **Перекрывающиеся фрагменты.** `tshark -o ip.defragment:FALSE` отключает сборку — иногда нужно, чтобы увидеть манипуляцию.
- **TCP-переупорядочивание.** Атакующие шлют сегменты в неверном порядке, чтобы разные ОС собрали разное; смотрите `tcp.options` и sequence numbers.
- **Covert-каналы.** Данные в TCP ISN, опциях, TTL или IP ID: `tshark -T fields -e ip.id -e tcp.options`.

```bash
# Посмотреть IP ID и TTL как возможный канал
tshark -r cap.pcap -T fields -e ip.src -e ip.id -e ip.ttl | head -30
# Фрагменты
tshark -r cap.pcap -Y 'ip.frag_offset>0' -T fields -e ip.id -e ip.frag_offset -e ip.len
```

Это редко нужно в обычных задачах, но в CTF с «необычным» трафиком такие приёмы решают.

## Итог

Пакетный анализ — фундамент сетевой форензики: `-z` даёт обзор, `-Y` сужает, `--export-objects` вытаскивает файлы, а `follow`/`tcpflow` восстанавливают сессии. Освоив эти приёмы, вы разберёте любой PCAP — от CTF-задачи до реального инцидента.

## Что дальше / решение

1. `-z io,phs` — обзор протоколов.
2. `-z conv,ip` — подозрительные пары.
3. `-Y` — сузить до протокола/хоста.
4. `--export-objects` — вытащить файлы; `-T fields` — нужные поля.
5. `follow`/`tcpflow` — реконструировать сессию.

Дальше — `forensics-tls-decrypt` (расшифровка), `forensics-suricata` (сигнатуры) и `forensics-exfil` (поиск утечки).

## Квиз

```quiz
- question: "Чем capture filter отличается от display filter?"
  options:
    - "Ничем"
    - "Capture (BPF) применяется до захвата, display — после"
    - "Capture — для TLS, display — для HTTP"
    - "Display — только в Wireshark"
  answer: 1
  explanation: "BPF фильтрует на входе (-f), display — на выходе (-Y)."
- question: "Какая опция tshark извлекает HTTP-объекты в каталог?"
  options:
    - "-z follow"
    - "--export-objects http,DIR"
    - "-T fields"
    - "-w out.pcap"
  answer: 1
  explanation: "--export-objects http,DIR сохраняет переданные по HTTP файлы."
- question: "Что показывает `tshark -z conv,ip`?"
  options:
    - "иерархию протоколов"
    - "разговоры между IP-адресами (пакеты/байты)"
    - "сертификаты"
    - "правила IDS"
  answer: 1
  explanation: "conv,ip — сводка по разговорам между адресами."
- question: "Почему при малом snaplen объекты не извлекаются?"
  options:
    - "tshark не поддерживает export"
    - "payload пакетов обрезан при захвате"
    - "PCAP слишком маленький"
    - "нужен Wireshark GUI"
  answer: 1
  explanation: "snaplen ограничивает длину сохраняемых байт; без payload файл не собрать."
```

## Где пригодится

- **CTF:** извлечение файлов и поиск данных в PCAP.
- **DFIR:** реконструкция сессий и объектов при инциденте.
- **Threat Hunting:** быстрый обзор и фильтрация трафика.
- **Работа:** повседневный анализ сетевых проблем и безопасности.
