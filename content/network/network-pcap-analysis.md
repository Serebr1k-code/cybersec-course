---
id: network-pcap-analysis
title: "Практический анализ PCAP: восстановление файлов, учёток и скрытых данных"
category: network
parent: network-wireshark
difficulty: medium
order: 2
tags: [network, pcap, forensics, exfiltration, ctf]
prerequisites: [network-wireshark]
useful_for:
  - "CTF-задачи с дампом трафика"
  - "Forensics: восстановление переданных файлов"
  - "Расследование сетевых инцидентов"
estimated_minutes: 50
summary: "Пошаговый разбор PCAP: чек-лист анализа, извлечение файлов, поиск учётных данных, выявление скрытых каналов и автоматизация."
---

Анализ PCAP — самая частая сетевая CTF-задача. Здесь нет единственно правильного пути, но есть отработанный чек-лист, который покрывает 90% случаев.

## Формат PCAP и PCAPNG

- **PCAP** — старый простой формат: глобальный заголовок + записи пакетов (timestamp, length, data).
- **PCAPNG** — современный, поддерживает несколько интерфейсов, комментарии, метаданные. Wireshark читает оба.

Если файл «не открывается» — проверь сигнатуру:

```bash
file capture.pcap
xxd capture.pcap | head -3
```

Магические байты: `d4 c3 b2 a1` (PCAP, little-endian) или `0a 0d 0d 0a` (PCAPNG). Иногда PCAP прячут внутри другого файла — тогда `binwalk`. Также полезно сразу выполнить `capinfos`, чтобы узнать число пакетов, длительность и snaplen: последнее критично, потому что при малом snaplen payload урезан и часть данных физически отсутствует.

## Чек-лист анализа

1. **Protocol Hierarchy** — какие протоколы вообще есть. Ищи необычные (FTP, Telnet, TFTP, ICMP с данными).
2. **Conversations** — самые «болтливые» пары хостов.
3. **Follow Stream** по каждому интересному потоку.
4. **Экспорт объектов** (HTTP/SMB/TFTP).
5. **Поиск строк** — `strings`, `frame contains`.
6. **Экспорт полей** — `tshark -T fields` для массового извлечения.

## Извлечение файлов

Самый быстрый способ — экспорт объектов:

```bash
mkdir out && tshark -r capture.pcap --export-objects http,./out
tshark -r capture.pcap --export-objects smb,./out
tshark -r capture.pcap --export-objects tftp,./out
```

Для потоков без «родного» протокола (например, кастомная передача по TCP):

```bash
# выгрузить payload конкретного потока
tshark -r capture.pcap -q -z follow,tcp,raw,3 | tail -n +7 | xxd -r -p > stream3.bin
file stream3.bin
```

`-z follow,tcp,raw,N` выдаёт payload потока N в hex — его можно собрать обратно в файл.

## Извлечение по протоколам

| Протокол | Как извлечь |
|---|---|
| HTTP | `--export-objects http,./out` |
| SMB | `--export-objects smb,./out` |
| TFTP | `--export-objects tftp,./out` |
| FTP-DATA | Follow Stream → Save As |
| IMAP/POP | `--export-objects imf,./out` |
| Кастомный TCP | `-z follow,tcp,raw,N` + `xxd -r -p` |

Если экспорт объектов не сработал, всегда есть «ручной» путь: Follow Stream → Save As (raw) → проверка сигнатуры `file`.

## Поиск учётных данных и флагов

```bash
# пароли в FTP/POP/IMAP/Telnet
tshark -r cap.pcap -Y 'ftp.request.command=="PASS"' -T fields -e ftp.request.arg
tshark -r cap.pcap -Y 'pop.request.command=="PASS"' -T fields -e pop.request.arg

# HTTP Basic Auth (base64)
tshark -r cap.pcap -Y 'http.authorization' -T fields -e http.authorization
# декодировать: echo <base64> | base64 -d

# HTTP POST с формами
tshark -r cap.pcap -Y 'http.request.method=="POST"' -T fields -e http.file_data | xxd -r -p
```

Флаг часто лежит прямо в незашифрованном протоколе. Прогон `strings capture.pcap | grep -iE 'flag|ctf|key'` — дешёвая первая проверка.

## Скрытые каналы в PCAP

- **DNS-туннель** — длинные поддомены, много запросов к одному домену, данные в base64/hex. Проверяй: `tshark -r cap.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head`.
- **ICMP-эксфильтрация** — данные в payload ICMP-эхо: `tshark -r cap.pcap -Y icmp -T fields -e data`.
- **IP ID / TTL** — данные в младших битах ID или в TTL.
- **Timing** — биты кодируются задержкой между пакетами.
- **Порядок портов** — последовательность номеров портов кодирует сообщение.

## Работа с большими дампами

Гигабайтный PCAP не открыть в GUI. Подходы:

```bash
capinfos big.pcap                       # статистика и snaplen
tshark -r big.pcap -q -z conv,ip | head # топ разговоров
tshark -r big.pcap -Y 'http.request' -w http_only.pcap   # вырезать подмножество
editcap -r big.pcap part.pcap 1-10000   # первые 10k пакетов
```

`-z` даёт статистику без полной загрузки; `-w`/`editcap` — подмножества для GUI. Для потоковой обработки — `tshark -T fields` + `sort`/`uniq`.

## Автоматизация

```bash
# все уникальные DNS-имена
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name | sort -u

# список всех HTTP host+uri
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri

# экспорт в JSON для дальнейшего разбора
tshark -r cap.pcap -T json > cap.json
```

## Полный разбор кейса

Задача: в дампе `capture.pcap` найти флаг.

1. `capinfos capture.pcap` — проверить snaplen и размер.
2. `Statistics → Protocol Hierarchy` — заметить необычное (например, много DNS).
3. `tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head` — увидеть аномалию.
4. Собрать поддомены в порядке времени, декодировать base32/base64.
5. Если пусто — `frame contains "flag"`, экспорт объектов HTTP, Follow Stream.
6. Зафиксировать цепочку: где нашёл, как декодировал, результат.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| capinfos | `capinfos f.pcap` | метаданные, snaplen |
| tshark | `--export-objects` | извлечь файлы |
| tshark | `-z follow,tcp,raw,N` | payload потока |
| tshark | `-T fields -e <field>` | автоматизация |
| tcpflow | `tcpflow -r f.pcap` | реконструкция потоков |
| binwalk | `-e f.pcap` | вложенные файлы |
| NetworkMiner | GUI | автоматическое извлечение |

## Частые ошибки

- **Не проверить snaplen.** Дамп мог быть записан с малым snaplen — полного payload нет. Проверяйте `capinfos capture.pcap` до выводов о содержимом.
- **Анализировать одиночные пакеты вместо потока.** HTTP keep-alive и параллельные соединения требуют `Follow Stream`; иначе картинка «рвётся».
- **Копировать бинарные данные из hex.** Так файл побьётся. Извлекайте через `Export Objects` или `tcpflow`, а не выделением текста.
- **Игнорировать тайминги.** Временные метки — часть скрытых каналов и таймлайна.

## Что делать дальше / решение

- **Нужен файл** → `--export-objects` / Follow Stream.
- **Нужны учётки** → фильтры FTP/POP/HTTP-auth.
- **Нужен скрытый канал** → DNS/ICMP/timing-анализ.
- **Нужен большой дамп** → `capinfos` + `-z` + `editcap`.
- **Нужен кастомный протокол** → `network-protocol-reversing`.

## Быстрая шпаргалка

```bash
capinfos capture.pcap                                  # метаданные, snaplen
tshark -r capture.pcap -q -z io,phs                    # иерархия протоколов
tshark -r capture.pcap --export-objects http,./out     # файлы HTTP
tshark -r capture.pcap -q -z follow,tcp,raw,3 | tail -n +7 | xxd -r -p > s3.bin
tshark -r capture.pcap -Y 'frame contains "flag"' -T fields -e frame.number
strings capture.pcap | grep -iE 'flag|ctf|key|pass'
```

Порядок: метаданные → иерархия → «болтливые» хосты → Follow Stream/экспорт → строки → скрытые каналы. Не забывайте про snaplen: если он мал, полного payload в дампе просто нет.

## Квиз

```quiz
- question: "Какой быстрый способ вытащить все файлы, переданные по HTTP, из PCAP?"
  options:
    - "Открыть в блокноте"
    - "tshark --export-objects http,./out"
    - "tcpdump -A"
    - "strings capture.pcap"
  answer: 1
  explanation: "export-objects восстанавливает переданные файлы в каталог."
- question: "Что может указывать на DNS-туннель в дампе?"
  options:
    - "Много DNS-запросов к одному домену с длинными случайными поддоменами"
    - "Один обычный запрос example.com"
    - "HTTP-ответ 200"
    - "TCP SYN на порт 443"
  answer: 0
  explanation: "Туннель кодирует данные в поддоменах: много длинных base64/hex-имён на один домен."
- question: "Как собрать payload TCP-потока номер 3 в файл?"
  options:
    - "tshark -z follow,tcp,raw,3 | ... | xxd -r -p > stream3.bin"
    - "tcpdump -c 3"
    - "wireshark --export stream3"
    - "nmap -p 3"
  answer: 0
  explanation: "-z follow,tcp,raw,3 выдаёт payload потока в hex, который декодируется xxd -r -p."
- question: "Где чаще всего лежат пароли в незашифрованном трафике?"
  options:
    - "В DNS-запросах"
    - "В командах FTP/POP/IMAP (USER/PASS) и HTTP Authorization"
    - "В TLS ClientHello"
    - "В ICMP-заголовке"
  answer: 1
  explanation: "Классические текстовые протоколы передают учётки в открытом виде."
- question: "Какой магический номер у PCAP-файла (little-endian)?"
  options:
    - "d4 c3 b2 a1"
    - "0a 0d 0d 0a"
    - "7f 45 4c 46"
    - "50 4b 03 04"
  answer: 0
  explanation: "d4 c3 b2 a1 — PCAP LE; 0a0d0d0a — PCAPNG; 7f454c46 — ELF; 504b0304 — ZIP."
```

## Где пригодится

- **CTF:** базовый сценарий категории Network/Forensics — разбор дампа и восстановление данных.
- **Пентест:** анализ перехваченного трафика, выявление эксфильтрации.
- **Работа SOC/IR:** восстановление файлов и учёток из инцидента.
