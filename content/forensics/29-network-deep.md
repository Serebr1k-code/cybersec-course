---
id: forensics-network-deep
title: "Глубокий анализ сети: протоколы и эксфильтрация"
category: forensics
parent: forensics-pcap
difficulty: hard
order: 2
tags: [pcap, exfiltration, dns, icmp, tls, ja3, zeek, network]
prerequisites: [forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "Network Security Monitoring"
  - "Incident Response"
estimated_minutes: 50
summary: "Продвинутый анализ трафика: реконструкция сессий, скрытые каналы (DNS/ICMP/HTTP), эксфильтрация, TLS/JA3, Zeek и статистические аномалии."
---
Продвинутый анализ трафика — это не только просмотр пакетов, но и реконструкция сессий, поиск скрытых каналов, статистический анализ и работа с TLS. Атакующие прячут эксфильтрацию и C2 в DNS, ICMP, HTTP-заголовках и легитимных сервисах. Этот урок — про методы и инструменты (`tshark`, `Zeek`, `NetworkMiner`, `Scapy`) для глубокого разбора PCAP.

## Подготовка и статистика

Начните с «карты» трафика: кто с кем говорил, сколько данных, какие протоколы.

```bash
# обзор протоколов
$ tshark -r capture.pcap -q -z io,phs
# топ разговоров по байтам
$ tshark -r capture.pcap -q -z conv,ip | sort -k3 -rn | head
# топ портов
$ tshark -r capture.pcap -T fields -e tcp.dstport | sort | uniq -c | sort -rn | head
# DNS-запросы
$ tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head
```

`-z io,phs` даёт иерархию протоколов, `-z conv,ip` — матрицу разговоров, `-z endpoints,ip` — эндпоинты.

## Реконструкция сессий

```bash
# извлечь HTTP-объекты (файлы)
$ tshark -r capture.pcap --export-objects http,out/
# извлечь SMB-файлы
$ tshark -r capture.pcap --export-objects smb,out_smb/
# собрать TCP-поток в текст
$ tshark -r capture.pcap -q -z follow,tcp,ascii,0
# диалоги (Wireshark: Follow → TCP Stream)
$ tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
```

`NetworkMiner` автоматически реконструирует файлы, изображения, учётные данные и хосты из PCAP — удобно для быстрого триажа.

## Скрытые каналы: DNS

DNS-туннели кодируют данные в поддоменах (часто base32/base64) и запросах типа TXT. Признаки: длинные имена, высокая энтропия, много запросов к одному домену, необычные типы (TXT, NULL, CNAME).

```bash
# аномально длинные имена
$ tshark -r capture.pcap -Y 'dns.qry.name' -T fields -e dns.qry.name | awk '{print length, $0}' | sort -rn | head
# частотный анализ домена
$ tshark -r capture.pcap -Y 'dns.qry.name contains "evil.com"' -T fields -e dns.qry.name | head
# извлечь данные из поддоменов (после декодирования base32)
$ tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | cut -d. -f1 | base32 -d 2>/dev/null
```

`iodine`/`dnscat2` — типичные инструменты туннелей; их трафик узнаваем по паттерну.

## Скрытые каналы: ICMP и HTTP

**ICMP**: данные в payload эхо-запросов. Признаки — большой и постоянный размер payload, нестандартные типы.

```bash
$ tshark -r capture.pcap -Y 'icmp' -T fields -e data | head
$ tshark -r capture.pcap -Y 'icmp.type==8' -T fields -e data.data | xxd -r -p
```

**HTTP**: данные в заголовках (Cookie, Referer, User-Agent), в теле POST, в нестандартных методах. Также domain fronting (Host ≠ SNI).

```bash
$ tshark -r capture.pcap -Y 'http.cookie' -T fields -e http.cookie | head
$ tshark -r capture.pcap -Y 'http.request.method=="POST"' -T fields -e http.file_data | head
```

## Эксфильтрация

Ищите аномалии объёмов и таймингов: клиент отправляет больше, чем получает; регулярные «пульсы» (beacon); сжатые/шифрованные блобы к внешним IP.

```bash
# исходящий объём по назначению
$ tshark -r capture.pcap -q -z conv,ip | awk '{print $3, $1}' | sort -rn | head
# регулярность соединений (beacon)
$ tshark -r capture.pcap -Y 'ip.dst==203.0.113.9' -T fields -e frame.time_relative | head
```

## TLS и JA3

TLS-трафик не читается без ключей, но метаданные (JA3/JA3S — отпечатки клиента/сервера, SNI, сертификаты) позволяют атрибутировать инструменты.

```bash
$ tshark -r capture.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3
$ tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name
# Zeek: ssl.log с ja3/ja3s
$ cat zeek/ssl.log | zeek-cut id.orig_h server_name ja3 ja3s | head
```

Cobalt Strike и другие C2 имеют характерные JA3 (см. `forensics-cobaltstrike`). Расшифровка — `forensics-tls-decrypt`.

## Zeek

`Zeek` превращает PCAP в структурированные логи: `conn.log`, `http.log`, `dns.log`, `ssl.log`, `files.log`, `notice.log`.

```bash
$ zeek -r capture.pcap
$ cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes
$ cat dns.log | zeek-cut query answers | head
$ cat files.log | zeek-cut filename mime_type md5
```

`zeek-cut` извлекает нужные колонки — основа для статистики и детекта.

## Разобранный пример

Дан `exfil.pcap`. Ищем утечку.

```bash
# 1. Кто передал больше всех
$ tshark -r exfil.pcap -q -z conv,ip | sort -k3 -rn | head -3
10.0.0.5 <-> 203.0.113.9  4521000 bytes
# 2. Что за протокол
$ tshark -r exfil.pcap -Y 'ip.dst==203.0.113.9' -q -z io,phs
dns  ...
# 3. Длинные DNS-имена -> туннель
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | awk '{print length,$0}' | sort -rn | head -1
62 dGhpcyBpcyB0aGUgc2VjcmV0...evil.com
# 4. Декодировать
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | cut -d. -f1 | base64 -d 2>/dev/null | strings | head
secret document contents
```

Итог: эксфильтрация через DNS-туннель (base64 в поддоменах).

## Частые ошибки

- **Смотреть только TCP/HTTP** — туннели живут в DNS/ICMP.
- **Не строить статистику** — аномалии видны только в агрегатах.
- **Забывать `--export-objects`** — файлы можно извлечь напрямую.
- **Игнорировать тайминги** — регулярность выдаёт beacon.
- **Путать JA3 клиента и сервера** (JA3/JA3S).
- **Анализировать огромный PCAP без фильтра** — используйте `-Y` и `-z`.

## Что дальше / решение

Конвейер: статистика (`-z io,phs`/`conv,ip`) → протоколы по интересу → реконструкция (`--export-objects`) → поиск аномалий (DNS/ICMP/тайминги) → атрибуция (JA3/SNI) → расшифровка (`forensics-tls-decrypt`). Связка: `forensics-pcap` (основы), `forensics-exfil` (эксфильтрация), `forensics-zeek`, `forensics-cobaltstrike`.

## Scapy: разбор и генерация пакетов

`Scapy` — Python-библиотека для чтения, разбора и генерации пакетов. Незаменима, когда нужно извлечь данные из нестандартного протокола или посчитать статистику, которую `tshark` не даёт.

```python
# извлечь payload всех ICMP echo-запросов
from scapy.all import rdpcap, ICMP
pkts = rdpcap('capture.pcap')
data = b''.join(bytes(p[ICMP].payload) for p in pkts if ICMP in p and p[ICMP].type == 8)
open('icmp_data.bin','wb').write(data)
```

```python
# частотный анализ DNS-запросов
from scapy.all import rdpcap, DNSQR
from collections import Counter
pkts = rdpcap('capture.pcap')
names = [p[DNSQR].qname.decode() for p in pkts if p.haslayer(DNSQR)]
for n, c in Counter(names).most_common(10):
    print(c, n)
```

`Scapy` также строит пакеты (`send`/`sr1`), что полезно для проверки гипотез о скрытом канале.

## Инструменты и их назначение

| Инструмент | Роль |
|-----------|------|
| `tshark` | фильтрация, статистика, экспорт объектов |
| `Wireshark` | GUI, follow stream, расшифровка TLS |
| `Zeek` | структурированные логи из PCAP |
| `NetworkMiner` | реконструкция файлов/креденшелов |
| `Scapy` | программный разбор/генерация |
| `tcpflow` | реконструкция TCP-потоков в файлы |
| `ngrep` | grep по сетевым данным в реальном времени |
| `argus`/`SiLK` | потоковые (flow) данные, большие объёмы |
| `bro/zeek-cut` | извлечение полей из логов Zeek |

```bash
# tcpflow: разложить потоки по файлам
$ tcpflow -r capture.pcap -o flows/
# ngrep: искать паттерн в данных
$ ngrep -I capture.pcap -W byline 'password'
# Zeek: логи
$ zeek -r capture.pcap && ls *.log
```

## Реконструкция сессий и объектов в деталях

`--export-objects` извлекает файлы из HTTP/SMB/DICOM и др.:

```bash
$ tshark -r capture.pcap --export-objects http,http_obj/
$ ls http_obj/
# по имени/типу
$ file http_obj/* | grep -i 'executable\|zip\|pdf'
# SMB
$ tshark -r capture.pcap --export-objects smb,smb_obj/
# TLS: без ключей не выйдет; с ключом — см. forensics-tls-decrypt
```

`NetworkMiner` делает то же через GUI и дополнительно восстанавливает учётные данные (HTTP Basic, FTP, POP) и хосты. Для больших PCAP предпочтительнее `Zeek` + `zeek-cut`, т.к. он обрабатывает потоково.

## Статистические аномалии

Ищите отклонения от «нормального» профиля:

- **Объём**: клиент передал намного больше, чем получил (эксфильтрация).
- **Регулярность**: соединения строго каждые N секунд (beacon/C2).
- **Размер**: постоянный размер пакетов (туннель с фиксированным чанком).
- **Порты**: нестандартные порты для «обычных» протоколов.
- **Домены**: DGA-имена (случайные), длинные поддомены (DNS-туннель).
- **User-Agent/SNI**: несоответствие (curl UA + Chrome JA3).

```bash
# распределение размеров пакетов к подозрительному IP
$ tshark -r capture.pcap -Y 'ip.dst==203.0.113.9' -T fields -e frame.len | sort | uniq -c | sort -rn | head
# интервалы между соединениями (регулярность)
$ tshark -r capture.pcap -Y 'tcp.flags.syn==1 && ip.dst==203.0.113.9' -T fields -e frame.time_relative | head -20
```

## Квиз

```quiz
- question: "Что такое JA3?"
  options:
    - "тип шифрования"
    - "отпечаток TLS-клиента по набору параметров"
    - "порт"
    - "домен"
  answer: 1
- question: "Как обнаружить DNS-туннель?"
  options:
    - "по большим файлам"
    - "по длинным/энтропийным поддоменам и множеству запросов"
    - "по MAC-адресам"
    - "по TTL"
  answer: 1
- question: "Какой инструмент даёт структурированные логи из PCAP?"
  options:
    - "`Zeek`"
    - "`binwalk`"
    - "`exiftool`"
    - "`nmap`"
  answer: 0
- question: "Что видно из TLS без ключей?"
  options:
    - "содержимое"
    - "SNI, версию, шифры, сертификаты"
    - "пароли"
    - "файлы"
  answer: 1
- question: "Признак эксфильтрации в статистике?"
  options:
    - "много входящего трафика"
    - "аномально большой исходящий поток к одному IP"
    - "DNS-запросы к локальному хосту"
    - "ARP"
  answer: 1
```

## Где пригодится

- **CTF:** задачи со скрытыми каналами и эксфильтрацией.
- **NSM/SOC:** обнаружение C2 и утечек.
- **Incident Response:** восстановление действий атакующего.
- **Malware analysis:** анализ C2-протоколов.
- **Threat Hunting:** выявление аномалий в трафике.
