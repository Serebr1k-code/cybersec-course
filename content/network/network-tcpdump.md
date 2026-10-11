---
id: network-tcpdump
title: "tcpdump: захват и фильтрация трафика в командной строке"
category: network
parent: network-tcpip
difficulty: easy
order: 1
tags: [network, tcpdump, capture, bpf, pcap]
prerequisites: [network-tcpip]
useful_for:
  - "Быстрый захват трафика на сервере без GUI"
  - "CTF: фильтрация PCAP через tshark/tcpdump"
  - "Отладка сетевых приложений"
estimated_minutes: 45
summary: "Синтаксис tcpdump, BPF-фильтры, запись в pcap и практические приёмы захвата нужного трафика."
---
`tcpdump` — базовый сниффер командной строки. Он есть практически на любом Linux, работает без GUI и умеет писать в `.pcap`, который потом открывается в Wireshark. Это первый инструмент, который стоит освоить: без него не обходится ни разведка, ни отладка, ни разбор инцидентов. Урок опирается на [`network-tcpip`](network-tcpip).

## Базовый синтаксис и опции

```bash
sudo tcpdump -i eth0              # слушать интерфейс
sudo tcpdump -i any               # все интерфейсы
sudo tcpdump -D                   # список интерфейсов
sudo tcpdump -c 100               # остановиться после 100 пакетов
sudo tcpdump -nn                  # не резолвить имена хостов и портов
sudo tcpdump -v / -vv / -vvv      # растущая детализация
sudo tcpdump -A                   # payload в ASCII
sudo tcpdump -X                   # payload в hex+ASCII
sudo tcpdump -e                   # заголовки L2 (MAC)
sudo tcpdump -s 0                 # snaplen без обрезки (весь пакет)
sudo tcpdump -w out.pcap          # запись в файл
```

`-nn` обязателен в пентесте: без него tcpdump делает DNS-запросы на каждый пакет, шумит, тормозит и сам становится источником трафика. `-s 0` (или `-s snaplen`) задаёт, сколько байт каждого пакета сохранять; в старых версиях дефолт был 68 байт, и payload обрезался — поэтому явное `-s0` надёжнее. `-p` выключает promiscuous-режим (по умолчанию интерфейс слушает весь трафик сегмента, а не только свой).

## Фильтры BPF (Berkeley Packet Filter)

Фильтр задаётся выражением после опций — это важнейший навык, потому что фильтр применяется **до** записи: чем точнее выражение, тем меньше дамп и нагрузка.

```bash
# по хосту
tcpdump host 10.0.0.5
tcpdump src 10.0.0.5
tcpdump dst 10.0.0.5
# по сети
tcpdump net 10.0.0.0/24
# по порту/протоколу
tcpdump port 443
tcpdump portrange 8000-8100
tcpdump tcp
tcpdump udp
tcpdump icmp
# комбинации
tcpdump 'src 10.0.0.5 and port 80'
tcpdump 'tcp and not port 22'
# флаги TCP (SYN, RST, ...)
tcpdump 'tcp[tcpflags] & tcp-syn != 0'      # только SYN
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'  # чистые SYN
# по размеру
tcpdump 'greater 1000'
tcpdump 'less 64'
# по содержимому (hex/ascii)
tcpdump -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)'  # "GET "
```

Побитовые выражения (`tcp[tcpflags] & tcp-syn`) — «острый» инструмент: они разбирают байты заголовка напрямую. `tcp[12:1] & 0xf0) >> 2` вычисляет длину TCP-заголовка в байтах (data offset), чтобы прочитать первые 4 байта payload — это стандартный приём для поиска строки `GET ` в открытом HTTP.

## Запись, чтение и ротация

```bash
# Запись с ротацией
tcpdump -i eth0 -w cap.pcap -G 3600 -W 24        # по часу, 24 файла
tcpdump -i eth0 -w cap.pcap -C 100               # новый файл каждые 100 МБ
# Чтение
tcpdump -r cap.pcap
tcpdump -r cap.pcap -nn 'port 443'
# Обрезка (для хранения только заголовков)
tcpdump -i eth0 -s 96 -w headers.pcap
```

`-G` и `-C` вместе с `-w` дают «часовые» и «размерные» наборы файлов — так строят длительный захват, не забивая диск. `-Z user` сбрасывает привилегии root после открытия интерфейса — хорошая практика безопасности.

## Практические сценарии

```bash
# Кто-то сканирует вас?
tcpdump -nn 'tcp[tcpflags] & tcp-syn != 0 and not port 22' -c 50
# HTTP-запросы в открытом виде
tcpdump -nn -A 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
# DNS-запросы
tcpdump -nn 'udp port 53'
# DHCP
tcpdump -nn 'udp port 67 or udp port 68'
# ARP-спуфинг (дубликаты ответов)
tcpdump -nn 'arp' -e
```

Первый фильтр — мини-IDS: всплеск SYN-пакетов от одного адреса = сканирование. `-e` показывает MAC-адреса, и если один IP отвечает с двумя разными MAC — это признак ARP-спуфинга или конфликта.

## tshark: разбор и извлечение

`tshark` — «tcpdump с диссекторами». Читает те же pcap и умеет фильтровать по полям протоколов:

```bash
tshark -r cap.pcap -Y 'http.request'                     # Wireshark-фильтр (-Y)
tshark -r cap.pcap -T fields -e ip.src -e ip.dst         # выбрать поля
tshark -r cap.pcap -Y 'dns.qry.name contains "evil"' -T fields -e dns.qry.name
tshark -r cap.pcap --export-objects http,out/            # выгрузить файлы
tshark -r cap.pcap -q -z io,phs                          # иерархия протоколов
tshark -r cap.pcap -q -z conv,tcp                        # разговоры
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name
```

Разница: `tcpdump` использует **BPF** (`port 80 and host x`), `tshark` — **display filters** (`http.request.method=="GET"`). BPF — грубый отбор на уровне байтов; display filter — семантический, по разобранным полям. Комбинируйте: сначала узкий BPF при захвате, потом точные display filters при разборе.

## Захват на удалённом хосте

На сервере без GUI (или в контейнере) удобно писать дамп и забирать локально:

```bash
# на сервере
tcpdump -i any -s0 -w /tmp/cap.pcap -G 300 -W 12 'not port 22'
# забрать
scp user@server:/tmp/cap.pcap .
# или стримить в Wireshark
ssh user@server 'tcpdump -i any -U -w - not port 22' | wireshark -k -i -
```

`-U` включает небуферизованный вывод (для стриминга), а `not port 22` исключает ваш же SSH, чтобы не захватывать собственный сеанс.

## Захват Wi-Fi, USB и особых интерфейсов

```bash
# список интерфейсов (включая usbmon, bluetooth)
tcpdump -D
# беспроводной monitor-режим (через airmon-ng)
sudo airmon-ng start wlan0
sudo tcpdump -i wlan0mon -w wifi.pcap
# USB (см. network-usb-pcap)
sudo tcpdump -i usbmon1 -w usb.pcap
```

В monitor-режиме карта видит все кадры 802.11 в эфире, включая чужие — это основа анализа Wi-Fi. `usbmon` позволяет разбирать USB-трафик (клавиатуры, накопители) тем же инструментарием.

## Производительность, буферы и типичные ошибки

- **-B <kB>** — размер буфера; при высоком трафике увеличьте (например, `-B 4096`), иначе ядро теряет пакеты.
- **-w + -G/-W** — ротация файлов по времени.
- **-C** — ротация по размеру (МБ).
- **-Z user** — сбросить привилегии после открытия интерфейса.
- **Забывать `-nn`** — медленно и шумно из-за DNS.
- **Ограниченный snaplen** — обрезанный payload; `-s 0` надёжнее.
- **Захват без `-w`** — вывод на экран при высокой нагрузке теряет пакеты.
- **Слишком широкий фильтр** — дамп на гигабайты.
- **Права root** — raw-сокеты требуют привилегий (или `CAP_NET_RAW`).

## Разбор кейса: от дампа к улике

Допустим, у нас `cap.pcap` с подозрительной активностью. Порядок разбора: (1) `tcpdump -r cap.pcap -nn | head` — общая картина; (2) `tshark -r cap.pcap -q -z conv,tcp` — топ разговоров по объёму (кто эксфильтровал больше всех); (3) `tshark -r cap.pcap -Y 'dns'` — подозрительные домены; (4) `--export-objects http,out/` — выгрузить переданные файлы; (5) при TLS — извлечь SNI (`extensions_server_name`), чтобы понять, куда ходил клиент, даже не имея ключей. Так за несколько минут получается связная картина без GUI.

## Что дальше / решение

Маршрут: **освоить BPF-фильтры → писать точные `-w`-дампы с ротацией → разбирать их через `tshark` и Wireshark**. Дальше — [`network-wireshark`](network-wireshark) для глубокого разбора, [`network-pcap-analysis`](network-pcap-analysis) для методичного разбора CTF-дампов и [`network-zeek`](network-zeek) для построения IDS-телеметрии. Для пентеста свяжите tcpdump с ARP- и DNS-спуфингом: [`network-arp-deep`](network-arp-deep).

## Синтаксис BPF: приоритеты, скобки и ловушки

Выражение BPF — это булева логика с приоритетами: `not` связывает сильнее `and`, а `and` — сильнее `or`. Поэтому `tcpdump 'host 10.0.0.5 or host 10.0.0.6 and port 80'` читается как `10.0.0.5 or (10.0.0.6 and port 80)` — почти наверняка не то, что имел в виду автор. Всегда расставляйте скобки: `'(host 10.0.0.5 or host 10.0.0.6) and port 80'`. Квалификаторы (`src`, `dst`, `host`, `port`, `portrange`, `net`) можно комбинировать с протоколами: `udp dst port 53`, `tcp src port 443`, `ether host aa:bb:cc:dd:ee:ff`. Для IPv6 используйте `ip6`, `ip6 host`, `icmp6`; для VLAN — `vlan` (сдвигает разбор на следующий тег, применяйте осторожно с двойным тегированием).

Отдельная ловушка — **`vlan` и оффсеты**: после ключевого слова `vlan` BPF-компилятор смещает все последующие оффсеты на 4 байта. Если тег не один, выражение становится неинтуитивным. Проверяйте фильтр на `-d` (дамп скомпилированного BPF) и `-dd`, а перед большим захватом прогоняйте `tcpdump -r known.pcap '<фильтр>'` на тестовом дампе.

## Сравнение снифферов и когда что брать

| Инструмент | Сильные стороны | Слабые стороны |
|---|---|---|
| `tcpdump` | везде есть, минимальный, быстрый | только BPF, без диссекторов |
| `tshark` | диссекторы, display filters, экспорт объектов | тяжелее, зависимость от Wireshark |
| `Wireshark` | GUI, визуализация, follow-stream | не для сервера без X |
| `Zeek` | превращает трафик в логи/события | не для ручного разбора |
| `ngrep` | grep по payload с BPF | узкая ниша |

Практическое правило: **захватывайте tcpdump (лёгкий, точный BPF), разбирайте tshark/Wireshark**. `ngrep -q -W byline 'pass|login' port 80` удобен для быстрого поиска строк в потоке, но не заменяет полноценный разбор.

## Квиз

```quiz
- question: "Зачем нужен флаг -nn в tcpdump?"
  options:
    - "Показать payload в ASCII"
    - "Отключить разрешение имён хостов и портов"
    - "Записать в файл"
    - "Остановиться после N пакетов"
  answer: 1
  explanation: "-nn отключает DNS-резолвинг и резолвинг портов, ускоряя вывод и убирая лишний трафик."
- question: "Какой фильтр покажет только SYN-пакеты?"
  options:
    - "tcpdump port 80"
    - "tcpdump 'tcp[tcpflags] & tcp-syn != 0'"
    - "tcpdump icmp"
    - "tcpdump -A"
  answer: 1
  explanation: "Проверка бита SYN в байтe флагов TCP (tcp[tcpflags] & tcp-syn) отбирает только SYN."
- question: "Что делает ключ -s 0?"
  options:
    - "Захватывает пакет целиком (без обрезки snaplen)"
    - "Сортирует пакеты"
    - "Показывает статистику"
    - "Отключает promiscuous mode"
  answer: 0
  explanation: "snaplen=0 означает «не обрезать»: сохраняется весь пакет вместе с payload."
- question: "Как прочитать ранее сохранённый дамп?"
  options:
    - "tcpdump -i eth0"
    - "tcpdump -w capture.pcap"
    - "tcpdump -r capture.pcap"
    - "tcpdump -D"
  answer: 2
  explanation: "-r читает пакеты из файла вместо интерфейса."
```

## Где пригодится

- **CTF:** быстрый разбор PCAP и фильтрация.
- **IR:** захват трафика на скомпрометированном хосте.
- **Пентест:** перехват и анализ трафика.
- **Отладка:** диагностика сетевых приложений.
- **SOC:** сбор телеметрии и написание BPF-правил.
