---
id: network-tool-tcpdump-wireshark
title: "tcpdump и Wireshark: практический справочник по анализу трафика"
category: network
parent: network-tools
difficulty: easy
order: 3
tags: [network, tcpdump, wireshark, tshark, pcap, filters, reference]
prerequisites: [network-tcpdump, network-wireshark]
useful_for:
  - "CTF: категория Network / PCAP"
  - "Пентест: анализ и перехват трафика"
  - "Работа: SOC, IR, диагностика"
estimated_minutes: 40
summary: "Все ключевые фильтры tcpdump (BPF) и Wireshark (display), follow stream, профили, tshark и готовые рецепты разбора дампа."
---

Захват трафика — навык, который нужен и в CTF (PCAP-задачи), и в пентесте (перехват учёток, анализ протоколов), и в SOC/IR (разбор инцидента). Этот урок — справочник по двум главным инструментам: **tcpdump** (командная строка, сервер без GUI) и **Wireshark/tshark** (GUI-анализ и автоматизация). Здесь таблицы фильтров, готовые команды и рецепты «что делать, когда есть дамп».

## Capture-фильтры vs display-фильтры

Это самое частое место ошибок. Есть **два разных языка фильтров**:

- **Capture-фильтр (BPF)** — задаётся при захвате (`tcpdump '...'`, Wireshark: поле Capture filter, `tshark -f`). Работает на уровне ядра, отбрасывает пакеты **до** записи. Синтаксис — libpcap: `host`, `port`, `tcp`, `and/or/not`.
- **Display-фильтр** — применяется к уже захваченному (`Wireshark: строка сверху`, `tshark -Y`). Богаче: обращается к полям протоколов (`http.request.uri`, `tcp.flags.syn`).

Захватывайте пошире (BPF), фильтруйте при просмотре (display). Если захватить слишком узко — данные потеряны навсегда.

## tcpdump: базовый синтаксис и флаги

```bash
sudo tcpdump [опции] [BPF-выражение]
```

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-i <if>` | Интерфейс (`any` — все) | `tcpdump -i eth0` |
| `-n` | Не резолвить имена хостов | `tcpdump -n` |
| `-nn` | Не резолвить хосты и порты | `tcpdump -nn` |
| `-c <n>` | Остановиться после N пакетов | `tcpdump -c 100` |
| `-w <f>` | Писать pcap в файл | `tcpdump -w cap.pcap` |
| `-r <f>` | Читать из pcap | `tcpdump -r cap.pcap` |
| `-A` | Печатать payload как ASCII | `tcpdump -A -r cap.pcap` |
| `-X` | Печатать hex + ASCII | `tcpdump -X` |
| `-XX` | Hex+ASCII, включая заголовки | `tcpdump -XX` |
| `-s <n>` | Snaplen (0 = весь пакет) | `tcpdump -s 0` |
| `-v/-vv/-vvv` | Подробность | `tcpdump -vvv` |
| `-e` | Печатать MAC-адреса | `tcpdump -e` |
| `-q` | Краткий вывод | `tcpdump -q` |
| `-D` | Список интерфейсов | `tcpdump -D` |
| `-l` | Построчный буфер (для pipe) | `tcpdump -l \| grep` |
| `-U` | Писать сразу (не буферизовать) | `tcpdump -U -w f.pcap` |
| `-p` | Не переводить интерфейс в promisc | `tcpdump -p` |
| `-Z <user>` | Сбросить привилегии до user | `tcpdump -Z nobody` |
| `-C <MB>` | Ротация по размеру | `tcpdump -C 100 -w f` |
| `-G <sec>` | Ротация по времени | `tcpdump -G 3600 -w f%M` |
| `-W <n>` | Число файлов ротации | `tcpdump -C 100 -W 10 -w f` |
| `-B <size>` | Размер буфера захвата (KiB) | `tcpdump -B 4096` |
| `-F <file>` | Взять BPF-выражение из файла | `tcpdump -F filter.txt` |
| `-K` | Не проверять контрольные суммы | `tcpdump -K` |
| `-T <type>` | Форсировать тип пакета | `tcpdump -T rpc` |
| `-t` | Без меток времени | `tcpdump -t` |
| `-tt` | Unix-время | `tcpdump -tt` |
| `-ttt` | Дельта между пакетами | `tcpdump -ttt` |
| `-tttt` | Дата и время | `tcpdump -tttt` |
| `-ttttt` | Дельта от первого пакета | `tcpdump -ttttt` |
| `-#` / `--number` | Печатать номер пакета | `tcpdump -#` |
| `-a` | Резолвить сетевые адреса в имена | `tcpdump -a` |
| `-b` | Печатать AS-номер для BGP | `tcpdump -b` |
| `-E <algo:secret>` | IPsec-секрет для расшифровки | `tcpdump -E aes-cbc:key` |
| `-m <module>` | Загрузить SMI MIB | `tcpdump -m ip` |
| `-M <secret>` | TCP-MD5 secret | `tcpdump -M secret` |
| `-O` | Не оптимизировать фильтр | `tcpdump -O` |
| `-J` | Список типов меток времени | `tcpdump -J` |
| `-L` | Список link-layer типов | `tcpdump -L` |
| `-j <tstamp>` | Тип метки времени | `tcpdump -j adapter_unsynced` |
| `--time-stamp-precision <p>` | Точность меток (`micro`/`nano`) | `tcpdump --time-stamp-precision=nano` |
| `--immediate-mode` | Отдавать пакеты сразу | `tcpdump --immediate-mode` |
| `-V <file>` | Список pcap-файлов для чтения | `tcpdump -V files.txt` |
| `-d` / `-dd` / `-ddd` | Дамп скомпилированного фильтра (as-машина/C/десятичный) | `tcpdump -d 'tcp port 80'` |
| `--version` | Версия tcpdump | `tcpdump --version` |
| `-h` | Краткая справка | `tcpdump -h` |

Базовая команда «увидеть, что происходит»:

```bash
sudo tcpdump -i any -nn -s0
```

## tcpdump: BPF-фильтры подробно

| Фильтр | Значение | Пример |
|--------|----------|--------|
| `host X` | Трафик с/на X | `host 10.0.0.5` |
| `src host X` / `dst host X` | Только от/к X | `src host 10.0.0.5` |
| `net X` | Сеть | `net 10.0.0.0/24` |
| `port N` | Порт (tcp или udp) | `port 443` |
| `portrange A-B` | Диапазон портов | `portrange 1-1024` |
| `tcp` / `udp` / `icmp` / `arp` / `ip6` | Протокол | `tcp` |
| `tcp port N` | TCP-порт | `tcp port 80` |
| `src port N` / `dst port N` | Направление порта | `dst port 53` |
| `and` / `or` / `not` | Логика | `host A and port 80` |
| `( ... )` | Группировка | `(port 80 or port 443)` |
| `ether host <mac>` | По MAC | `ether host aa:bb:cc:dd:ee:ff` |
| `vlan <id>` | VLAN | `vlan 10` |
| `greater N` / `less N` | Размер пакета | `greater 1000` |
| `broadcast` / `multicast` | Широковещание | `broadcast` |
| `tcp[tcpflags] & tcp-syn != 0` | SYN-пакеты | см. пример |
| `tcp[tcpflags] & (tcp-syn\|tcp-fin) != 0` | SYN или FIN | см. пример |
| `src net X` / `dst net X` | Сеть-источник / назначение | `src net 10.0.0.0/24` |
| `net X mask Y` | Сеть с явной маской | `net 10.0.0.0 mask 255.255.255.0` |
| `ether src/dst <mac>` | MAC-источник / назначение | `ether src aa:bb:cc:dd:ee:ff` |
| `ip proto N` | IP-протокол по номеру | `ip proto 47` |
| `ip6 proto N` | IPv6-протокол по номеру | `ip6 proto 58` |
| `icmp6` | ICMPv6 | `icmp6` |
| `ip broadcast` / `ip multicast` | IP broadcast / multicast | `ip multicast` |
| `ether broadcast` / `ether multicast` | Ethernet broadcast / multicast | `ether broadcast` |
| `len <op> N` | Длина пакета | `len > 1000` |
| `greater N` / `less N` | Длиннее / короче N | `greater 1000` |
| `mpls` | MPLS-пакеты | `mpls` |
| `pppoes` | PPPoE session | `pppoes` |
| `wlan` / `radio` | Wi-Fi-кадры | `wlan` |
| `llc` / `stp` | LLC / STP | `stp` |
| `ifindex N` | По индексу интерфейса | `ifindex 2` |
| `gateway X` | Через шлюз (MAC+IP) | `gateway 10.0.0.1` |
| `ip[0] & 0xf != 5` | Пакеты с IP-опциями | `ip[0] & 0xf != 5` |
| `ip[6:2] & 0x1fff != 0` | IP-фрагменты | `ip[6:2] & 0x1fff != 0` |
| `tcp[tcpflags] & tcp-rst != 0` | RST-пакеты | `tcp[tcpflags] & tcp-rst != 0` |
| `tcp[tcpflags] & tcp-push != 0` | PSH-пакеты | `tcp[tcpflags] & tcp-push != 0` |
| `udp[8:2] = N` | Байты по смещению в UDP | `udp[8:2] = 0x1234` |
| `ip[2:2] > N` | Общая длина IP-пакета | `ip[2:2] > 1000` |

```bash
# только SYN-пакеты (новые соединения)
sudo tcpdump -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# HTTP-трафик между двумя хостами
sudo tcpdump -nn -A 'host 10.0.0.5 and host 10.0.0.9 and port 80'

# DNS-запросы
sudo tcpdump -nn 'udp port 53'

# ICMP (ping, traceroute)
sudo tcpdump -nn 'icmp'

# ARP (кто где)
sudo tcpdump -nn -e 'arp'
```

## tcpdump: практические рецепты

**Захватить трафик хоста в файл и потом разобрать:**

```bash
sudo tcpdump -i any -nn -s0 host 10.0.0.5 -w host.pcap
sudo tcpdump -nn -r host.pcap 'tcp port 80' -A
```

**Поймать учётные данные в открытом виде (HTTP/FTP/POP3):**

```bash
sudo tcpdump -i any -nn -s0 -A 'tcp port 80 or tcp port 21 or tcp port 110' -w creds.pcap
grep -a -i -E 'user|pass|login|authorization' <(tcpdump -nn -r creds.pcap -A)
```

**TLS-хендшейк (видно SNI и версию):**

```bash
sudo tcpdump -nn -s0 'tcp port 443' -w tls.pcap
tshark -r tls.pcap -Y 'tls.handshake.extensions_server_name'
```

**Поймать трафик, пока не увидишь нужное, потом остановиться:**

```bash
sudo tcpdump -i any -nn -A -c 50 'tcp port 80'
```

**Ротация логов захвата:**

```bash
sudo tcpdump -i any -s0 -G 3600 -W 24 -w /var/cap/cap-%Y%m%d-%H.pcap
```

## Wireshark: display-фильтры подробно

Открываем дамп и фильтруем в строке Display Filter:

| Фильтр | Что показывает |
|--------|----------------|
| `ip.addr == 10.0.0.5` | Пакеты с/на хост |
| `ip.src == 10.0.0.5` / `ip.dst == ...` | Направление |
| `tcp.port == 80` / `udp.port == 53` | По порту |
| `http` | Весь HTTP |
| `http.request` / `http.response` | Только запросы/ответы |
| `http.request.method == "POST"` | POST-запросы |
| `http.host == "example.com"` | По Host |
| `http.request.uri contains "admin"` | По пути |
| `http.response.code >= 400` | Ошибки |
| `dns` | DNS |
| `dns.qry.name contains "evil"` | По имени запроса |
| `tls.handshake` | TLS-handshake |
| `tls.handshake.extensions_server_name` | SNI |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN (новые соединения) |
| `tcp.flags.reset == 1` | RST |
| `tcp.analysis.retransmission` | Ретрансмиссии |
| `tcp.analysis.flags` | Проблемы TCP |
| `tcp.stream eq 5` | Конкретный поток |
| `frame contains "password"` | Поиск строки в пакете |
| `icmp.type == 8` | Echo-request (ping) |
| `arp` | ARP |
| `eth.addr == aa:bb:cc:dd:ee:ff` | По MAC |
| `ip.ttl < 5` | Малый TTL |
| `smb2` / `smb` | SMB |
| `ftp` / `ftp-data` | FTP-команды / данные |
| `smtp` / `pop` / `imap` | Почтовые протоколы |
| `ssh` | SSH (без расшифровки — только транспорт) |
| `kerberos` | Kerberos |
| `ntlmssp` | NTLMSSP (в HTTP/SMB) |
| `ldap` / `snmp` | LDAP / SNMP |
| `http2` / `quic` | HTTP/2 и QUIC |
| `http.cookie` | HTTP-Cookie |
| `http.authorization` | Заголовок Authorization |
| `http.response.code == 302` | Редиректы |
| `tcp.len > 0` | Пакеты с данными |
| `tcp.analysis.zero_window` | Нулевое окно (перегрузка) |
| `tcp.analysis.duplicate_ack` | Дубликаты ACK |
| `tcp.analysis.ack_rtt > 0.1` | Большой RTT |
| `tls.record.version` | Версия TLS-записи |
| `dns.flags.rcode != 0` | DNS-ответы с ошибкой |
| `icmpv6` | ICMPv6 |
| `usb` | USB-трафик |
| `frame.time >= "2025-01-01 00:00:00"` | По времени |

Операторы: `==`, `!=`, `>`, `<`, `contains`, `matches` (регулярка), `&&`/`and`, `||`/`or`, `!`/`not`.

```text
http.request && ip.addr == 10.0.0.5
tcp.port == 445 && tcp.flags.syn == 1
frame contains "flag{"
dns.qry.name matches ".*\\.ru$"
```

## Follow stream и реконструкция сессий

Правый клик по пакету → **Follow → TCP/UDP/HTTP Stream** — Wireshark соберёт всю беседу по потоку. Это главный приём для чтения переписки: HTTP-запросы, SMTP-диалоги, чаты.

В tshark то же самое:

```bash
tshark -r cap.pcap -q -z follow,tcp,ascii,0        # поток №0
tshark -r cap.pcap -q -z follow,http,ascii,0
```

Экспорт объектов (файлы, картинки) прямо из дампа:

```bash
tshark -r cap.pcap --export-objects http,./out_http
tshark -r cap.pcap --export-objects smb,./out_smb
```

## Статистика, эксперты и цветовые правила

Wireshark: меню **Statistics** → Conversations (кто с кем говорил), Protocol Hierarchy (доля протоколов), Endpoints, IO Graph. **Analyze → Expert Information** подсветит ретрансмиссии, дубликаты, нулевые окна — признаки проблем и атак.

Через tshark:

```bash
tshark -r cap.pcap -q -z conv,tcp            # разговоры TCP
tshark -r cap.pcap -q -z io,phs              # иерархия протоколов
tshark -r cap.pcap -q -z endpoints,ip
tshark -r cap.pcap -q -z expert
```

Цветовые правила (View → Coloring Rules) помогают мгновенно видеть аномалии: RST, ретрансмиссии, HTTP-ошибки. Полезный приём — создать правило для `tcp.analysis.flags` и красить проблемы в красный.

## tshark: командная строка и автоматизация

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-r <f>` | Читать дамп | `tshark -r cap.pcap` |
| `-i <if>` | Захват с интерфейса | `tshark -i eth0` |
| `-f <bpf>` | Capture-фильтр | `-f "tcp port 80"` |
| `-Y <disp>` | Display-фильтр | `-Y "http.request"` |
| `-c <n>` | Ограничить число пакетов | `-c 100` |
| `-T fields -e <f>` | Печатать поля | `-T fields -e ip.src -e http.host` |
| `-T json` | JSON-вывод | `-T json` |
| `-q` | Меньше служебного | `-q -z conv,tcp` |
| `-z <stat>` | Статистика | `-z io,phs` |
| `-x` | Hex+ASCII | `-x` |
| `-w <f>` | Писать pcap | `-w out.pcap` |
| `-Y` + `-T fields` | Извлечь таблицу | см. пример |

```bash
# все Host из HTTP-запросов
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host | sort -u

# все SNI (домены) из TLS
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e tls.handshake.extensions_server_name | sort -u

# все DNS-запросы
tshark -r cap.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u

# HTTP-ответы 4xx/5xx
tshark -r cap.pcap -Y 'http.response.code >= 400' -T fields -e http.response.code -e http.request.uri
```

## Полезные профили и настройки

- **Профили** (Edit → Configuration Profiles): под CTF, под веб, под SMB — разные наборы колонок и фильтров.
- **Колонки**: добавьте `tcp.stream`, `http.host`, `tls.handshake.extensions_server_name` как отдельные колонки — сразу видно контекст.
- **Настройки протоколов**: Preferences → Protocols → TLS, чтобы подставить ключи (RSA key log) и расшифровать HTTPS.
- **Decode As**: если протокол на нестандартном порту — Analyze → Decode As (например, HTTP на 8080).
- **Разрешить небезопасный TLS-ключ**: задайте `(Pre)-Master-Secret log filename`, экспортировав `SSLKEYLOGFILE` из браузера, — и увидите расшифрованный HTTPS.

## Практические рецепты (PCAP из CTF и инцидента)

**Чек-лист разбора незнакомого дампа:**

```bash
tshark -r challenge.pcap -q -z io,phs                 # 1) какие протоколы
tshark -r challenge.pcap -q -z conv,tcp               # 2) кто с кем говорил
tshark -r challenge.pcap -Y 'http' -T fields -e http.host -e http.request.uri | sort -u
tshark -r challenge.pcap --export-objects http,./files # 3) вытащить файлы
strings challenge.pcap | grep -i -E 'flag|pass|user'   # 4) быстрый grep
```

**Поиск флага/пароля прямо в дампе:**

```bash
strings cap.pcap | grep -i -E 'flag\{|password|token'
tshark -r cap.pcap -Y 'frame contains "flag{"' -T fields -e frame.number
```

**Восстановление переданного файла (например, по FTP):**

```bash
tshark -r cap.pcap -q -z follow,tcp,raw,0 | xxd -r -p > recovered.bin
file recovered.bin
```

**Изоляция трафика одного хоста из большого дампа:**

```bash
tshark -r big.pcap -Y 'ip.addr == 10.0.0.5' -w host_only.pcap
```

## Частые ошибки

- **Путать capture- и display-фильтры.** `http.request` не сработает как capture-фильтр (это поле протокола, не BPF). Для захвата — `tcp port 80`.
- **Забыть `-s 0`.** По умолчанию snaplen ограничен — payload обрежется. Для анализа содержимого всегда `-s 0`.
- **Захватывать слишком узко.** Поймали не тот порт — данные потеряны. Лучше записать шире и отфильтровать потом.
- **Читать большой дамп в GUI без фильтра.** Wireshark задумается. Сначала `tshark -Y`/`-z` для сужения.
- **Забыть про права.** tcpdump нужен root (или capabilities `CAP_NET_RAW`). `-Z` понижает привилегии после старта.

## Квиз

```quiz
- question: "Какое выражение является корректным CAPTURE-фильтром для tcpdump?"
  options:
    - "tcp port 80 and host 10.0.0.5"
    - "http.request.uri contains admin"
    - "tcp.flags.syn == 1"
    - "ip.addr == 10.0.0.5 && tcp.port == 80"
  answer: 0
  explanation: "tcpdump понимает только BPF: host/port/proto. Остальные варианты — display-фильтры Wireshark."
- question: "Какой флаг tcpdump печатает payload в виде ASCII?"
  options:
    - "-A"
    - "-X"
    - "-e"
    - "-q"
  answer: 0
  explanation: "-A выводит содержимое пакета как ASCII; -X — hex+ASCII."
- question: "Каким display-фильтром в Wireshark найти только SYN-пакеты?"
  options:
    - "tcp.flags.syn == 1 && tcp.flags.ack == 0"
    - "tcp port 80"
    - "http.request"
    - "ip.proto == 6"
  answer: 0
  explanation: "SYN без ACK — начало соединения: tcp.flags.syn==1 и tcp.flags.ack==0."
- question: "Что делает команда tshark --export-objects http,./out?"
  options:
    - "Извлекает переданные по HTTP файлы в каталог ./out"
    - "Сохраняет все пакеты в ./out"
    - "Печатает только HTTP-заголовки"
    - "Расшифровывает HTTPS"
  answer: 0
  explanation: "--export-objects выгружает объекты протокола (файлы) в указанный каталог."
- question: "Зачем в tcpdump указывают -s 0?"
  options:
    - "Захватить пакет целиком, без обрезки snaplen"
    - "Отключить захват"
    - "Писать в файл"
    - "Сбросить привилегии"
  answer: 0
  explanation: "-s 0 задаёт snaplen 0 = весь пакет, иначе payload может обрезаться."
```

## Где пригодится

- **CTF:** Network/PCAP — извлечь файлы, найти флаг, расшифровать сессию.
- **Пентест:** перехват учётных данных в открытых протоколах, анализ протокола сервиса.
- **Работа (SOC/IR):** разбор трафика инцидента, реконструкция атаки, извлечение артефактов.
- **Диагностика:** найти ретрансмиссии, потери, проблему TLS-хендшейка.
