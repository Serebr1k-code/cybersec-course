---
id: network-wireshark
title: "Wireshark и tshark: display-фильтры, follow stream и статистика"
category: network
parent: network-tcpdump
difficulty: easy
order: 1
tags: [network, wireshark, tshark, filters, analysis]
prerequisites: [network-tcpdump]
useful_for:
  - "Анализ PCAP в CTF"
  - "Разбор протоколов и сессий"
  - "Поиск аномалий в трафике"
estimated_minutes: 50
summary: "Работа в Wireshark: разница capture/display-фильтров, follow stream, цветовые правила, статистика и tshark для автоматизации."
---

Wireshark — главный инструмент анализа трафика. Он открывает `.pcap`/`.pcapng`, разбирает сотни протоколов и позволяет фильтровать как при захвате, так и при отображении. `tshark` — его консольный близнец, незаменимый для скриптов.

## Capture-фильтры против Display-фильтров

Это главная путаница новичков. Это **два разных синтаксиса**:

| | Capture filter | Display filter |
|---|---|---|
| Синтаксис | BPF (`tcp port 80`) | Wireshark (`tcp.port == 80`) |
| Когда работает | во время захвата | после захвата, на отображение |
| Можно менять | только до старта | в любой момент |
| Возможности | ограниченные | очень богатые |

Capture-фильтр пишется в поле на экране захвата. Display-фильтр — в верхней строке: `http`, `dns`, `ip.addr == 10.0.0.5`, `tcp.port == 443 && tls.handshake.type == 1`.

Основные операторы display-фильтра: `==`, `!=`, `contains`, `matches` (regex), `&&`, `||`, `!`.

## Ключевые display-фильтры

```
http                                  # весь HTTP
http.request.method == "POST"         # только POST
dns.qry.name contains "flag"          # DNS-запросы со словом flag
tcp.flags.syn == 1 && tcp.flags.ack == 0   # только SYN
tls.handshake.type == 2               # TLS ServerHello
ftp || telnet || pop                  # незашифрованные протоколы
ip.addr == 192.168.1.10 && frame contains "password"
frame.len > 1000                      # крупные кадры
tcp.stream eq 3                       # конкретный поток
```

`frame contains "..."` — один из самых полезных: ищет подстроку в сырых байтах кадра.

## Follow Stream

Правый клик по пакету → **Follow → TCP/UDP/HTTP Stream**. Wireshark собирает всю сессию в читаемый вид. Это стандартный способ:

- прочитать переписку по HTTP (в т.ч. заголовки авторизации);
- восстановить переданный по TCP файл;
- увидеть диалог кастомного протокола.

Соответствующий display-фильтр потока: `tcp.stream eq N`. Номер потока виден в дереве разбора.

## Статистика и Expert Information

Меню **Statistics** даёт быстрый обзор:

- **Conversations** — кто с кем и сколько трафика (быстро находит «интересный» хост).
- **Protocol Hierarchy** — какие протоколы присутствуют (замечаешь необычные).
- **Endpoints** — список адресов.
- **HTTP → Requests** — все HTTP-запросы списком (экспорт в CSV).
- **Analyze → Expert Information** — автоматические предупреждения об аномалиях (retransmission, malformed).

## Профили и цветовые правила

Для повторяющихся задач настройте окружение:

- **Profiles** (Edit → Configuration Profiles) — разные наборы колонок и фильтров для разных типов дампов (web, ICS, wireless).
- **Coloring Rules** — подсветка по фильтру (например, красным — `tcp.analysis.flags` для проблем).
- **Custom columns** — добавьте `tcp.stream`, `http.host`, `tls.handshake.extensions_server_name` в колонки для быстрого обзора.
- **Decode As** — если протокол определён неверно, принудительно задайте разбор (Analyze → Decode As).

## Извлечение файлов и объектов

```bash
# все файлы из HTTP
tshark -r cap.pcap --export-objects http,./out
# объекты SMB/TFTP/IMF
tshark -r cap.pcap --export-objects smb,./out
```

`--export-objects` — «магический» приём: вытаскивает переданные файлы в каталог. В GUI — **File → Export Objects → HTTP**. Дополнительно: `File → Export Specified Packets` для вырезания подмножества, `File → Export Packet Dissections` для текста.

## tshark: автоматизация

```bash
# список HTTP-запросов
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri

# извлечь DNS-запросы
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name

# все пароли, переданные по незашифрованным протоколам
tshark -r cap.pcap -Y 'ftp.request.command=="PASS" || http.authorization' \
  -T fields -e ftp.request.arg -e http.authorization

# экспорт объектов HTTP (файлов)
tshark -r cap.pcap --export-objects http,./out
```

`-T fields -e <поле>` — сердце автоматизации: вы получаете машиночитаемый вывод, который легко фильтровать `sort`/`uniq`/`grep`.

## tshark для больших дампов

Большие PCAP не открыть в GUI — используйте потоковую обработку:

```bash
# топ-адреса по числу пакетов
tshark -r big.pcap -q -z conv,ip | head -20
# топ-портов
tshark -r big.pcap -q -z io,phs | head
# фильтровать и писать подмножество
tshark -r big.pcap -Y 'http.request' -w http_only.pcap
```

`-z` даёт готовую статистику без выгрузки всех пакетов; `-w` — запись отфильтрованного подмножества для дальнейшего разбора в GUI.

## Полезные фильтры по протоколам

| Задача | Display-фильтр |
|---|---|
| HTTP-логины | `http.request.method=="POST" && frame contains "password"` |
| DNS-туннель | `dns && frame.len > 200` |
| NTLM-аутентификация | `ntlmssp` |
| Kerberos | `kerberos` |
| Подозрительные TLS SNI | `tls.handshake.extensions_server_name` |
| FTP-пароли | `ftp.request.command=="PASS"` |
| ARP-спуфинг | `arp.duplicate-address-detected` |

## Разбор кейса CTF

Задача: найти флаг в дампе.

1. `Statistics → Protocol Hierarchy` — какие протоколы есть.
2. `frame contains "flag"` — прямой поиск.
3. `Statistics → Conversations` — найти «интересный» хост/порт.
4. `Follow → TCP Stream` по этому потоку — прочитать диалог.
5. `File → Export Objects → HTTP` — вытащить файлы.
6. Для кастомного протокола — выгрузить payload и разбирать структуру (см. `network-protocol-reversing`).

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| tshark | `-r f -Y '<df>' -T fields -e <field>` | фильтр + поля |
| tshark | `--export-objects http,./out` | извлечь файлы |
| tshark | `-q -z conv,ip` | статистика разговоров |
| tshark | `-w out.pcap` | записать подмножество |
| Wireshark GUI | Follow Stream / Export Objects | ручной разбор |
| `editcap` | `-r a-b` | вырезать диапазон пакетов |

## Частые ошибки

- **Путать capture- и display-фильтры.** `tcp.port==80` — синтаксис display (Wireshark). В `tshark -f` (BPF) нужен `tcp port 80`, иначе фильтр не применится.
- **Скроллить пакеты вручную вместо Follow Stream.** Диалог удобнее собрать через `Follow → TCP/HTTP Stream` — там же видны запросы и ответы целиком.
- **Забыть про Export Objects.** Файл из HTTP удобнее достать через `File → Export Objects → HTTP`, а не собирать вручную из отдельных пакетов.
- **Открывать гигабайтные PCAP в GUI.** Используйте `tshark -z`/`editcap`.

## Что делать дальше / решение

- **Нужен обзор** → Statistics (Hierarchy/Conversations).
- **Нужен диалог** → Follow Stream.
- **Нужны файлы** → Export Objects.
- **Нужна автоматизация** → `tshark -T fields`.
- **Нужен кастомный протокол** → `network-protocol-reversing`.

## Быстрая шпаргалка

```bash
# фильтр + поля (автоматизация)
tshark -r cap.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
# поиск подстроки в сырых байтах
tshark -r cap.pcap -Y 'frame contains "flag"' -T fields -e frame.number
# извлечь файлы
tshark -r cap.pcap --export-objects http,./out
# статистика
tshark -r cap.pcap -q -z conv,ip | head
```

## Разбор кейса: DNS-туннель

Частая CTF-задача — эксфильтрация через DNS. Признаки: длинные поддомены, много запросов к одному домену, редкие типы записей (TXT).

```bash
# все запросы к подозрительному домену
tshark -r cap.pcap -Y 'dns.qry.name contains "evil.example"' -T fields -e dns.qry.name
# крупные DNS-ответы (данные в TXT)
tshark -r cap.pcap -Y 'dns && frame.len > 200' -T fields -e dns.qry.name -e dns.txt
```

Собрав поддомены в порядке времени, часто получаешь base32/base64-строку — декодируй и получишь флаг. Так один display-фильтр превращает шумный дамп в понятную эксфильтрацию.

## Квиз

```quiz
- question: "Чем display-фильтр отличается от capture-фильтра?"
  options:
    - "Они идентичны"
    - "Display-фильтр применяется после захвата и использует синтаксис Wireshark; capture-фильтр — BPF во время захвата"
    - "Capture-фильтр работает только для UDP"
    - "Display-фильтр замедляет сеть"
  answer: 1
  explanation: "Capture-фильтр (BPF) отбирает пакеты при записи; display-фильтр скрывает ненужное при просмотре."
- question: "Какой фильтр найдёт подстроку 'password' в сырых байтах кадров?"
  options:
    - "tcp contains password"
    - 'frame contains "password"'
    - "http == password"
    - "ip.addr == password"
  answer: 1
  explanation: "frame contains ищет байтовую подстроку в любом месте кадра."
- question: "Что делает tshark --export-objects http,./out?"
  options:
    - "Экспортирует HTTP-заголовки в CSV"
    - "Извлекает переданные по HTTP файлы в каталог ./out"
    - "Удаляет HTTP-трафик"
    - "Строит график"
  answer: 1
  explanation: "export-objects восстанавливает файлы, переданные по протоколу, на диск."
- question: "Какая функция собирает всю TCP-сессию в читаемый вид?"
  options:
    - "Expert Information"
    - "Protocol Hierarchy"
    - "Follow → TCP Stream"
    - "Capture Options"
  answer: 2
  explanation: "Follow Stream собирает все пакеты одного потока в единый диалог."
- question: "Какой раздел Statistics помогает понять, какие протоколы есть в дампе?"
  options:
    - "Protocol Hierarchy"
    - "Follow Stream"
    - "Display Filter"
    - "Coloring Rules"
  answer: 0
  explanation: "Protocol Hierarchy показывает распределение протоколов в дампе."
```

## Где пригодится

- Ежедневный инструмент анализа любых PCAP — от CTF до реальных инцидентов.
- `tshark` встраивается в скрипты обработки больших дампов.
