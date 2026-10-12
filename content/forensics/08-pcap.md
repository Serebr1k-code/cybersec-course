---
id: forensics-pcap
title: "Введение в анализ PCAP: сетевой дамп"
category: forensics
parent: forensics-img-captures
difficulty: medium
order: 1
tags: [pcap, tshark, wireshark, http, network-forensics]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Network forensics / IR"
  - "Анализ инцидентов"
estimated_minutes: 40
summary: "Как открыть и прочитать сетевой дамп: фильтры tshark, реконструкция HTTP-сессии, извлечение объектов."
---

## Вопрос, с которого всё начинается

Пока мы копались в файлах и дисках, мимо шёл трафик. Иногда его успели записать —
и тогда у нас на руках **PCAP** (packet capture): файл, в котором лежат все сетевые
пакеты за промежуток времени. Там могут быть пароли, загруженные файлы, целые сессии.

Задача: дан `capture.pcap` с подозрительной активностью. Найти, куда ходил клиент,
с какими данными, и вытащить то, что передавалось. В этом уроке пройдём это шаг за
шагом.

Начнём с общего принципа: в сетевом дампе мы всегда идём от «кто с кем говорил»
к «что именно передали». Сначала протоколы, потом потоки, потом конкретные поля и
файлы. Такой порядок не даёт утонуть в тысячах пакетов.

## Наш пример: capture.pcap

```bash
$ file capture.pcap
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4
(Ethernet, capture length 65535)
```

Классический дамп, записанный `tcpdump` или Wireshark. Открывать графический
Wireshark необязательно — для разбора и автоматизации удобнее консольный `tshark`.

## Первый взгляд: что вообще внутри

Прежде чем искать иголку, посмотрим на стог. Протокольная статистика:

```bash
$ tshark -r capture.pcap -q -z io,phs
Protocol Hierarchy Statistics
frame                                    frames:10 bytes:774
  eth                                    frames:10 bytes:774
    ip                                   frames:10 bytes:774
      tcp                                frames:10 bytes:774
        http                             frames:2 bytes:342
          data-text-lines                frames:1 bytes:160
```

`-r` — читать файл, `-q` — не печатать каждый пакет, `-z io,phs` — показать
**иерархию протоколов**. Видно: десять пакетов, внутри TCP и HTTP. Никакого TLS —
значит, содержимое не зашифровано и читается напрямую.

## Фильтруем нужное

Смотреть все пакеты подряд бессмысленно — нужны **фильтры отображения**. Найдём
HTTP-запросы:

```bash
$ tshark -r capture.pcap -Y http.request
    4   0.030000  10.10.10.50 → 10.10.10.80  HTTP 182 GET /admin/secret.txt HTTP/1.1
```

`-Y` — фильтр (например `http.request`), в отличие от `-f` (фильтр захвата, работает
по BPF). Видим: клиент `10.10.10.50` обратился к `10.10.10.80` по адресу
`/admin/secret.txt`. Достанем сразу конкретные поля:

```bash
$ tshark -r capture.pcap -T fields -e http.request.method -e http.host \
  -e http.request.uri -e http.authorization -Y http.request
GET	files.local	/admin/secret.txt	Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=
```

`-T fields` печатает только выбранные поля — идеально для скриптов и `grep`. Здесь
нас интересует `Authorization: Basic ...` — заголовок с логином и паролем.

## Реконструируем сессию целиком

Пакеты в дампе — это отдельные куски разговора. Собрать их обратно в текст можно
командой `follow`:

```bash
$ tshark -r capture.pcap -q -z follow,tcp,ascii,0
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 0
Node 0: 10.10.10.50:49152
Node 1: 10.10.10.80:80
128
GET /admin/secret.txt HTTP/1.1
Host: files.local
Authorization: Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=
User-Agent: curl/8.5.0

	106
HTTP/1.1 200 OK
Server: nginx/1.24.0
Content-Type: text/plain
Content-Length: 19

CTF{pl41nt3xt_h77p}
===================================================================
```

Вот и весь разговор: запрос, заголовки, ответ сервера и тело. Номер в конце
`follow,...,0` — это **номер TCP-потока** (`tcp.stream`); нулевой — первый поток
в дампе. Числа `128` и `106` — длины сторон.

## Расшифровываем Basic-авторизацию

HTTP Basic передаёт логин и пароль в **base64** — это не шифрование, а просто
кодирование, любой может декодировать:

```bash
$ echo 'YWRtaW46U3VwZXJTZWNyZXQxMjM=' | base64 -d
admin:SuperSecret123
```

Формат — `логин:пароль`. Мы добыли учётные данные прямо из трафика. Именно поэтому
HTTP без TLS опасен: всё видно.

## Вытаскиваем файлы из дампа

Если по сети передавали файл, `tshark` умеет «экспортировать объекты»:

```bash
$ tshark -r capture.pcap --export-objects http,out/ -q
$ ls -la out/
-rw-r--r-- 1 user user 19 secret.txt
$ cat out/secret.txt
CTF{pl41nt3xt_h77p}
```

`--export-objects http,out/` собрал все HTTP-ответы в файлы в каталоге `out/`. Так же
работает для `smb`, `tftp`, `imf` (почта). Если бы это был TLS — объекты не собрались
бы без ключей (об этом в уроке про расшифровку TLS).

## Полезные фильтры

| Задача | Фильтр `-Y` |
|--------|-------------|
| Только HTTP-запросы | `http.request` |
| Логины/пароли Basic | `http.authorization` |
| DNS-запросы | `dns.qry.name` |
| Пакеты по IP | `ip.addr == 10.10.10.80` |
| Конкретный поток | `tcp.stream eq 0` |
| POST-данные | `http.request.method == "POST"` |
| Скачанные файлы | `http.response` + `--export-objects` |

## Как посмотреть один пакет целиком

Иногда нужно разобрать конкретный пакет по полям. Флаг `-V` («verbose») показывает
весь разбор кадра:

```bash
$ tshark -r capture.pcap -Y http.request -V | head -25
Frame 4: 182 bytes on wire
Ethernet II, Src: ..., Dst: ...
Internet Protocol Version 4, Src: 10.10.10.50, Dst: 10.10.10.80
Transmission Control Protocol, Src Port: 49152, Dst Port: 80
Hypertext Transfer Protocol
    GET /admin/secret.txt HTTP/1.1\r\n
    Host: files.local\r\n
    Authorization: Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=\r\n
```

Здесь видно весь путь данных сверху вниз: кадр → IP → TCP → HTTP. Такой разбор
помогает, когда «обычные» поля не отвечают на вопрос.

## Если трафик большой

На больших дампах смотреть всё подряд нельзя. Приёмы:

- **Фильтруй как можно раньше.** `-Y` применяется после чтения, но при огромных
  файлах сначала сузь по BPF: `-f "tcp port 80"`.
- **Выгружай поля, а не пакеты.** `-T fields -e ...` даёт таблицу, которую легко
  разобрать `sort`/`uniq`:

```bash
$ tshark -r big.pcap -T fields -e http.host -Y http.request | sort | uniq -c | sort -rn
     84 files.local
     12 updates.example.com
```

- **Ищи строки напрямую.** Если протокол нестандартный, работает старый добрый `grep`:

```bash
$ strings capture.pcap | grep -iE 'flag|passw|user='
```

## Работаем с трафиком, который не HTTP

Не всё в дампах — HTTP. Быстрые зацепки для других протоколов:

- **DNS** — куда резолвились имена (часто выдаёт домены C2):

```bash
$ tshark -r capture.pcap -T fields -e dns.qry.name -Y dns 2>/dev/null | sort -u
files.local
update.evil.example
```

- **TLS** — видно только имя сервера (SNI) и размеры, но не содержимое; для
  расшифровки нужен ключ (см. урок про TLS).
- **Нестандартные порты** — данные могут идти «сырым» TCP; собирай поток через
  `follow,tcp,ascii,N` и читай глазами.
- **Файлы по SMB/TFTP** — `--export-objects smb,out/` или `tftp,out/`.

Общее правило: если содержимое не читается, сначала определи протокол (`-z io,phs`),
потом реши, чем его разбирать.

## Что мы теперь знаем

- PCAP — запись сетевых пакетов; читается консольно через `tshark`.
- `-z io,phs` даёт общую картину протоколов, `-Y` — точечный фильтр.
- `follow,tcp,ascii,N` собирает поток обратно в читаемый диалог.
- Basic-авторизация — просто base64, декодируется одной командой.
- `--export-objects` вытаскивает переданные по HTTP/SMB файлы.

## Квиз

```quiz
- question: "Чем фильтр `-Y` отличается от `-f` в tshark?"
  options:
    - "ничем"
    - "`-Y` — фильтр отображения, `-f` — фильтр захвата (BPF)"
    - "`-Y` быстрее"
    - "`-f` показывает только HTTP"
  answer: 1
- question: "Что делает `-z follow,tcp,ascii,0`?"
  options:
    - "считает пакеты"
    - "собирает TCP-поток 0 в читаемый текст"
    - "экспортирует файлы"
    - "фильтрует по IP"
  answer: 1
- question: "Заголовок `Authorization: Basic ...` — это…"
  options:
    - "зашифрованные логин и пароль"
    - "логин и пароль в base64 (не шифрование)"
    - "токен сессии"
    - "хеш пароля"
  answer: 1
- question: "Как вытащить переданные по HTTP файлы из дампа?"
  options:
    - "tshark --export-objects http,out/"
    - "file capture.pcap"
    - "unzip capture.pcap"
    - "strings capture.pcap"
  answer: 0
- question: "Почему в нашем дампе всё читается без ключей?"
  options:
    - "использован слабый пароль"
    - "трафик по HTTP, без TLS-шифрования"
    - "файл не защищён паролем"
    - "так работает pcap"
  answer: 1
```

## Куда дальше

Мы разобрали сеть. Следующий источник — **память**: дамп RAM содержит то, чего уже
нет на диске, — запущенные процессы, открытые соединения и даже ключи шифрования
в открытом виде. В следующем уроке возьмём `memory.raw` и разберём его через
Volatility. А пока запомни: **`tshark -Y` фильтрует, `follow` собирает поток,
`--export-objects` достаёт файлы**.

## Где пригодится

- **CTF:** задачи с дампами трафика и извлечением файлов.
- **Network forensics:** восстановление сессий и эксфильтрации.
- **Incident Response:** определение C2-каналов и утечек.
- **SOC / Threat Hunting:** разбор подозрительной сетевой активности.
- **Пентест:** анализ перехваченного трафика для поиска учётных данных.
