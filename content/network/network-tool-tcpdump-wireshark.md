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
lab:
  kind: shell
  title: "Практика: tcpdump и tshark на одном дампе"
  toolset: [core, tcpdump, tshark]
  workdir: /home/student/task
  files: [task.md, capture.pcap]
  check: "grep -q 'portal.corp.local' answer.txt"
  hints:
    - "HTTP-трафик идёт по порту 80. Сначала выдели его: `tcpdump -r capture.pcap -nn port 80`."
    - "tshark умеет вынимать конкретное поле: `tshark -r capture.pcap -Y http.request -T fields -e http.host`."
    - "Нужное значение — имя хоста вида `*.corp.local`."
---
## Вопрос, с которого всё начинается

Ты уже умеешь открывать дамп и фильтровать пакеты. Но фильтры у двух главных инструментов анализа трафика — tcpdump и Wireshark — пишутся **по-разному**, и это путает больше всего. Этот урок — справочник: одна задача, два инструмента, и таблицы фильтров в конце, чтобы не искать их каждый раз.

## Наш пример: разобрать один дамп двумя инструментами

У нас есть `http.pcap`, где клиент скачал файл и залогинился. Задача: увидеть только HTTP-трафик и вытащить файл.

В Wireshark/tshark это делается **display-фильтром** (`-Y`):

```
$ tshark -r http.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
files.example.com	/secret.zip
```

Фильтр `http.request` — синтаксис Wireshark: имена полей через точку. А tcpdump использует **BPF** — другой язык, ближе к «сетевым» понятиям (`host`, `port`, `net`):

```
$ tcpdump -r http.pcap -n 'tcp port 80'
14:22:31.412 IP 10.0.0.5.51234 > 93.184.216.34.80: Flags [P.], length 74
```

Запомни главное: **это два разных синтаксиса, и они не взаимозаменяемы**. `tcp.port==80` — Wireshark, `tcp port 80` — tcpdump/BPF.

## Справочник tcpdump: захват и чтение

| Команда | Значение |
|---------|----------|
| `tcpdump -i eth0` | слушать интерфейс |
| `tcpdump -D` | список интерфейсов |
| `tcpdump -n` | не разрешать имена |
| `tcpdump -w cap.pcap` | записать в файл |
| `tcpdump -r cap.pcap` | читать из файла |
| `tcpdump -c 100` | остановиться после 100 пакетов |
| `tcpdump -A` | содержимое в ASCII |
| `tcpdump -X` | содержимое в hex+ASCII |
| `tcpdump -s 0` | захватывать пакет целиком |
| `tcpdump -B 4096` | размер буфера |

## Справочник BPF-фильтров (tcpdump и tshark -f)

| Фильтр | Значение |
|--------|----------|
| `host 10.0.0.5` | трафик с этим адресом в обе стороны |
| `src host 10.0.0.5` | только от этого адреса |
| `dst port 80` | только на порт 80 |
| `net 10.0.0.0/24` | вся подсеть |
| `tcp` / `udp` / `icmp` | по протоколу |
| `port 80 or port 443` | любой из портов |
| `tcp and not port 22` | TCP, кроме 22 |
| `ether host 00:11:22:33:44:55` | по MAC |
| `greater 1000` | пакеты длиннее 1000 байт |

Соединяются операторами `and`/`&&`, `or`/`||`, `not`/`!`.

## Справочник display-фильтров Wireshark

| Фильтр | Значение |
|--------|----------|
| `http` | весь HTTP |
| `http.request.method == "POST"` | только POST |
| `ip.addr == 10.0.0.5` | по адресу |
| `tcp.port == 443` | по порту |
| `dns.qry.name contains "flag"` | DNS с подстрокой |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | только SYN |
| `frame contains "password"` | подстрока в сырых байтах |
| `tcp.stream eq 3` | конкретный поток |
| `tls.handshake.extensions_server_name` | SNI из ClientHello |

## Follow Stream и Export Objects

Оба инструмента умеют собирать соединение и доставать файлы. В tshark:

```
$ tshark -r http.pcap -q -z follow,tcp,ascii,0
$ tshark -r http.pcap --export-objects http,./out
```

В Wireshark то же самое — правый клик → Follow Stream и меню File → Export Objects. Синтаксис display-фильтра один и тот же, поэтому найденный в GUI фильтр переносится в `-Y`.

## Готовые рецепты

```
# поймать скачивание и записать в файл
sudo tcpdump -i eth0 -n -s 0 'tcp port 80 or tcp port 443' -w web.pcap

# только DNS-запросы
sudo tcpdump -i eth0 -n 'udp port 53'

# все пароли по незашифрованным протоколам (tshark)
tshark -r cap.pcap -Y 'ftp.request.command=="PASS" || http.authorization' \
  -T fields -e ftp.request.arg -e http.authorization

# топ разговоров
tshark -r cap.pcap -q -z conv,ip

# вытащить файлы
tshark -r cap.pcap --export-objects http,./out
```

Заметь: tcpdump отвечает за **захват** (что записать), tshark/Wireshark — за **анализ** (что показать). Рабочий цикл: `tcpdump -w` на сервере, `tshark`/Wireshark на машине аналитика.

## Разбираем один инцидент целиком

Соберём рабочую сессию, чтобы увидеть, как оба инструмента дополняют друг друга. Задача: клиент скачал `secret.zip`, надо достать файл и доказать, кто его запросил.

**1. Захват на сервере.** Фильтруем на входе, чтобы не писать лишнее:

```
$ sudo tcpdump -i eth0 -n -s 0 'tcp port 80' -w http.pcap
```

**2. Разбор на машине аналитика.** Сначала — кто и что просил:

```
$ tshark -r http.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
10.0.0.5	files.example.com	/secret.zip
```

**3. Достаём сам файл** через Export Objects:

```
$ tshark -r http.pcap --export-objects http,./out
$ ls out
secret.zip
```

**4. Проверяем целостность.** Убеждаемся, что файл собран целиком — по заголовку `Content-Length`:

```
$ tshark -r http.pcap -Y 'http.response' -T fields -e http.content_length
4096
$ wc -c out/secret.zip
4096 out/secret.zip
```

Совпало — файл выгружен корректно.

**5. Ищем учётные данные** в том же дампе:

```
$ tshark -r http.pcap -Y 'http.authorization' -T fields -e http.authorization
Basic dXNlcjpwYXNzd29yZA==
$ echo dXNlcjpwYXNzd29yZA== | base64 -d
user:password
```

Вот и полный цикл: захват (tcpdump) → разбор (tshark) → извлечение файла и секретов. Именно так выглядит работа с трафиком на пентесте и в IR.

## Что мы теперь знаем

По-простому:

1. tcpdump — захват и фильтрация BPF; Wireshark/tshark — разбор и display-фильтры.
2. BPF-фильтр (`host`/`port`) и display-фильтр (`tcp.port==80`) — разные языки.
3. tcpdump пишет pcap (`-w`), tshark читает (`-r`).
4. Follow Stream собирает диалог, Export Objects достаёт файлы.
5. Рабочий цикл: захват на сервере — анализ на машине аналитика.

## На что смотреть дальше

- **Не путай `-f` и `-Y`.** Первый — BPF (захват), второй — display (просмотр).
- **Фильтруй на захвате.** Меньше данных — меньше потерь и диска.
- **Бери `-s 0`.** Иначе длинные пакеты обрежутся.

## Готовые рецепты для сложных случаев

Справочник полезен, когда знаешь, что искать. Вот набор «однострочников» под частые задачи разбора дампа:

| Задача | Команда |
|---|---|
| Топ talker'ов по объёму | `tshark -r x.pcap -q -z endpoints,ip` |
| Топ доменов DNS | `tshark -r x.pcap -Y dns -T fields -e dns.qry.name \| sort \| uniq -c \| sort -rn` |
| Все HTTP-запросы | `tshark -r x.pcap -Y http.request -T fields -e http.host -e http.request.uri` |
| Пароли в FTP | `tshark -r x.pcap -Y ftp.request.command==PASS -T fields -e ftp.request.arg` |
| Файлы в HTTP | `tshark -r x.pcap --export-objects http,/tmp/out` |
| Размер ответа сервера | `tshark -r x.pcap -Y "ip.src==10.0.0.20" -q -z io,stat,0` |
| Уникальные TLS SNI | `tshark -r x.pcap -Y tls.handshake.extensions_server_name -T fields -e tls.handshake.extensions_server_name \| sort -u` |

Эти команды покрывают 80% «быстрого триажа» — когда надо за минуту понять, что вообще в дампе.

## Разбираем дамп по шагам: триаж инцидента

Порядок действий для незнакомого дампа:

1. **Обзор.** `capinfos x.pcap` — время, размер, число пакетов. Уже это отсекает «не тот дамп».
2. **Протоколы.** `tshark -r x.pcap -q -z io,phs` — какие протоколы вообще есть, в каком объёме.
3. **Эндпоинты.** `tshark -r x.pcap -q -z endpoints,ip` — кто с кем говорил больше всего.
4. **Аномалии.** Смотрим на редкие протоколы и нестандартные порты — там обычно и живёт интересное.
5. **Цель.** Только теперь — детальный разбор конкретного потока (`Follow Stream`).

Такой порядок экономит время: не открывать тысячи пакетов вручную, а сразу выйти на «горячую точку».

## Фильтры: чем BPF отличается от display

Важно не путать два языка фильтрации:

| | BPF (`tcpdump`, `tshark -f`) | Display (`tshark -Y`) |
|---|---|---|
| Когда применяется | во время захвата | при чтении |
| Синтаксис | `host 10.0.0.1 and tcp port 80` | `ip.addr==10.0.0.1 && tcp.port==80` |
| Доступ к полям | только L2–L4 | любые поля протоколов |
| Отбрасывает | да, пакеты не пишутся | нет, только скрывает |

Практический вывод: BPF — для экономии места при захвате, display — для точного анализа при разборе. Ошибка новичка — пытаться писать `http.host` в `tcpdump`: такого поля BPF не знает.

## Если не сработало: фильтр ничего не находит

Причины. Первая — **поле называется иначе**: проверь точное имя через `tshark -G fields | grep <слово>`. Вторая — **порт нестандартный**: HTTP может идти на 8080, и тогда `-Y http` не сработает без `-d tcp.port==8080,http` (decode as). Третья — **трафик фрагментирован**, и поле видно только в собранном потоке. Четвёртая — пакеты **не попали в дамп** (фильтр захвата был слишком узким). Пятая — протокол **шифрован** (TLS/QUIC), и полей просто нет. Всегда начинай с широкого обзора (`-z io,phs`) и сужай постепенно.

## Квиз

Проверь себя.

```quiz
- question: 'Чем BPF-фильтр отличается от display-фильтра?'
  options:
    - 'BPF — синтаксис захвата (host/port), display — синтаксис Wireshark (tcp.port==80)'
    - 'Они идентичны'
    - 'BPF работает только по UDP'
    - 'Display-фильтр работает только в tcpdump'
  answer: 0
  explanation: 'BPF отбирает пакеты при захвате, display-фильтр скрывает их при просмотре.'
- question: 'Какой флаг tcpdump пишет захват в файл?'
  options:
    - '-r'
    - '-w'
    - '-A'
    - '-n'
  answer: 1
  explanation: '-w записывает в pcap, -r читает из него.'
- question: 'Какой display-фильтр оставит только SYN-пакеты?'
  options:
    - 'tcp.flags.syn == 1 && tcp.flags.ack == 0'
    - 'tcp port 80'
    - 'syn'
    - 'host syn'
  answer: 0
  explanation: 'SYN без ACK — установка соединения.'
- question: 'Что делает tcpdump -s 0?'
  options:
    - 'Захватывает пакет целиком'
    - 'Не разрешает имена'
    - 'Читает файл'
    - 'Останавливается после 0 пакетов'
  answer: 0
  explanation: '-s 0 задаёт неограниченный snaplen — пакет сохраняется полностью.'
- question: 'Какой инструмент отвечает за захват, а какой — за анализ?'
  options:
    - 'tcpdump — захват, Wireshark/tshark — анализ'
    - 'Wireshark — захват, tcpdump — анализ'
    - 'Оба только анализируют'
    - 'Оба только захватывают'
  answer: 0
  explanation: 'tcpdump пишет pcap; Wireshark/tshark разбирают его.'
```

## Куда дальше

В следующем уроке мы разберём NFS — сетевую файловую систему, ошибки настройки которой ведут к захвату хоста. А пока запомни главное: tcpdump и Wireshark — два разных синтаксиса фильтров, и это первое, что нужно держать в голове.

## Где пригодится

- **CTF:** шпаргалка по фильтрам для PCAP-задач.
- **Пентест:** перехват и анализ трафика цели.
- **Работа / SOC:** захват и разбор для расследования.
- **Администрирование:** диагностика сети.
