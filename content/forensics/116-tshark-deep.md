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

## Вопрос, с которого всё начинается

В прошлых уроках мы смотрели на трафик «сверху»: через сигнатуры (Suricata) и потоки (NetFlow). Но часто нужно спуститься на уровень отдельных пакетов: найти конкретный запрос, вытащить переданный файл, восстановить сессию. Для этого есть **`tshark`** — консольная версия Wireshark.

## Наш пример: attack.pcap

Есть захват `attack.pcap`. Начнём с общего обзора — кто с кем и сколько. Флаг `-q` отключает построчный вывод пакетов, `-z` включает готовые отчёты:

```bash
$ tshark -r attack.pcap -q -z conv,tcp | head
TCP Conversations
10.0.0.5:51234 <-> 203.0.113.9:443   | 1200 | 90 kB | 3 | 400 B | 1203 | 90 kB |
```

Читаем: клиент `10.0.0.5` отправил на `203.0.113.9:443` заметно больше, чем получил (90 kB против 400 B). Для HTTPS это нетипично — обычно скачивают, а не отдают. Гипотеза: выгрузка данных.

## Шаг 1: два разных языка фильтров

Ключевое различие, на котором спотыкаются новички:

- **Capture filter (BPF)** — применяется **до** захвата, синтаксис `tcp port 80`, задаётся флагом `-f`.
- **Display filter** — применяется **после**, синтаксис `http.request.method == "GET"`, задаётся флагом `-Y`.

```bash
# Захват только нужного (BPF)
tshark -i eth0 -f "tcp port 443"
# Чтение PCAP с display-фильтром
tshark -r attack.pcap -Y 'http.request.method == "POST"'
```

## Шаг 2: ищем подозрительный запрос

Применим display-фильтр к HTTP-запросам и выведем нужные поля через `-T fields`:

```bash
$ tshark -r attack.pcap -Y 'http.request.method=="POST"' -T fields -e http.host -e http.request.uri -e http.user_agent
evil.example  /upload  Mozilla/5.0 (compatible; MSIE 9.0)
```

Странность: хост `evil.example` (необычное имя), путь `/upload`, а User-Agent притворяется старым Internet Explorer 9 — типичная маскировка под легитимный браузер. Куда и что именно загружают — смотрим дальше.

## Шаг 3: извлекаем объекты

`tshark` умеет вытаскивать переданные по протоколам файлы. Это делается директивой `--export-objects`:

```bash
$ tshark -r attack.pcap --export-objects http,./objs
$ ls ./objs
%2Fupload  index.html
$ file './objs/%2Fupload'
./objs/%2Fupload: Zip archive data, at least v2.0 to extract
```

Мы получили ZIP-архив, который атакующий отправил методом POST на `evil.example/upload`. Имя `%2Fupload` — URL-кодированное (`/upload`), это нормально: `tshark` санитизирует имена. Теперь содержимое можно распаковать и проанализировать.

## Шаг 4: полезные display-фильтры

Display-фильтры — сердце анализа. Набор, который экономит часы:

| Задача | Фильтр |
|--------|--------|
| Только новые соединения | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| Ретрансмиссии | `tcp.analysis.retransmission` |
| HTTP 4xx/5xx | `http.response.code >= 400` |
| DNS-запросы | `dns.flags.response == 0` |
| TLS SNI | `tls.handshake.extensions_server_name` |
| Credentials HTTP | `http.authorization` |
| FTP-логин | `ftp.request.command == "USER"` |
| Скрытый ICMP | `icmp.type==8 && data.len > 100` |

```bash
# Креды в открытых протоколах
$ tshark -r attack.pcap -Y 'ftp.request.command=="USER" || ftp.request.command=="PASS"' -T fields -e ftp.request.command -e ftp.request.arg
```

## Шаг 5: реконструкция сессии

Иногда нужен весь диалог целиком, а не отдельные поля. Функция **follow** собирает поток в читаемый вид:

```bash
$ tshark -r attack.pcap -q -z follow,tcp,ascii,0
```

В Wireshark то же самое — правый клик по пакету → Follow → TCP Stream. Альтернатива на диске — `tcpflow`, который раскладывает каждый поток в отдельный файл:

```bash
$ tcpflow -r attack.pcap -o ./flows
$ ls ./flows
```

## Полный разбор: от PCAP к извлечённому файлу

Соберём работу с `attack.pcap` в один сценарий.

1. **Обзор протоколов.** Что вообще в трафике:
   ```bash
   $ tshark -r attack.pcap -q -z io,phs
   ```
2. **Топ разговоров.** Кто с кем и сколько:
   ```bash
   $ tshark -r attack.pcap -q -z conv,tcp
   ```
3. **Сужаем до подозрительного потока** (например, HTTP-загрузки):
   ```bash
   $ tshark -r attack.pcap -Y 'http.request.method=="GET"' -T fields -e ip.dst -e http.host -e http.request.uri
   ```
4. **Извлекаем объекты.** Файлы, переданные по HTTP:
   ```bash
   $ tshark -r attack.pcap --export-objects http,/evidence/http
   ```
5. **Проверяем содержимое.** Хешируем извлечённое и пробиваем по базе.

Ключ: `-Y` (display filter) отбирает пакеты, `-T fields` печатает только нужные поля, `--export-objects` собирает файлы. Так из гигабайтного PCAP получается конкретный артефакт.

## Шпаргалка -z статистик

| Задача | Ключ `-z` |
|--------|-----------|
| Иерархия протоколов | `io,phs` |
| Разговоры TCP/IP | `conv,tcp` / `conv,ip` |
| Объём по протоколу | `io,stat,1` |
| HTTP-запросы | `http,tree` |
| DNS-ответы | `dns,tree` |
| Экспертные ошибки | `expert` |

Полезные поля для `-T fields`: `frame.time`, `ip.src`, `ip.dst`, `tcp.stream`, `http.request.uri`, `tls.handshake.extensions_server_name` (SNI). Поле `tcp.stream` позволяет «достать» все пакеты одного соединения: `-Y 'tcp.stream==3'`.

## Частые вопросы

**Чем `-Y` отличается от `-R`?** `-Y` — display-фильтр (по разобранным полям), `-R` — read-фильтр (более узкий, по BPF-подобному синтаксису). В `tshark` чаще используют `-Y`.

**Как следить за потоком в реальном времени?** `-i <iface>` вместо `-r file` и `Follow → TCP Stream` в Wireshark, либо `-z follow,tcp,ascii,<stream>`.

**PCAP большой, команда тормозит.** Ограничьте окно (`-Y 'frame.time < "..."'`), используйте `-2` для двухпроходных статистик и `-q`, чтобы не печатать пакеты.

**TLS зашифрован.** Без ключей видно только SNI и метаданные; расшифровка требует `SSLKEYLOGFILE` или приватного ключа сервера.

## Что мы теперь знаем

- **Capture filter (BPF, `-f`)** работает до захвата; **display filter (`-Y`)** — после.
- `-z conv,ip` / `conv,tcp` дают разговоры; `-z io,phs` — иерархию протоколов; `-z expert` — аномалии.
- `-T fields` выгружает нужные поля, `--export-objects http,DIR` — переданные файлы.
- `follow`/`tcpflow` реконструируют сессию целиком.
- При малом **snaplen** payload обрезан — объекты не извлекутся.
- Без ключей TLS доступны только метаданные (SNI, сертификаты).

## Если не сработало: частые сложности

Несколько ситуаций, которые ставят в тупик:

- **Путаница BPF и display.** `-f "http.request"` не сработает (это не BPF), а `-Y "tcp port 80"` тоже неверно. Правило простое: `-f` — только BPF (`tcp port 80`), `-Y` — только display (`http.request.method=="GET"`).
- **Обрезанный payload.** Если захват шёл с малым snaplen, файлы не извлекутся: `--export-objects` сохранит «огрызки».
- **TLS.** Без `SSLKEYLOGFILE` или приватного ключа содержимое не читается — остаются SNI и сертификаты.
- **Фрагментация.** Атакующие дробят пакеты, чтобы обойти IDS: `-Y 'ip.flags.mf==1 || ip.frag_offset>0'` покажет фрагменты.

```bash
# IP ID и TTL как возможный скрытый канал
$ tshark -r cap.pcap -T fields -e ip.src -e ip.id -e ip.ttl | head
```

Держите под рукой `editcap`/`mergecap`: первый режет и фильтрует захват по времени (`editcap -A "…" -B "…"`), второй склеивает несколько PCAP в один.

## Квиз

Проверь себя.

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
- question: "Что показывает tshark -z conv,ip?"
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
- question: "Какой флаг задаёт capture-фильтр (BPF) при съёме трафика?"
  options:
    - "-Y"
    - "-f"
    - "-z"
    - "-T"
  answer: 1
  explanation: "-f задаёт BPF-фильтр на входе; -Y — display-фильтр на выходе."
```

## Куда дальше

Мы научились вытаскивать файлы и восстанавливать сессии из PCAP. В следующем уроке (`forensics-azure-forensics`) перейдём в облако и разберём логи Azure/Entra ID. А пока главное запомни: **`-z` даёт обзор, `-Y` сужает, `--export-objects` вытаскивает файлы, а `follow`/`tcpflow` собирают сессию**.

## Где пригодится

- **CTF:** извлечение файлов и поиск данных в PCAP.
- **DFIR:** реконструкция сессий и объектов при инциденте.
- **Threat Hunting:** быстрый обзор и фильтрация трафика.
- **Работа:** повседневный анализ сетевых проблем и безопасности.
