---
id: network-tool-masscan-naabu
title: "masscan и naabu: высокоскоростное сканирование диапазонов"
category: network
parent: network-tools
difficulty: easy
order: 2
tags: [network, masscan, naabu, scanning, internet-scale, reference]
prerequisites: [network-portscan]
useful_for:
  - "CTF: категория Network"
  - "Bug bounty: поиск хостов в больших CIDR"
  - "Работа: инвентаризация и мониторинг"
estimated_minutes: 35
summary: "Полный справочник по masscan и naabu: скорость, диапазоны, баннеры, исключения, вывод и связка с nmap."
---

`nmap` точен, но медленный: он ведёт состояние по каждому соединению и ждёт ответы. Когда нужно «прочесать» `/16` или весь `10.0.0.0/8` за минуты, на сцену выходят асинхронные сканеры — **masscan** и **naabu**. Этот урок — практический справочник по обоим: все флаги, что они делают, и как их правильно готовить, чтобы не устроить себе бан и не положить чужую сеть.

## Чем masscan отличается от nmap

masscan использует **собственный асинхронный TCP/IP-стек**: он шлёт SYN-пакеты с заданной скоростью и не держит состояние соединения. Отсюда его суперсила — миллионы пакетов в секунду — и слабость: он **не определяет версии сервисов и ОС**. Его задача — быстро найти открытые порты; уточнение сервисов делается потом `nmap`.

| | nmap | masscan |
|---|------|---------|
| Модель | синхронная, stateful | асинхронная, stateless |
| Скорость | десятки-сотни пакетов/с | тысячи-миллионы пакетов/с |
| Версии/ОС | да (`-sV`, `-O`) | нет |
| NSE-скрипты | да | нет |
| Лучший сценарий | точная разведка хоста | грубая карта большого диапазона |

## Установка и базовый запуск

```bash
# Debian/Ubuntu
sudo apt install masscan

# из исходников
git clone https://github.com/robertdavidgraham/masscan && cd masscan && make -j && sudo make install

# базовый скан
sudo masscan 10.0.0.0/24 -p 80,443 --rate 1000
```

masscan почти всегда требует `sudo` (raw-сокеты). `--rate` обязателен по смыслу: без него вы либо слишком медленны, либо перегружаете канал.

## Все ключевые флаги masscan

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-p <spec>` | Порты/диапазон/список | `-p 80,443,8000-8100` |
| `-p0-65535` | Все порты | `-p0-65535` |
| `--ports <spec>` | То же, что `-p` (длинная форма) | `--ports 80,443` |
| `--range <ip-range>` | Диапазон адресов | `--range 10.0.0.1-10.0.0.254` |
| `--rate <pps>` | Пакетов в секунду | `--rate 5000` |
| `--banners` | Забрать баннер сервиса | `--banners` |
| `--exclude <ip>` | Исключить адрес/диапазон | `--exclude 10.0.0.1` |
| `--excludefile <f>` | Исключения из файла | `--excludefile excl.txt` |
| `--includefile <f>` | Цели из файла | `--includefile hosts.txt` |
| `--wait <sec>` | Подождать после завершения (баннеры) | `--wait 3` |
| `-e <iface>` | Интерфейс | `-e eth0` |
| `--source-ip <ip>` | Исходный IP | `--source-ip 10.0.0.9` |
| `--source-port <p>` | Исходный порт | `--source-port 40000` |
| `--router-ip <ip>` | IP шлюза | `--router-ip 10.0.0.1` |
| `--router-mac <mac>` | MAC шлюза | `--router-mac 00:11:22:33:44:55` |
| `--adapter-ip <ip>` | IP адаптера (для виртуальных сетей) | `--adapter-ip 192.168.56.1` |
| `--adapter-port <p>` | Порт адаптера | `--adapter-port 40000` |
| `--adapter-mac <mac>` | MAC адаптера | `--adapter-mac 00:11:22:33:44:55` |
| `--adapter-vlan <id>` | VLAN адаптера | `--adapter-vlan 10` |
| `--retries <n>` | Повторы | `--retries 2` |
| `--status` | Периодический статус | `--status` |
| `--resume <file>` | Продолжить прерванный скан | `--resume paused.conf` |
| `--readscan <file>` | Перечитать бинарный дамп | `--readscan out.bin` |
| `--interactive` | Интерактивный режим | `--interactive` |
| `--regress` | Регрессионный self-test | `--regress` |
| `--http-user-agent <ua>` | User-Agent для баннеров | `--http-user-agent "Mozilla/5.0"` |
| `--http-header <h>` | Свой HTTP-заголовок | `--http-header "Host: x"` |
| `--http-method <m>` | HTTP-метод для баннеров | `--http-method GET` |
| `--http-url <u>` | URL для баннера | `--http-url /index.html` |
| `--http-cookie <c>` | Cookie для баннера | `--http-cookie "a=1"` |
| `--http-payload <p>` | Свой HTTP-payload | `--http-payload "GET / HTTP/1.0"` |
| `--hello <s>` | Своё приветствие (banner grab) | `--hello "EHLO x"` |
| `--helo <s>` | SMTP HELO-строка | `--helo "test"` |
| `--vhost <name>` | HTTP Host для баннера | `--vhost example.com` |
| `--ping` | Проверить живость перед сканом | `--ping` |
| `--shard <n>/<m>` | Часть работы (для распределённого скана) | `--shard 1/4` |
| `--seed <n>` | Детерминированный порядок | `--seed 12345` |
| `--randomize-hosts` | Случайный порядок целей | `--randomize-hosts` |
| `--top-ports <n>` | N популярных портов | `--top-ports 100` |
| `--offline` | Не слать, только сгенерировать (для проверки) | `--offline` |
| `--infinite` | Бесконечный повтор скана | `--infinite` |
| `--capture <file>` | Писать захваченные пакеты | `--capture cap.pcap` |
| `--nocapture` | Не сохранять захваченные пакеты | `--nocapture` |
| `--pcap-payloads` | Извлекать payload'ы из pcap | `--pcap-payloads` |
| `--pcap-map <f>` | Карта IP из pcap | `--pcap-map map.txt` |
| `--output-filename <f>` | Имя файла вывода | `--output-filename out.txt` |
| `--output-format <fmt>` | Формат (list/grepable/xml/json/binary) | `--output-format json` |
| `--output-status <what>` | Что печатать в статус | `--output-status open` |
| `--append-output` | Дописывать в файл вывода | `--append-output` |
| `--iflist` | Список интерфейсов | `--iflist` |
| `--config <file>` | Свой конфиг | `--config masscan.conf` |
| `--verbosity <n>` | Подробность | `--verbosity 2` |
| `--debug <n>` | Уровень отладки | `--debug 1` |
| `--version` | Версия masscan | `--version` |

## Цели: диапазоны, CIDR, файлы

```bash
sudo masscan 10.0.0.0/24 -p 22,80,443 --rate 2000        # CIDR
sudo masscan --range 10.0.0.1-10.0.0.254 -p 445 --rate 1000   # диапазон
sudo masscan --includefile targets.txt -p 1-1024 --rate 5000  # из файла
sudo masscan 10.0.0.0/16 -p 3389 --excludefile excl.txt --rate 3000
```

`--includefile` — ваш основной способ задать цели: один CIDR/адрес на строку. `--excludefile` — то же для исключений (ваш собственный IP, критичные хосты, шлюз).

## Скорость и --rate: как не положить сеть

`--rate` — это **число пакетов в секунду**, а не портов. Один адрес × 1000 портов при `--rate 1000` сканируется одну секунду. Практические ориентиры:

| Сценарий | rate |
|----------|------|
| Чувствительная сеть/через VPN | 100–500 |
| Локальная лаборатория | 1000–10000 |
| Свой внешний диапазон | 10000–100000 |
| Интернет-масштаб (исследование) | 100000+ (только свои диапазоны) |

```bash
sudo masscan 10.0.0.0/24 -p0-65535 --rate 10000 -oG full.gnmap
```

Начните с малого rate, измерьте, как реагирует сеть, и поднимайте. Никогда не сканируйте чужие сети с высоким rate — это выглядит как DoS.

## Баннеры и определение сервисов

```bash
sudo masscan 10.0.0.0/24 -p 80,443,22,21 --banners --rate 1000 --wait 3
```

`--banners` заставляет masscan не только установить соединение, но и **забрать начальный баннер** (для HTTP — GET, для FTP/SMTP — приветствие). `--wait` даёт время на сбор баннеров после завершения скана. Баннеры грубые: точную версию всё равно добивает `nmap -sV`.

## Исключения и безопасность сканирования

```bash
# всегда исключайте свой хост и критичные узлы
sudo masscan 10.0.0.0/16 -p 1-1024 --exclude 10.0.0.1,10.0.0.2 --rate 2000
# исключить из файла
sudo masscan 10.0.0.0/16 -p 22 --excludefile do_not_scan.txt --rate 1000
# распределить скан между четырьмя машинами
sudo masscan 10.0.0.0/8 -p 443 --shard 1/4 --rate 10000
```

`--shard 1/4` берёт на себя только первую четверть работы — так несколько узлов делят огромный диапазон. `--offline` полезен, чтобы проверить, сколько пакетов сгенерирует скан, не отправляя их.

## Форматы вывода и парсинг

| Флаг | Формат |
|------|--------|
| `-oL file` | Простой список (`open tcp 80 10.0.0.5`) |
| `-oG file` | Grepable (как у nmap) |
| `-oX file` | XML |
| `-oJ file` | JSON |
| `-oB file` | Бинарный (для `--readscan`) |
| `--output-filename` | Имя файла |
| `--output-format` | Формат (list/grepable/xml/json/binary) |

```bash
sudo masscan 10.0.0.0/24 -p 80,443 --rate 2000 -oJ out.json
cat out.json | jq -r '.[].ports[].port' | sort -u
sudo masscan --readscan out.bin -oG out.gnmap   # перечитать бинарный дамп
```

Бинарный `-oB` + `--readscan` удобен, когда нужно потом переформатировать результат без повторного скана.

## naabu: полный справочник

`naabu` (из ProjectDiscovery) — современный сканер портов с приятным выводом, встроенной дедупликацией и интеграцией с `httpx`/`nuclei`. Под капотом умеет SYN и connect.

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-host <h>` | Один хост/диапазон | `-host 10.0.0.5` |
| `-list <f>` | Список целей | `-list hosts.txt` |
| `-input-file <f>` | Список целей (то же, что `-list`) | `-input-file hosts.txt` |
| `-p <spec>` | Порты | `-p 80,443,8000-9000` |
| `-top-ports <n>` | Top-N портов | `-top-ports 1000` |
| `-exclude-ports <p>` | Исключить порты | `-exclude-ports 9100` |
| `-exclude-ports-file <f>` | Исключить порты из файла | `-exclude-ports-file ex.txt` |
| `-exclude-hosts <h>` | Исключить хосты | `-exclude-hosts 10.0.0.1` |
| `-exclude-cdn` | Пропускать CDN-адреса | `-exclude-cdn` |
| `-scan-all-ips` | Сканировать все IP имени | `-scan-all-ips` |
| `-rate <n>` | Пакетов/сек | `-rate 2000` |
| `-c <n>` | Конкурентность (потоки) | `-c 100` |
| `-timeout <s>` | Таймаут | `-timeout 3` |
| `-retries <n>` | Повторы | `-retries 2` |
| `-warm-up-time <n>` | Время прогрева | `-warm-up-time 2` |
| `-scan-type <t>` | `c` (connect) / `s` (syn) | `-scan-type s` |
| `-source-ip <ip>` | Исходный IP | `-source-ip 10.0.0.9` |
| `-source-port <p>` | Исходный порт | `-source-port 40000` |
| `-interface-list` / `-il` | Список интерфейсов | `-il` |
| `-interface` / `-i` | Интерфейс | `-i eth0` |
| `-s` | Silent (только результаты) | `-s` |
| `-v` / `-verbose` | Подробный вывод | `-v` |
| `-json` | JSON-вывод | `-json` |
| `-o <f>` | Файл вывода | `-o ports.txt` |
| `-nmap` | Прогнать nmap по найденному | `-nmap` |
| `-verify` | Проверить порты ещё раз | `-verify` |
| `-proxy <url>` | Через прокси | `-proxy socks5://127.0.0.1:9050` |
| `-resolvers <f>` | Свои DNS-резолверы | `-resolvers res.txt` |
| `-passive` | Пассивный режим (shodan) | `-passive` |
| `-host-discovery` | Только найти живые хосты | `-host-discovery` |
| `-cdn` | Показывать CDN-хосты | `-cdn` |
| `-ip-version <v>` | Версия IP (4/6) | `-ip-version 4` |
| `-stats` | Показывать статистику | `-stats` |
| `-health-check` | Проверка работоспособности | `-health-check` |
| `-stream` | Стриминговый вывод (для пайпов) | `-stream` |
| `-nc` / `-no-color` | Без цвета | `-nc` |
| `-config <f>` | Свой конфиг | `-config naabu.yaml` |
| `-disable-update-check` / `-duc` | Не проверять обновления | `-duc` |
| `-version` | Версия naabu | `-version` |

```bash
naabu -host 10.0.0.5 -top-ports 1000 -s
naabu -list hosts.txt -p 80,443,8080 -rate 2000 -c 100 -json -o out.jsonl
naabu -host 10.0.0.0/24 -p - -exclude-ports 9100 -s
echo 10.0.0.5 | naabu -p 22,80,443 -s
```

`-scan-type s` использует SYN (нужен root, быстрее), `-scan-type c` — обычный connect (без root). `-nmap` автоматически передаёт найденные порты в nmap — удобный «мост» от быстрого скана к точному.

## Связка masscan + nmap (рабочий процесс)

Классический конвейер для большого диапазона:

```bash
# 1) массовый быстрый поиск открытых портов
sudo masscan 10.0.0.0/16 -p0-65535 --rate 20000 -oG mass.gnmap

# 2) извлечь живые хосты с открытыми портами
grep "/open" mass.gnmap | awk '{print $2}' | sort -u > live.txt

# 3) точная разведка только этих хостов
nmap -sV -sC -iL live.txt -oA detail
```

То же через naabu + httpx:

```bash
naabu -list targets.txt -top-ports 1000 -s -o ports.txt
httpx -l ports.txt -title -tech-detect -status-code -o web.txt
```

## Практические рецепты

**Быстрая карта подсети:**

```bash
sudo masscan 10.0.0.0/24 -p 21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080,8443 --rate 3000 -oL ports.txt
```

**Полный скан одного /16 (в своей сети):**

```bash
sudo masscan 10.0.0.0/16 -p0-65535 --rate 15000 -oG all.gnmap
```

**Веб-периметр с баннерами:**

```bash
sudo masscan 10.0.0.0/24 -p 80,443,8080,8443 --banners --rate 1000 --wait 3
```

**naabu → nmap одной командой:**

```bash
naabu -host 10.0.0.0/24 -top-ports 1000 -nmap -s
```

## Частые ошибки

- **Забыть `sudo`.** masscan без root не поднимет raw-сокеты. Если прав нет — используйте `naabu -scan-type c` или `nmap -sT`.
- **Слишком высокий `--rate`.** Это выглядит как флуд: вас забанит IDS или провайдер. Начинайте с 100–1000 в чужой сети.
- **Ждать от masscan версий.** Он их не определяет — это работа nmap. Комбинируйте оба.
- **Сканировать чужие диапазоны.** Скан без разрешения — юридически и этически недопустим; `--rate` усугубляет (DoS).
- **Путать `--rate` (пакеты/с) и число портов.** Один адрес с 1000 портами при `rate 1000` = 1 секунда.

## Квиз

```quiz
- question: "Почему masscan быстрее nmap на огромных диапазонах?"
  options:
    - "Он использует асинхронный stateless TCP/IP-стек"
    - "Он определяет версии быстрее"
    - "Он запускает NSE-скрипты параллельно"
    - "Он сжимает трафик"
  answer: 0
  explanation: "masscan не хранит состояние соединений и шлёт SYN-пакеты с заданной скоростью."
- question: "Что задаёт флаг --rate в masscan?"
  options:
    - "Число пакетов в секунду"
    - "Число портов на хост"
    - "Количество потоков CPU"
    - "Таймаут на хост"
  answer: 0
  explanation: "--rate — это пакетов в секунду, не портов и не хостов."
- question: "Чего masscan НЕ умеет делать сам?"
  options:
    - "Определять версии сервисов и ОС"
    - "Сканировать CIDR-диапазоны"
    - "Писать результат в XML"
    - "Работать с --exclude"
  answer: 0
  explanation: "Версии и ОС — это nmap; masscan только находит открытые порты."
- question: "Зачем нужен --shard 1/4 в masscan?"
  options:
    - "Разделить огромный скан между несколькими машинами"
    - "Сканировать только каждый четвёртый порт"
    - "Ускорить скан в четыре раза"
    - "Ограничить вывод четырьмя строками"
  answer: 0
  explanation: "--shard делит работу на m частей, чтобы несколько узлов сканировали диапазон параллельно."
- question: "Какой флаг naabu прогоняет nmap по найденным портам?"
  options:
    - "-nmap"
    - "-verify"
    - "-passive"
    - "-host-discovery"
  answer: 0
  explanation: "-nmap автоматически передаёт найденные открытые порты в nmap для определения версий."
```

## Где пригодится

- **CTF:** Network — быстрая разведка больших диапазонов и поиск нестандартных сервисов.
- **Bug bounty:** поиск хостов в широких CIDR перед веб-анализом; `naabu` → `httpx` → `nuclei`.
- **Пентест:** первый проход по внутренней сети или периметру, затем точечный nmap.
- **Работа:** инвентаризация и мониторинг доступности сервисов, аудит «что вообще открыто».
