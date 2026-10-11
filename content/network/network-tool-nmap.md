---
id: network-tool-nmap
title: "nmap: полный практический справочник"
category: network
parent: network-tools
difficulty: easy
order: 1
tags: [network, nmap, scanning, nse, reference, enumeration]
prerequisites: [network-portscan, network-nmap-deep]
useful_for:
  - "CTF: категория Network"
  - "Пентест: карта сервисов и версий"
  - "Работа: инвентаризация и аудит"
estimated_minutes: 45
summary: "Все ключевые флаги nmap с примерами: хост-дискавери, типы сканов, порты, версии, NSE, тайминги, обход фильтров, вывод и готовые рецепты."
---

`nmap` — главный инструмент сетевой разведки. Этот урок не про теорию сканирования (она в уроках `network-portscan` и `network-nmap-deep`), а про **практику**: полный набор флагов, что каждый делает, готовая команда и в какой ситуации за него хвататься. Держите его открытым рядом с терминалом.

## Как читать этот справочник

Каждый раздел — одна задача: найти хосты, выбрать тип скана, сузить порты, определить сервис, запустить скрипт, ускориться, спрятаться, сохранить вывод. В таблицах — флаг, что делает и типовой пример. В конце — раздел «что запускать и когда», который решает 80% задач.

Базовый синтаксис:

```bash
nmap [тип скана] [опции] [цели]
nmap -sS -sV -p- 10.0.0.5
nmap -iL targets.txt -oA scan_all
```

Цели можно задавать как IP, диапазон, CIDR, имя хоста или файл: `10.0.0.5`, `10.0.0.1-50`, `10.0.0.0/24`, `example.com`, `-iL hosts.txt`. Исключить — `--exclude 10.0.0.1` или `--excludefile`.

## Хост-дискавери: находим живые хосты

Перед сканом портов нужно понять, кто вообще жив. По умолчанию nmap делает это сам (ARP в локальной сети, ICMP/TCP на удалённых).

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-sn` | Ping-scan: только живость, без портов | `nmap -sn 10.0.0.0/24` |
| `-Pn` | Не пинговать, считать хост живым | `nmap -Pn 10.0.0.5` |
| `-sL` | List scan: только перечислить цели, без пакетов | `nmap -sL 10.0.0.0/24` |
| `-PR` | ARP-ping (только локальная сеть) | `nmap -PR -sn 10.0.0.0/24` |
| `-PS<ports>` | TCP SYN-ping на порты (по умолч. 80) | `nmap -PS22,80,443 -sn 10.0.0.0/24` |
| `-PA<ports>` | TCP ACK-ping на порты | `nmap -PA80 -sn 10.0.0.5` |
| `-PU<ports>` | UDP-ping (по умолч. 40125) | `nmap -PU53 -sn 10.0.0.5` |
| `-PY<ports>` | SCTP INIT-ping | `nmap -PY80 -sn 10.0.0.5` |
| `-PE` | ICMP echo-ping (по умолч. с root) | `nmap -PE -sn 10.0.0.5` |
| `-PP` | ICMP timestamp-ping | `nmap -PP -sn 10.0.0.5` |
| `-PM` | ICMP netmask-ping | `nmap -PM -sn 10.0.0.5` |
| `-PO<proto>` | IP protocol ping | `nmap -PO 1,2,4 -sn 10.0.0.5` |
| `-n` | Не резолвить DNS | `nmap -n -sS 10.0.0.5` |
| `-R` | Резолвить DNS всегда (обратный) | `nmap -R -sn 10.0.0.0/24` |
| `--dns-servers <srv>` | Свои DNS-серверы | `nmap --dns-servers 8.8.8.8 -sS 10.0.0.5` |
| `--system-dns` | Использовать резолвер ОС | `nmap --system-dns -sS 10.0.0.5` |
| `--traceroute` | Трассировка маршрута до хоста | `nmap --traceroute 10.0.0.5` |
| `-iR <num>` | Случайные цели (num хостов) | `nmap -iR 100 -Pn -p 80` |
| `--exclude <h>` | Исключить хосты/сети | `nmap 10.0.0.0/24 --exclude 10.0.0.1` |
| `--excludefile <f>` | Исключения из файла | `nmap 10.0.0.0/24 --excludefile excl.txt` |

Внутри локальной сети nmap использует ARP — он точнее любого ICMP. Если хост блокирует ping, всегда переходите на `-Pn` и сканируйте порты напрямую.

## Типы сканов

Тип скана определяет, как вы «спрашиваете» порт, и влияет на скрытность и требуемые права.

| Флаг | Имя | Права | Особенности |
|------|-----|-------|-------------|
| `-sS` | TCP SYN (half-open) | root | Быстрый, скрытный, по умолчанию с root |
| `-sT` | TCP connect() | любой | Полный handshake, шумный, работает без root |
| `-sU` | UDP | root | Медленный, критичен для DNS/SNMP/DHCP |
| `-sA` | TCP ACK | root | Определяет фильтрацию (не открытость) |
| `-sN` | TCP NULL | root | Флаги не выставлены — обход тупых фильтров |
| `-sF` | TCP FIN | root | Только FIN |
| `-sX` | Xmas | root | FIN+PSH+URG |
| `-sW` | Window | root | Анализ TCP-окна |
| `-sM` | Maimon | root | Старый обход фильтров |
| `-sI <zombie>` | Idle scan | root | Скан «через зомби», ваш IP не светится |
| `-sY` | SCTP INIT | root | SCTP-сервисы |
| `-sZ` | SCTP COOKIE-ECHO | root | SCTP-сервисы |
| `-sO` | IP protocol scan | root | Какие IP-протоколы отвечают |
| `-b <FTP relay>` | FTP bounce scan | — | Устаревший обход через FTP-сервер |
| `--scanflags` | Свои TCP-флаги | root | `--scanflags SYNURG` |

Примеры:

```bash
sudo nmap -sS -p- --min-rate 2000 -oA full 10.0.0.5   # быстрый SYN по всем портам
nmap -sT -p 1-1000 10.0.0.5                          # без root
sudo nmap -sU -p 53,123,161 10.0.0.5                 # целевой UDP
sudo nmap -sA -p 80,443 10.0.0.5                     # фильтр или нет
```

Правило: для скорости — `-sS`, если нет root — `-sT`, для сервисов на UDP — `-sU`, а `-sA`/`-sN`/`-sF`/`-sX` — чтобы понять поведение фильтра.

## Выбор портов

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-p <spec>` | Явный список портов | `-p 22,80,443` |
| `-p-` | Все 65535 портов | `-p-` |
| `-p 1-1024` | Диапазон | `-p 1-1024` |
| `-p U:53,T:80` | Смешанный протокол/порт (UDP/TCP/SCTP) | `-p U:53,111,T:80,S:9` |
| `--top-ports N` | N самых частых портов | `--top-ports 1000` |
| `--port-ratio <r>` | Порты «популярнее» доли r (0–1) | `--port-ratio 0.1` |
| `-F` | Fast: top-100 | `-F` |
| `--exclude-ports` | Исключить порты | `--exclude-ports 22,3389` |
| `-r` | Сканировать по порядку (не рандомизировать) | `-r -p 1-1024` |

```bash
nmap -sS --top-ports 1000 10.0.0.5          # быстрая разведка
nmap -sS -p- --exclude-ports 9100 10.0.0.5  # все, кроме шумного принтера
```

## Определение сервисов, версий и ОС

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-sV` | Определить сервис и версию | `nmap -sV 10.0.0.5` |
| `--version-intensity 0..9` | Глубина проб (по умолч. 7) | `-sV --version-intensity 9` |
| `--version-all` | Пробовать все пробы | `-sV --version-all` |
| `--version-light` | Быстрый режим (intensity 2) | `-sV --version-light` |
| `--version-trace` | Отладка version-скана | `-sV --version-trace` |
| `-O` | Определить ОС (fingerprint) | `sudo nmap -O 10.0.0.5` |
| `--osscan-guess` | Агрессивнее угадывать ОС | `-O --osscan-guess` |
| `--osscan-limit` | Только для обещающих хостов | `-O --osscan-limit` |

```bash
nmap -sV --version-all -p 22,80,443,3306 10.0.0.5
sudo nmap -O --osscan-guess 10.0.0.5
```

Версия сервиса — это то, что превращает «порт 80 открыт» в «nginx 1.18.0 → ищем CVE». Без `-sV` сканирование почти бесполезно для эксплуатации.

## NSE — скриптовый движок

NSE (Nmap Scripting Engine) — Lua-скрипты, которые перечисляют данные, брутят и проверяют CVE.

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-sC` | Дефолтные скрипты (категория default) | `nmap -sC 10.0.0.5` |
| `--script <name\|cat>` | Конкретный скрипт или категория | `--script vuln` |
| `--script-args` | Аргументы скриптов | `--script-args user=admin,pass=admin` |
| `--script-args-file <f>` | Аргументы из файла | `--script-args-file nse.args` |
| `--script-help <name>` | Справка по скрипту | `--script-help http-enum` |
| `--script-trace` | Отладка скриптов | `--script-trace` |
| `--script-updatedb` | Обновить базу скриптов | `nmap --script-updatedb` |

Категории NSE: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`. Список скриптов: `ls /usr/share/nmap/scripts/ | grep http`.

Полезные скрипты:

| Скрипт | Что даёт |
|--------|----------|
| `http-title` | Заголовок страницы |
| `http-enum` | Перечисление путей/панелей |
| `http-headers` | HTTP-заголовки и версия сервера |
| `http-shellshock` | Проверка Shellshock (CVE-2014-6271) |
| `smb-enum-shares` | SMB-шары |
| `smb-enum-users` | Пользователи SMB |
| `smb-vuln-ms17-010` | EternalBlue |
| `smb-vuln-*` | Пакет проверок SMB |
| `ftp-anon` | Анонимный FTP |
| `vulners` | Сверка версий с базой CVE (требует ключ/интернет) |

```bash
nmap -sV --script vuln 10.0.0.5
nmap -p 445 --script smb-enum-shares,smb-enum-users 10.0.0.5
nmap -p 80 --script http-enum,http-title 10.0.0.5
nmap --script "http-* and safe" -p 80 10.0.0.5
```

Категория `vuln` может быть шумной и иногда роняет сервис — в продакшене предпочитайте точечные скрипты, а не всю категорию.

## Тайминги и производительность

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-T0..-T5` | Шаблон агрессивности (paranoid…insane) | `-T4` |
| `--min-rate N` | Не медленнее N пакетов/сек | `--min-rate 5000` |
| `--max-rate N` | Не быстрее N пакетов/сек | `--max-rate 500` |
| `--min-parallelism` | Мин. параллельных проб | `--min-parallelism 100` |
| `--max-parallelism` | Макс. параллельных проб | `--max-parallelism 1` |
| `--min-hostgroup N` | Мин. размер группы хостов | `--min-hostgroup 64` |
| `--max-hostgroup N` | Макс. размер группы хостов | `--max-hostgroup 256` |
| `--max-retries N` | Число повторов проб | `--max-retries 1` |
| `--host-timeout` | Таймаут на хост | `--host-timeout 5m` |
| `--initial-rtt-timeout` | Начальное ожидание ответа | `--initial-rtt-timeout 100ms` |
| `--max-rtt-timeout` | Максимальное ожидание ответа | `--max-rtt-timeout 200ms` |
| `--scan-delay N` | Пауза между пробами (мин.) | `--scan-delay 1s` |
| `--max-scan-delay N` | Макс. пауза между пробами | `--max-scan-delay 10s` |

`-T0/-T1` — для IDS-чувствительных целей, `-T3` — по умолчанию, `-T4` — быстрая локальная сеть, `-T5` — только лаборатория. В реальной сети `-T5` даёт ложные результаты.

```bash
nmap -sS -p- -T4 --min-rate 3000 --max-retries 1 -oA fast 10.0.0.5
nmap -sS -p- -T2 --max-rate 100 -oA stealth 10.0.0.5
```

## Обход фильтров и скрытность

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-f` | Фрагментировать пакеты (8 байт) | `nmap -f 10.0.0.5` |
| `--mtu N` | Свой размер фрагмента (кратен 8) | `--mtu 16` |
| `-D <decoys>` | Приманки-хосты | `-D RND:10` |
| `-S <ip>` | Подменить исходный IP (spoof) | `-S 10.0.0.9 -e eth0` |
| `-e <iface>` | Интерфейс | `-e eth0` |
| `--source-port N` / `-g N` | Исходный порт (обход правил) | `--source-port 53` |
| `--data <hex>` | Доп. payload в hex | `--data 0xdeadbeef` |
| `--data-string <s>` | Доп. ASCII-строка в пакет | `--data-string "hello"` |
| `--data-length N` | Добить пакет случайными данными | `--data-length 25` |
| `--ip-options <opts>` | IP-опции | `--ip-options 'R'` |
| `--ttl N` | Задать IP TTL | `--ttl 64` |
| `--badsum` | Пакеты с неверной контрольной суммой | `--badsum` |
| `--randomize-hosts` | Перемешать порядок хостов | `--randomize-hosts` |
| `--spoof-mac <mac>` | Подменить MAC | `--spoof-mac 0` |
| `--proxies` | Через HTTP/SOCKS-прокси | `--proxies socks4://127.0.0.1:9050` |
| `--send-eth` / `--send-ip` | Слать кадры Ethernet / IP-пакеты | `--send-ip` |

```bash
sudo nmap -sS -f --mtu 16 --source-port 53 -T2 10.0.0.5
sudo nmap -sS -D RND:10 10.0.0.5
```

Приманки (`-D RND:10`) маскируют ваш IP среди случайных, но в локальной сети почти бесполезны. `--source-port 53` обходит глупые фильтры, разрешающие «ответы DNS».

## Форматы вывода и автоматизация

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-oN file` | Обычный текстовый вывод | `-oN scan.txt` |
| `-oX file` | XML (парсится машиной) | `-oX scan.xml` |
| `-oG file` | Grepable (удобно грепать) | `-oG scan.gnmap` |
| `-oS file` | «Script kiddie» формат | `-oS scan.l33t` |
| `-oA base` | Все три сразу (`base.nmap/.xml/.gnmap`) | `-oA scan_full` |
| `--append-output` | Дописывать, а не перезаписывать файлы | `--append-output -oN s.txt` |
| `--resume <file>` | Продолжить прерванный скан | `--resume scan.gnmap` |
| `--reason` | Показывать причину состояния порта | `--reason` |
| `-v` / `-vv` | Подробнее | `-vv` |
| `-d` / `-dd` | Отладочный вывод | `-d` |
| `--packet-trace` | Показывать все отправленные/принятые пакеты | `--packet-trace` |
| `--stats-every 10s` | Прогресс каждые 10 сек | `--stats-every 10s` |
| `--iflist` | Список интерфейсов и маршрутов | `--iflist` |
| `--open` | Показывать только открытые порты | `--open` |
| `--noninteractive` | Отключить интерактив клавиатуры | `--noninteractive` |
| `--stylesheet <f>` | XSL для HTML-отчёта | `--stylesheet nmap.xsl` |
| `--webxml` | Ссылаться на стиль Nmap.Org | `--webxml` |
| `--no-stylesheet` | Без XSL в XML | `--no-stylesheet` |
| `--datadir <dir>` | Своя папка данных nmap | `--datadir /opt/nmap` |

```bash
nmap -sS -sV -p- -oA scan_full 10.0.0.5
grep -E "open" scan_full.gnmap
nmap -sS -oX - 10.0.0.5 | xsltproc nmap.xsl - > report.html
```

Всегда сохраняйте `-oA` — потом данные парсятся скриптами (`nmap_parse`, python-libnmap) без повторного скана.

## IPv6, DNS и особые случаи

```bash
nmap -6 -sS fe80::1%eth0          # сканирование IPv6
nmap --resolve-all 10.0.0.5       # все адреса имени
nmap -Pn -sS -p 80 --open 10.0.0.0/24   # только открытые порты
nmap -sV --open -iL targets.txt -oA out
```

`--open` показывает только хосты с открытыми портами — экономит глаза. `-6` включает IPv6 (там нет ARP и часть типов сканов недоступна).

## Агрессивный режим и прочие флаги

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-A` | Агрессивный режим: `-O -sV -sC --traceroute` одним флагом | `nmap -A 10.0.0.5` |
| `--privileged` | Считать, что есть raw-права | `--privileged` |
| `--unprivileged` | Считать, что raw-прав нет | `--unprivileged` |
| `-V` | Версия nmap | `nmap -V` |
| `-h` | Краткая справка | `nmap -h` |

`-A` — «всё сразу»: определение ОС + версии сервисов + дефолтные NSE-скрипты + traceroute. Идеально для одиночного хоста, слишком шумно для большого диапазона.

## Практические рецепты: что запускать и когда

**Быстрая полная разведка одного хоста (основной рабочий запуск):**

```bash
nmap -sS -sV -sC -p- -T4 --min-rate 2000 -oA host_full 10.0.0.5
```

**Тихо, чтобы не задеть IDS:**

```bash
nmap -sS -T2 --max-rate 100 -f --source-port 53 -p 1-1024 10.0.0.5
```

**UDP top-порты:**

```bash
sudo nmap -sU --top-ports 50 -T4 10.0.0.5
```

**Проверка уязвимостей:**

```bash
nmap -sV --script vuln -p 80,443,445,3306 10.0.0.5
```

**Энумерация SMB:**

```bash
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery 10.0.0.5
```

**Определение ОС и сервисов для хоста из сегмента:**

```bash
sudo nmap -O -sV --osscan-guess -p 22,80,443 10.0.0.5
```

**Живые хосты в подсети:**

```bash
sudo nmap -sn -PS22,80,443,3389 10.0.0.0/24 -oG alive.gnmap
grep Up alive.gnmap
```

## Частые ошибки

- **Забыть `-Pn`.** Хост с закрытым ICMP покажется мёртвым. В интернете и в фильтруемых сетях всегда проверяйте `-Pn`.
- **Гнаться за `-T5`.** В реальной сети это ложные срабатывания и бан от IDS. По умолчанию `-T4` в локалке, `-T2` в чувствительной среде.
- **Не сохранять вывод.** Без `-oA` большой скан приходится повторять. XML потом парсится инструментами.
- **Слепо включать `--script vuln`.** Некоторые скрипты роняют сервис. В продакшене — точечно и по согласованию.
- **Путать `open|filtered`.** Это не «открыт»: для UDP/фильтруемых портов результат неоднозначен — уточняйте другими сканами.

## Квиз

```quiz
- question: "Каким флагом nmap заставляет сканировать хост, который не отвечает на ping?"
  options:
    - "-Pn"
    - "-sn"
    - "-PE"
    - "-PS"
  answer: 0
  explanation: "-Pn отключает хост-дискавери и считает цель живой — обязательно при закрытом ICMP."
- question: "Какой флаг сканирует все 65535 портов?"
  options:
    - "-p all"
    - "-p-"
    - "-F"
    - "--top-ports"
  answer: 1
  explanation: "-p- это сокращение диапазона 1-65535; -F — только top-100."
- question: "Что делает ключ -sC?"
  options:
    - "Запускает дефолтный набор NSE-скриптов"
    - "Определяет версию ОС"
    - "Сканирует UDP"
    - "Сохраняет вывод в CSV"
  answer: 0
  explanation: "-sC = --script=default: типовые скрипты перечисления без явного указания имён."
- question: "Какой формат вывода сразу создаёт текстовый, XML и grepable-файлы?"
  options:
    - "-oN"
    - "-oX"
    - "-oG"
    - "-oA"
  answer: 3
  explanation: "-oA <base> пишет base.nmap, base.xml и base.gnmap одновременно."
- question: "Зачем в тихом скане добавляют --source-port 53?"
  options:
    - "Чтобы обойти фильтры, пропускающие трафик с порта DNS"
    - "Чтобы ускорить скан в 53 раза"
    - "Чтобы определить версию сервиса"
    - "Чтобы включить IPv6"
  answer: 0
  explanation: "Некоторые ACL разрешают входящий трафик с source port 53 (ответы DNS) — это классический обход."
```

## Где пригодится

- **CTF:** Network/Pentest — быстро найти сервис и его версию, дальше выбрать эксплойт.
- **Bug bounty:** инвентаризация периметра перед веб-анализом, поиск нестандартных портов.
- **Пентест:** первый активный этап любого проекта — карта хостов, портов, сервисов и версий.
- **Работа:** аудит конфигураций и инвентаризация; SOC — проверка доступности сервисов.
