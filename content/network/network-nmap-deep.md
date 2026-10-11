---
id: network-nmap-deep
title: "Nmap глубоко: NSE, тайминги, OS-фингерпринт и скрытность"
category: network
parent: network-portscan
difficulty: medium
order: 1
tags: [network, nmap, nse, fingerprint, timing, scanning]
prerequisites: [network-portscan, network-tcpip]
useful_for:
  - "CTF Network (разведка сервисов)"
  - "Пентест: точная карта сервисов и версий"
  - "Работа: инвентаризация и аудит"
estimated_minutes: 55
summary: "Продвинутый nmap: скриптовый движок NSE, точные тайминги, определение ОС, сканирование за фильтрами и UDP."
---
Nmap — не просто «сканер портов». Его главная сила — NSE (скриптовый движок), тайминги, OS-фингерпринт и техники скрытности. Этот урок — про глубокое использование nmap там, где базовый `-sS -sV` уже недостаточно. Разберём NSE-скрипты, тонкую настройку таймингов, фингерпринт ОС, скрытность и практические сценарии.

## NSE: архитектура и категории

NSE-скрипты написаны на Lua и выполняются встроенным интерпретатором. Скрипт получает информацию о порте/сервисе и может отправлять пакеты, делать запросы, парсить ответы. Категории:

| Категория | Смысл |
|---|---|
| `default` | безопасные, запускаются с `-sC` |
| `safe` | не ломают цель |
| `intrusive` | могут влиять на сервис |
| `vuln` | проверки уязвимостей |
| `exploit` | эксплуатация (осторожно!) |
| `auth` | обход/проверка аутентификации |
| `discovery` | сбор информации |
| `brute` | брутфорс |
| `dos` | отказ в обслуживании (опасно) |

```bash
# запуск по имени/категории/шаблону
nmap --script default -p 80,443 10.0.0.5
nmap --script "http-*" -p 80 10.0.0.5
nmap --script vuln -p 445,139 10.0.0.5
nmap --script smb-vuln-ms17-010 -p 445 10.0.0.5
nmap --script "not intrusive" -p 80 10.0.0.5
# передача аргументов скрипту
nmap --script http-brute --script-args http-brute.path=/admin -p 80 10.0.0.5
# список скриптов
ls /usr/share/nmap/scripts/ | grep smb
nmap --script-help http-enum
```

Операторы в выражении скриптов: `and`/`or`/`not` (по категориям), запятая — объединение. Так `--script "default or safe"` запускает безопасные, а `--script "(http-* or ssl-*) and not brute"` — все HTTP/TLS-скрипты, кроме брутфорса.

## Практические NSE-скрипты

```bash
# веб
nmap --script http-enum,http-title,http-headers,http-methods -p 80 10.0.0.5
nmap --script http-vuln-cve2021-41773 -p 80 10.0.0.5
nmap --script http-wordpress-enum -p 80 10.0.0.5

# SMB/Windows
nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p 445 10.0.0.5
nmap --script smb-vuln-* -p 445 10.0.0.5

# TLS
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed -p 443 10.0.0.5

# DNS
nmap --script dns-zone-transfer -p 53 10.0.0.5
nmap --script "dns-*" -p 53 10.0.0.5

# SNMP
nmap --script snmp-info,snmp-interfaces -sU -p 161 10.0.0.5
```

`-sC` эквивалентен `--script default`. Комбинируйте `-sV -sC` для максимума информации за один проход.

## Тайминги: тонкая настройка

Пресеты `-T0..-T5` — это наборы параметров. Иногда нужен ручной контроль:

```bash
nmap -sS --min-rate 1000 --max-rate 5000 \
     --min-parallelism 10 --max-parallelism 100 \
     --max-retries 2 --host-timeout 60s \
     --scan-delay 50ms --max-scan-delay 200ms \
     -p- 10.0.0.5
```

- `--min-rate/--max-rate` — пакетов в секунду.
- `--min-parallelism/--max-parallelism` — число проб в полёте.
- `--scan-delay/--max-scan-delay` — задержка между пробами (скрытность).
- `--max-retries` — меньше повторов = тише и быстрее.
- `--host-timeout` — не застревать.

Правило: для WAN `--max-retries 1..2` и разумный `--min-rate`; для LAN можно агрессивнее. Слишком высокий `--min-rate` на канале с потерями даёт ложные `filtered`.

## OS-фингерпринт

```bash
nmap -O --osscan-guess -p 22,80,443 10.0.0.5
nmap -O --osscan-limit 10.0.0.0/24      # только перспективные хосты
nmap -O --max-os-tries 2 10.0.0.5
```

Nmap отправляет серию проб (TCP/UDP/ICMP) и сравнивает с базой отпечатков. Точность зависит от открытых/закрытых портов: нужно минимум один открытый и один закрытый. `--osscan-guess` показывает вероятностную догадку. Фингерпринт также требует root (raw-сокеты) и работает хуже через NAT/прокси.

## Скрытность

```bash
# фрагментация
nmap -f -sS -p 80,443 10.0.0.5
# decoys
nmap -D RND:10 -sS -p 22 10.0.0.5
# source port из доверенных
nmap --source-port 53 -sS -p 22 10.0.0.5
# данные в опциях TCP (обход простых фильтров)
nmap --data-length 25 -sS -p 22 10.0.0.5
# медленно и тихо
nmap -T1 --scan-delay 1s -p- 10.0.0.5
# idle-скан через зомби
nmap -sI zombie.example.com 10.0.0.5
# спуфинг MAC (только в LAN)
nmap --spoof-mac 0 -sS -p 22 10.0.0.5
```

`-sI` (idle scan) полностью скрывает ваш IP, если у зомби предсказуемый IP ID — классическая техника, которую надо уметь объяснить. `--source-port 53` эксплуатирует правило firewall «доверять порту DNS»; `-f` разбивает заголовок на фрагменты, которые часть IDS не собирает.

## Разобранный пример: полный профиль хоста

```bash
# 1. быстрый обзор
nmap -sS -p- --min-rate 2000 -T4 -n -Pn 10.0.0.5 -oX p1.xml
# 2. сервисы, скрипты, ОС
nmap -sV -sC -O --osscan-guess -p 22,80,445,3306 10.0.0.5 -oX p2.xml
# 3. vuln-скрипты по найденному
nmap --script vuln -p 445 10.0.0.5
# 4. UDP
nmap -sU --top-ports 20 10.0.0.5
```

Вывод `-sV -sC -O`:

```
22/tcp   open  ssh     OpenSSH 8.4p1
80/tcp   open  http    Apache httpd 2.4.49
445/tcp  open  microsoft-ds Windows Server 2016
Running: Microsoft Windows 2016
```

Apache 2.4.49 — CVE-2021-41773 (path traversal/RCE) — сразу целевой NSE-скрипт. Это иллюстрирует принцип «версия → известная CVE → проверка».

## Разобранный пример: зонтрансфер и DNS

```bash
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 ns.example.com
# | dns-zone-transfer:
# | example.com. SOA ...
# | www.example.com. A 203.0.113.10
```

Если зона открыта — получаете полную карту домена без брута.

## Reference-таблица: NSE-скрипты по сервисам

| Сервис | Скрипты |
|---|---|
| HTTP | http-enum, http-title, http-headers, http-methods, http-vuln-* |
| SMB | smb-enum-shares, smb-enum-users, smb-os-discovery, smb-vuln-* |
| TLS/SSL | ssl-enum-ciphers, ssl-cert, ssl-heartbleed, ssl-poodle |
| DNS | dns-zone-transfer, dns-brute, dns-cache-snoop |
| SNMP | snmp-info, snmp-interfaces, snmp-brute |
| FTP | ftp-anon, ftp-brute, ftp-vsftpd-backdoor |
| SSH | ssh-auth-methods, ssh-hostkey, ssh-brute |
| SMTP | smtp-open-relay, smtp-enum-users, smtp-commands |
| RDP | rdp-enum-encryption, rdp-ntlm-info |
| VNC | vnc-info, vnc-brute |

## Reference-таблица: техники скрытности

| Техника | Флаг | Что скрывает |
|---|---|---|
| Фрагментация | `-f`/`-ff` | сигнатуру пакета от IDS |
| Decoys | `-D RND:10` | реальный источник |
| Source port | `--source-port 53` | обход фильтров по порту |
| Idle scan | `-sI zombie` | ваш IP полностью |
| MAC spoof | `--spoof-mac 0` | MAC в LAN |
| Медленный скан | `-T1 --scan-delay 1s` | аномалию скорости |

## Советы по производительности и надёжности

- `-n` отключает DNS-резолвинг — быстрее и меньше шума в логах резолвера.
- `-Pn` пропускает ping-проверку — обязательно, если ICMP заблокирован.
- `--open` показывает только открытые порты — чище вывод.
- `-oA basename` сохраняет сразу в трёх форматах (normal, XML, grepable).
- Для больших диапазонов сначала `masscan`, затем `nmap -sV` по найденным портам.
- Проверяйте результат повторным сканом с другими таймингами — `filtered` бывает ложным.

## Чек-лист глубокого nmap

1. Полный диапазон портов (`-p-`) с `--min-rate`.
2. Версии и скрипты (`-sV -sC`) — сохранить `-oX`.
3. OS-фингерпринт (`-O --osscan-guess`) при наличии открытого+закрытого порта.
4. Targeted NSE по сервисам (см. таблицу).
5. `--script vuln` по критичным портам.
6. UDP (`-sU`) и IPv6 (`-6`).
7. Для скрытности — `-sI`/decoys/source-port.
8. Скармливать `-oX` парсеру, а не грепать вручную.

## Частые ошибки

- `-T5` по WAN — потери и ложные `filtered`.
- `--script vuln` без нужды — шумно и иногда опасно (некоторые скрипты intrusive).
- `-O` без открытого/закрытого порта — фингерпринт ненадёжен.
- Игнорировать UDP и IPv6 (`-sU`, `-6`).
- Не сохранять `-oX` — теряется структурированный вывод.

## Что дальше / решение

Методика: `-sS -p-` → `-sV -sC -O` → targeted NSE (`vuln`, сервисные скрипты) → UDP/IPv6. Для скрытности — `-sI`, decoys, `--source-port`. Всегда сохраняйте `-oX` для парсера и отчёта. Nmap — это платформа: NSE превращает его в швейцарский нож разведки. Дальше — [`network-portscan`](network-portscan), [`network-service-enum`](network-service-enum) и [`network-masscan`](network-masscan).

## UDP и IPv6: то, что чаще всего забывают

UDP-скан (`-sU`) принципиально медленнее TCP: у UDP нет handshake, и «открыт» порт только если сервис ответит на специфичный зонд. Nmap отправляет пустой датаграм и ждёт ICMP port-unreachable (закрыт) или ответ (открыт); отсутствие ответа = `open|filtered`. Поэтому UDP всегда ограничивают топ-портами: `nmap -sU --top-ports 50 -sV -Pn 10.0.0.5`. Критичные UDP-сервисы, которые легко пропустить: DNS (53), SNMP (161), DHCP (67/68), NTP (123), TFTP (69), IPsec/IKE (500/4500), mDNS (5353), а также RDP-over-UDP и QUIC (443/udp).

IPv6 часто забывают: `nmap -6 -sS fe80::1%eth0` или по глобальному адресу. В IPv6 нет ARP (его роль играет NDP), а ICMPv6 критичен для работы — его фильтрация ломает сеть, поэтому `-6` сканы проходят там, где IPv4 прикрыт firewall. Отдельный полезный режим — `nmap -6 --script targets-ipv6-multicast-echo` для обнаружения хостов через multicast.

## Разбор вывода: парсинг -oX и -oG

`-oX` даёт XML, который удобно скармливать парсерам и конвертерам (`xsltproc`, `xmlstarlet`, Python-`xml.etree`). Быстрые выборки из grepable-формата (`-oG`): `grep 'Ports:' scan.gnmap` — все хосты с открытыми портами, `grep -oE '[0-9]+/open' scan.gnmap | sort | uniq -c` — частотность портов. Не грепайте XML регулярками вручную — используйте парсер (`nmap_parse` в этом фреймворке), чтобы не терять вложенную структуру скриптов.

## Квиз

```quiz
- question: "Какой флаг nmap включает NSE-скрипты по умолчанию?"
  options:
    - "-sC"
    - "-sV"
    - "-O"
    - "-Pn"
  answer: 0
  explanation: "-sC (--script=default) запускает стандартный набор скриптов."
- question: "Какой тип скана не требует root и работает через ОС?"
  options:
    - "-sT (connect)"
    - "-sS (SYN)"
    - "-sU (UDP)"
    - "-sA (ACK)"
  answer: 0
  explanation: "Connect-скан использует системный connect() и не требует привилегий."
- question: "Каким флагом задают паузу между зондами для обхода пороговых IDS?"
  options:
    - "--scan-delay"
    - "--min-rate"
    - "-oX"
    - "-n"
  answer: 0
  explanation: "--scan-delay добавляет задержку между зондами, снижая заметность."
- question: "Почему важно сканировать UDP?"
  options:
    - "Многие сервисы (DNS/SNMP/DHCP) работают только на UDP"
    - "UDP быстрее TCP"
    - "UDP не требует root"
    - "UDP показывает ОС"
  answer: 0
  explanation: "Пропуск UDP скрывает целые классы сервисов."
- question: "Какой флаг сохраняет результат во всех форматах сразу?"
  options:
    - "-oA"
    - "-oX"
    - "-oG"
    - "-oS"
  answer: 0
  explanation: "-oA сохраняет normal/greppable/XML — удобно для парсинга и отчётов."
```

## Где пригодится

- **CTF:** точная разведка сервисов и версий.
- **Пентест:** карта сервисов, скрипты, обход фильтров.
- **Работа:** инвентаризация и аудит инфраструктуры.
- **Bug bounty:** обнаружение технологий и уязвимостей.
- **IR:** понимание, что было доступно атакующему.
