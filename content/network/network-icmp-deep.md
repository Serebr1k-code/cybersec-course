---
id: network-icmp-deep
title: "ICMP глубоко: типы, redirect, TTL-трюки и сканирование"
category: network
parent: network-icmp-tunnel
difficulty: medium
order: 1
tags: [network, icmp, traceroute, redirect, ttl, ping, scanning]
prerequisites: [network-module-ip, network-icmp-tunnel]
useful_for:
  - "CTF Network (ICMP-задачи, traceroute)"
  - "Пентест: ICMP-разведка и скрытые каналы"
  - "Работа (SOC): детект ICMP-аномалий"
estimated_minutes: 55
summary: "Все значимые типы ICMP, ICMP redirect и его опасность, TTL как инструмент traceroute, ICMP-сканирование хостов и портов, timestamp и unreachable — с командами и разбором."
---

ICMP — не «просто ping». Это полноценный служебный протокол, который умеет сообщать об ошибках, перенаправлять трафик и даже картографировать маршрут. Понимание его типов объясняет, почему traceroute работает, почему ICMP-redirect опасен и как по ICMP можно сканировать сеть. Урок — часть модуля [`network-module-ip`](network-module-ip).

## Карта типов ICMP

| Type | Название | Зачем |
|---|---|---|
| 0 / 8 | Echo Reply / Request | ping |
| 3 | Destination Unreachable | сеть/хост/порт недоступны, frag needed |
| 4 | Source Quench | устарел (congestion) |
| 5 | Redirect | «шлюз лучше по такому адресу» |
| 9 / 10 | Router Advertise / Solicit | обнаружение маршрутизаторов |
| 11 | Time Exceeded | TTL истёк (traceroute) |
| 12 | Parameter Problem | битый заголовок |
| 13 / 14 | Timestamp Request / Reply | время на хосте |
| 15 / 16 | Information Request / Reply | устарел |

```bash
# Какие типы ICMP в дампе
tshark -r cap.pcap -Y 'icmp' -T fields -e icmp.type | sort | uniq -c | sort -rn
```

## ICMP Destination Unreachable: полезные коды

Type 3 имеет коды: 0 (net unreachable), 1 (host unreachable), 2 (protocol unreachable), 3 (port unreachable), 4 (**frag needed, DF set**), 13 (admin prohibited). Код 4 критичен для PMTU discovery: без него крупные сессии «зависают».

```bash
# Специально вызвать frag-needed
ping -M do -s 1473 10.0.0.1
# Ответ: "Frag needed and DF set"
```

Код 13 (admin prohibited) — удобный индикатор firewall: значит пакет дошёл до фильтра и был отклонён политикой.

## ICMP Redirect: перенаправление трафика

Type 5 сообщает хосту: «для этой подсети используй другой шлюз». Легитимно — когда есть два маршрутизатора в сегменте. Опасно: атакующий шлёт redirect и заставляет жертву гнать трафик через него.

```bash
# Отправить поддельный ICMP redirect (лаборатория)
python3 - <<'PY'
from scapy.all import *
pkt = IP(src="10.0.0.1", dst="10.0.0.50")/ICMP(type=5, gw="10.0.0.99")/IP(src="10.0.0.50", dst="8.8.8.8")/UDP()
send(pkt)
PY
```

Защита: `accept_redirects=0` на хостах, `no ip redirects` на маршрутизаторах.

```bash
# Отключить приём redirects
sysctl -w net.ipv4.conf.all.accept_redirects=0
```

## TTL и traceroute

TTL уменьшается на каждом маршрутизаторе. Traceroute шлёт пакеты с TTL=1,2,3… и собирает ICMP «Time Exceeded» от каждого хопа — так строится карта маршрута.

```bash
# Классический traceroute (UDP) и ICMP-вариант
traceroute 8.8.8.8
traceroute -I 8.8.8.8        # через ICMP
# Linux tracepath (не требует root)
tracepath 8.8.8.8
# Скапy-вариант с фиксированным TTL
python3 -c "from scapy.all import *; sr1(IP(dst='8.8.8.8',ttl=3)/ICMP(),verbose=0).show()"
```

## ICMP-сканирование хостов

```bash
# Ping-скан подсети
nmap -sn 10.0.0.0/24
# Быстрый параллельный пинг
fping -a -g 10.0.0.0/24 2>/dev/null
# Спуфинг источника (осторожно)
sudo hping3 --icmp -a 10.0.0.99 -c 2 10.0.0.1
```

ICMP-скан тише TCP-скана, но часто блокируется. Если ping «не работает», хост может быть жив — проверьте другие типы.

## Timestamp и Information: утечка времени

Type 13/14 отдают время хоста — полезно для синхронизации атак (Kerberos, TLS) и определения ОС. Многие хосты их игнорируют, но старые устройства отвечают.

```bash
# Timestamp-запрос через scapy
python3 -c "from scapy.all import *; sr1(IP(dst='10.0.0.1')/ICMP(type=13),timeout=2).show()"
```

## ICMP для туннелей и каналов

ICMP Echo несёт payload — это основа туннелей (ptunnel, icmpsh) и covert-каналов. Подробно — в [`network-icmp-tunnel`](network-icmp-tunnel). Здесь важно: **type/code/identifier/sequence** тоже можно использовать как скрытые биты.

```bash
# Данные в payload ping
ping -c 1 -p 666c6167 10.0.0.1
sudo tcpdump -i eth0 -nn -X icmp
```

## Детект ICMP-аномалий

- **Большой/нестандартный payload** — туннель или эксфильтрация;
- **высокая частота** echo-запросов — флуд/скан;
- **ICMP redirect** в сегменте — MITM;
- **необычные типы** (timestamp, router advertise) — разведка;
- **асимметрия** request/reply — подделка источника.

```bash
# Топ источников по числу echo-запросов
tshark -r cap.pcap -Y 'icmp.type==8' -T fields -e ip.src | sort | uniq -c | sort -rn | head
```

## Частые ошибки

- **Считать ICMP только ping** — есть redirect, timestamp, unreachable.
- **Блокировать весь ICMP** — ломает PMTU.
- **Игнорировать redirect** — тихий MITM.
- **Путать код 3/4** — port unreachable vs frag needed.
- **Забывать про rate-limit** — ICMP часто лимитируется.
- **Доверять traceroute как точной карте** — фильтры искажают.
- **Не проверять TTL ответа** — по нему оценивают ОС и число хопов.

## Что дальше / решение

После ICMP переходите к [`network-udp-deep`](network-udp-deep), [`network-ipv6-tunneling`](network-ipv6-tunneling) и [`network-dhcpv6`](network-dhcpv6). Для практики каналов — [`network-icmp-tunnel`](network-icmp-tunnel).

## ICMP-флуд и его последствия

Простейшая DoS-атака — завалить цель echo-запросами. Даже если хост отвечает, канал и CPU загружаются. Современные ОС rate-лимитируют ICMP, но флуд всё равно опасен для каналов и старых устройств.

```bash
# ICMP-флуд (только против своей лаборатории)
sudo hping3 --icmp --flood -d 1200 10.0.0.1
# Спуфинг источника — «слепой» флуд
sudo hping3 --icmp --flood -a 10.0.0.99 10.0.0.1
```

Защита — rate-limit ICMP на периметре и хосте (`net.ipv4.icmp_ratelimit`, `icmp_ratemask`).

## PMTU Discovery пошагово

Когда хост отправляет крупный пакет с флагом **DF** (don't fragment), а на пути MTU меньше, маршрутизатор отвечает **ICMP type 3 code 4** с указанием нужного MTU. Хост уменьшает размер и повторяет. Если этот ICMP заблокирован — «чёрная дыра»: мелкие пакеты идут, крупные теряются.

```bash
# Проверить PMTU до цели
tracepath 8.8.8.8
# Найти максимальный размер без фрагментации
ping -M do -s 1472 8.8.8.8 && echo "1500 OK"
ping -M do -s 1473 8.8.8.8 || echo "нужен меньший MTU"
```

Типичный симптом проблемы: TLS-хендшейк проходит, а передача данных «зависает» — как раз на пакете, превышающем MTU.

## Лаборатория: разбор ICMP-дампов

```bash
# 1. Собрать ICMP за минуту
sudo tcpdump -i eth0 -nn -w icmp.pcap icmp
# 2. Сводка типов
tshark -r icmp.pcap -T fields -e icmp.type | sort | uniq -c | sort -rn
# 3. Найти redirect
tshark -r icmp.pcap -Y 'icmp.type==5' -V | head -30
# 4. Найти frag-needed
tshark -r icmp.pcap -Y 'icmp.type==3 && icmp.code==4' | head
# 5. Оценить payload echo
tshark -r icmp.pcap -Y 'icmp.type==8' -T fields -e data.len | sort -n | uniq -c
```

Чек-лист анализа ICMP: типы, частота, размер payload, наличие redirect, асимметрия request/reply. Любое отклонение от baseline — повод копать глубже.

## ICMPv6 и его отличия

В IPv6 ICMP играет куда большую роль: на нём построены Neighbor Discovery, Router Advertisement, MLD и PMTU. Типы ICMPv6: 128/129 (echo), 133/134 (Router Solicit/Advertise), 135/136 (Neighbor Solicit/Advertise), 1 (unreachable), 2 (packet too big), 3 (time exceeded), 4 (parameter problem).

Особенность: **packet too big** (type 2) — аналог frag-needed. Если его блокировать, ломается PMTUD в IPv6. А **Neighbor Solicitation/Advertisement** — замена ARP, и их спуфинг даёт тот же эффект, что ARP-спуфинг в IPv4.

```bash
# Сводка типов ICMPv6
tshark -r cap.pcap -Y 'icmpv6' -T fields -e icmpv6.type | sort | uniq -c | sort -rn
# NDP-спуфинг виден по частым Advertisement
tshark -r cap.pcap -Y 'icmpv6.type==136' -T fields -e ipv6.src -e icmpv6.nd.na.target | head
```

## Практика: карта маршрута разными протоколами

Один и тот же маршрут можно трассировать ICMP, UDP и TCP — и получить разные карты из-за фильтров. Полезно сравнивать:

```bash
# UDP (по умолчанию) — часто фильтруется
traceroute -n 8.8.8.8
# ICMP
traceroute -I -n 8.8.8.8
# TCP SYN на 443 — обходит блокировки ICMP/UDP
sudo traceroute -T -p 443 -n 8.8.8.8
# Параллельно — версия в scapy с фиксированным TTL
python3 -c "from scapy.all import *; [sr1(IP(dst='8.8.8.8',ttl=t)/ICMP(),timeout=1,verbose=0).src for t in range(1,10)]"
```

Расхождение карт — признак фильтрации или промежуточного устройства, которое по-разному обрабатывает протоколы. Для атакующего это подсказка, какой протокол «проходит» дальше.

## Квиз

```quiz
- question: "Какой тип ICMP сообщает об истечении TTL?"
  options:
    - "11"
    - "8"
    - "3"
    - "5"
  answer: 0
  explanation: "Type 11 Time Exceeded — основа traceroute."
- question: "Что означает код 4 в Destination Unreachable?"
  options:
    - "Fragmentation needed, but DF set (нужен меньший MTU)"
    - "Порт закрыт"
    - "Сеть недоступна"
    - "Административный запрет"
  answer: 0
  explanation: "Код 4 — frag needed; критичен для PMTU discovery."
- question: "Чем опасен ICMP redirect?"
  options:
    - "Позволяет перенаправить трафик жертвы через атакующего"
    - "Ускоряет сеть"
    - "Шифрует данные"
    - "Назначает IP"
  answer: 0
  explanation: "Type 5 меняет шлюз по умолчанию для подсети."
- question: "Как traceroute узнаёт промежуточные хопы?"
  options:
    - "Шлёт пакеты с увеличивающимся TTL и ловит Time Exceeded"
    - "Читает DNS"
    - "Использует ARP"
    - "Спрашивает DHCP"
  answer: 0
  explanation: "Каждый хоп, где TTL истёк, отвечает ICMP type 11."
- question: "Какой признак указывает на ICMP-туннель?"
  options:
    - "Большой нестандартный payload и высокая частота"
    - "TTL=64"
    - "Ровные короткие пинги"
    - "ICMP отключён"
  answer: 0
  explanation: "Туннель несёт данные — растут payload и частота."
```

## Где пригодится

- **CTF:** задачи на traceroute, ICMP-типы, скрытые каналы.
- **Пентест:** ICMP-разведка, redirect-MITM, эксфильтрация.
- **SOC:** детект ICMP-туннелей, флуда и redirect.
- **Инженерия:** диагностика MTU и маршрутизации.
