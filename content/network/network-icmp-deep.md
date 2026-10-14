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
lab:
  kind: shell
  title: "Практика: типы ICMP"
  toolset: [core, tshark]
  workdir: /home/student/task
  files: [task.md, icmp.pcap]
  check: "grep -q '3' answer.txt"
  hints:
    - "Типы ICMP: `tshark -r icmp.pcap -Y icmp -T fields -e icmp.type`."
    - "8 — echo request, 0 — echo reply, 11 — time exceeded, 3 — destination unreachable."
    - "Ошибка доставки — это Destination Unreachable, тип 3."
---

## Вопрос, с которого всё начинается

`ping` до сервера `10.10.20.5` проходит, но TLS-сессия с ним «зависает» на крупных пакетах: мелкие проходят, а передача данных замирает. Классический симптом, который ищут часами.

ICMP — не «просто ping». Это полноценный служебный протокол: он сообщает об ошибках, перенаправляет трафик и картографирует маршрут. Разберём один такой случай и попутно поймём весь ICMP.

## Наш пример: почему крупные пакеты не проходят

Трассируем путь до цели и смотрим на MTU:

```
$ tracepath 10.10.20.5
 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                          0.512ms
 2:  10.10.0.1                         1.204ms asymm 3
 3:  10.10.20.5                        4.331ms reached
     Resume: pmtu 1400 hops 3 back 3
```

Обрати внимание: локальный MTU — `1500`, а до цели — `1400`. Где-то на пути MTU меньше, и об этом хосту сообщают как раз через ICMP. Проверим, где начинается предел:

```
$ ping -M do -s 1472 10.10.20.5
ping: local error: message too long, mtu=1400
$ ping -M do -s 1372 10.10.20.5
1380 bytes from 10.10.20.5: icmp_seq=1 ttl=62 time=4.31 ms
```

`-M do` запрещает фрагментацию. Пакет 1472 байта «не лезет» в MTU 1400, а 1372 — проходит. Смотрим, кто именно сообщил о пределе:

```
$ sudo tcpdump -i eth0 -nn 'icmp[icmptype]==3 and icmp[icmpcode]==4' -c 1
10.10.0.1 > 10.0.0.2: ICMP 10.10.20.5 unreachable - need to frag (mtu 1400), length 556
```

Вот он — **ICMP type 3, code 4**: «Fragmentation needed, but DF set». Маршрутизатор `10.10.0.1` не смог протолкнуть пакет и сообщил хосту нужный MTU. Это **PMTU discovery** (Path MTU Discovery). Если такое сообщение заблокировать firewall'ом, получится «чёрная дыра»: ping идёт, а крупные пакеты молча теряются — ровно наш симптом.

## Шаг 1: карта типов ICMP

Чтобы понимать ICMP, надо знать его типы. Вот основные:

| Type | Название | Зачем |
|---|---|---|
| 0 / 8 | Echo Reply / Request | ping |
| 3 | Destination Unreachable | сеть/хост/порт недоступны, frag needed |
| 5 | Redirect | «шлюз лучше по такому адресу» |
| 11 | Time Exceeded | TTL истёк (traceroute) |
| 13 / 14 | Timestamp Request / Reply | время на хосте |
| 9 / 10 | Router Advertise / Solicit | обнаружение маршрутизаторов |

Посмотреть, какие типы есть в дампе, можно так:

```
$ tshark -r cap.pcap -Y 'icmp' -T fields -e icmp.type | sort | uniq -c | sort -rn
   412	8
    88	0
     3	11
```

У type 3 есть коды: 0 (net unreachable), 1 (host unreachable), 2 (protocol unreachable), 3 (port unreachable), 4 (**frag needed**), 13 (admin prohibited). Код 13 — удобный индикатор firewall: значит пакет дошёл до фильтра и был отклонён политикой.

## Шаг 2: как traceroute узнаёт маршрут

Механизм traceroute целиком держится на ICMP. **TTL** (Time To Live) уменьшается на каждом маршрутизаторе; когда он доходит до нуля, устройство отбрасывает пакет и отвечает **ICMP Time Exceeded (type 11)**. Traceroute шлёт пакеты с TTL=1, 2, 3… и собирает ответы с каждого хопа:

```
$ traceroute -n 8.8.8.8
 1  10.0.0.1      0.512 ms
 2  10.10.0.1     1.204 ms
 3  8.8.8.8      12.402 ms
```

Разные протоколы дают разные карты из-за фильтров, и это полезно для атакующего — видно, что «проходит»:

```
$ traceroute -I -n 8.8.8.8      # ICMP
$ sudo traceroute -T -p 443 -n 8.8.8.8   # TCP SYN на 443 — обходит блокировки
```

## Шаг 3: ICMP Redirect — тихий MITM

**Type 5 (Redirect)** сообщает хосту: «для этой подсети используй другой шлюз». Легитимно это бывает при двух маршрутизаторах в сегменте. Опасно тем, что атакующий может подделать redirect и заставить жертву гнать трафик через него:

```python
from scapy.all import *
pkt = IP(src="10.0.0.1", dst="10.0.0.50")/ICMP(type=5, gw="10.0.0.99")/IP(src="10.0.0.50", dst="8.8.8.8")/UDP()
send(pkt)
```

Защита проста: отключить приём redirect'ов на хостах и отправку на маршрутизаторах.

```
$ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_redirects = 0
```

## Шаг 4: ICMP-сканирование и timestamp

ICMP годится и для разведки. Ping-скан тише TCP-скана, но часто блокируется:

```
$ nmap -sn 10.0.0.0/24
$ fping -a -g 10.0.0.0/24 2>/dev/null
10.0.0.1
10.0.0.5
```

Если ping «не работает», хост может быть жив — проверьте другие типы. **Type 13/14 (Timestamp)** отдают время хоста, что полезно для синхронизации атак (Kerberos, TLS) и определения ОС.

## ICMP-флуд и PMTU на практике

Простейшая DoS — завалить цель echo-запросами. Даже если хост отвечает, канал и CPU загружаются; современные ОС rate-лимитируют ICMP, но флуд опасен для старых устройств и каналов.

```
$ sudo hping3 --icmp --flood -d 1200 10.0.0.1
```

А вот PMTU мы уже разобрали на примере: когда хост шлёт крупный пакет с флагом **DF**, а MTU на пути меньше, маршрутизатор отвечает **type 3 code 4** с нужным MTU, и хост уменьшает размер. Если этот ICMP заблокирован — «чёрная дыра»: мелкие пакеты идут, крупные теряются. Типичный симптом — TLS-хендшейк проходит, а передача данных «зависает».

```
$ ping -M do -s 1472 8.8.8.8 && echo "1500 OK"
$ tracepath 8.8.8.8
```

## ICMPv6: те же идеи, другие типы

В IPv6 ICMP играет куда большую роль: на нём построены Neighbor Discovery, Router Advertisement и PMTU. Типы: 128/129 (echo), 133/134 (Router Solicit/Advertise), 135/136 (Neighbor Solicit/Advertise), 2 (packet too big). Если блокировать **packet too big**, ломается PMTUD в IPv6 — та же «чёрная дыра», что и в IPv4.

## Что мы теперь знаем

- ICMP — это не только ping: unreachable, redirect, time exceeded, timestamp.
- Type 3 code 4 (frag needed) обеспечивает PMTU discovery; его блокировка = «чёрная дыра».
- Traceroute работает на TTL и ICMP type 11.
- ICMP redirect (type 5) позволяет перенаправить трафик жертвы — тихий MITM.
- ICMP применяют и для сканирования хостов, и для covert-каналов.

## Разбираем ICMP unreachable и PMTU в дампе

Вернёмся к ситуации «крупные пакеты не проходят». Причина часто в **PMTU** (Path MTU Discovery). Хост шлёт пакет, который не влезает в линк по пути, и получает обратно ICMP-сообщение «фрагментация нужна, но запрещена»:

```
$ sudo tcpdump -i eth0 -nn -v 'icmp' -c 3
10.0.0.1 > 10.0.0.9: ICMP 10.0.0.9 unreachable - need to frag (mtu 1400), length 556
10.0.0.9 > 10.0.0.1: ICMP echo request, id 4711, seq 1, length 64
10.0.0.1 > 10.0.0.9: ICMP echo reply, id 4711, seq 1, length 64
```

Первая строка — тип 3, код 4 (`need to frag`), и в ней указан MTU узкого места (1400). Хост должен снизить размер пакета до 1400 и повторить. Если ICMP по пути **фильтруется** (частая ошибка), хост о снижении не узнает и соединение «зависнет» на крупных данных — типичный симптом «ping работает, а сайт не открывается».

## Карта значимых типов ICMP

| Тип | Название | Зачем смотреть |
|---|---|---|
| 0 / 8 | Echo reply / request | ping, обнаружение хостов |
| 3 | Destination Unreachable | нет маршрута/порта/фрагментации |
| 5 | Redirect | тихий подмена шлюза |
| 11 | Time Exceeded | основа traceroute (TTL=0) |
| 12 | Parameter Problem | ошибка в заголовке |
| 13 / 14 | Timestamp request/reply | устаревший, раскрывает время |

Для сканирования особенно полезен тип 3: **code 3** (port unreachable) на UDP говорит, что порт закрыт, а **code 0** (net unreachable) — что не туда маршрутизируют. Разница между «порт закрыт» и «хост недоступен» для пентеста принципиальна.

## ICMP Redirect: тихий MITM

Тип 5 заслуживает отдельного внимания. Когда хост шлёт пакет неоптимальным путём, шлюз может ответить «иди напрямую через X». Проблема — ответ **не аутентифицирован**, и атакующий может подсунуть себя:

```
10.0.0.1 > 10.0.0.9: ICMP redirect 10.0.0.20 to host 10.0.0.66, length 36
```

Читается: «для 10.0.0.20 используй 10.0.0.66». Если жертва примет редирект, весь её трафик к цели пойдёт через атакующего — без ARP-спуфинга. Лечение простое: на хостах `sysctl net.ipv4.conf.all.accept_redirects=0`, на шлюзах `send_redirects=0`.

## ICMPv6: те же идеи, другие номера

В IPv6 у ICMP своя нумерация, но логика та же. Особенно важны два типа:

- **Neighbor Solicitation / Advertisement (135/136)** — замена ARP; спуфинг NS/NA даёт MITM.
- **Router Advertisement (134)** — раздаёт адреса и шлюз; rogue RA делает атакующего шлюзом (разбирается в уроке про IPv6).

Практический нюанс: IPv6-сети часто блокируют «лишний» ICMP, но при этом сам ICMPv6 **нельзя** блокировать полностью — без него не работает Neighbor Discovery и PMTU. Поэтому политики для v4 и v6 должны различаться.

## Если не сработало: ICMP молчит

Пинг не отвечает — это ещё не значит «хоста нет». Многие фильтруют ICMP целиком, и тогда `nmap` без `-Pn` пропустит живую машину. Используй альтернативные методы: TCP SYN на открытый порт, TCP ACK (для определения firewall), или ARP (в своём L2-сегменте — его не фильтруют). И не путай «unreachable» с «filtered»: первое приходит от маршрутизатора, второе — просто отсутствие ответа.

## Квиз

Проверь себя.

```quiz
- question: 'Какой тип ICMP сообщает об истечении TTL?'
  options:
    - '11'
    - '8'
    - '3'
    - '5'
  answer: 0
  explanation: 'Type 11 Time Exceeded — основа traceroute.'
- question: 'Что означает код 4 в Destination Unreachable?'
  options:
    - 'Fragmentation needed, but DF set (нужен меньший MTU)'
    - 'Порт закрыт'
    - 'Сеть недоступна'
    - 'Административный запрет'
  answer: 0
  explanation: 'Код 4 — frag needed; критичен для PMTU discovery.'
- question: 'Чем опасен ICMP redirect?'
  options:
    - 'Позволяет перенаправить трафик жертвы через атакующего'
    - 'Ускоряет сеть'
    - 'Шифрует данные'
    - 'Назначает IP'
  answer: 0
  explanation: 'Type 5 меняет шлюз по умолчанию для подсети.'
- question: 'Как traceroute узнаёт промежуточные хопы?'
  options:
    - 'Шлёт пакеты с увеличивающимся TTL и ловит Time Exceeded'
    - 'Читает DNS'
    - 'Использует ARP'
    - 'Спрашивает DHCP'
  answer: 0
  explanation: 'Каждый хоп, где TTL истёк, отвечает ICMP type 11.'
- question: 'Какой признак указывает на ICMP-туннель?'
  options:
    - 'Большой нестандартный payload и высокая частота'
    - 'TTL=64'
    - 'Ровные короткие пинги'
    - 'ICMP отключён'
  answer: 0
  explanation: 'Туннель несёт данные — растут payload и частота.'
```

## Куда дальше

Мы разобрали служебную сторону ICMP и один практический случай с MTU. Дальше — UDP-протоколы, где тоже есть свои ловушки и слабости. А пока запомни: **ICMP — это язык, на котором сеть сообщает о своих проблемах, и его сообщения можно как блокировать себе во вред, так и использовать против цели.**

## Где пригодится

- **CTF:** задачи на traceroute, ICMP-типы, скрытые каналы.
- **Пентест:** ICMP-разведка, redirect-MITM, эксфильтрация.
- **SOC:** детект ICMP-туннелей, флуда и redirect.
- **Инженерия:** диагностика MTU и маршрутизации.
