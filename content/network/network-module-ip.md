---
id: network-module-ip
title: "Сетевой уровень глубоко: IPv4, ICMP, UDP и IPv6"
category: network
parent: network-frag-attacks
difficulty: easy
order: 1
tags: [network, ip, ipv4, icmp, udp, ipv6, l3]
prerequisites: [network-tcpip, network-basics]
useful_for:
  - "CTF Network (разбор L3-трафика)"
  - "Пентест: ICMP/UDP-разведка и туннели"
  - "Работа (SOC): анализ сетевых аномалий"
estimated_minutes: 60
summary: "Модуль по сетевому уровню: поля датаграммы IPv4, реальные возможности ICMP (redirect, traceroute, timestamp), UDP без соединений и мир IPv6 — база для практических уроков модуля."
lab:
  kind: shell
  title: "Практика: скрытый канал в ICMP"
  toolset: [core, tshark, tcpdump]
  workdir: /home/student/task
  files: [task.md, icmp.pcap]
  check: "grep -q 'nto{1cmp_3xf1l_4nd_c0v3rt_ch4nn3l}' answer.txt"
  hints:
    - "Сводка дампа: `tshark -r icmp.pcap -nn`."
    - "Кто-то выносит данные в полезной нагрузке эхо-запросов ICMP (`icmp.type==8`)."
    - "ASCII-содержимое пакетов: `tcpdump -r icmp.pcap -A icmp` (или `strings icmp.pcap`)."
    - "Метка в payload: `nto{1cmp_3xf1l_4nd_c0v3rt_ch4nn3l}`."
---

## Вопрос, с которого всё начинается

`ping` не проходит, но сеть работает, сайты открываются. Почему? Потому что за «сетью» стоит **сетевой уровень (L3)** — IP, — который доставляет датаграммы без гарантий и умеет много больше, чем кажется. Именно здесь спрятаны мощные инструменты разведки и атак: ICMP-редиректы, UDP-амплификация, переходные механизмы IPv6.

Этот модуль — теоретическая база для [`network-icmp-deep`](network-icmp-deep), [`network-udp-deep`](network-udp-deep), [`network-ipv6-tunneling`](network-ipv6-tunneling) и [`network-dhcpv6`](network-dhcpv6). Опирается на [`network-tcpip`](network-tcpip) и [`network-frag-attacks`](network-frag-attacks).

## Наш пример: разбираем один ICMP-пакет

Возьмём дамп и посмотрим, из чего состоит один пакет `ping`:

```
$ tshark -r cap.pcap -c 1 -V | grep -E "Internet Protocol|Time to Live|Protocol:|Type:|Code:"
Internet Protocol Version 4, Src: 10.0.0.5, Dst: 8.8.8.8
    Protocol: ICMP (1)
    Time to Live: 64
Internet Control Message Protocol
    Type: 8 (Echo (ping) request)
    Code: 0
```

Строка `Protocol: ICMP (1)` — это поле **Protocol** в IP-заголовке: число `1` означает ICMP (для сравнения: `6` — TCP, `17` — UDP). Поле **Time to Live** (`TTL`) ограничивает число хопов. `Type: 8` — это запрос ping. Разберём эти поля по порядку.

## Шаг 1: датаграмма IPv4

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Ключевые поля для анализа и атак: **TTL** (защита от петель; по нему оценивают число хопов), **Protocol** (что внутри), **Identification/Flags/Fragment Offset** (фрагментация), **TOS/DSCP** (приоритет). По полученному пакету можно грубо оценить путь: если ответ пришёл с TTL=57, а начальный TTL обычно 64, значит было ~7 маршрутизаторов.

## Шаг 2: ICMP — не только ping

ICMP — служебный протокол L3. Важные типы: `echo request/reply` (ping), `destination unreachable` (type 3, включая «нужна фрагментация»), `time exceeded` (type 11, на нём построен traceroute), `redirect` (type 5), `timestamp` (13/14), `router advertisement` (9/10).

```
$ tshark -r cap.pcap -Y 'icmp' -T fields -e icmp.type | sort | uniq -c
     42 8
     42 0
      3 3
      1 5
```

Здесь 42 запроса (`8`) и 42 ответа (`0`) — обычный ping, три «недостижимо» (`3`) и один **redirect** (`5`). ICMP-redirect говорит хосту «ходи к этой сети через другой шлюз» — то есть L3 можно перенаправить без всякой аутентификации.

Многие фильтры блокируют «весь ICMP» — и ломают определение MTU пути (**PMTU discovery**) и диагностику. Правильно — разрешать нужные типы. Подробно — в [`network-icmp-deep`](network-icmp-deep).

## Шаг 3: UDP — простота и её последствия

UDP-заголовок — всего 8 байт: порт источника, порт назначения, длина, контрольная сумма. Нет соединения, нет состояния, нет подтверждений. Следствия:

- **спуфинг тривиален** — ответ уйдёт жертве, а не атакующему;
- **амплификация** — маленький запрос с поддельным адресом источника вызывает большой ответ (DNS, NTP, memcached);
- **UDP-скан шумный и медленный** — нет SYN/RST, статус порта неоднозначен.

```
$ nmap -sU -p 53,123,161 10.0.0.1
PORT    STATE         SERVICE
53/udp  open          domain
123/udp open|filtered ntp
161/udp closed        snmp
```

Обратите внимание на `open|filtered` у порта 123 — это и есть неоднозначность UDP: нет ответа, а значит либо открыт и молчит, либо отфильтрован.

## Шаг 4: IPv6 — другой мир

IPv6 использует 128-битные адреса. В нём нет broadcast (есть multicast), нет ARP (его заменяет **Neighbor Discovery**), а адрес можно получить автоматически без DHCP через **SLAAC**. Заголовок фиксированный (40 байт) с цепочкой extension-заголовков. Атаки: RA-спуфинг, NDP-poisoning, rogue DHCPv6, туннелирование.

```
$ ip -6 addr show
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link
    inet6 2001:db8::5/64 scope global
$ ip -6 neigh show
2001:db8::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
```

`scope link` — локальный адрес (аналог MAC-производного), `scope global` — маршрутизируемый. `neigh show` — это NDP-таблица, аналог ARP-кэша.

| Свойство | IPv4 | IPv6 |
|---|---|---|
| Длина адреса | 32 бита | 128 бит |
| Заголовок | 20–60 байт | 40 байт |
| Контрольная сумма | есть | нет |
| Фрагментация | маршрутизаторами и хостами | только источником |
| Broadcast | есть | нет (multicast) |
| ARP | есть | NDP (ICMPv6) |
| Автоконфигурация | DHCP | SLAAC + DHCPv6 |
| TTL | TTL | Hop Limit |

## Шаг 5: путь пакета и размеры заголовков

Данные идут сверху вниз: приложение → TCP/UDP → IP → Ethernet. На каждом уровне добавляется заголовок. Полезно помнить накладные расходы: Ethernet 14+4, IP 20, TCP 20, UDP 8. Отсюда максимальный TCP-payload в 1500-байтном кадре — 1460 байт.

```
$ tshark -r cap.pcap -V -c 1 | grep -E "Frame|Ethernet|Internet Protocol|Transmission Control"
Frame 1: 74 bytes on wire
Ethernet II, Src: ..., Dst: ...
Internet Protocol Version 4, Src: 10.0.0.5, Dst: 8.8.8.8
Transmission Control Protocol, Src Port: 51234, Dst Port: 443
```

Если датаграмма больше MTU канала, она фрагментируется; фрагменты собираются на получателе по полю Identification. Атаки на этом — teardrop, overlap, tiny fragment (см. [`network-frag-attacks`](network-frag-attacks)).

## Что мы теперь знаем

- IP доставляет датаграммы без гарантий; поля TTL, Protocol, фрагментации — основа анализа.
- ICMP умеет много: redirect, unreachable, time exceeded, timestamp — и всё без аутентификации.
- UDP без состояния: тривиальный спуфинг и амплификация; скан неоднозначен.
- IPv6 заменяет ARP на NDP, DHCP на SLAAC, добавляя свои атаки.
- «Не работает ping» и «сеть жива» — обычно следствие фильтрации ICMP.

## Если защита мешает

- **Блокировка ICMP.** Обходится TCP/UDP-пробами (`hping3`, `nmap -PS/-PA`) — но тогда теряется часть диагностики.
- **Фильтрация IPv6.** Двойной стек часто фильтруют слабее — проверяй оба протокола.
- **Анти-спуфинг (uRPF).** Подделка адреса источника режется — амплификация из сегмента не сработает.
- **PMTU чёрные дыры.** Большие пакеты теряются — уменьшай размер (`ping -M do -s 1400`).

<!-- lab -->

## Практика: разбор L3 в дампе

```
$ tcpdump -i eth0 -nn -v -c 3 'ip'
$ tshark -r cap.pcap -T fields -e ip.ttl -e ip.proto | head
$ tshark -r cap.pcap -Y 'ip.flags.mf==1 || ip.frag_offset>0' | head
$ nmap -sn -PE 10.0.0.0/24 --reason | grep -i ttl
```

Первые три команды разбирают заголовки и находят фрагментированные пакеты, последняя — оценивает топологию по TTL: разница TTL между хостами одной подсети обычно постоянна, а отклонение указывает на промежуточное устройство или туннель.

## Квиз

Проверь себя.

```quiz
- question: 'Какой номер протокола в IP-заголовке соответствует UDP?'
  options:
    - '17'
    - '6'
    - '1'
    - '41'
  answer: 0
  explanation: 'Protocol=17 — UDP; 6 — TCP, 1 — ICMP.'
- question: 'Что кодирует поле TTL?'
  options:
    - 'Максимальное число хопов до отбрасывания пакета'
    - 'Длину пакета'
    - 'Тип сервиса'
    - 'Адрес источника'
  answer: 0
  explanation: 'TTL уменьшается на каждом маршрутизаторе; при 0 пакет дропается.'
- question: 'Почему UDP удобен для амплификации?'
  options:
    - 'Нет рукопожатия и можно подделать src-адрес'
    - 'Он шифрует данные'
    - 'Он надёжен'
    - 'Он использует порт 443'
  answer: 0
  explanation: 'UDP без состояния: поддельный src и маленький запрос дают большой ответ жертве.'
- question: 'Чем IPv6 заменяет ARP?'
  options:
    - 'Neighbor Discovery'
    - 'DHCPv6'
    - 'SLAAC'
    - 'ICMPv6 echo'
  answer: 0
  explanation: 'NDP разрешает адреса L2 для IPv6-адресов.'
- question: 'Почему нельзя блокировать весь ICMP?'
  options:
    - 'Сломается PMTU discovery и диагностика'
    - 'Ускорится сеть'
    - 'Отключится IPv6'
    - 'Пропадёт DNS'
  answer: 0
  explanation: 'Нужны как минимум frag-needed и time-exceeded.'
```

## Куда дальше

Мы разобрали сетевой уровень от заголовка IPv4 до IPv6. Дальше — четыре практических урока: [`network-icmp-deep`](network-icmp-deep), [`network-udp-deep`](network-udp-deep), [`network-ipv6-tunneling`](network-ipv6-tunneling), [`network-dhcpv6`](network-dhcpv6). А пока запомни: **L3 доверяет адресам и служебным сообщениям без аутентификации — отсюда и redirect, и амплификация, и RA-спуфинг.**

## Где пригодится

- **CTF:** задачи на разбор L3, ICMP-каналы, IPv6.
- **Пентест:** ICMP/UDP-разведка, туннели через переходные механизмы.
- **SOC:** анализ аномалий L3, амплификации, фрагментации.
- **Инженерия:** диагностика MTU и маршрутизации.
