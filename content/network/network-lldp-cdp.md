---
id: network-lldp-cdp
title: "LLDP и CDP: разведка топологии через discovery-протоколы"
category: network
parent: network-module-l2
difficulty: easy
order: 2
tags: [network, lldp, cdp, discovery, recon, topology, 802.1ab]
prerequisites: [network-ethernet, network-module-l2]
useful_for:
  - "CTF Network (разбор discovery-кадров)"
  - "Пентест: пассивная разведка топологии без сканирования"
  - "Работа (SOC): инвентаризация и детект rogue-устройств"
estimated_minutes: 50
summary: "LLDP (802.1AB) и CDP: какие поля раскрывают устройство, порт, VLAN и версию ПО; как пассивно собрать топологию из дампа и почему discovery-протоколы — утечка и вектор атаки."
---

Пока одни сканируют порты, другие просто **слушают**. Коммутаторы и маршрутизаторы сами объявляют о себе через **LLDP** и **CDP**: имя устройства, модель, версию ОС, порт, VLAN. Это готовая карта сети без единого активного пакета. Урок продолжает модуль [`network-module-l2`](network-module-l2) и опирается на [`network-ethernet`](network-ethernet).

## Что такое LLDP и CDP

- **LLDP** (Link Layer Discovery Protocol, IEEE 802.1AB) — вендоронезависимый. Отправляет кадры с EtherType `0x88CC` на multicast `01:80:c2:00:00:0e` раз в 30 секунд.
- **CDP** (Cisco Discovery Protocol) — проприетарный Cisco. EtherType `0x2000`, multicast `01:00:0c:cc:cc:cc`, раз в 60 секунд. Болтливее: несёт native VLAN, management IP, IOS-версию.

Оба протокола **не маршрутизируются** — работают только между соседями по L2.

## Какие поля раскрывают LLDP

LLDP — это TLV (Type-Length-Value) блоки. Основные:

| TLV | Содержимое |
|---|---|
| Chassis ID | MAC или имя шасси устройства |
| Port ID | имя/номер порта |
| TTL | время жизни записи |
| System Name | hostname |
| System Description | модель + версия ОС |
| Port Description | описание порта |
| Management Address | IP управления |
| VLAN / PVID | VLAN порта |
| Capabilities | switch/router/AP |

```bash
# Захватить LLDP
sudo tcpdump -i eth0 -nn -v -c 3 'ether proto 0x88cc'
# Разобрать TLVs
tshark -r lldp.pcap -V | grep -A1 "System Name\|Port ID\|Management Address"
```

## Какие поля раскрывает CDP

CDP-кадр содержит: Device ID, Addresses (IP), Port ID, Capabilities, Version (модель + IOS), Platform, VTP Domain, Native VLAN, Duplex. Именно **Version** и **Native VLAN** делают CDP находкой для пентестера.

```bash
# Захватить CDP
sudo tcpdump -i eth0 -nn -v -c 3 'ether proto 0x2000'
# Ключевые поля
tshark -r cdp.pcap -V | grep -E "Device ID|Platform|Version|Native VLAN"
```

## Пассивная разведка: собрать топологию из дампа

```bash
# 1. Захватить discovery-трафик за 60 секунд
sudo tcpdump -i eth0 -nn -w disc.pcap 'ether proto 0x88cc or ether proto 0x2000'
# 2. Вытащить имена устройств
tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.system.name | sort -u
# 3. Вытащить порты и VLAN
tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.port.id -e lldp.tlv.port.vlan.id | sort -u
# 4. CDP-соседи
tshark -r disc.pcap -Y 'cdp' -T fields -e cdp.device.id -e cdp.platform | sort -u
```

За минуту пассивного слушания вы получаете карту соседей — без единого пакета от себя.

## Активная разведка: LLDP на своём интерфейсе

Можно и самому «представиться» и посмотреть, что ответят соседи:

```bash
# ladvd — отправка LLDP от имени своего хоста
sudo ladvd -e eth0 -f
# Или открытый инструмент lldpd
sudo lldpd -d -I eth0
# Посмотреть, что узнали соседи
lldpcli show neighbors
```

## Почему это утечка

Discovery-протоколы раскрывают:

- **модели и версии ПО** — можно подобрать CVE;
- **hostname и домен** — полезно для целевой атаки;
- **management IP** — точка входа в устройство;
- **VLAN** — карта сегментации;
- **тип порта** — access/trunk/hybrid.

Для атакующего это «бесплатная» разведка; для обороны — обязательная к фильтрации на внешних портах.

## Атака: rogue LLDP/CDP

Можно и обмануть: отправлять поддельные LLDP/CDP-кадры с чужим именем, чтобы:

- выдать свой хост за легитимный коммутатор;
- «подружиться» с портом и получить доверие;
- засорить инвентаризацию ложными данными.

```bash
# Отправить поддельный LLDP с чужим system name (лаборатория)
python3 - <<'PY'
from scapy.contrib.lldp import *
from scapy.all import sendp, Ether
pkt = Ether(dst="01:80:c2:00:00:0e")/LLDP()/LLDPChassisID(subtype=4, id=b"\xaa\xbb\xcc\xdd\xee\xff")/LLDPPortID(subtype=5, id=b"Gi0/1")/LLDPTTL(ttl=120)
sendp(pkt, iface="eth0")
PY
```

## Защита

| Мера | Против чего |
|---|---|
| Выключить LLDP/CDP на внешних портах (`no lldp transmit`) | утечка топологии |
| Отдельный management VLAN | раскрытие IP управления |
| Port security / NAC | rogue-устройства |
| Не использовать CDP между вендорами | лишняя болтливость |
| Мониторинг неожиданных LLDP-соседей | rogue LLDP |

```text
interface Gi0/1
 no lldp transmit
 no cdp enable
```

## Практика: сопоставить MAC и топологию

```bash
# Связать Chassis ID (MAC) с системным именем
tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.chassis.id -e lldp.tlv.system.name
# Затем сопоставить с MAC-таблицей коммутатора
# show mac address-table | include <mac>
```

Так пассивная разведка превращается в точную карту «кто на каком порту».

## Частые ошибки

- **Слушать 2 секунды** — LLDP/CDP периодичны (30/60 с), нужно окно ≥60 с.
- **Путать LLDP и CDP multicast** — адреса и ethertype разные.
- **Искать их под IP-фильтром** — это чистый L2, IP-фильтр их не покажет.
- **Считать LLDP «безопасным»** — он раскрывает management IP.
- **Игнорировать rogue LLDP** — подделка искажает инвентаризацию.
- **Забывать про LLDP-MED** — телефония несёт ещё больше данных.
- **Не фильтровать на uplink** — топология утекает за пределы сегмента.

## Что дальше / решение

После discovery-разведки переходите к [`network-layer2-attacks`](network-layer2-attacks) (port security) и [`network-vlan-hopping`](network-vlan-hopping). Для практики анализа — [`network-tcpdump`](network-tcpdump) и [`network-wireshark`](network-wireshark).

## LLDP-MED и VoIP

**LLDP-MED** (Media Endpoint Discovery) расширяет LLDP для телефонии: сообщает VLAN, приоритет QoS, параметры PoE. Из него видно, какая voice VLAN используется и какие телефоны стоят. Это дополнительный источник разведки.

```bash
# Захватить LLDP-MED
tshark -r disc.pcap -Y 'lldp.med' -T fields -e lldp.med.network.policy.vlan.id
```

## Инвентаризация сети пассивно

Из discovery-трафика можно построить инвентарь без активного сканирования:

```bash
# Сводка по всем устройствам за окно захвата
tshark -r disc.pcap -Y 'lldp' -T fields \
  -e lldp.tlv.chassis.id -e lldp.tlv.system.name -e lldp.tlv.system.desc \
  -e lldp.tlv.port.id -e lldp.tlv.mgmt.addr | sort -u
# CDP-инвентарь
tshark -r disc.pcap -Y 'cdp' -T fields \
  -e cdp.device.id -e cdp.platform -e cdp.version -e cdp.native.vlan | sort -u
```

Результат — таблица «устройство → модель → порт → IP управления → VLAN», полученная только слушанием.

## Детект и мониторинг rogue-устройств

Аномалии, на которые смотрит SOC:

- **новый LLDP-сосед** на порту доступа, где его быть не должно;
- **несовпадение System Name** с инвентарём;
- **частые LLDP-кадры** от неизвестного MAC (rogue-устройство);
- **поддельный Chassis ID**, дублирующий легитимный.

```bash
# Найти дубликаты Chassis ID (возможный спуфинг)
tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.chassis.id | sort | uniq -d
```

## Сравнение LLDP и CDP

| Свойство | LLDP | CDP |
|---|---|---|
| Стандарт | IEEE 802.1AB | Cisco проприетарный |
| EtherType | 0x88CC | 0x2000 |
| Multicast | 01:80:c2:00:00:0e | 01:00:0c:cc:cc:cc |
| Период | 30 с | 60 с |
| Несёт IP управления | да | да |
| Native VLAN | ограниченно | да |
| Вендоронезависим | да | нет |

## Настройка на стороне хоста

```bash
# Установить lldpd и смотреть соседей
sudo apt install lldpd
sudo systemctl enable --now lldpd
lldpcli show neighbors ports eth0
# Отключить передачу на недоверенном интерфейсе
sudo lldpcli configure ports eth0 lldp transmit disable
```

На хосте LLDP полезен для диагностики: сразу видно, в какой коммутатор и порт вы включены, какая VLAN назначена, поддерживается ли PoE.

## Квиз

```quiz
- question: "Какой EtherType использует LLDP?"
  options:
    - "0x88CC"
    - "0x2000"
    - "0x8100"
    - "0x0806"
  answer: 0
  explanation: "LLDP (802.1AB) — EtherType 0x88CC."
- question: "Какой EtherType использует CDP?"
  options:
    - "0x2000"
    - "0x88CC"
    - "0x0800"
    - "0x86DD"
  answer: 0
  explanation: "CDP — проприетарный Cisco, EtherType 0x2000."
- question: "Какое поле LLDP раскрывает модель и версию ОС?"
  options:
    - "System Description"
    - "TTL"
    - "Chassis ID"
    - "Port ID"
  answer: 0
  explanation: "System Description несёт модель и версию ПО."
- question: "Почему LLDP/CDP опасны для безопасности?"
  options:
    - "Раскрывают топологию, версии и адреса управления"
    - "Шифруют трафик"
    - "Замедляют сеть"
    - "Меняют MAC"
  answer: 0
  explanation: "Это готовая пассивная разведка для атакующего."
- question: "Как правильно фильтровать discovery на внешнем порту?"
  options:
    - "Отключить передачу LLDP/CDP (no lldp transmit)"
    - "Включить IPv6"
    - "Поднять VLAN 1"
    - "Отключить STP"
  answer: 0
  explanation: "На недоверенных портах передачу discovery отключают."
```

## Где пригодится

- **CTF:** разбор discovery-кадров и восстановление топологии.
- **Пентест:** пассивная разведка сети без активного сканирования.
- **SOC:** инвентаризация, детект rogue LLDP/CDP-устройств.
- **Инженерия:** настройка фильтрации discovery на периметре.
