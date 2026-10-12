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

## Вопрос, с которого всё начинается

Тебя подключили к сети, и вокруг — сплошная неизвестность: какие тут коммутаторы, куда ведут порты, какие VLAN. Можно запустить `nmap` и сканировать — но это шумно и заметно. А можно просто **послушать**: коммутаторы и маршрутизаторы сами объявляют о себе служебными кадрами. Эти кадры несут имя устройства, модель, версию ОС, номер порта и даже IP управления.

Два таких протокола — **LLDP** и **CDP**. Разберём, что из них можно вытащить и почему это утечка.

Этот урок продолжает модуль [`network-module-l2`](network-module-l2) и опирается на [`network-ethernet`](network-ethernet).

## Наш пример: слушаем 60 секунд

Мы только что подключились к порту. Запускаем захват только discovery-трафика (по EtherType, который мы уже знаем):

```
$ sudo tcpdump -i eth0 -nn -w disc.pcap 'ether proto 0x88cc or ether proto 0x2000'
^C
12 packets captured
```

За минуту набралось 12 кадров — даже ничего не делая. Теперь разберём, что в них. Но сначала — что это за протоколы.

## Шаг 1: LLDP и CDP — кто это

- **LLDP** (Link Layer Discovery Protocol, стандарт IEEE 802.1AB) — вендоронезависимый. Отправляет кадры с EtherType `0x88CC` на multicast-адрес `01:80:c2:00:00:0e` раз в 30 секунд.
- **CDP** (Cisco Discovery Protocol) — проприетарный, только у Cisco. EtherType `0x2000`, multicast `01:00:0c:cc:cc:cc`, раз в 60 секунд. Болтливее: несёт native VLAN, IP управления, версию IOS.

Оба **не маршрутизируются** — работают только между соседями по каналу L2. Именно поэтому их надо слушать с того порта, где ты физически сидишь.

## Шаг 2: что раскрывает LLDP

LLDP состоит из блоков **TLV** (Type-Length-Value — тип, длина, значение). Главные:

| TLV | Содержимое |
|---|---|
| Chassis ID | MAC или имя устройства |
| Port ID | имя/номер порта |
| System Name | hostname |
| System Description | модель + версия ОС |
| Management Address | IP управления |
| VLAN / PVID | VLAN порта |

Вытащим имена устройств и порты из нашего дампа:

```
$ tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.system.name -e lldp.tlv.port.id
core-sw-01    Gi1/0/24
```

Уже знаем: мы подключены к порту `Gi1/0/24` коммутатора `core-sw-01`. Смотрим описание системы — там модель и версия:

```
$ tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.system.desc
Cisco IOS Software, C2960X Software, Version 15.2(4)E7, RELEASE SOFTWARE
```

Версия ПО — `15.2(4)E7`. Это конкретная версия, по которой можно искать известные уязвимости. Вот почему discovery-протоколы — подарок для атакующего.

## Шаг 3: что раскрывает CDP

Если рядом Cisco, слушаем ещё и CDP. Его поля: Device ID, Platform, Version, Native VLAN, Duplex:

```
$ tshark -r disc.pcap -Y 'cdp' -T fields -e cdp.device.id -e cdp.platform -e cdp.native.vlan
core-sw-01    cisco WS-C2960X-24TS    1
```

Здесь видно **native VLAN = 1**. Это прямая подсказка для double tagging ([`network-vlan-hopping`](network-vlan-hopping)): атака работает как раз когда native VLAN равен 1.

## Шаг 4: собираем карту сети из дампа

Из одного окна захвата получаем инвентарь — «устройство → модель → порт → IP управления → VLAN»:

```
$ tshark -r disc.pcap -Y 'lldp' -T fields \
  -e lldp.tlv.chassis.id -e lldp.tlv.system.name -e lldp.tlv.mgmt.addr | sort -u
00:1b:0d:aa:bb:cc   core-sw-01   10.0.0.1
$ tshark -r disc.pcap -Y 'lldp' -T fields -e lldp.tlv.port.vlan.id | sort -u
10
```

Мы узнали: коммутатор `core-sw-01`, IP управления `10.0.0.1`, наш порт в VLAN 10. Всё это — **без единого пакета от себя**. Такая разведка неотличима от обычного подключения и не шумит, как сканирование.

Можно и «представиться» самому и посмотреть на ответы соседей:

```
$ sudo lldpd -d -I eth0 &
$ lldpcli show neighbors
-------------------------------------------------------------------------------
LLDP neighbors:
  Interface: eth0, via: LLDP
    Chassis: core-sw-01
    Port: Gi1/0/24
```

## Шаг 5: rogue LLDP/CDP — атака от нашего имени

Discovery можно и **подделать**: отправить LLDP/CDP-кадр с чужим именем, чтобы выдать свой хост за легитимный коммутатор, «подружиться» с портом или засорить инвентаризацию ложными данными:

```
$ python3 - <<'PY'
from scapy.contrib.lldp import *
from scapy.all import sendp, Ether
pkt = Ether(dst="01:80:c2:00:00:0e")/LLDP()/LLDPChassisID(subtype=4, id=b"\xaa\xbb\xcc\xdd\xee\xff")/LLDPPortID(subtype=5, id=b"Gi0/1")/LLDPTTL(ttl=120)
sendp(pkt, iface="eth0")
PY
```

## Шаг 6: защита

- **Выключить передачу LLDP/CDP на внешних портах** (`no lldp transmit`, `no cdp enable`) — топология не утечёт.
- **Отдельный management VLAN** — чтобы IP управления не попадал в пользовательский сегмент.
- **Port security / NAC** — против rogue-устройств.
- **Мониторинг** неожиданных LLDP-соседей: новый сосед на порту доступа или дубликат Chassis ID — аномалия.

## Чем LLDP отличается от CDP

Оба делают одно и то же, но детали важны при разборе дампа:

| Свойство | LLDP | CDP |
|---|---|---|
| Стандарт | IEEE 802.1AB | Cisco, проприетарный |
| EtherType | `0x88CC` | `0x2000` |
| Multicast | `01:80:c2:00:00:0e` | `01:00:0c:cc:cc:cc` |
| Период | 30 с | 60 с |
| Native VLAN | ограниченно | да |
| Вендоронезависим | да | нет |

Практический вывод: если сеть не на Cisco, слушай LLDP; если Cisco — обязательно и CDP, потому что именно он отдаёт native VLAN и версию IOS.

## Как посмотреть соседей со своей стороны

На своём хосте LLDP полезен и для диагностики: сразу видно, в какой коммутатор и порт ты включён и какая тебе назначена VLAN.

```
$ sudo apt install lldpd
$ sudo systemctl enable --now lldpd
$ lldpcli show neighbors ports eth0
```

Если нужно, наоборот, не «светиться» — отключи передачу на недоверенном интерфейсе: `lldpcli configure ports eth0 lldp transmit disable`.

## Что мы теперь знаем

- LLDP (`0x88CC`) и CDP (`0x2000`) — служебные протоколы, которыми устройства сами себя объявляют.
- Они раскрывают имя, модель, версию ПО, порт, VLAN и IP управления — пассивная разведка без сканирования.
- Окно захвата должно быть ≥60 секунд (период отправки 30/60 с).
- Их можно подделать (rogue LLDP/CDP), чтобы выдать себя за коммутатор.
- Защита — отключить передачу на недоверенных портах и вынести управление в отдельный VLAN.

## Квиз

Проверь себя.

```quiz
- question: 'Какой EtherType использует LLDP?'
  options:
    - '0x88CC'
    - '0x2000'
    - '0x8100'
    - '0x0806'
  answer: 0
  explanation: 'LLDP (802.1AB) — EtherType 0x88CC.'
- question: 'Какой EtherType использует CDP?'
  options:
    - '0x2000'
    - '0x88CC'
    - '0x0800'
    - '0x86DD'
  answer: 0
  explanation: 'CDP — проприетарный Cisco, EtherType 0x2000.'
- question: 'Какое поле LLDP раскрывает модель и версию ОС?'
  options:
    - 'System Description'
    - 'TTL'
    - 'Chassis ID'
    - 'Port ID'
  answer: 0
  explanation: 'System Description несёт модель и версию ПО.'
- question: 'Почему LLDP/CDP опасны для безопасности?'
  options:
    - 'Раскрывают топологию, версии и адреса управления'
    - 'Шифруют трафик'
    - 'Замедляют сеть'
    - 'Меняют MAC'
  answer: 0
  explanation: 'Это готовая пассивная разведка для атакующего.'
- question: 'Как правильно фильтровать discovery на внешнем порту?'
  options:
    - 'Отключить передачу LLDP/CDP (no lldp transmit)'
    - 'Включить IPv6'
    - 'Поднять VLAN 1'
    - 'Отключить STP'
  answer: 0
  explanation: 'На недоверенных портах передачу discovery отключают.'
```

## Куда дальше

Мы научились пассивно собирать карту L2-сети. Дальше разберём сегментацию глубже — вложенные VLAN-теги (QinQ), а затем петли и дерево STP. А пока запомни: **устройства сами рассказывают о себе; хороший пентестер сначала слушает, потом сканирует.**

## Где пригодится

- **CTF:** разбор discovery-кадров и восстановление топологии.
- **Пентест:** пассивная разведка сети без активного сканирования.
- **SOC:** инвентаризация, детект rogue LLDP/CDP-устройств.
- **Инженерия:** настройка фильтрации discovery на периметре.
