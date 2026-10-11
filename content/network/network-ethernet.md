---
id: network-ethernet
title: "Ethernet и MAC-адресация: кадр 802.3, learning и коммутация"
category: network
parent: network-module-l2
difficulty: easy
order: 1
tags: [network, ethernet, mac, 802.3, switching, cam, framing]
prerequisites: [network-basics, network-module-l2]
useful_for:
  - "CTF Network (разбор кадров)"
  - "Пентест: понимание коммутации и L2-атак"
  - "Работа (SOC): чтение L2-дампов"
estimated_minutes: 50
summary: "Кадр Ethernet II и 802.3, типы MAC-адресов, как коммутатор обучается и пересылает кадры, CAM-таблица, flooding и фильтрация — с командами tcpdump/bridge и разбором."
---

Ethernet — самый нижний практический уровень, с которым работает пентестер внутри сети. Прежде чем говорить об ARP-спуфинге, VLAN hopping или MAC-flooding, нужно точно понимать, из чего состоит кадр, как выбирается адрес получателя и почему коммутатор иногда ведёт себя как hub. Этот урок — практическая база модуля [`network-module-l2`](network-module-l2).

## Кадр Ethernet II: поля и размеры

В современной сети используется формат **Ethernet II (DIX)**:

| Поле | Размер | Назначение |
|---|---|---|
| Preamble + SFD | 8 байт | синхронизация (не считается полезной нагрузкой) |
| Dst MAC | 6 | адрес получателя |
| Src MAC | 6 | адрес отправителя |
| EtherType | 2 | тип протокола верхнего уровня |
| Payload | 46–1500 | данные (при <46 — padding) |
| FCS | 4 | CRC-32 |

```text
+-----------+-----------+----------+------------------+------+
| Dst MAC   | Src MAC   | EtherType| Payload          | FCS  |
| 6 байт    | 6 байт    | 2 байта  | 46..1500 байт    | 4    |
+-----------+-----------+----------+------------------+------+
```

Частые EtherType: `0x0800` IPv4, `0x0806` ARP, `0x86DD` IPv6, `0x8100` 802.1Q, `0x8847` MPLS, `0x88CC` LLDP.

## Типы MAC-адресов

MAC — 48 бит, обычно `aa:bb:cc:dd:ee:ff`. Разбираются так:

- **Один адрес (unicast)** — младший бит первого октета = 0.
- **Групповой (multicast)** — младший бит = 1 (`01:00:5e:...` — IPv4 multicast).
- **Broadcast** — `ff:ff:ff:ff:ff:ff`.
- **Локально администрируемый (U/L)** — второй бит первого октета = 1. Атакующий может выставить любой MAC — это и есть **MAC spoofing**.

Первые 3 октета (OUI) выдают производителя: `00:50:56` — VMware, `08:00:27` — VirtualBox, `00:1C:42` — Parallels. По OUI в дампе легко понять, виртуалка это или железо.

```bash
# Определить вендора по MAC
macchanger -l | grep -i vmware
# Сменить MAC на интерфейсе (лаборатория)
sudo ip link set dev eth0 down
sudo macchanger -r eth0     # случайный
sudo ip link set dev eth0 up
```

## Как коммутатор обучается и пересылает

Коммутатор работает по трём правилам:

1. **Learning** — запомнить `Src MAC` ↔ порт входа.
2. **Forwarding** — искать `Dst MAC` в CAM; найден → отдать в конкретный порт.
3. **Flooding** — если `Dst MAC` неизвестен, broadcast или multicast → разослать во все порты, кроме входного.
4. **Filtering** — если вход = выход, кадр дропается.

CAM-запись «стареет» (ageing, обычно 300 с) и удаляется без трафика.

```bash
# MAC-таблица Linux-бриджа
bridge fdb show br br0
# В Cisco IOS
# show mac address-table dynamic
```

## Неизвестный unicast, broadcast и штормы

**Unknown unicast flooding** — нормальное поведение: пока коммутатор не знает адрес, он флудит. Этим пользуются сниферы: если залить CAM поддельными адресами (`macof`), коммутатор перестанет знать реальные MAC и начнёт флудить чужой unicast во все порты.

```bash
# macof из dsniff — переполнение CAM (только в своей лаборатории)
sudo macof -i eth0 -n 100000
# Проверить, что коммутатор начал флудить
sudo tcpdump -i eth0 -nn -e 'not arp and not broadcast' -c 20
```

**Broadcast storm** возникает при петле без STP: broadcast-кадры множатся экспоненциально и вырубают сеть за секунды. Признак — мгновенный рост broadcast в дампе.

```bash
# Оценить долю broadcast в трафике
sudo tcpdump -i eth0 -nn -c 1000 'broadcast' | wc -l
```

## Duplex, автосогласование и ошибки

- **Half duplex** — одна передача за раз; коллизии (редко сегодня).
- **Full duplex** — приём и передача одновременно; коллизий нет.
- **Autonegotiation** — стороны договариваются о скорости/дуплексе; при ошибке часто получают **duplex mismatch** → ошибки CRC, потеря пакетов.

```bash
# Статистика ошибок интерфейса
ip -s link show eth0
# Счётчики CRC/коллизий на Cisco
# show interfaces counters errors
```

## EtherType, VLAN-тег и вложенность

Когда кадр идёт по trunk-порту, между `Src MAC` и `EtherType` вставляется **VLAN-тег** (802.1Q): `EtherType=0x8100`, затем TCI (12 бит VLAN ID + 3 бита priority), затем исходный EtherType. Двойное тегирование (QinQ) добавляет ещё один тег — см. `network-vlan-qinq`.

```bash
# Показать VLAN-теги в дампе
sudo tcpdump -i eth0 -e -nn vlan | head
# Wireshark-фильтр: vlan
```

## Практика: разбор кадра вручную

```bash
# Захват 5 кадров с MAC и типом
sudo tcpdump -i eth0 -e -nn -c 5
# Вывод:
# 14:22:01.1 08:00:27:aa:bb:cc > 52:54:00:11:22:33, ethertype IPv4 (0x0800), length 74
# 14:22:01.2 ff:ff:ff:ff:ff:ff > 08:00:27:aa:bb:cc, ethertype ARP (0x0806), length 42

# Хекс-дамп первого кадра
sudo tcpdump -i eth0 -nn -e -XX -c 1
```

Разбор: `08:00:27` = VirtualBox (источник), `52:54:00` = QEMU/KVM (назначение), EtherType `0x0800` = IPv4. Broadcast-ARP — нормальный запрос «кто владеет этим IP».

## Практика: ARP-обмен и MAC-таблица

```bash
# Посмотреть ARP-кэш и MAC
ip neigh show
# Просканировать сегмент и собрать MAC
sudo arp-scan --interface=eth0 --localnet
# Найти дубликаты MAC (спуфинг)
arp -an | awk '{print $4}' | sort | uniq -d
```

Дубликат MAC в ARP-кэше — сильный признак ARP-спуфинга или конфликта адресов.

## Частые ошибки

- **Считать MAC постоянным** — он легко подделывается (U/L бит).
- **Игнорировать OUI** — по нему видно виртуалки и вендора.
- **Путать broadcast и multicast** — фильтры различаются.
- **Забывать про FCS** — битый кадр молча дропается, «пакет исчез».
- **Думать, что коммутатор всегда forward по назначению** — при переполнении CAM он флудит.
- **Не учитывать ageing** — таблица пустеет, и снова появляется flood.
- **Смотреть только IP** — ARP/STP/LLDP не видны под фильтром `ip`.

## Что дальше / решение

Поняв кадр и коммутацию, переходите к [`network-stp-deep`](network-stp-deep) (петли и дерево), [`network-vlan-qinq`](network-vlan-qinq) (сегментация) и [`network-lldp-cdp`](network-lldp-cdp) (разведка топологии). Для атак — [`network-layer2-attacks`](network-layer2-attacks) (MAC-flooding, port security).

## Jumbo-кадры, MTU и фрагментация на L2

Стандартный MTU Ethernet — 1500 байт. **Jumbo-кадры** поднимают его до 9000 на датацентровых линках, снижая накладные расходы. Опасность: если один хост шлёт jumbo, а другой нет, крупные кадры молча дропаются — классический «MTU mismatch». Признак — TCP-сессии зависают на передаче больших данных, а мелкие пинги проходят.

```bash
# Проверить MTU интерфейса
ip link show eth0 | grep mtu
# Найти максимальный проходящий размер
ping -M do -s 1472 -c 1 10.0.0.1
```

## Storm control и защита от флуда

Коммутаторы умеют ограничивать broadcast/multicast/unicast-флуд (**storm control**): при превышении порога порт блокируется. Это защита от петель и от MAC-flooding. На Linux роль storm control играет `tc` или лимиты bridge.

```bash
# Ограничить broadcast на интерфейсе (пример через tc)
sudo tc qdisc add dev eth0 root handle 1: htb default 10
sudo tc class add dev eth0 parent 1: classid 1:10 htb rate 10mbit
```

## Сравнение Ethernet-стандартов

| Стандарт | Скорость | Среда | Кадр |
|---|---|---|---|
| 10BASE-T | 10 Мбит/с | витая пара | 802.3 |
| 100BASE-TX | 100 Мбит/с | витая пара | 802.3u |
| 1000BASE-T | 1 Гбит/с | витая пара (4 пары) | 802.3ab |
| 10GBASE-SR | 10 Гбит/с | оптика | 802.3ae |
| 25/40/100G | 25–100 Гбит/с | оптика/DAC | 802.3by/bm |

Независимо от скорости, **формат кадра** остаётся совместимым — меняется только физический уровень (кодирование, среда, скорость).

## Обнаружение MAC-flooding в дампе

```bash
# Много кадров с меняющимися Src MAC в короткое время
sudo tcpdump -i eth0 -nn -e -c 200 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -rn | head
# Всплеск unknown unicast (коммутатор флудит)
tshark -r cap.pcap -Y 'eth.dst != ff:ff:ff:ff:ff:ff' | wc -l
```

Аномально быстрая смена Src MAC и рост числа «неадресованных» кадров — прямой признак переполнения CAM.

## Квиз

```quiz
- question: "Какое поле кадра Ethernet II определяет протокол верхнего уровня?"
  options:
    - "EtherType"
    - "FCS"
    - "Preamble"
    - "Src MAC"
  answer: 0
  explanation: "EtherType (0x0800, 0x0806 и т.д.) указывает протокол."
- question: "Как отличить multicast MAC от unicast?"
  options:
    - "Младший бит первого октета равен 1"
    - "Адрес начинается с ff"
    - "Он всегда 6 байт"
    - "Второй бит первого октета равен 1"
  answer: 0
  explanation: "I/G-бит (младший бит первого октета) = 1 означает групповой адрес."
- question: "Что делает коммутатор с кадром, чей Dst MAC ему неизвестен?"
  options:
    - "Флудит во все порты, кроме входного"
    - "Дропает кадр"
    - "Отправляет обратно отправителю"
    - "Перезаписывает MAC"
  answer: 0
  explanation: "Unknown unicast flooding — базовая функция коммутатора."
- question: "Что произойдёт при переполнении CAM-таблицы?"
  options:
    - "Коммутатор начнёт вести себя как hub и флудить трафик"
    - "Ускорится маршрутизация"
    - "Отключится IPv6"
    - "Пропадёт DNS"
  answer: 0
  explanation: "Без записей forwarding вырождается в flooding."
- question: "Какой OUI указывает на виртуальную машину VirtualBox?"
  options:
    - "08:00:27"
    - "00:50:56"
    - "ff:ff:ff"
    - "01:00:5e"
  answer: 0
  explanation: "08:00:27 — префикс VirtualBox; 00:50:56 — VMware."
```

## Где пригодится

- **CTF:** задачи с hex-дампом кадра, поиск вендора по OUI, VLAN-теги.
- **Пентест:** база для MAC-spoofing, MAC-flooding и ARP-атак.
- **SOC:** чтение L2-дампов, детект штормов и дубликатов MAC.
- **Инженерия:** диагностика duplex mismatch и ошибок CRC.
