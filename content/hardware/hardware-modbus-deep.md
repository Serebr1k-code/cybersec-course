---
id: hardware-modbus-deep
title: "Modbus глубоко: функции, реверс, спуфинг и запись в PLC"
category: hardware
parent: hardware-ics
difficulty: hard
order: 1
tags: [modbus, plc, pymodbus, tcp, rtu, holding-registers, coils, ics, scada]
prerequisites: [hardware-ics]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест АСУ ТП"
  - "Реверс промышленных протоколов"
estimated_minutes: 50
summary: "Modbus изнутри: функции, регистры и coils, TCP/RTU, pymodbus, реверс логики PLC, спуфинг и безопасная запись."
---

**Modbus** — старейший и самый распространённый промышленный протокол. Он прост до предела: запрос содержит адрес устройства, код функции и данные; ответ — эхо функции и данные (или код ошибки). Аутентификации нет, шифрования нет, целостности нет. Именно поэтому Modbus — идеальная отправная точка для изучения ICS-атак: он понятен, доступен и позволяет как читать, так и изменять состояние PLC.

## Модель данных Modbus

Modbus оперирует четырьмя таблицами:

| Таблица | Тип | Доступ | Адреса |
|---------|-----|--------|--------|
| Coils | 1 бит | R/W | 00001–09999 |
| Discrete Inputs | 1 бит | R | 10001–19999 |
| Input Registers | 16 бит | R | 30001–39999 |
| Holding Registers | 16 бит | R/W | 40001–49999 |

Важно различать **адресацию**: в документации используются «человеческие» адреса (40001), а в протоколе — 0-based (0). Поэтому «holding register 40001» = адрес 0 в запросе. Путаница с этим — классическая ошибка.

## Функции (Function Codes)

| Код | Функция | Назначение |
|-----|---------|-----------|
| 01 | Read Coils | читать биты |
| 02 | Read Discrete Inputs | читать входы |
| 03 | Read Holding Registers | читать регистры |
| 04 | Read Input Registers | читать входные регистры |
| 05 | Write Single Coil | записать бит |
| 06 | Write Single Register | записать регистр |
| 15 | Write Multiple Coils | записать биты |
| 16 | Write Multiple Registers | записать регистры |
| 43 | Read Device Identification | идентификация |

Ответы с ошибкой имеют старший бит функции (например, 0x83 для 0x03) и код исключения (01 — illegal function, 02 — illegal address).

## TCP и RTU

Modbus бывает двух основных видов:

- **Modbus TCP** — поверх Ethernet, порт 502. Кадр: MBAP-заголовок (transaction ID, protocol, length, unit ID) + PDU.
- **Modbus RTU** — поверх RS-485/RS-232, с CRC и таймингом. Часто за шлюзом Modbus TCP↔RTU.

```bash
# Поймать Modbus TCP
sudo tcpdump -i eth0 -n port 502 -w modbus.pcap
# В Wireshark — dissector mbtcp покажет функцию и значения
```

## pymodbus: чтение и запись

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient('10.0.0.10', port=502)
c.connect()

# Чтение 10 holding registers с адреса 0
r = c.read_holding_registers(0, 10, slave=1)
print(r.registers)   # [1234, 0, 500, ...]

# Чтение coils
r = c.read_coils(0, 8, slave=1)
print(r.bits)

# Запись одного регистра
c.write_register(0, 9999, slave=1)
# Запись нескольких
c.write_registers(0, [100, 200, 300], slave=1)

c.close()
```

Функция `slave`/`unit` важна: за одним IP может быть несколько устройств (через шлюз), и обращаться надо к правильному unit ID.

## Реверс логики PLC

Чтобы понять, какой регистр за что отвечает, используется корреляция: меняйте вход процесса (или наблюдайте реальные изменения) и смотрите, какие регистры меняются.

```python
# Снимок состояния и поиск изменений
import time
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.10'); c.connect()
def snap():
    return c.read_holding_registers(0, 100, slave=1).registers
a = snap(); time.sleep(2); b = snap()
for i,(x,y) in enumerate(zip(a,b)):
    if x != y: print(f'reg {i}: {x} -> {y}')
```

Сопоставляя изменения с показаниями на HMI и физическими событиями, восстанавливают карту регистров. Документация производителя (иногда доступная) ускоряет процесс.

## Спуфинг и атаки

- **Спуфинг датчика**: подмена input register, чтобы система «увидела» другое давление/температуру.
- **Подмена команды**: запись в coil, управляющий насосом/клапаном.
- **Replay**: воспроизведение легитимных команд.
- **DoS**: flood запросами, забивающий PLC.
- **Man-in-the-middle**: если трафик идёт через контролируемый шлюз.

```bash
# Пример flood (только в лаборатории!)
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.10')
while True: c.read_holding_registers(0,1)
"
```

## Разобранный пример: безопасное исследование

```bash
# 1. Идентификация устройства
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.10'); c.connect()
r = c.read_device_information()
print(r)
"
# 2. Снять карту регистров (только чтение)
# 3. Определить, какие регистры меняются (корреляция)
# 4. СОГЛАСОВАТЬ запись с эксплуатацией
# 5. Записать в тестовый/симулированный PLC (Conpot/GRFICS), не в реальный
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `pymodbus` | клиент/сервер Modbus |
| `modbus-cli` | CLI-доступ |
| `nmap --script modbus-discover` | обнаружение |
| Wireshark (mbtcp) | разбор трафика |
| Conpot | honeypot/симулятор |
| `mbpoll` | CLI-опрос |

## Частые ошибки и подводные камни

- **Адресация 0-based vs 1-based**: 40001 → 0.
- **Не тот unit/slave ID**: ответ пустой или ошибка.
- **Слишком частый опрос**: legacy-PLC перегружается.
- **Запись не туда**: необратимые последствия для процесса.
- **Byte order**: в некоторых устройствах слова/байты переставлены (word swap).
- **Modbus over TLS**: редко, но встречается — тогда нужен порт 802.

## Modbus RTU и шлюзы

Modbus RTU передаётся по RS-485 (или RS-232) с CRC-16 и таймингом между кадрами (3.5 символа). В современной инфраструктуре RTU часто «заворачивают» в TCP через **шлюз** (Modbus TCP↔RTU). Тогда один IP может обслуживать несколько устройств, и важен **unit ID**.

```bash
# RTU через USB-адаптер
sudo modbus_rtu /dev/ttyUSB0 9600
# Через шлюз: обращаться к разным unit ID по одному IP
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.10', port=502)
for uid in (1,2,3):
    r = c.read_holding_registers(0, 4, slave=uid)
    print(uid, r.registers if not r.isError() else 'err')
"
```

Особенности RTU: чувствительность к таймингам, CRC, эхо на шине. При реверсе смотрите, какой unit отвечает на какие адреса.

## Расширенные функции и диагностика

Помимо базовых, есть сервисные функции:

- **08 Diagnostics** — счётчики, эхо, сброс.
- **11 Get Comm Event Counter**, **12 Get Comm Event Log**.
- **17 Report Server ID**.
- **43 Read Device Identification** — вендор, модель, версия.
- **20/21 Read/Write File Record** — доступ к файлам.

```bash
# Идентификация устройства
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.0.0.10'); c.connect()
r = c.read_device_information()
print(r)
"
```

Эти функции дают «паспорт» устройства и иногда — доступ к недокументированным областям.

## Практический стенд и защита

- **Conpot** — honeypot с Modbus/S7.
- **OpenPLC** — программный PLC с веб-интерфейсом.
- **GRFICS** — полноценный симулятор завода.
- **pymodbus-сервер** — свой Modbus-сервер для тестов.

```bash
# Свой Modbus-сервер для отработки клиента
python3 -c "
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0]*100))
StartTcpServer(context=ModbusServerContext(slaves=store, single=True))
"
```

Защита: сегментация, шлюзы с фильтрацией функций, read-only режимы, мониторинг аномальных записей, замена на OPC UA с аутентификацией там, где возможно.

## Безопасность и мониторинг

Modbus не имеет аутентификации, поэтому защита строится вокруг сети:

- **Сегментация** и firewall с разрешёнными функциями (например, только чтение).
- **Шлюз** с валидацией адресов и unit ID.
- **Мониторинг** аномалий: неожиданные записи, новые unit ID, частые ошибки.
- **Read-only режимы** там, где запись не нужна.
- **IDS** с правилами под конкретный процесс.

Zeek/Wireshark + скрипты позволяют построить базлайн и ловить отклонения. Для пентеста важно проверить, включены ли эти меры и можно ли обойти сегментацию.

## Modbus over TLS и безопасные альтернативы

Стандартный Modbus не шифруется, но существуют расширения: **Modbus/TLS** (порт 802) и шлюзы с VPN. Там, где требуется защита, лучше переходить на **OPC UA** с аутентификацией и шифрованием. Для пентеста проверьте: используется ли TLS, какой сертификат, можно ли обойти (downgrade до plaintext). Часто «защита» — это лишь туннель, а внутри — тот же открытый Modbus.

## Что дальше / решение

- Нужен общий обзор ICS → `hardware-ics`.
- Нужен SCADA → `hardware-scada`.
- Нужен honeypot для практики → Conpot.
- Нужен разбор сети → Wireshark.

## Квиз

```quiz
- question: "Какой порт у Modbus TCP?"
  options:
    - "502"
    - "102"
    - "20000"
    - "44818"
  answer: 0
  explanation: "Modbus TCP слушает 502."
- question: "Что читает функция 03?"
  options:
    - "Coils"
    - "Holding Registers"
    - "Discrete Inputs"
    - "Device ID"
  answer: 1
  explanation: "03 = Read Holding Registers."
- question: "Чему равен holding register 40001 в запросе?"
  options:
    - "40001"
    - "0"
    - "1"
    - "40000"
  answer: 1
  explanation: "Адресация 0-based: 40001 → 0."
- question: "Что такое спуфинг датчика в Modbus?"
  options:
    - "Шифрование трафика"
    - "Подмена значения регистра, чтобы система увидела другое показание"
    - "Перезагрузка PLC"
    - "Обновление прошивки"
  answer: 1
  explanation: "Подмена input/holding register искажает картину."
- question: "Почему запись в реальный PLC требует согласования?"
  options:
    - "Она медленная"
    - "Может повлиять на физический процесс и вызвать аварию"
    - "Требует интернета"
    - "Портит HMI"
  answer: 1
  explanation: "Изменение состояния влияет на оборудование."
```

## Где пригодится

- **CTF:** Hardware/ICS-задачи с Modbus.
- **Пентест:** аудит PLC и промышленных сетей.
- **Реверс:** восстановление карты регистров.
- **Работа:** защита OT, мониторинг аномалий.
- **Дальше по дереву:** `hardware-ics`, `hardware-scada`.
