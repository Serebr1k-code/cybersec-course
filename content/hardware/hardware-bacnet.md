---
id: hardware-bacnet
title: 'BACnet: здания, объекты и запись точек'
category: hardware
parent: hardware-mod-iot-mesh
difficulty: medium
order: 4
tags: [hardware, bacnet, building, bms, scada, ot]
prerequisites: [hardware-iot-network]
useful_for:
  - 'Пентест зданий и BMS'
  - 'CTF Hardware/OT'
  - 'Аудит АСУ зданий'
estimated_minutes: 40
summary: 'BACnet для систем управления зданиями: объектная модель, сервисы чтения/записи, широковещательный discovery и атаки на BMS без аутентификации.'
lab:
  kind: shell
  toolset: [core, python]
  workdir: /home/student/bacnet
  files: [task.md, notes.md, bacnet.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`bacnet.log` — BACnet-трафик BMS.'
    - 'Смотри объекты и сервис WriteProperty.'
    - 'Найди флаг: `grep nto bacnet.log | cut -d= -f2 > found.txt`.'
---

## Вопрос, с которого всё начинается

Отопление, вентиляция, кондиционирование, доступ в здание, лифты — всем управляет **BMS** (Building Management System). Протокол, на котором она работает десятки лет, — **BACnet**. И у него по умолчанию почти нет аутентификации.

Вопрос урока: как устроен BACnet и как записать «точку» в чужом здании.

## Наш пример: BACnet-трафик BMS

У нас есть дамп BACnet-трафика: обнаружение устройств и команда записи. Разберём объектную модель и найдём записываемую точку.

<!-- lab -->

## Шаг 1: объектная модель

BACnet описывает всё как **объекты**. У каждого объекта есть **instance number** и набор **properties**. Примеры типов объектов:

- **Analog Input** — датчик (температура, влажность).
- **Analog Output** — управляющее значение (положение заслонки).
- **Binary Input/Output** — дискретные (включено/выключено).
- **Device** — само устройство.

```text
$ grep -m2 'object' bacnet.log
object: type=AnalogInput instance=1 present_value=21.5 units=C
object: type=AnalogOutput instance=2 present_value=45.0 units=percent
```

## Шаг 2: сервисы

BACnet — это сервисы поверх объектов. Ключевые:

- **Who-Is / I-Am** — discovery: кто есть в сети.
- **ReadProperty** — прочитать свойство.
- **WriteProperty** — записать свойство.
- **SubscribeCOV** — подписка на изменения.

```text
$ grep -n 'WriteProperty' bacnet.log
WriteProperty: dev=1001 obj=AnalogOutput:2 prop=Present_Value value=100.0
```

Вот она — запись. Если WriteProperty не защищён, любой в сети меняет уставку.

## Шаг 3: discovery по broadcast

BACnet широковещательно рассылает **Who-Is**, устройства отвечают **I-Am**. Это значит, что достаточно оказаться в том же L2-сегменте, чтобы увидеть всю BMS.

```text
$ grep -n 'Who-Is\|I-Am' bacnet.log
Who-Is: broadcast
I-Am: device=1001 vendor=Acme name=AHU-1
```

Порт BACnet/IP — **47808/UDP** (`0xBAC0`). Скан по нему быстро находит устройства.

## Шаг 4: чтение и запись

Читать состояние можно без пароля — многие BMS отдают всё открыто. Запись критичных точек (уставки, режимы, двери) — то, что превращает «прочитал» в «управляю».

```text
$ python3 -c "print('BACnet/IP: BVLC 0x81 0x0A + NPDU + APDU WriteProperty')"
BACnet/IP: BVLC 0x81 0x0A + NPDU + APDU WriteProperty
```

Инструменты: `BACnet Stack`, `bacnet-tools`, YABE, `nmap --script bacnet-info`.

## Шаг 5: атаки

1. **Запись уставок** — изменить температуру, режим вентиляции.
2. **Разблокировка дверей** — записать в Binary Output доступа.
3. **DoS** — залить устройства WriteProperty.
4. **Ложные датчики** — подделать ReadProperty-ответы (спуфинг).

Ограничение: современные BMS иногда используют BACnet/SC (Secure Connect) с TLS. Но legacy-устройств с открытым BACnet — огромное количество.

## Что мы теперь знаем

- BACnet — протокол BMS, порт 47808/UDP.
- Всё описывается объектами с instance и properties.
- Сервисы: Who-Is/I-Am, ReadProperty, WriteProperty.
- По умолчанию аутентификации нет; запись точек = управление зданием.
- BACnet/SC добавляет TLS, но применяется не везде.

## Квиз

```quiz
- question: На каком порту BACnet/IP?
  options:
    - 47808/UDP
    - 502/TCP
    - 102/TCP
  answer: 0
  explanation: BACnet/IP использует 47808/UDP (0xBAC0).
- question: Какой сервис записывает значение?
  options:
    - WriteProperty
    - ReadProperty
    - Who-Is
  answer: 0
  explanation: WriteProperty меняет свойство объекта.
- question: Почему BACnet опасен по умолчанию?
  options:
    - Нет аутентификации — любой в сети может писать
    - Он слишком медленный
    - Он не поддерживает Ethernet
  answer: 0
  explanation: BACnet без защиты позволяет управлять зданием.
- question: Что делает BACnet/SC?
  options:
    - Добавляет защищённое соединение (TLS)
    - Ускоряет обмен
    - Меняет порт на 80
  answer: 0
  explanation: Secure Connect защищает трафик BACnet.
```

## Куда дальше

Дальше перейдём к прикладному уровню АСУ ТП — **OPC UA**. А пока запомни: в BMS запись точки часто равна физическому действию в здании.

## Где пригодится

- **Пентест:** аудит BMS, отелей, офисов, ЦОД.
- **CTF:** категория Hardware/OT.
- **Работа:** безопасность инженерных систем зданий.
- **Дальше по дереву:** `hardware-mod-ics-app`, `hardware-6lowpan`.
