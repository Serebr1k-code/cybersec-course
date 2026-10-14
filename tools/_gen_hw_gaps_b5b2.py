#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch HW-GAP-5b2: 6LoWPAN + BACnet."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402


def quiz(qs):
    out = ['```quiz']
    for q, opts, a, exp in qs:
        out.append('- question: ' + q)
        out.append('  options:')
        for o in opts:
            out.append('    - ' + o)
        out.append('  answer: ' + str(a))
        if exp:
            out.append('  explanation: ' + exp)
    out.append('```')
    return '\n'.join(out)


def lab(workdir, files, check, hints, expect_contains, fs):
    return dict(workdir=workdir, files=files, check=check, hints=hints,
                expect={'file': expect_contains[0], 'contains': expect_contains[1]},
                fs=fs)


# ===========================================================================
# 11. hardware-6lowpan
# ===========================================================================
L = dict(
    id='hardware-6lowpan',
    title='6LoWPAN: IPv6 поверх 802.15.4',
    category='hardware', parent='hardware-mod-iot-mesh', difficulty='hard',
    order=3,
    tags=['hardware', 'iot', '6lowpan', 'ipv6', '802154', 'compression'],
    prerequisites=['hardware-iot-network'], estimated_minutes=40,
    summary='6LoWPAN: как IPv6 ужимается в кадры 802.15.4, сжатие заголовков (IPHC/NHC), фрагментация и практические атаки на сеть.',
    useful_for=['CTF Hardware/IoT', 'Пентест IoT', 'Анализ промышленных mesh'],
)
body = '''## Вопрос, с которого всё начинается

IPv6-заголовок — 40 байт. Кадр 802.15.4 вмещает около 100 байт полезной нагрузки, а часто и меньше. Как втиснуть IPv6 в такую сеть?

Ответ — **6LoWPAN**: слой адаптации, который сжимает заголовки и умеет фрагментировать.

Вопрос урока: как 6LoWPAN ужимает IPv6 и что из этого следует для атак.

## Наш пример: кадр 6LoWPAN

У нас есть декодированный кадр 6LoWPAN со сжатым заголовком. Разберём, как из нескольких байт восстанавливается полный IPv6-пакет.

## Шаг 1: зачем нужен 6LoWPAN

**6LoWPAN** (IPv6 over Low-Power Wireless Personal Area Networks) — стандарт, который позволяет устройствам 802.15.4 участвовать в IP-сети. Это мост между крошечным IoT-устройством и интернетом. Thread, Zigbee IP и другие стеки используют 6LoWPAN.

Он решает три задачи: сжатие заголовков, фрагментацию, маршрутизацию mesh.

## Шаг 2: сжатие заголовков

Полный IPv6+UDP заголовок — 48 байт. 6LoWPAN умеет сокращать его до нескольких байт, если адреса можно вывести из контекста. Механизм называется **IPHC** (IPv6 Header Compression) в связке с **NHC** (Next Header Compression).

Идея: MAC-адреса 802.15.4 уже уникальны, поэтому IPv6-адрес можно сконструировать из них (link-local или по префиксу), а не передавать целиком.

```text
$ grep -m1 'IPHC' lowpan.log
IPHC: tf=11 nhc=1 hoplimit=64 src=linklocal dst=linklocal (compressed 40B->6B)
```

## Шаг 3: фрагментация

Если пакет не влезает в кадр, 6LoWPAN режет его на **фрагменты** с заголовком, содержащим датаграммный тег, размер и смещение. Сборка происходит на приёмнике.

```text
$ grep -n 'frag' lowpan.log | head -3
frag: tag=0x1A2B size=120 off=0
frag: tag=0x1A2B size=120 off=88
frag: tag=0x1A2B size=120 off=... (последний)
```

Атака на фрагментацию: слать фрагменты с перекрывающимися смещениями (как в классических IP-фрагментных атаках) и путать сборку.

## Шаг 4: маршрутизация mesh

6LoWPAN часто работает поверх **RPL** — протокола маршрутизации для LLN (low-power and lossy networks). Узлы строят дерево маршрутов к корню. Атаки на RPL: подделка метрик, создание «чёрной дыры», сброс ранга.

```text
$ grep -m1 'RPL' lowpan.log
RPL: root=fd00::1 rank=256 parent=fe80::1a2b
```

## Шаг 5: практические атаки

1. **Фрагментные аномалии** — перекрытие, неполная сборка.
2. **Подделка IPHC-контекста** — неверная реконструкция адресов.
3. **RPL-инъекции** — испортить маршрутное дерево.
4. **6LoWPAN-шлюз как цель** — скомпрометировать border router.

Практика: для теста подойдёт Contiki-NG / OpenThread и сниффер 802.15.4 (CC2531, nRF).

## Что мы теперь знаем

- 6LoWPAN адаптирует IPv6 к малым кадрам 802.15.4.
- IPHC/NHC сжимают заголовки за счёт вывода адресов из MAC.
- Фрагментация режет большие пакеты и уязвима к аномалиям.
- Поверх часто работает RPL, который можно атаковать.
- Border router — ключевая точка компрометации.

## Квиз

''' + quiz([
    ('Зачем нужен 6LoWPAN?',
     ['Чтобы запустить IPv6 в сети 802.15.4 с малыми кадрами',
      'Чтобы шифровать Zigbee', 'Чтобы заменить MAC-адреса'],
     0, '6LoWPAN — адаптация IPv6 к 802.15.4.'),
    ('Что делает IPHC?',
     ['Сжимает IPv6-заголовок, выводя адреса из контекста',
      'Шифрует пакет', 'Увеличивает MTU'],
     0, 'IPHC сокращает IPv6-заголовок до нескольких байт.'),
    ('Почему фрагментация 6LoWPAN уязвима?',
     ['Перекрывающиеся/неполные фрагменты путают сборку',
      'Она слишком медленная', 'Она не поддерживает теги'],
     0, 'Аномалии фрагментации — классический вектор.'),
    ('Что такое RPL?',
     ['Протокол маршрутизации для low-power сетей', 'Тип батарейки', 'Модуляция'],
     0, 'RPL строит маршрутное дерево в LLN.'),
]) + '''

## Куда дальше

Дальше перейдём к проводным сетям зданий — **BACnet**. А пока запомни: 6LoWPAN соединяет крошечный IoT с интернетом, и на этом стыке больше всего ошибок.

## Где пригодится

- **Пентест:** аудит IoT и промышленных mesh.
- **CTF:** категория Hardware/IoT.
- **Работа:** безопасность Thread/6LoWPAN-инсталляций.
- **Дальше по дереву:** `hardware-bacnet`, `hardware-zigbee-deep`.
'''
lab_b = lab(
    '/home/student/lowpan', ['task.md', 'notes.md', 'lowpan.log'],
    "grep -q 'nto{' found.txt",
    ['`lowpan.log` — декодированный 6LoWPAN-трафик.',
     'Смотри IPHC и фрагменты.',
     'Найди флаг: `grep nto lowpan.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/lowpan/found.txt', 'nto{'),
    [_dir('/home/student/lowpan'),
     _f('/home/student/lowpan/task.md', '# Задача: 6LoWPAN\n\nРазбери 6LoWPAN-трафик и найди флаг в восстановленном пакете.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/lowpan/notes.md', 'Заметки\n------\n- 6LoWPAN = IPv6 над 802.15.4.\n- IPHC/NHC сжимают заголовки.\n- Фрагменты имеют tag/size/offset.\n'),
     _f('/home/student/lowpan/lowpan.log',
        'IPHC: tf=11 nhc=1 hoplimit=64 src=linklocal dst=linklocal (compressed 40B->6B)\n'
        'frag: tag=0x1A2B size=120 off=0\n'
        'frag: tag=0x1A2B size=120 off=88\n'
        'RPL: root=fd00::1 rank=256 parent=fe80::1a2b\n'
        'reassembled: payload=nto{6l0wp4n_hc_c0mpr3ss10n}\n')]
)
write_lesson(L, body, lab_b)


# ===========================================================================
# 12. hardware-bacnet
# ===========================================================================
L = dict(
    id='hardware-bacnet',
    title='BACnet: здания, объекты и запись точек',
    category='hardware', parent='hardware-mod-iot-mesh', difficulty='medium',
    order=4,
    tags=['hardware', 'bacnet', 'building', 'bms', 'scada', 'ot'],
    prerequisites=['hardware-iot-network'], estimated_minutes=40,
    summary='BACnet для систем управления зданиями: объектная модель, сервисы чтения/записи, широковещательный discovery и атаки на BMS без аутентификации.',
    useful_for=['Пентест зданий и BMS', 'CTF Hardware/OT', 'Аудит АСУ зданий'],
)
body = '''## Вопрос, с которого всё начинается

Отопление, вентиляция, кондиционирование, доступ в здание, лифты — всем управляет **BMS** (Building Management System). Протокол, на котором она работает десятки лет, — **BACnet**. И у него по умолчанию почти нет аутентификации.

Вопрос урока: как устроен BACnet и как записать «точку» в чужом здании.

## Наш пример: BACnet-трафик BMS

У нас есть дамп BACnet-трафика: обнаружение устройств и команда записи. Разберём объектную модель и найдём записываемую точку.

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

''' + quiz([
    ('На каком порту BACnet/IP?',
     ['47808/UDP', '502/TCP', '102/TCP'],
     0, 'BACnet/IP использует 47808/UDP (0xBAC0).'),
    ('Какой сервис записывает значение?',
     ['WriteProperty', 'ReadProperty', 'Who-Is'],
     0, 'WriteProperty меняет свойство объекта.'),
    ('Почему BACnet опасен по умолчанию?',
     ['Нет аутентификации — любой в сети может писать',
      'Он слишком медленный', 'Он не поддерживает Ethernet'],
     0, 'BACnet без защиты позволяет управлять зданием.'),
    ('Что делает BACnet/SC?',
     ['Добавляет защищённое соединение (TLS)', 'Ускоряет обмен', 'Меняет порт на 80'],
     0, 'Secure Connect защищает трафик BACnet.'),
]) + '''

## Куда дальше

Дальше перейдём к прикладному уровню АСУ ТП — **OPC UA**. А пока запомни: в BMS запись точки часто равна физическому действию в здании.

## Где пригодится

- **Пентест:** аудит BMS, отелей, офисов, ЦОД.
- **CTF:** категория Hardware/OT.
- **Работа:** безопасность инженерных систем зданий.
- **Дальше по дереву:** `hardware-mod-ics-app`, `hardware-6lowpan`.
'''
lab_b = lab(
    '/home/student/bacnet', ['task.md', 'notes.md', 'bacnet.log'],
    "grep -q 'nto{' found.txt",
    ['`bacnet.log` — BACnet-трафик BMS.',
     'Смотри объекты и сервис WriteProperty.',
     'Найди флаг: `grep nto bacnet.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/bacnet/found.txt', 'nto{'),
    [_dir('/home/student/bacnet'),
     _f('/home/student/bacnet/task.md', '# Задача: BACnet\n\nРазбери BACnet-трафик BMS и найди флаг в записанном значении.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/bacnet/notes.md', 'Заметки\n------\n- BACnet/IP: 47808/UDP (0xBAC0).\n- Объекты: AnalogInput/Output, BinaryInput/Output, Device.\n- Сервисы: Who-Is/I-Am, ReadProperty, WriteProperty.\n'),
     _f('/home/student/bacnet/bacnet.log',
        'Who-Is: broadcast\n'
        'I-Am: device=1001 vendor=Acme name=AHU-1\n'
        'object: type=AnalogInput instance=1 present_value=21.5 units=C\n'
        'WriteProperty: dev=1001 obj=AnalogOutput:2 prop=Present_Value value=100.0\n'
        'capture: secret=nto{b4cn3t_wr1t3_p01nt_0wn3d}\n')]
)
write_lesson(L, body, lab_b)

print('b5b2 written')
