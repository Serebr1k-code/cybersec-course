#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch HW-GAP-5c: ICS app — OPC UA, CIP/EtherNet-IP, smart-grid/DLMS."""
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
# 13. hardware-opc-ua
# ===========================================================================
L = dict(
    id='hardware-opc-ua',
    title='OPC UA: безопасность, сертификаты и обход',
    category='hardware', parent='hardware-mod-ics-app', difficulty='hard',
    order=1,
    tags=['hardware', 'ics', 'opcua', 'scada', 'certificates', 'security-policy'],
    prerequisites=['hardware-ics', 'hardware-mod-ics-protocols'], estimated_minutes=45,
    summary='OPC UA: адресное пространство, эндпоинты и security policies, сертификаты, анонимные сессии и типовые ошибки конфигурации, ведущие к обходу.',
    useful_for=['Пентест АСУ ТП', 'CTF Hardware/ICS', 'Аудит промышленных протоколов'],
)
body = '''## Вопрос, с которого всё начинается

OPC UA задуман как безопасный промышленный протокол: шифрование, подписи, сертификаты. Но в реальных АСУ ТП он часто настроен так, что «безопасность» остаётся на бумаге.

Вопрос урока: как устроена защита OPC UA и где она ломается конфигурацией.

## Наш пример: OPC UA-сервер

У нас есть дамп сессии с OPC UA-сервером. Видны эндпоинты, согласование политики безопасности и чтение узла. Разберём, какая политика была выбрана и что это значит.

## Шаг 1: адресное пространство и узлы

OPC UA представляет данные как **узлы** (nodes) в адресном пространстве: переменные, объекты, методы. У каждого узла есть **NodeId** (идентификатор) и атрибуты, главный — **Value**.

```text
$ grep -m2 'NodeId' opcua.log
Read ns=2;s=Machine.Temperature -> 72.4
Read ns=2;s=Machine.Setpoint -> 70.0
```

Здесь `ns=2;s=Machine.Temperature` — строковый NodeId в пространстве имён 2. Чтение значения — базовый сервис.

## Шаг 2: эндпоинты и security policy

При подключении клиент запрашивает **GetEndpoints** — список доступных точек входа, у каждой своя **SecurityPolicy**. Политики бывают:

- **None** — без шифрования и подписи.
- **Basic128Rsa15 / Basic256 / Basic256Sha256** — разные уровни.
- **Aes128Sha256RsaOaep / Aes256Sha256RsaPss** — современные.

```text
$ grep -n 'SecurityPolicy' opcua.log
Endpoint: SecurityPolicy=None, SecurityMode=None
Endpoint: SecurityPolicy=Basic256Sha256, SecurityMode=SignAndEncrypt
```

Сервер отдаёт оба. Если клиент выберет **None**, сессия будет открытой.

## Шаг 3: анонимные сессии

Даже при хорошей политике сервер может разрешить **Anonymous** аутентификацию. Тогда любой подключается без учётных данных.

```text
$ grep -n 'UserToken' opcua.log
UserTokenPolicy: Anonymous
UserTokenPolicy: UserName
ActivateSession: anonymous=true -> OK
```

Частая ошибка: политика SignAndEncrypt, но токен Anonymous. Шифрование есть, но доступа лишён никто.

## Шаг 4: сертификаты

OPC UA использует X.509-сертификаты. Слабые места:

1. **Self-signed без проверки** — сервер принимает любой сертификат.
2. **Просроченные сертификаты** — приложение отключает проверку, чтобы «работало».
3. **Один сертификат на всех** — компрометация одного даёт доступ ко всем.
4. **Доверие всему хранилищу** — если в trust list попал лишний сертификат.

## Шаг 5: практический обход

Типичный сценарий пентеста:

1. `GetEndpoints` → найти эндпоинт с `None`.
2. Если его нет — проверить, разрешён ли Anonymous.
3. Если и это закрыто — посмотреть, принимает ли сервер произвольный сертификат (MITM).
4. Через разрешённую сессию — перечислить узлы и найти методы (методы могут выполнять действия на оборудовании).

```text
$ python3 -c "print('UAExpert / opcua-client: connect, browse, read, call method')"
UAExpert / opcua-client: connect, browse, read, call method
```

Инструменты: UaExpert, `opcua-client`, Prosys, `nmap --script opcua-info`.

## Что мы теперь знаем

- OPC UA описывает данные как узлы с NodeId и атрибутами.
- Каждый эндпоинт имеет SecurityPolicy; политика None = открытая сессия.
- Anonymous-токен обнуляет смысл шифрования.
- Сертификаты часто не проверяются — возможен MITM.
- Методы-узлы могут управлять оборудованием.

## Квиз

''' + quiz([
    ('Что определяет SecurityPolicy в OPC UA?',
     ['Алгоритмы аутентификации/шифрования сессии', 'Список узлов', 'IP-адрес сервера'],
     0, 'Политика задаёт криптографию сессии; None = без защиты.'),
    ('Чем опасна политика None?',
     ['Сессия без шифрования и подписи', 'Она медленная', 'Она несовместима с TCP'],
     0, 'None означает полностью открытую сессию.'),
    ('Почему Anonymous-токен подрывает защиту?',
     ['Доступ получает кто угодно, даже при шифровании',
      'Он слишком короткий', 'Он ломает сертификат'],
     0, 'Анонимная сессия не требует учётных данных.'),
    ('Какая типичная ошибка с сертификатами OPC UA?',
     ['Проверка отключена или принимается любой сертификат',
      'Слишком длинный ключ', 'Слишком много узлов'],
     0, 'Отсутствие проверки сертификата открывает MITM.'),
]) + '''

## Куда дальше

Дальше разберём **CIP/EtherNet-IP** — промышленный Ethernet с объектной моделью. А пока запомни: OPC UA ломается не криптографией, а настройками.

## Где пригодится

- **Пентест:** аудит АСУ ТП и производств.
- **CTF:** категория Hardware/ICS.
- **Работа:** проектирование и проверка OPC UA.
- **Дальше по дереву:** `hardware-cip-enip`, `hardware-mod-ics-protocols`.
'''
lab_b = lab(
    '/home/student/opcua', ['task.md', 'notes.md', 'opcua.log'],
    "grep -q 'nto{' found.txt",
    ['`opcua.log` — OPC UA-сессия с эндпоинтами.',
     'Смотри SecurityPolicy, UserTokenPolicy и чтение узлов.',
     'Найди флаг: `grep nto opcua.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/opcua/found.txt', 'nto{'),
    [_dir('/home/student/opcua'),
     _f('/home/student/opcua/task.md', '# Задача: OPC UA\n\nРазбери OPC UA-сессию, найди небезопасную конфигурацию и флаг.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/opcua/notes.md', 'Заметки\n------\n- Узлы: NodeId + атрибуты; главный атрибут Value.\n- SecurityPolicy None = открытая сессия.\n- Anonymous-токен обнуляет смысл шифрования.\n'),
     _f('/home/student/opcua/opcua.log',
        'Endpoint: SecurityPolicy=None, SecurityMode=None\n'
        'Endpoint: SecurityPolicy=Basic256Sha256, SecurityMode=SignAndEncrypt\n'
        'UserTokenPolicy: Anonymous\n'
        'ActivateSession: anonymous=true -> OK\n'
        'Read ns=2;s=Machine.Secret -> nto{0pc_u4_p0l1cy_n0n3}\n')]
)
write_lesson(L, body, lab_b)


# ===========================================================================
# 14. hardware-cip-enip
# ===========================================================================
L = dict(
    id='hardware-cip-enip',
    title='CIP / EtherNet-IP глубоко: объекты и запись',
    category='hardware', parent='hardware-mod-ics-app', difficulty='hard',
    order=2,
    tags=['hardware', 'ics', 'cip', 'enip', 'ethernet-ip', 'scada', 'allen-bradley'],
    prerequisites=['hardware-ics'], estimated_minutes=45,
    summary='CIP/EtherNet-IP: объектная модель, явный и неявный обмен, классы и атрибуты, чтение/запись тегов и атаки на промышленные контроллеры.',
    useful_for=['Пентест АСУ ТП', 'CTF Hardware/ICS', 'Аудит промышленного Ethernet'],
)
body = '''## Вопрос, с которого всё начинается

EtherNet-IP — промышленный Ethernet, популярный у Allen-Bradley/Rockwell. Он несёт **CIP** — Common Industrial Protocol, объектную модель, похожую на то, что мы видели в BACnet, но в АСУ ТП.

Вопрос урока: как разобрать CIP-обмен и найти теги, которые можно записать.

## Наш пример: CIP-обмен с ПЛК

У нас есть дамп EtherNet-IP-трафика с контроллером. Видны сессия ENIP, затем CIP-запросы к объектам. Разберём и найдём записываемый тег.

## Шаг 1: два уровня — ENIP и CIP

**EtherNet-IP** — это обёртка над **CIP**. Сообщение состоит из:

- **ENCAP** (Encapsulation) — заголовок ENIP с командами сессии (ListIdentity, RegisterSession, SendRRData).
- **CIP** — собственно запрос: service + class + instance + attribute.

```text
$ grep -m2 'ENIP' enip.log
ENIP: cmd=ListIdentity -> reply vendor=Rockwell device=1756-L83E
ENIP: cmd=RegisterSession session=0x01020304
```

Порт по умолчанию — **44818/TCP** (явные сообщения) и **2222/UDP** (неявные/IO).

## Шаг 2: объектная модель CIP

CIP описывает устройство как набор **объектов** (class), у каждого — **instances** и **attributes**. Ключевые классы:

- **Identity (0x01)** — информация об устройстве.
- **Message Router (0x02)** — маршрутизация.
- **Assembly (0x04)** — сборки данных IO.
- **Symbol (0x6B)** — доступ к тегам ПЛК.

```text
$ grep -n 'class=' enip.log | head -3
CIP: service=0x0E (Get_Attribute_Single) class=0x01 inst=1 attr=1
CIP: service=0x52 (Unconnected_Send) path=Tag/Setpoint
```

## Шаг 3: чтение тегов

Теги ПЛК (`Setpoint`, `Run`, `Valve_1`) читаются и пишутся CIP-сервисами. Сервис `0x4C` (Read Tag) и `0x4D` (Write Tag) работают с Symbol object.

```text
$ grep -n 'Read Tag\|Write Tag' enip.log
CIP: Read Tag Setpoint = 70.0
CIP: Write Tag Setpoint = 100.0
```

Если Write Tag доступен анонимно, вы управляете процессом.

## Шаг 4: явный и неявный обмен

- **Explicit messaging** (TCP 44818) — запрос/ответ: чтение тегов, диагностика.
- **Implicit messaging** (UDP 2222) — циклический IO-обмен в реальном времени, часто без аутентификации и с фиксированными сборками.

Неявный обмен сложнее подделать (нужны тайминги и сборки), но и там бывают инъекции.

## Шаг 5: атаки

1. **Анонимное чтение** — вытянуть всю логику и теги.
2. **Запись тегов** — изменить уставки, запустить/остановить.
3. **Stop CPU** — некоторые контроллеры имеют сервис остановки (CIP Security).
4. **Спуфинг IO** — подменить неявные данные.
5. **Выгрузка проекта** — скачать проект ПЛК через CIP.

Инструменты: `cpppo`, `enip`, Scapy, Wireshark-профиль ENIP, `nmap --script enip-info`.

## Что мы теперь знаем

- EtherNet-IP = ENIP-обёртка + CIP-объекты.
- Порты: 44818/TCP (явный), 2222/UDP (неявный IO).
- CIP: service + class + instance + attribute; теги через Symbol object.
- Чтение/запись тегов и остановка CPU — ключевые сервисы для атаки.
- По умолчанию аутентификации нет (CIP Security — редкое исключение).

## Квиз

''' + quiz([
    ('Какой порт у EtherNet-IP (явный обмен)?',
     ['44818/TCP', '502/TCP', '47808/UDP'],
     0, 'EtherNet-IP explicit messaging — 44818/TCP.'),
    ('Что такое CIP?',
     ['Объектная модель поверх EtherNet-IP', 'Протокол шины давления', 'Замена TCP'],
     0, 'CIP — Common Industrial Protocol, объектная модель.'),
    ('Какой сервис пишет тег ПЛК?',
     ['Write Tag (0x4D)', 'ListIdentity', 'RegisterSession'],
     0, 'Write Tag меняет значение тега в контроллере.'),
    ('Чем опасен неявный обмен (UDP 2222)?',
     ['Циклические IO-данные часто без аутентификации', 'Он слишком медленный', 'Он шифрует трафик'],
     0, 'Implicit messaging — циклический обмен сборками без защиты.'),
]) + '''

## Куда дальше

Дальше разберём энергетику — **Smart grid и DLMS/COSEM**. А пока запомни: в EtherNet-IP запись тега = физическое действие на производстве.

## Где пригодится

- **Пентест:** аудит производств и АСУ ТП.
- **CTF:** категория Hardware/ICS.
- **Работа:** безопасность промышленного Ethernet.
- **Дальше по дереву:** `hardware-smart-grid`, `hardware-opc-ua`.
'''
lab_b = lab(
    '/home/student/enip', ['task.md', 'notes.md', 'enip.log'],
    "grep -q 'nto{' found.txt",
    ['`enip.log` — EtherNet-IP/CIP-трафик.',
     'Смотри сервисы Read/Write Tag.',
     'Найди флаг: `grep nto enip.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/enip/found.txt', 'nto{'),
    [_dir('/home/student/enip'),
     _f('/home/student/enip/task.md', '# Задача: CIP/EtherNet-IP\n\nРазбери CIP-обмен и найди флаг в записанном теге.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/enip/notes.md', 'Заметки\n------\n- ENIP: 44818/TCP (explicit), 2222/UDP (implicit).\n- CIP: service + class + instance + attribute.\n- Read Tag 0x4C, Write Tag 0x4D.\n'),
     _f('/home/student/enip/enip.log',
        'ENIP: cmd=ListIdentity -> reply vendor=Rockwell device=1756-L83E\n'
        'ENIP: cmd=RegisterSession session=0x01020304\n'
        'CIP: service=0x0E (Get_Attribute_Single) class=0x01 inst=1 attr=1\n'
        'CIP: Read Tag Setpoint = 70.0\n'
        'CIP: Write Tag Flag = nto{c1p_t4g_wr1t3_0wn3d}\n')]
)
write_lesson(L, body, lab_b)


# ===========================================================================
# 15. hardware-smart-grid
# ===========================================================================
L = dict(
    id='hardware-smart-grid',
    title='Smart grid / AMI / DLMS-COSEM: счётчики и инфраструктура',
    category='hardware', parent='hardware-mod-ics-app', difficulty='hard',
    order=3,
    tags=['hardware', 'ics', 'smart-grid', 'ami', 'dlms', 'cosem', 'metering'],
    prerequisites=['hardware-ics'], estimated_minutes=45,
    summary='Умные счётчики и AMI: DLMS/COSEM поверх HDLC, ассоциации и пароли, оптический порт, манипуляции показаниями и защита энергетической инфраструктуры.',
    useful_for=['Пентест энергетики', 'CTF Hardware/ICS', 'Аудит AMI'],
)
body = '''## Вопрос, с которого всё начинается

«Умные» электросчётчики подключены к сети и передают показания. Внутри них — протокол **DLMS/COSEM**. Если к счётчику есть доступ (оптический порт или радио), можно не только прочитать данные, но и повлиять на учёт.

Вопрос урока: как устроен DLMS/COSEM и что там типично слабо.

## Наш пример: обмен со счётчиком

У нас есть лог обмена со счётчиком по оптическому порту. Видны HDLC-кадры, установка ассоциации и чтение объекта. Разберём и найдём данные учёта.

## Шаг 1: AMI и роль счётчика

**AMI** (Advanced Metering Infrastructure) — сеть умных счётчиков: сами счётчики, концентраторы и head-end система. Счётчик измеряет потребление и передаёт его наверх. Протокол общения — **DLMS/COSEM** (IEC 62056).

DLMS описывает данные как **объекты COSEM** (классы, атрибуты), а передаётся либо по HDLC (оптика/последовательный), либо по IP (через концентратор).

## Шаг 2: HDLC-кадры

По оптическому порту DLMS идёт поверх **HDLC** — кадрового протокола с адресами и CRC. Кадр начинается и заканчивается флагом `0x7E`.

```text
$ grep -n 'HDLC' meter.log | head -2
HDLC: 7E A0 1E 21 03 93 ... 7E (SNRM, установка связи)
HDLC: 7E A0 1A 21 03 73 ... 7E (UA, подтверждение)
```

Порт для оптической головки по IEC 62056-21 часто `/dev/ttyUSB0`, скорость 300/9600 бод.

## Шаг 3: ассоциации и пароли

DLMS работает через **associations** — логические соединения. Публичная ассоциация (`public client`) часто читает базовые данные без пароля. Ассоциация управления требует пароля (LOW или HLS — high-level security).

```text
$ grep -n 'association\|password' meter.log
AARQ: association=public client, auth=none -> AARE accepted
AARQ: association=management client, auth=LOW, password=00000000 (default)
```

**Дефолтные пароли** (например, `00000000` или фабричный) — классическая слабость. С ними вы получаете управляющую ассоциацию.

## Шаг 4: чтение и запись объектов

Через ассоциацию вы читаете объекты: регистры энергии, тарифы, журналы. Некоторые объекты доступны и на запись (уставки, тарифы, иногда сброс).

```text
$ python3 -c "print('GET obis=1.0.1.8.0.255 -> energy A+ = 1234.5 kWh')"
GET obis=1.0.1.8.0.255 -> energy A+ = 1234.5 kWh
```

Инструменты: `gurux.dlms`, `dlms-cosem`, `openmeter`, скрипты на Python.

## Шаг 5: атаки

1. **Дефолтный пароль** — управляющая ассоциация без усилий.
2. **Физический оптический порт** — доступ к счётчику у щитка.
3. **Манипуляция показаниями** — запись регистров или тарифов.
4. **Отключение** — через реле счётчика (если есть).
5. **Широковещательные команды** — некоторые счётчики реагируют на broadcast.

Защита: HLS-аутентификация (challenge-response с ключом), шифрование (security suite), пломбы и контроль доступа.

## Что мы теперь знаем

- AMI = счётчики + концентраторы + head-end; протокол DLMS/COSEM.
- Транспорт: HDLC (оптика) или IP.
- Ассоциации: public (чтение) и management (запись, требует пароля).
- Дефолтные пароли — главная практическая слабость.
- Защита — HLS + шифрование + физические пломбы.

## Квиз

''' + quiz([
    ('Какой протокол используют умные счётчики?',
     ['DLMS/COSEM (IEC 62056)', 'Modbus', 'HTTP'],
     0, 'Счётчики общаются по DLMS/COSEM.'),
    ('Что такое ассоциация в DLMS?',
     ['Логическое соединение с уровнем доступа', 'Пароль администратора', 'Тип кабеля'],
     0, 'Ассоциация задаёт права: public читает, management пишет.'),
    ('Какая типичная слабость счётчиков?',
     ['Дефолтные пароли управляющей ассоциации', 'Слишком быстрый обмен', 'Отсутствие HDLC'],
     0, 'Фабричные/дефолтные пароли открывают управляющий доступ.'),
    ('Что защищает счётчик лучше всего?',
     ['HLS-аутентификация и шифрование', 'Длинный пароль в открытом виде', 'Смена частоты'],
     0, 'HLS (challenge-response) и security suite — реальная защита.'),
]) + '''

## Куда дальше

Мы закрыли прикладной ICS-кластер. Дальше логично взять физические атаки и side-channel глубину. А пока запомни: счётчик — это компьютер в щитке, и дефолтный пароль открывает учёт.

## Где пригодится

- **Пентест:** аудит AMI и энергетической инфраструктуры.
- **CTF:** категория Hardware/ICS.
- **Работа:** безопасность smart grid.
- **Дальше по дереву:** `hardware-mod-ics-protocols`, `hardware-mod-silicon`.
'''
lab_b = lab(
    '/home/student/meter', ['task.md', 'notes.md', 'meter.log'],
    "grep -q 'nto{' found.txt",
    ['`meter.log` — обмен со счётчиком по HDLC/DLMS.',
     'Смотри ассоциации и пароли.',
     'Найди флаг: `grep nto meter.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/meter/found.txt', 'nto{'),
    [_dir('/home/student/meter'),
     _f('/home/student/meter/task.md', '# Задача: DLMS/COSEM\n\nРазбери обмен со счётчиком и найди флаг в прочитанном объекте.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/meter/notes.md', 'Заметки\n------\n- DLMS/COSEM поверх HDLC (оптика) или IP.\n- Ассоциации: public (чтение), management (запись).\n- Дефолтные пароли — частая слабость.\n'),
     _f('/home/student/meter/meter.log',
        'HDLC: 7E A0 1E 21 03 93 ... 7E (SNRM)\n'
        'HDLC: 7E A0 1A 21 03 73 ... 7E (UA)\n'
        'AARQ: association=public client, auth=none -> AARE accepted\n'
        'AARQ: association=management client, auth=LOW, password=00000000 (default)\n'
        'GET obis=1.0.1.8.0.255 -> energy A+ = nto{d1m5_d3f4ult_p4ssw0rd}\n')]
)
write_lesson(L, body, lab_b)

print('b5c written')
