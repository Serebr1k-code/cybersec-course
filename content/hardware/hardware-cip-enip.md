---
id: hardware-cip-enip
title: 'CIP / EtherNet-IP глубоко: объекты и запись'
category: hardware
parent: hardware-mod-ics-app
difficulty: hard
order: 2
tags: [hardware, ics, cip, enip, ethernet-ip, scada, allen-bradley]
prerequisites: [hardware-ics]
useful_for:
  - 'Пентест АСУ ТП'
  - 'CTF Hardware/ICS'
  - 'Аудит промышленного Ethernet'
estimated_minutes: 45
summary: 'CIP/EtherNet-IP: объектная модель, явный и неявный обмен, классы и атрибуты, чтение/запись тегов и атаки на промышленные контроллеры.'
lab:
  kind: shell
  toolset: [core, python]
  workdir: /home/student/enip
  files: [task.md, notes.md, enip.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`enip.log` — EtherNet-IP/CIP-трафик.'
    - 'Смотри сервисы Read/Write Tag.'
    - 'Найди флаг: `grep nto enip.log | cut -d= -f2 > found.txt`.'
---

## Вопрос, с которого всё начинается

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

```quiz
- question: Какой порт у EtherNet-IP (явный обмен)?
  options:
    - 44818/TCP
    - 502/TCP
    - 47808/UDP
  answer: 0
  explanation: EtherNet-IP explicit messaging — 44818/TCP.
- question: Что такое CIP?
  options:
    - Объектная модель поверх EtherNet-IP
    - Протокол шины давления
    - Замена TCP
  answer: 0
  explanation: CIP — Common Industrial Protocol, объектная модель.
- question: Какой сервис пишет тег ПЛК?
  options:
    - Write Tag (0x4D)
    - ListIdentity
    - RegisterSession
  answer: 0
  explanation: Write Tag меняет значение тега в контроллере.
- question: Чем опасен неявный обмен (UDP 2222)?
  options:
    - Циклические IO-данные часто без аутентификации
    - Он слишком медленный
    - Он шифрует трафик
  answer: 0
  explanation: Implicit messaging — циклический обмен сборками без защиты.
```

## Куда дальше

Дальше разберём энергетику — **Smart grid и DLMS/COSEM**. А пока запомни: в EtherNet-IP запись тега = физическое действие на производстве.

## Где пригодится

- **Пентест:** аудит производств и АСУ ТП.
- **CTF:** категория Hardware/ICS.
- **Работа:** безопасность промышленного Ethernet.
- **Дальше по дереву:** `hardware-smart-grid`, `hardware-opc-ua`.
