---
id: spec-iot
title: 'IoT-форензика: датчики, хабы и умные устройства'
category: forensics
parent: forensics-embedded-devices
difficulty: medium
order: 2
tags: [forensics, iot, embedded, firmware, mqtt]
prerequisites: [forensics-special-devices]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как расследовать IoT-устройства: носители, прошивки, локальные хабы и облачные привязки.'
lab:
  kind: shell
  title: 'Практика: IoT-форензика'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

В умном доме/офисе десятки устройств: датчики, камеры, хабы. Одно из них
скомпрометировано. Где смотреть? IoT-форензика — это работа с маленькими Linux-системами
и их привязкой к облаку.

## Наш пример: умная розетка

## Шаг 1: что внутри

Типичное IoT-устройство: SoC (ARM/MIPS), флеш (SPI NAND), Wi-Fi, минимальный Linux
или RTOS. Данных мало — но они есть.

```
$ binwalk -e device_firmware.bin
$ ls _device_firmware.bin.extracted/squashfs-root/
bin  etc  lib  usr
```

`binwalk` извлёк корневую ФС. Внутри — конфиги, скрипты, ключи.

## Шаг 2: локальные артефакты

- **конфиг Wi-Fi** (SSID, пароль);
- **токены облака** (привязка к аккаунту);
- **логи** (короткие, во флеше);
- **сертификаты** (для TLS к облаку).

```
$ grep -riE 'token|password|ssid' squashfs-root/etc/ | head
```

Часто токены лежат **в открытом виде** — это ключ к облачному аккаунту.

## Шаг 3: сетевые следы

IoT говорит по MQTT/CoAP/HTTP. Дамп трафика показывает:

- брокер/сервер;
- топики;
- команды.

```
$ tshark -r iot.pcap -Y 'mqtt' -T fields -e mqtt.topic | sort -u | head
```

## Шаг 4: хаб как точка сбора

Умный хаб (Hubitat/Home Assistant/SmartThings) агрегирует устройства и **хранит
логи**:

```
$ sqlite3 homeassistant.db 'SELECT * FROM states LIMIT 3;'
```

Это лучший источник: одна точка со всей историей.

## Шаг 5: облако

Производитель хранит данные в облаке. Если есть доступ к аккаунту — там история,
события, записи. Иначе — только локальные остатки.

## Что мы теперь знаем

- IoT — маленькие Linux/RTOS-устройства.
- `binwalk` извлекает ФС прошивки.
- Токены/пароли часто в открытом виде.
- Трафик — MQTT/CoAP/HTTP.
- Хаб и облако — точки сбора истории.

## Если не сработало

- Флеш зашифрована? Нужен дамп с работающего устройства.
- Нет доступа к облаку? Работай с хабом и трафиком.
- Устройство простое (RTOS)? Данных минимум — смотри сеть.

## Квиз

Проверь себя.

```quiz
- question: Что часто находят в прошивке IoT?
  options:
    - 'пароли диска'
    - 'токены облака и конфиги в открытом виде'
    - 'обои'
    - 'маршруты BGP'
  answer: 1
  explanation: 'Производители нередко хранят секреты без шифрования.'
- question: Какой инструмент извлекает ФС из прошивки?
  options:
    - 'grep'
    - 'binwalk'
    - 'cp'
    - 'ssh'
  answer: 1
  explanation: 'binwalk распознаёт squashfs и другие вложенные форматы.'
- question: Почему умный хаб ценен для форензики?
  options:
    - 'он быстрый'
    - 'хранит историю всех устройств'
    - 'шифрует'
    - 'мало места'
  answer: 1
  explanation: 'Хаб агрегирует состояния и события устройств.'
- question: Какой протокол типичен для IoT?
  options:
    - 'SMB'
    - 'MQTT'
    - 'RDP'
    - 'IPsec'
  answer: 1
  explanation: 'MQTT — лёгкий pub/sub протокол для устройств.'
```
