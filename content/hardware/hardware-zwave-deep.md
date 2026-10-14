---
id: hardware-zwave-deep
title: 'Z-Wave глубоко: S0/S2, кадры и атаки на ключи'
category: hardware
parent: hardware-mod-iot-mesh
difficulty: hard
order: 1
tags: [hardware, iot, zwave, s0, s2, smart-home, crypto]
prerequisites: [hardware-rf-protocols]
useful_for:
  - 'Пентест умных домов'
  - 'CTF Hardware/RF'
  - 'Аудит IoT'
estimated_minutes: 45
summary: 'Z-Wave: топология mesh, кадры, режимы шифрования S0 и S2, включение устройства в сеть (inclusion) и практические атаки на слабые ключи.'
lab:
  kind: shell
  toolset: [core, python]
  workdir: /home/student/zwave
  files: [task.md, notes.md, zwave.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`zwave.log` — Z-Wave-трафик сети.'
    - 'Смотри command class и процедуру inclusion.'
    - 'Найди флаг: `grep nto zwave.log | cut -d= -f2 > found.txt`.'
---

## Вопрос, с которого всё начинается

Z-Wave — самый распространённый протокол «умного дома» после Zigbee: замки, датчики, выключатели. У него есть шифрование, и на бумаге он защищён. Но реальные атаки на Z-Wave существуют, и они почти всегда про ключи и включение устройства в сеть.

Вопрос урока: как устроен Z-Wave и где ломается его защита.

## Наш пример: кадры Z-Wave из сети

У нас есть лог Z-Wave-трафика: включение устройства в сеть и обмен командами. Разберём кадры и найдём момент, где ключ передаётся слабо.

## Шаг 1: mesh и роли

Z-Wave — mesh-сеть: устройства пересылают сообщения друг через друга, чтобы дотянуться дальше. Есть **controller** (хаб) и **nodes** (устройства). Каждое устройство имеет **home ID** (идентификатор сети) и **node ID**.

```text
$ grep -m2 'homeid' zwave.log
frame: homeid=0xDEADBEEF src=1 dst=2 type=REQ
frame: homeid=0xDEADBEEF src=2 dst=1 type=RESP
```

`homeid` — общий для всей сети, `node ID` — уникален в её пределах.

## Шаг 2: кадры и команды

Кадр Z-Wave содержит заголовок с home/node ID, длиной, и **command class** — тип команды. Например, `COMMAND_CLASS_SWITCH_BINARY` управляет реле, `COMMAND_CLASS_DOOR_LOCK` — замком.

```text
$ grep -m1 'SWITCH_BINARY' zwave.log
cmd: class=0x25 (SWITCH_BINARY) set=0xFF node=3
```

Без шифрования эти команды видны открыто. С шифрованием — payload закрыт.

## Шаг 3: S0 — слабый режим

Z-Wave **S0** (Security 0) — первый режим шифрования. Он использует AES, но с известной проблемой: обмен ключом и вектор инициализации согласуются предсказуемо, что даёт возможность атаки на этапе включения.

Ключевой момент — процедура **inclusion**: когда вы добавляете новое устройство, контроллер передаёт ему сетевой ключ. В S0 этот обмен уязвим, если злоумышленник находится в радиоэфире в нужный момент.

## Шаг 4: S2 и его улучшения

**S2** исправляет слабости S0: используется аутентифицированный обмен ключом (ECDH) и проверка **DSK** (Device Specific Key) — код на наклейке устройства. При S2 включение требует либо ввода DSK, либо QR-кода.

```text
$ grep -n 'S2\|DSK' zwave.log
inclusion: security=S2 authenticated=true dsk=12345-67890-...
```

Но если сеть работает в режиме «S2 unauthenticated» (без ввода DSK), защита слабее. А многие старые устройства поддерживают только S0.

## Шаг 5: атаки

1. **S0 inclusion** — перехватить обмен ключом при добавлении устройства.
2. **Downgrade** — заставить сеть использовать S0 вместо S2.
3. **Replay** — если счётчики не проверяются, повторить команду.
4. **Кража контроллера** — физический доступ к хабу даёт ключи.
5. **Zniffer** — специализированный сниффер Z-Wave для анализа.

Практика: для теста нужен Z-Wave-радио (Silicon Labs, `Zniffer`) и разрешение на передачу.

## Что мы теперь знаем

- Z-Wave — mesh-сеть с home ID и node ID.
- Кадры содержат command class; команды видны без шифрования.
- S0 уязвим на этапе обмена ключом при включении.
- S2 использует ECDH и DSK, но «unauthenticated» слабее.
- Атаки чаще всего на inclusion и downgrade, а не на сам AES.

## Квиз

```quiz
- question: Что идентифицирует сеть Z-Wave?
  options:
    - Home ID
    - MAC-адрес
    - SSID
  answer: 0
  explanation: Home ID общий для всей сети Z-Wave.
- question: Почему S0 считают слабым?
  options:
    - Уязвимый обмен ключом и IV при включении
    - Он не шифрует
    - Он медленный
  answer: 0
  explanation: S0 имеет известные слабости в согласовании ключа.
- question: Что использует S2 для защиты включения?
  options:
    - ECDH и DSK устройства
    - Пароль по умолчанию
    - Только CRC
  answer: 0
  explanation: S2 — аутентифицированный обмен ключом с DSK.
- question: Что такое Zniffer?
  options:
    - Сниффер Z-Wave
    - Прошивка хаба
    - Тип батарейки
  answer: 0
  explanation: Zniffer — инструмент захвата Z-Wave-трафика.
```

## Куда дальше

Дальше разберём **Zigbee** — второго гиганта mesh-сетей. А пока запомни: слабое место Z-Wave — момент включения устройства, а не сам алгоритм.

## Где пригодится

- **Пентест:** аудит умных домов и отелей.
- **CTF:** категория Hardware/RF.
- **Работа:** безопасность IoT-инсталляций.
- **Дальше по дереву:** `hardware-zigbee-deep`, `hardware-6lowpan`.
