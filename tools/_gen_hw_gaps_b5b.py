#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch HW-GAP-5b: RF-IoT mesh — Z-Wave, Zigbee, 6LoWPAN, BACnet."""
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
# 9. hardware-zwave-deep
# ===========================================================================
L = dict(
    id='hardware-zwave-deep',
    title='Z-Wave глубоко: S0/S2, кадры и атаки на ключи',
    category='hardware', parent='hardware-mod-iot-mesh', difficulty='hard',
    order=1,
    tags=['hardware', 'iot', 'zwave', 's0', 's2', 'smart-home', 'crypto'],
    prerequisites=['hardware-rf-protocols'], estimated_minutes=45,
    summary='Z-Wave: топология mesh, кадры, режимы шифрования S0 и S2, включение устройства в сеть (inclusion) и практические атаки на слабые ключи.',
    useful_for=['Пентест умных домов', 'CTF Hardware/RF', 'Аудит IoT'],
)
body = '''## Вопрос, с которого всё начинается

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

''' + quiz([
    ('Что идентифицирует сеть Z-Wave?',
     ['Home ID', 'MAC-адрес', 'SSID'],
     0, 'Home ID общий для всей сети Z-Wave.'),
    ('Почему S0 считают слабым?',
     ['Уязвимый обмен ключом и IV при включении', 'Он не шифрует', 'Он медленный'],
     0, 'S0 имеет известные слабости в согласовании ключа.'),
    ('Что использует S2 для защиты включения?',
     ['ECDH и DSK устройства', 'Пароль по умолчанию', 'Только CRC'],
     0, 'S2 — аутентифицированный обмен ключом с DSK.'),
    ('Что такое Zniffer?',
     ['Сниффер Z-Wave', 'Прошивка хаба', 'Тип батарейки'],
     0, 'Zniffer — инструмент захвата Z-Wave-трафика.'),
]) + '''

## Куда дальше

Дальше разберём **Zigbee** — второго гиганта mesh-сетей. А пока запомни: слабое место Z-Wave — момент включения устройства, а не сам алгоритм.

## Где пригодится

- **Пентест:** аудит умных домов и отелей.
- **CTF:** категория Hardware/RF.
- **Работа:** безопасность IoT-инсталляций.
- **Дальше по дереву:** `hardware-zigbee-deep`, `hardware-6lowpan`.
'''
lab_b = lab(
    '/home/student/zwave', ['task.md', 'notes.md', 'zwave.log'],
    "grep -q 'nto{' found.txt",
    ['`zwave.log` — Z-Wave-трафик сети.',
     'Смотри command class и процедуру inclusion.',
     'Найди флаг: `grep nto zwave.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/zwave/found.txt', 'nto{'),
    [_dir('/home/student/zwave'),
     _f('/home/student/zwave/task.md', '# Задача: Z-Wave\n\nРазбери Z-Wave-трафик и найди флаг в служебных данных.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/zwave/notes.md', 'Заметки\n------\n- home ID + node ID. command class задаёт команду.\n- S0: слабый обмен ключом. S2: ECDH + DSK.\n- Zniffer — сниффер.\n'),
     _f('/home/student/zwave/zwave.log',
        'frame: homeid=0xDEADBEEF src=1 dst=2 type=REQ\n'
        'cmd: class=0x25 (SWITCH_BINARY) set=0xFF node=3\n'
        'inclusion: security=S2 authenticated=true dsk=12345-67890-...\n'
        'note: legacy device uses S0 (weak inclusion)\n'
        'capture: secret=nto{zw4v3_s0_1nclus10n_w34k}\n')]
)
write_lesson(L, body, lab_b)


# ===========================================================================
# 10. hardware-zigbee-deep
# ===========================================================================
L = dict(
    id='hardware-zigbee-deep',
    title='Zigbee глубоко: стек, ключи, OTA и атаки',
    category='hardware', parent='hardware-mod-iot-mesh', difficulty='hard',
    order=2,
    tags=['hardware', 'iot', 'zigbee', '802154', 'keys', 'ota', 'smart-home'],
    prerequisites=['hardware-rf-protocols'], estimated_minutes=45,
    summary='Zigbee поверх 802.15.4: стек, типы ключей (network/TC link), извлечение ключей, OTA-обновления и практические атаки на mesh-сеть.',
    useful_for=['Пентест умных домов', 'CTF Hardware/RF', 'Аудит IoT'],
)
body = '''## Вопрос, с которого всё начинается

Zigbee — второй после Z-Wave массовый протокол умного дома: лампы Hue, датчики, розетки. Он построен поверх 802.15.4 и использует шифрование AES-128. Казалось бы, безопасно. Но большинство публичных атак на Zigbee — это атаки на ключи и на то, как они передаются.

Вопрос урока: как устроен стек Zigbee и где взять ключ.

## Наш пример: перехваченный обмен Zigbee

У нас есть дамп Zigbee-сети с ключом, переданным открыто при подключении. Разберём кадры и найдём ключ.

## Шаг 1: стек 802.15.4 → Zigbee

Zigbee работает на радио 802.15.4 (2.4 ГГц, но бывает и sub-GHz). Физический и MAC-уровни — это 802.15.4, а поверх них Zigbee добавляет **NWK** (сеть) и **APS** (приложения).

Устройства делятся на роли: **coordinator** (координатор), **router** и **end device**. Маршрутизацию по mesh-сети ведёт NWK.

```text
$ grep -m2 'NWK' zigbee.log
NWK: src=0x1A2B dst=0x0000 broadcast=true
APS: cluster=0x0006 (OnOff) ep=1
```

## Шаг 2: типы ключей

В Zigbee есть два главных ключа:

- **Network key** — шифрует весь трафик сети. Один на всех.
- **TC link key** (Trust Center link key) — используется при подключении устройства к координатору (Trust Center).

Проблема: у многих устройств **TC link key по умолчанию** — известная всем строка `ZigBeeAlliance09`. Зная её, можно выдать себя за устройство и получить сетевой ключ.

```text
$ grep -n 'linkkey' zigbee.log
join: TC_link_key=5A6967426565416C6C69616E63653039  # ZigBeeAlliance09 (default)
transport-key: network_key=00112233445566778899AABBCCDDEEFF
```

## Шаг 3: извлечение ключа

Ключи можно добыть несколькими путями:

1. **Default TC link key** — как выше.
2. **Sniff на этапе join** — если ключ передаётся в момент подключения.
3. **OTA-дамп** — вытащить из прошивки устройства.
4. **Физический доступ** — прочитать flash.

С добытым сетевым ключом весь трафик расшифровывается.

## Шаг 4: расшифровка и инъекции

Зная network key и счётчик кадра, расшифровываем полезную нагрузку AES-CCM*:

```text
$ python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESCCM; k=bytes.fromhex('00112233445566778899AABBCCDDEEFF'); a=AESCCM(k); print(a.decrypt(bytes(13), open('ct.bin','rb').read(), None))"
b'...plaintext...'
```

Расшифровав, можно подделать команды (например, `OnOff`) и зашифровать их тем же ключом — устройство примет их как легитимные.

## Шаг 5: OTA и атаки

Zigbee поддерживает **OTA** (over-the-air) обновления. Атаки:

1. **OTA downgrade** — откатить устройство на уязвимую версию.
2. **Подмена образа** — если подпись не проверяется.
3. **Replay команд** — если счётчики не строгие.
4. **Отказ в обслуживании** — залить сеть кадрами.

Практика: нужен адаптер CC2531/CC2652 и инструменты `zigbee2mqtt`, `killerbee`, Wireshark с dissector.

## Что мы теперь знаем

- Zigbee = 802.15.4 + NWK + APS.
- Два ключа: network key (трафик) и TC link key (join).
- Дефолтный TC link key `ZigBeeAlliance09` — классическая слабость.
- Зная ключ, трафик расшифровывается и подделывается.
- OTA добавляет риск downgrade и подмены образа.

## Квиз

''' + quiz([
    ('Поверх какого радио работает Zigbee?',
     ['802.15.4', '802.11', 'Bluetooth Classic'],
     0, 'Zigbee строится поверх 802.15.4.'),
    ('Что шифрует network key?',
     ['Весь трафик сети', 'Только OTA', 'Ничего'],
     0, 'Network key защищает трафик всей Zigbee-сети.'),
    ('Чем опасен дефолтный TC link key?',
     ['Позволяет выдать себя за устройство и получить сетевой ключ',
      'Он слишком длинный', 'Он замедляет сеть'],
     0, 'Известный default key даёт доступ к join-процедуре.'),
    ('Какой риск у OTA-обновлений Zigbee?',
     ['Downgrade и подмена образа', 'Увеличение частоты', 'Смена канала'],
     0, 'OTA можно откатить или подменить, если нет строгой подписи.'),
]) + '''

## Куда дальше

Дальше разберём, как поверх 802.15.4 запускают настоящий IPv6 — **6LoWPAN**. А пока запомни: в Zigbee почти всегда побеждает не крипто, а слабый ключ.

## Где пригодится

- **Пентест:** аудит умных домов и промышленных mesh.
- **CTF:** категория Hardware/RF.
- **Работа:** безопасность IoT и зданий.
- **Дальше по дереву:** `hardware-6lowpan`, `hardware-zwave-deep`.
'''
lab_b = lab(
    '/home/student/zigbee', ['task.md', 'notes.md', 'zigbee.log'],
    "grep -q 'nto{' found.txt",
    ['`zigbee.log` — Zigbee-трафик и join-процедура.',
     'Смотри типы ключей и транспортируемый network key.',
     'Найди флаг: `grep nto zigbee.log | cut -d= -f2 > found.txt`.'],
    ('/home/student/zigbee/found.txt', 'nto{'),
    [_dir('/home/student/zigbee'),
     _f('/home/student/zigbee/task.md', '# Задача: Zigbee\n\nРазбери Zigbee-трафик, найди ключи и спрятанный флаг.\n\nИнструменты: `cat`, `grep`, `cut`.\n'),
     _f('/home/student/zigbee/notes.md', 'Заметки\n------\n- Zigbee = 802.15.4 + NWK + APS.\n- network key (трафик) + TC link key (join).\n- default TC link key = ZigBeeAlliance09.\n'),
     _f('/home/student/zigbee/zigbee.log',
        'NWK: src=0x1A2B dst=0x0000 broadcast=true\n'
        'APS: cluster=0x0006 (OnOff) ep=1\n'
        'join: TC_link_key=5A6967426565416C6C69616E63653039  # ZigBeeAlliance09 (default)\n'
        'transport-key: network_key=00112233445566778899AABBCCDDEEFF\n'
        'capture: secret=nto{z1gb33_d3f4ult_1ink_k3y}\n')]
)
write_lesson(L, body, lab_b)

print('b5b part1 written')
