---
id: hardware-zigbee-deep
title: 'Zigbee глубоко: стек, ключи, OTA и атаки'
category: hardware
parent: hardware-mod-iot-mesh
difficulty: hard
order: 2
tags: [hardware, iot, zigbee, 802154, keys, ota, smart-home]
prerequisites: [hardware-rf-protocols]
useful_for:
  - 'Пентест умных домов'
  - 'CTF Hardware/RF'
  - 'Аудит IoT'
estimated_minutes: 45
summary: 'Zigbee поверх 802.15.4: стек, типы ключей (network/TC link), извлечение ключей, OTA-обновления и практические атаки на mesh-сеть.'
lab:
  kind: shell
  toolset: [core, python]
  workdir: /home/student/zigbee
  files: [task.md, notes.md, zigbee.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`zigbee.log` — Zigbee-трафик и join-процедура.'
    - 'Смотри типы ключей и транспортируемый network key.'
    - 'Найди флаг: `grep nto zigbee.log | cut -d= -f2 > found.txt`.'
---

## Вопрос, с которого всё начинается

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

```quiz
- question: Поверх какого радио работает Zigbee?
  options:
    - 802.15.4
    - 802.11
    - Bluetooth Classic
  answer: 0
  explanation: Zigbee строится поверх 802.15.4.
- question: Что шифрует network key?
  options:
    - Весь трафик сети
    - Только OTA
    - Ничего
  answer: 0
  explanation: Network key защищает трафик всей Zigbee-сети.
- question: Чем опасен дефолтный TC link key?
  options:
    - Позволяет выдать себя за устройство и получить сетевой ключ
    - Он слишком длинный
    - Он замедляет сеть
  answer: 0
  explanation: Известный default key даёт доступ к join-процедуре.
- question: Какой риск у OTA-обновлений Zigbee?
  options:
    - Downgrade и подмена образа
    - Увеличение частоты
    - Смена канала
  answer: 0
  explanation: OTA можно откатить или подменить, если нет строгой подписи.
```

## Куда дальше

Дальше разберём, как поверх 802.15.4 запускают настоящий IPv6 — **6LoWPAN**. А пока запомни: в Zigbee почти всегда побеждает не крипто, а слабый ключ.

## Где пригодится

- **Пентест:** аудит умных домов и промышленных mesh.
- **CTF:** категория Hardware/RF.
- **Работа:** безопасность IoT и зданий.
- **Дальше по дереву:** `hardware-6lowpan`, `hardware-zwave-deep`.
