---
id: network-ble-attacks
title: "BLE-атаки: GATT, sniffing, MITM и взлом pairing"
category: network
parent: network-wireless-80211
difficulty: hard
order: 4
tags: [network, ble, bluetooth-low-energy, gatt, iot, sniffing]
prerequisites: [network-wireless-80211]
useful_for:
  - "IoT-пентест"
  - "CTF Hardware"
  - "Защита BLE-устройств"
estimated_minutes: 42
summary: "Bluetooth Low Energy: реклама, GATT-профили, сканирование, sniffing, MITM, атаки на pairing (Just Works, crackle), инструменты bettercap/btlejack/gattacker."
---

BLE (Bluetooth Low Energy) — отдельный стек, придуманный для экономии энергии. Он повсюду: фитнес-трекеры, умные замки, медицинские датчики, маяки, автомобильные ключи. Архитектура «характеристик» GATT, часто без аутентификации, делает BLE-устройства легкой целью: можно читать состояние, писать значения, перехватывать pairing и подменять устройство.

## BLE: реклама, каналы, GATT

BLE использует 40 каналов по 2 МГц; **3 из них — advertising** (37, 38, 39), остальные 37 — data. Устройство периодически шлёт **advertising-пакеты** с адресом, именем, списком сервисов и флагами. После подключения центральное устройство (central) исследует **GATT**-таблицу:

- **Service** — группа характеристик (например, Heart Rate Service);
- **Characteristic** — значение (read/write/notify);
- **Descriptor** — метаданные (например, Client Characteristic Configuration);
- **UUID** — 16-бит (стандартные) или 128-бит (кастомные).

Многие устройства разрешают **read/write без аутентификации** — это и есть основная дыра.

| Понятие | Смысл |
|---|---|
| Advertising | Широковещательные пакеты |
| GATT | Таблица сервисов/характеристик |
| Central/Peripheral | Роли после подключения |
| Notify | Пуш значения от устройства |
| UUID | Идентификатор сервиса/характеристики |

## Сканирование BLE

```bash
# Linux, BlueZ
hcitool lescan
bluetoothctl
> scan on
> connect AA:BB:CC:DD:EE:FF
> list-attributes
# bettercap
sudo bettercap -iface hci0
> ble.recon on
> ble.show
```

`bettercap ble.recon` покажет устройства с RSSI, адресом, именем и списком сервисов. Дальше — подключение и перечисление характеристик.

## Инструменты

- **bettercap** — recon/enum/подключение BLE.
- **gatttool** (BlueZ) — чтение/запись характеристик.
- **btlejack** — аппаратный перехват и injection (Micro:bit/HackRF).
- **gattacker** — BLE MITM (клонирование peripheral).
- **crackle** — взлом BLE pairing (Just Works/Legacy).
- **nRF Connect / LightBlue** — мобильные GUI-клиенты.
- **ubertooth / HackRF** — аппаратный сниффинг.

```bash
# Перечислить характеристики и прочитать значение
gatttool -b AA:BB:CC:DD:EE:FF --char-read -u 0x2a37
# Записать значение (например, открыть замок)
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x001b -n 01
```

## Атаки на BLE

| Атака | Суть |
|---|---|
| Sniffing | Перехват advertising/data (Ubertooth/btlejack) |
| GATT enumeration | Чтение/запись характеристик без auth |
| MITM (gattacker) | Клонирование peripheral и проксирование |
| Pairing downgrade | Принуждение к Just Works |
| crackle | Взлом BLE pairing-обмена |
| Replay | Повтор пакетов управления (замки, двери) |
| Fuzzing | Отправка некорректных GATT-запросов |
| Beacon spoofing | Подмена iBeacon/Eddystone |
| Key relay | Реле ключа автомобиля (relay attack) |

## Разобранный пример: взлом Just Works pairing через crackle

1. Включаем сниффинг BLE-обмена при спаривании. С Ubertooth:
   ```bash
   ubertooth-btle -f -c capture.pcap
   ```
   (или btlejack с Micro:bit).
2. Спариваем своё устройство с target в лабе — захватываем **pairing-обмен** (Legacy/Just Works).
3. Прогоняем дамп через crackle:
   ```bash
   crackle -i capture.pcap -o decrypted.pcap
   # crackle выведет TK (temporary key) и восстановленный LTK/STK
   ```
   Для Just Works TK = 0, поэтому ключ восстанавливается мгновенно; далее расшифровывается весь трафик.
4. С восстановленным ключом читаем/подменяем данные GATT.

Для устройств с кастомным протоколом поверх GATT шаг 4 — это реверс формата (см. `network-protocol-reversing`).

## MITM через gattacker

`gattacker` клонирует peripheral: центральное устройство подключается к нему, думая, что это оригинал, а он проксирует запросы к настоящему устройству. Нужны два BLE-адаптера. Так можно перехватывать и модифицировать read/write/notify.

## Защита

| Мера | Против чего |
|---|---|
| Требовать authenticated pairing (MITM-protected) | Sniffing, MITM |
| Шифрование на прикладном уровне (поверх GATT) | Перехват после pairing |
| Не разрешать read/write без auth | GATT enumeration |
| Random resolvable addresses | Трекинг устройства |
| Whitelist центральных устройств | Неавторизованное подключение |
| Обновление прошивок | Известные CVE |
| Anti-replay (nonce/counter) | Replay-атаки |

## Частые ошибки и подводные камни

- **Путать BLE и Classic.** Инструменты и атаки разные.
- **Забывать про MAC-рандомизацию.** Некоторые устройства меняют адрес — нужен трекинг по другим признакам.
- **Пытаться MITM одним адаптером.** Для gattacker нужно два.
- **Игнорировать прикладной уровень.** Шифрование BLE не защищает от записи «правильных» команд.
- **Считать Just Works безопасным.** TK=0 → crackle ломает за секунды.
- **Забывать про relay-атаки авто.** Ключи с UWB/дистанцией снижают риск, но не всегда.

## Что дальше / решение

BLE — часть беспроводного/IoT пентеста. Свяжите с `network-bluetooth` (Classic), hardware-веткой (NFC/RFID, SDR) и `network-protocol-reversing` (кастомные протоколы). Для защиты требуйте authenticated pairing и прикладное шифрование, добавьте anti-replay. Для CTF/Hardware потренируйтесь на собственных датчиках и Ubertooth/btlejack.

## Справочная таблица

| Инструмент | Назначение |
|---|---|
| bettercap | BLE recon/enum |
| gatttool | Чтение/запись GATT |
| btlejack | Аппаратный перехват |
| gattacker | BLE MITM |
| crackle | Взлом pairing |
| ubertooth | Сниффер |

| Роль | Смысл |
|---|---|
| Central | Инициирует подключение |
| Peripheral | Отдаёт GATT |
| Broadcaster | Только advertising |
| Observer | Только сканирует |

## Advertising в деталях и beacon spoofing

Advertising-пакет содержит до 31 байта данных и набор **AD-структур** (length/type/value). Важнейшие типы: `0x01` (Flags), `0x09` (Complete Local Name), `0x03`/`0x02` (UUID сервисов), `0x16` (Service Data), `0xff` (Manufacturer Specific Data). Именно в manufacturer data часто лежит «телеметрия» устройства: уровень заряда, состояние замка, версия прошивки — иногда в открытом виде, иногда с обфускацией.

Beacon-протоколы (iBeacon, Eddystone) — это просто форматированные advertising-пакеты. Их легко подделать:

```bash
# bettercap: эмулировать iBeacon
> ble.beacons
> set ble.beacons.beacon1.uuid 12345678-1234-1234-1234-1234567890ab
> ble.beacons on
```

Спуфинг маяков используют для подмены навигации в музеях/магазинах, а также для «угона» устройств, доверяющих маяку как триггеру. Eddystone-URL особенно опасен: он несёт URL, который телефон может открыть — вектор для фишинга.

## Кастомные протоколы поверх GATT

Стандартные UUID легко распознать, но большинство производителей используют **128-битные кастомные UUID** и собственный формат значений. Рабочий процесс реверса:

1. Перечислить все сервисы/характеристики (`bettercap ble.enum` или `gatttool`).
2. Включить `notify` на всех характеристиках и наблюдать поток значений при действиях с устройством (нажатие кнопки, открытие замка).
3. Менять по одному байту и смотреть реакцию — так восстанавливается «команда управления».
4. Проверить наличие CRC/чек-суммы и счётчика (если есть — replay без пересчёта не сработает).

Типовой пример: замок, где характеристика `0x001b` принимает `01` = «открыть», `00` = «закрыть», а последний байт — контрольная сумма. Такой реверс — ядро IoT-пентеста.

## Лаборатория: полный цикл

1. Возьмите BLE-датчик (фитнес-браслет, умная лампа) и Linux с BlueZ.
2. `bettercap -iface hci0` → `ble.recon on` → `ble.show` — соберите список устройств и сервисов.
3. Подключитесь и перечислите GATT; включите notify и запишите поток.
4. Воспроизведите управляющую команду через `gatttool --char-write-req`.
5. Поставьте Ubertooth/btlejack, перехватите pairing и прогоните через `crackle`.
6. Включите authenticated pairing и прикладное шифрование — убедитесь, что простая запись команды больше не проходит.

Это полный цикл от разведки до защиты.

## Квиз

```quiz
- question: "Сколько BLE-каналов используются только для advertising?"
  options:
    - "1"
    - "3"
    - "37"
    - "40"
  answer: 1
  explanation: "Advertising-каналы — 37, 38 и 39 (всего три)."
- question: "Почему Just Works pairing легко взломать?"
  options:
    - "Он использует слабый пароль"
    - "Temporary Key равен нулю, поэтому crackle восстанавливает ключ"
    - "Он не использует шифрование"
    - "Он требует сертификат"
  answer: 1
  explanation: "В Just Works TK=0, что делает восстановление ключа тривиальным."
- question: "Какой инструмент клонирует BLE-периферию для MITM?"
  options:
    - "gattacker"
    - "gatttool"
    - "crackle"
    - "hcitool"
  answer: 0
  explanation: "gattacker проксирует соединение, клонируя peripheral."
- question: "Что такое GATT?"
  options:
    - "Протокол маршрутизации"
    - "Таблица сервисов и характеристик BLE"
    - "Тип антенны"
    - "Метод шифрования"
  answer: 1
  explanation: "GATT описывает сервисы и характеристики, к которым обращается central."
- question: "Какая мера защищает от replay-атак в BLE?"
  options:
    - "Смена UUID"
    - "Anti-replay (nonce/счётчик) и прикладное шифрование"
    - "Рандомизация адреса"
    - "Увеличение мощности"
  answer: 1
  explanation: "Nonce/счётчики и шифрование на прикладном уровне не дают повторно использовать перехваченные команды."
```

## Где пригодится

- **IoT-пентест:** умные замки, датчики, трекеры, медприборы.
- **Red team:** физический доступ и беспроводные векторы.
- **CTF:** Hardware/Radio задачи.
- **Работа:** аудит BLE-устройств и политик.
