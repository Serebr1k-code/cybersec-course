---
id: hardware-bluetooth
title: "Bluetooth и BLE: сниффинг, спаривание, GATT-атаки"
category: hardware
parent: hardware-rf-protocols
difficulty: medium
order: 2
tags: [bluetooth, ble, gatt, btle, sniffing, ubertooth, crackle, kismet, pairing]
prerequisites: [hardware-rf]
useful_for:
  - "CTF-задачи категории Hardware/Radio"
  - "Пентест IoT и BLE-устройств"
  - "Аппаратная безопасность"
estimated_minutes: 40
summary: "Как устроены Bluetooth Classic и BLE, как сниффить трафик, ломать устаревшее спаривание (Crackle), исследовать GATT и находить уязвимости BLE-устройств."
---
## Зачем этот урок

Bluetooth есть почти в каждом IoT-устройстве: замки, трекеры, медгаджеты, автомобили. Classic и BLE — разные протоколы с разными слабостями. Здесь — про сниффинг трафика, взлом устаревшего спаривания (Crackle), исследование GATT-дерева и практические атаки на BLE-устройства, включая незащищённые характеристики записи.

## Classic vs BLE: архитектура и различия

| | Bluetooth Classic | BLE |
|---|-------------------|-----|
| Профиль | SPP, A2DP, HID | GATT (сервисы/характеристики) |
| Спаривание | legacy PIN / SSP | Just Works / Passkey / OOB |
| Сниффинг | Ubertooth, nRF | nRF Sniffer, Adafruit |
| Атака | Crackle (legacy/KNOB) | GATT-анализ, replay, MITM |
| MAC | статичный | рандомизированный (RPA) |

Classic ориентирован на потоковые данные (аудио, HID), BLE — на короткие обмены с низким энергопотреблением. Инструменты и атаки различаются: `gatttool` работает только с BLE.

## Каналы, частоты и hopping

Оба используют 2.4 ГГц ISM. Classic применяет 79 каналов по 1 МГц с frequency hopping; BLE — 40 каналов по 2 МГц (3 advertising-канала 37/38/39 и 37 data-каналов). Чтобы сниффить, нужно следовать за hopping-последовательностью, зная параметры соединения (для BLE — Access Address и hop increment). Поэтому сниффинг возможен с момента захвата соединения, а advertising-пакеты ловятся всегда.

## Инструменты

```bash
sudo apt install bluetooth bluez bluez-tools
hcitool lescan                  # сканирование BLE
bluetoothctl                    # scan on, devices, info <MAC>
# nRF Sniffer (Wireshark extcap) — BLE-сниффинг
# Ubertooth — Classic-сниффинг
crackle -i capture.pcap -o decrypted.pcap
```

| Инструмент | Назначение |
|------------|-----------|
| `bluetoothctl` | Управление, спаривание |
| `hcitool` | Низкоуровневые команды |
| nRF Sniffer | BLE-сниффинг в Wireshark |
| Ubertooth | Classic-сниффинг |
| Crackle | Взлом BLE legacy pairing |
| `gatttool` | Чтение/запись GATT |

## BLE-сниффинг: настройка nRF Sniffer

nRF Sniffer — прошивка для дongle nRF52840 (Nordic), интегрируется в Wireshark через extcap. Порядок: прошить дongle, установить плагин, выбрать интерфейс в Wireshark, включить канал (37/38/39 для advertising). Для сниффинга соединения нужно поймать момент установления связи. Альтернатива — Ubertooth One для Classic и части BLE.

## GATT: сервисы, характеристики, дескрипторы

GATT — дерево. Устройство объявляет **сервисы** (UUID), внутри — **характеристики** (UUID + свойства: read/write/notify/indicate), у характеристик — **дескрипторы** (например, `0x2902` CCC — Client Characteristic Configuration, управляет notify). Значения читаются/пишутся по handle.

```bash
gatttool -b <MAC> -I
> connect
> primary                 # список сервисов
> characteristics         # характеристики с handle
> char-read-hnd 0x0016
> char-write-req 0x0018 01
```

## Практика GATT: чтение и запись

Через bluetoothctl: `bluetoothctl connect <MAC>`, `bluetoothctl gatt.list-attributes`. Частые находки: незащищённые характеристики записи (управление замком), чтение серийников/токенов, notify с секретами. Всегда проверяйте, требует ли write аутентификации/шифрования — многие устройства пишут команды «просто так».

## Спаривание: SSP, Just Works, Passkey, OOB

- **Just Works** — без MITM-защиты; уязвимо к активному MITM.
- **Passkey** — 6-значный код, требует участия пользователя.
- **Numeric Comparison** — обе стороны показывают код и подтверждают.
- **OOB** — внеполосный канал (NFC).
- **Legacy pairing** — взламывается Crackle (восстановление TK).

## Crackle: взлом legacy pairing

```bash
crackle -i pairing.pcap -o out.pcap
# Затем расшифровать в Wireshark (BTLE с ключом)
```

Crackle восстанавливает Temporary Key (TK) из перехваченного legacy-спаривания: TK предсказуем (обычно нули), из него выводится STK, и трафик расшифровывается. Работает, если удалось перехватить весь обмен спаривания.

## KNOB и снижение энтропии

**KNOB (CVE-2019-9506)** — атакующий в середине снижает энтропию сессионного ключа до 1 байта, что позволяет перебрать его и расшифровать трафик. Требует позиции MITM при спаривании. Производители закрыли уязвимость проверкой энтропии.

## RPA и отслеживание устройств

BLE-устройства рандомизируют MAC (Resolvable Private Address, RPA), чтобы затруднить трекинг. RPA меняется каждые ~15 минут и выводится из Identity Resolving Key. Для атаки привязывайтесь к адресу в момент активности или используйте IRK, если он утёк. При сниффинге отслеживайте смену адресов.

## Разобранный пример: BLE-замок без auth

1. `bluetoothctl scan on` → находим MAC устройства.
2. Подключаемся и перечисляем GATT (`gatttool`, `primary`, `characteristics`).
3. Находим характеристику с `write` без аутентификации (handle 0x0018).
4. Пишем команду открытия: `char-write-req 0x0018 01`.
5. Для replay — записываем notify-трафик через nRF Sniffer и воспроизводим. Если устройство использует RPA, привязываемся к адресу в момент активности.

## Защита и hardening

- Требовать аутентифицированное спаривание (Passkey/Numeric Comparison), не Just Works.
- Проверять авторизацию на каждой write-характеристике, не только при подключении.
- Использовать шифрование связи и свежие nonce против replay.
- Не отдавать секреты в notify без аутентификации.
- Обновлять прошивку (KNOB/BIAS).

## Частые ошибки

- **Путать BLE и Classic.** Инструменты и атаки разные.
- **Игнорировать notify.** Секреты часто приходят в notify-характеристиках.
- **Пробовать gatttool на Classic.** Он только для BLE.
- **Забывать про MITM.** Just Works не защищает от активного MITM.
- **Считать MAC статичным.** BLE рандомизирует адрес (RPA).
- **Не проверять дескрипторы.** `0x2902` (CCC) управляет notify.

## Что дальше / решение

- BLE → nRF Sniffer + GATT-анализ + Crackle.
- Classic → Ubertooth + Crackle.
- Нашли токен → идите в облако производителя.
- Смежные: `hardware-rf-protocols`, `hardware-zigbee-zwave`, `hardware-iot-cloud`.

## BIAS: атака импersonation

**BIAS (Bluetooth Impersonation AttackS)** показывает, что при установленном шифрованном соединении атакующий может выдать себя за одно из устройств и установить новое соединение без повторного спаривания. Это ломает модель «спарено — значит доверено». Защита — обновления прошивок и отказ от доверия по одному лишь факту спаривания.

## Разведка Bluetooth-периметра

```bash
hcitool scan            # Classic-устройства
hcitool lescan          # BLE
bluetoothctl scan on
btlejack -s             # обзор BLE-устройств и соединений
bettercap -iface hci0   # модуль ble.*
```

Фиксируйте MAC, имена, UUID сервисов — это карта поверхности. Для каждого устройства: тип (Classic/BLE), наличие спаривания, доступные характеристики.

## Сниффинг Classic с Ubertooth

Ubertooth One ловит Classic-трафик. Процесс: выбрать канал, следовать за hopping, захватить соединение. Для расшифровки нужен ключ (взломанный Crackle или известный). Ubertooth также умеет BLE (частично) и базовый анализ.

## GATT fuzzing

Если устройство принимает write-команды, попробуйте fuzzing: неверные длины, граничные значения, случайные байты. Цель — найти креш, утечку памяти или обход проверки. Инструменты: `gatttool` в скрипте, `bettercap`, кастомные скрипты на Python (`bleak`). Фиксируйте, какие команды меняют состояние устройства.

## Инструменты: btlejack, bettercap, bleak

- **btlejack** — работа с BLE: сканирование, hijacking, sniffing.
- **bettercap** — модули `ble.recon`, `ble.enum`, `ble.write`.
- **bleak** (Python) — удобный API для GATT из скриптов.
- **Wireshark + nRF Sniffer** — глубокий разбор протокола.

Комбинация разведки (btlejack), анализа GATT (bleak) и сниффинга (nRF) покрывает большинство BLE-задач.

## Квиз

```quiz
- question: "Что такое GATT в BLE?"
  options:
    - "Дерево сервисов и характеристик устройства"
    - "Протокол питания"
    - "Тип антенны"
    - "Формат прошивки"
  answer: 0
  explanation: "GATT описывает сервисы/характеристики BLE."
- question: "Чем взламывают BLE legacy pairing?"
  options:
    - "Crackle"
    - "nmap"
    - "sqlmap"
    - "binwalk"
  answer: 0
  explanation: "Crackle восстанавливает ключ legacy-спаривания."
- question: "Какой режим спаривания уязвим к MITM?"
  options:
    - "Just Works"
    - "Passkey с 6 цифрами"
    - "OOB"
    - "Numeric Comparison"
  answer: 0
  explanation: "Just Works не аутентифицирует стороны."
- question: "Каким инструментом перечисляют GATT-характеристики?"
  options:
    - "gatttool / bluetoothctl"
    - "tcpdump"
    - "hydra"
    - "ffuf"
  answer: 0
  explanation: "gatttool показывает services/characteristics."
- question: "Почему MAC BLE-устройства может меняться?"
  options:
    - "Устройства используют рандомизированный адрес (RPA)"
    - "Из-за батареи"
    - "Из-за региона"
    - "Он не меняется"
  answer: 0
  explanation: "RPA — приватность адреса BLE."
```

## Где пригодится

- **CTF:** Hardware/Radio-задачи с BLE.
- **Пентест IoT:** анализ BLE-устройств и спаривания.
- **Аппаратная безопасность:** оценка беспроводных интерфейсов.
- **Работа:** тестирование и защита BLE-продуктов.
- **Дальше по дереву:** `hardware-rf-protocols`, `hardware-zigbee-zwave`.
