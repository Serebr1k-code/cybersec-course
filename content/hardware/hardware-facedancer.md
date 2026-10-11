---
id: hardware-facedancer
title: "FaceDancer: эмуляция USB-устройств"
category: hardware
parent: hardware-mod-usb-offensive
difficulty: hard
order: 2
tags: [facedancer, usb, emulation, mitm]
prerequisites: [hardware-rubber-ducky, hardware-usb-device-exploit]
useful_for:
  - "Red team: USB-импланты и MitM"
  - "Пентест: обход USB-whitelist"
  - "CTF Hardware"
estimated_minutes: 70
summary: "FaceDancer и эмуляция USB-устройств: почему нельзя доверять VID/PID, подделка HID/сетевой карты/накопителя, USB-прокси и MitM между хостом и устройством, аппаратная база (GreatFET, FPGA), практические скрипты и защита."
---

**FaceDancer** — фреймворк для эмуляции произвольных USB-устройств на уровне дескрипторов и конечных точек. Если BadUSB — это «притвориться клавиатурой», то FaceDancer — это «притвориться **кем угодно**»: сетевой картой, накопителем, HID, хабом, даже устройством с нестандартным классом. На нём же строится **USB MitM**: устройство-прокси, которое встаёт между хостом и настоящей периферией, прозрачно модифицируя трафик. Этот урок — про то, почему USB-безопасность, основанная на VID/PID и классе устройства, ломается.

## Идея: дескрипторы — это заявление о себе

При подключении устройство отдаёт **дескрипторы**:

- **Device descriptor** — VID, PID, класс, производитель, серийник.
- **Configuration descriptor** — набор интерфейсов.
- **Interface descriptor** — класс интерфейса (HID, Mass Storage, CDC-ECM/NCM и т. д.).
- **Endpoint descriptor** — точки передачи (IN/OUT, bulk/interrupt/isochronous).

Хост верит дескрипторам. USB-whitelist, фильтрующий по VID/PID, обходится подделкой этих полей. Класс-фильтр обходится сменой interface class. FaceDancer даёт полный контроль над всеми дескрипторами.

## Аппаратная база

| Плата | Особенности |
|-------|-------------|
| **GreatFET One** | референсная плата проекта, USB host/device, GPIO |
| **Luna** (Great Scott Gadgets) | современная, high-speed, FPGA-ускорение |
| **Raspberry Pi Pico** (с USB-stack) | дешёвая альтернатива, device-режим |
| **Facedancer21** (legacy) | на базе Teensy, историческая |
| **FPGA-платы** (Lattice ECP5) | для high-speed USB 2.0 и точных таймингов |
| **USB Armory** | полноценный Linux + USB device |

Для high-speed USB (480 Мбит/с) нужен FPGA: микроконтроллеры не тянут полный поток.

## Установка FaceDancer

```bash
# Клонировать и установить
git clone https://github.com/greatscottgadgets/facedancer
cd facedancer
pip install -e .
# Проверить, что плата видна
facedancer-info
```

Пример вывода:

```text
Found a GreatFET One!
  Board: GreatFET One
  Firmware: v1.3.0
  Serial: 0000000000000000
```

## Эмуляция HID-устройства

```python
from facedancer import *
from facedancer.devices.keyboard import USBKeyboardDevice
from facedancer.classes import USBDeviceClass

# Готовый пример: клавиатура
device = USBKeyboardDevice()
device.connect()
device.type_letter('a')
```

Кастомный дескриптор — подделка VID/PID:

```python
from facedancer import *
from facedancer.devices import USBDevice

class FakeDevice(USBDevice):
    device_class = 0x00            # per-interface class
    id_vendor = 0x046d             # Logitech (подделка)
    id_product = 0xc534

    def __init__(self):
        super().__init__()
        self.add_interface(USBInterface(self, number=0, class_number=0x03))  # HID
```

## Эмуляция сетевой карты (CDC-ECM/NCM)

Сетевая USB-карта даёт хосту новый интерфейс. Атакующий может подсунуть «сетевую карту», которая на самом деле перенаправляет трафик, отвечает на DHCP/DNS и MITM'ит.

```python
from facedancer import *
from facedancer.devices import USBDevice

class FakeNIC(USBDevice):
    device_class = 0x02            # Communications (CDC)
    id_vendor = 0x0bda             # Realtek (подделка)
    id_product = 0x8153
```

Класс **CDC-NCM/ECM** заставляет Linux/Windows считать устройство Ethernet. Комбинация с сетевыми сервисами (DHCP-спуфинг, DNS-подмена) превращает USB-имплант в MITM-точку.

## Эмуляция накопителя и «злого» USB

Mass Storage эмуляция позволяет:

- Подсунуть накопитель с авто-run содержимым (устаревшие ОС).
- Эксплуатировать парсер файловых систем хоста (например, fuzzing ФС).
- Показать «пустой» том, а на деле отдавать произвольные сектора.

```python
from facedancer import *
from facedancer.devices import USBDevice

class FakeStorage(USBDevice):
    device_class = 0x00
    id_vendor = 0x1234
    id_product = 0x5678
    # интерфейс Mass Storage class 0x08, subclass SCSI 0x06
```

## USB MitM: проксирование

Ключевая сила FaceDancer — **USB-прокси**: плата встаёт между хостом и настоящим устройством, пересылая дескрипторы и данные, но с возможностью **модификации на лету**. Пример: клавиатура «печатает» ровно то, что вводит пользователь, плюс несколько инъектированных символов.

```text
Host  <-->  [GreatFET: proxy]  <-->  Real keyboard
                  |
             модификация отчётов
```

Применения:

- **Inject keystrokes** в реальный поток ввода незаметно.
- **Подмена содержимого накопителя** (изменение секторов).
- **Перехват паролей** с HID-устройств (например, клавиатур с шифрованием).
- **Fuzzing** настоящего устройства через прокси.

## Разобранный пример: обход USB-whitelist

```text
1. Организация разрешает только клавиатуры Logitech (VID 046d).
2. Атакующий на GreatFET эмулирует устройство с VID 046d, PID разрешённой модели.
3. Но интерфейс — не HID, а CDC-ECM (сетевая карта).
4. Хост пропускает устройство по whitelist, драйвер поднимает сетевой интерфейс.
5. Имплант отвечает на DHCP/DNS и MITM'ит трафик.
```

```python
from facedancer import *
from facedancer.devices import USBDevice

class WhitelistBypass(USBDevice):
    id_vendor = 0x046d        # выглядит как Logitech
    id_product = 0xc534
    # но интерфейс CDC-Ethernet, а не HID
```

Урок: whitelist по VID/PID не защищает, если не проверять **весь** набор дескрипторов и поведение устройства.

## Edge cases и подводные камни

- **Скорость**: на MCU эмуляция high-speed нестабильна — нужен FPGA (Luna).
- **Тайминги USB**: окна (SOF, timeouts) жёсткие; неточный ответ = устройство «отваливается».
- **Хаб-порты**: некоторые хабы перечисляют устройство иначе.
- **Windows 10/11**: строже к дескрипторам, чем Linux; мусорные поля = отказ.
- **Драйверы**: подмена сетевой карты требует совместимого класса (ECM/NCM/RNDIS).
- **Питание**: эмуляция сетевой карты может требовать больше тока.
- **OS-кеши**: VID/PID уже могли «запомниться» — меняйте серийник.

## Ссылочные таблицы

| Класс USB | Код | Что эмулирует |
|-----------|-----|---------------|
| HID | 0x03 | клавиатура, мышь |
| Mass Storage | 0x08 | накопитель |
| CDC (Comms) | 0x02 | сетевая карта, serial |
| Audio | 0x01 | микрофон, колонки |
| Video | 0x0E | камера |
| Hub | 0x09 | USB-хаб |

| Поле дескриптора | Что подделывают |
|------------------|-----------------|
| idVendor / idProduct | обход whitelist |
| bDeviceClass | тип устройства |
| bInterfaceClass | функционал интерфейса |
| iSerialNumber | уникальность/кеш |
| iManufacturer | социальная инженерия |

## Что дальше / решение

- Нужны атаки на питание USB-C → `hardware-usbc-pd`.
- Нужен HID-инъектор → `hardware-rubber-ducky`.
- Эксплуатация USB-стека хоста → `hardware-usb-device-exploit`.
- База по USB → `hardware-usb`, `hardware-usb-hid`.

## Классы и подклассы: как хост решает, кто вы

Когда устройство подключено, хост читает дескрипторы по порядку и на их основе выбирает драйвер. Класс может быть задан на трёх уровнях: **device class**, **interface class** и **endpoint**. Это важная тонкость: устройство с `bDeviceClass = 0x00` («класс задаётся интерфейсами») может объявить несколько интерфейсов разных классов — например, HID + Mass Storage + CDC в одном составном устройстве. Именно так строятся «композитные» импланты, которые одновременно и клавиатура, и сетевая карта, и накопитель.

FaceDancer позволяет собрать любое составное устройство. Каждый интерфейс имеет свой `bInterfaceClass`, `bInterfaceSubClass` и `bInterfaceProtocol`. Для Mass Storage важны подклассы: `0x06` — SCSI transparent command set, `0x02` — MMC/SD, `0x04` — UFI. Драйвер хоста по этим полям выбирает обработчик, и ошибка в подклассе приводит к тому, что устройство распознаётся, но не работает.

| Уровень | Поле | Что определяет |
|---------|------|----------------|
| Device | bDeviceClass | общий класс (или 0x00 = по интерфейсам) |
| Interface | bInterfaceClass | функционал интерфейса |
| Interface | bInterfaceSubClass | конкретный подтип |
| Interface | bInterfaceProtocol | протокол поверх класса |
| Endpoint | bmAttributes | тип передачи (bulk/int/isoc) |

## Составные устройства и USB-хабы

Составное устройство (composite) объединяет функции под одним VID/PID и одним адресом. Хост видит один дескриптор конфигурации с несколькими интерфейсами. Это удобно атакующему: один физический разъём даёт сразу несколько векторов — HID для ввода, CDC для сети, Storage для файлов. Защитные решения, анализирующие только device-class, пропускают такое устройство, потому что device-class = 0x00.

USB-хаб внутри импланта позволяет эмулировать несколько устройств одновременно: хост видит хаб, к которому подключены «клавиатура» и «сетевая карта». Так обходят политики, которые ограничивают число устройств или фильтруют конкретные классы.

## Инструментальная обвязка GreatFET

GreatFET — референсная плата проекта. Полезные команды:

```bash
# Информация о плате
greatfet info
# Прошивка/обновление
greatfet firmware --update
# Работа с GPIO
greatfet gpio --dir out --state 1 0 1 0
# Захват USB-трафика (совместно с анализатором)
greatfet usb --monitor
```

Пример вывода `greatfet info`:

```text
GreatFET One
  Board ID:   0x01
  Firmware:   2023.1.0
  Serial:     0x0000000000000000
  USB Speed:  High-Speed (480 Mbps)
```

GreatFET сочетает роль USB-устройства и инструмента: его можно использовать и как эмулятор, и как сниффер при подключении к пинам.

## Диагностика проблем эмуляции

Когда эмуляция «не заводится», полезно смотреть на уровне хоста:

```bash
# Linux: следим за ядром при подключении
sudo dmesg -w
# Список USB-устройств
lsusb -v 2>/dev/null | head -60
# Мониторинг событий USB
sudo udevadm monitor --property
```

Пример ошибки в `dmesg` при неверных дескрипторах:

```text
usb 1-2: new high-speed USB device number 7 using xhci_hcd
usb 1-2: device descriptor read/64, error -71
usb 1-2: unable to read config index 0 descriptor/start: -71
```

`error -71` (EPROTO) означает, что плата ответила некорректным пакетом — частая проблема таймингов или неверной длины дескриптора. Сверяйте поля с реальным устройством, которое вы копируете: `lsusb -v` показывает все дескрипторы эталона, их и нужно воспроизвести байт-в-байт.

## Практические сценарии red team

- **Кража данных через HID+Storage**: клавиатура печатает команду, накопитель принимает архив.
- **Сетевой MITM**: CDC-ECM поднимает интерфейс, DHCP/DNS-сервисы перенаправляют трафик.
- **Обход whitelist**: подмена VID/PID разрешённого устройства с другим функционалом.
- **Keystroke injection в реальный поток**: прокси встраивает символы в настоящий ввод.
- **Fuzzing устройства**: прокси между хостом и периферией для поиска багов драйвера.

Каждый сценарий требует согласованного контракта; работа на чужом оборудовании без разрешения незаконна.

## Квиз

```quiz
- question: "Что эмулирует FaceDancer?"
  options:
    - "Только клавиатуры"
    - "Произвольные USB-устройства на уровне дескрипторов и конечных точек"
    - "Только сетевые карты"
    - "Bluetooth-устройства"
  answer: 1
  explanation: "FaceDancer даёт полный контроль над дескрипторами."
- question: "Почему USB-whitelist по VID/PID обходится?"
  options:
    - "Дескрипторы можно подделать"
    - "USB не имеет VID"
    - "Whitelist не существует"
    - "Нужен пароль"
  answer: 0
  explanation: "VID/PID — это заявление устройства о себе, его легко подделать."
- question: "Для чего нужна FPGA-плата (Luna) в FaceDancer?"
  options:
    - "Для зарядки"
    - "Для стабильной эмуляции high-speed USB 480 Мбит/с"
    - "Для Wi-Fi"
    - "Для хранения паролей"
  answer: 1
  explanation: "MCU не тянет high-speed; нужен FPGA."
- question: "Что такое USB MitM на FaceDancer?"
  options:
    - "Удалённая атака по сети"
    - "Плата-прокси между хостом и устройством с модификацией трафика"
    - "Атака на драйвер"
    - "Шифрование USB"
  answer: 1
  explanation: "Прокси пересылает данные, модифицируя их на лету."
- question: "Какой класс эмулирует сетевую карту?"
  options:
    - "0x08 Mass Storage"
    - "0x03 HID"
    - "0x02 CDC (ECM/NCM)"
    - "0x0E Video"
  answer: 2
  explanation: "CDC-класс даёт сетевой интерфейс."
```

## Где пригодится

- **Red team:** USB-импланты, MitM, обход whitelist.
- **Пентест:** оценка USB-контроля и драйверной поверхности.
- **CTF:** категория Hardware — эмуляция устройств.
- **Работа:** fuzzing USB-устройств, проектирование безопасных дескрипторов.
- **Дальше по дереву:** `hardware-usbc-pd`, `hardware-usb-device-exploit`.
