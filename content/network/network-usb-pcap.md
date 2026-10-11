---
id: network-usb-pcap
title: "USB и serial в PCAP: извлечение HID-нажатий и данных"
category: network
parent: network-pcap-analysis
difficulty: hard
order: 3
tags: [network, usb, hid, pcap, capture, forensics]
prerequisites: [network-pcap-analysis, network-traffic-analysis-ctf]
useful_for:
  - "CTF Network/Forensics (USB-задачи)"
  - "Работа (IR): анализ USB-трафика"
  - "Пентест: физические устройства"
estimated_minutes: 55
summary: "Как разбирать захваченный USB-трафик: определять устройства, восстанавливать нажатия клавиатуры и данные с накопителей."
---
USB можно захватить через `usbmon` (Linux) или специализированные драйверы (USBPcap на Windows). В CTF это даёт классические задачи: восстановить набранный текст по HID-нажатиям или вытащить файл с «флешки». Урок опирается на [`network-pcap-analysis`](network-pcap-analysis) и [`network-traffic-analysis-ctf`](network-traffic-analysis-ctf).

## Как выглядит USB в захвате

- **Устройство** = адрес (`usb.device_address`), **эндпоинт** = направление и тип.
- **Типы передачи**: Control, Interrupt, Bulk, Isochronous.
- **`usb.capdata`** — полезные данные запроса/ответа (полезная нагрузка).
- Linux: `usbmon` (интерфейсы `usbmon0`, `usbmon1`, …), Windows: USBPcap.
- Заголовок USB имеет **URB** (USB Request Block): `URB_CONTROL`, `URB_INTERRUPT`, `URB_BULK`.
- Направление кодируется в `usb.endpoint_address`: чётный = OUT (хост→устройство), нечётный = IN (устройство→хост).

```bash
# Linux-захват USB
sudo modprobe usbmon
sudo tcpdump -i usbmon1 -w usb.pcap
# Windows: установить USBPcap, выбрать шину в Wireshark
# Просмотр в Wireshark: usb.device_address, usb.endpoint_address, usb.capdata
```

## USB HID (клавиатура/мышь)

HID-клавиатура передаёт **8-байтовые отчёты** в interrupt-эндпоинте:

```
byte0: modifier (Shift/Ctrl/Alt/GUI)
byte1: reserved
byte2..7: нажатые коды (keycodes), обычно один ненулевой
```

Ключ: **модификатор** меняет регистр и символы (Shift+a = A, Shift+1 = !). Keycode → символ берётся из **HID Usage Table**. Отчёт с keycode=0 — это release (клавиша отпущена).

```bash
# Только HID-отчёты
tshark -r usb.pcap -Y 'usb.capdata && usb.data_len==8' -T fields -e usb.capdata
# Пример вывода:
# 00:00:04:00:00:00:00:00   (a)
# 02:00:04:00:00:00:00:00   (Shift+a = A)
# 00:00:00:00:00:00:00:00   (release)
```

Инструменты: `tshark` + скрипт, **CTF-скрипты** (usbhid-dump), Wireshark «USB HID» dissector, `UsbKeyboardParser`, `ctf-usb-keyboard-parser`.

## Инструменты и команды

```bash
# Извлечь все capdata для декодирования
tshark -r usb.pcap -Y 'usb.capdata' -T fields -e usb.capdata > hid.txt
# Декодировать (python + таблица HID)
python3 hid_decode.py hid.txt
# Список устройств в захвате
tshark -r usb.pcap -Y 'usb.device_address' -T fields -e usb.device_address | sort -u
# Описания дескрипторов (модель устройства)
tshark -r usb.pcap -Y 'usb.bDescriptorType' -V | grep -iE 'idVendor|idProduct|iProduct'
# Только интерфейс HID (класс 3)
tshark -r usb.pcap -Y 'usb.bInterfaceClass==3' -T fields -e usb.device_address | sort -u
```

## USB-накопители (bulk)

Флешки используют **bulk**-передачу. Данные можно собрать по сигнатурам файлов (carving) или экспортом.

```bash
# Собрать bulk-payload
tshark -r usb.pcap -Y 'usb.transfer_type==0x03' -T fields -e usb.capdata | \
  tr -d ':' | xxd -r -p > disk.raw
# Carving
binwalk -e disk.raw
foremost -i disk.raw -o carved/
# Поиск сигнатур
grep -abo 'PK' disk.raw     # zip
grep -abo $'\xff\xd8\xff' disk.raw   # jpeg
# Определить тип
file disk.raw
```

Учтите: bulk-потоки могут быть не по порядку и содержать несколько эндпоинтов (in/out). Для более точной сборки фильтруйте по `usb.endpoint_address` и сортируйте по `frame.number`.

## Разобранный пример: восстановление набранного пароля

```bash
# 1. Находим HID-устройство (клавиатуру)
tshark -r usb.pcap -Y 'usb.capdata' -T fields -e usb.capdata | head
# 2. Выгружаем отчёты
tshark -r usb.pcap -Y 'usb.capdata && usb.data_len==8' -T fields -e usb.capdata > hid.txt
# 3. Декодируем в текст (скрипт по HID Usage Table)
python3 hid_decode.py hid.txt
# -> "password123"   (или флаг)
# 4. Учитываем Shift/Backspace/Enter
#    (модификатор 0x02 = Shift; keycode 0x28 = Enter)
```

## Детект и защита

- **BadUSB**: устройство эмулирует HID и набирает команды — детект по внезапному появлению «клавиатуры» и быстрому вводу.
- **Device control** в EDR: whitelist USB-устройств по VID/PID.
- **Логирование** подключений (см. [`forensics-usb-deep`](forensics-usb-deep)).
- **Отключение** USB-портов/только HID-зарядка.
- **USB Data Blocking** (Windows 10+), политики macOS.

## Частые ошибки

- **Игнорировать modifier-байт** — неверный регистр/символы.
- **Путать типы передачи** — HID = interrupt, флешка = bulk.
- **Забывать про release-пакеты** (все нули) — иначе символы дублируются.
- **Смотреть один эндпоинт** — данные могут идти в in/out.
- **Ожидать «прямой» текст** — данные бинарные, нужна таблица HID.
- **Не учитывать порядок bulk** — carving может дать «рваный» файл.
- **Путать left/right вариант клавиши** — Shift/Ctrl/Alt бывают слева и справа (разные байты в отчёте).

## Декодирование HID: полная таблица

Ключевые коды HID Usage Table (byte2):

| Код | Символ | Код | Символ |
|-----|--------|-----|--------|
| 0x04 | a | 0x1E | 1 |
| 0x05 | b | 0x1F | 2 |
| 0x06 | c | 0x20 | 3 |
| 0x07 | d | 0x2C | Space |
| 0x28 | Enter | 0x2B | Tab |
| 0x29 | Esc | 0x2A | Backspace |
| 0x2D | - | 0x2E | = |
| 0x2F | [ | 0x30 | ] |
| 0x31 | \ | 0x33 | ; |

Модификатор (byte0): `0x01` Ctrl, `0x02` Shift, `0x04` Alt, `0x08` GUI, `0x40` AltGr.

```python
# Декодер: hid.txt -> строка
KEY = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x1E:'1',0x1F:'2',0x20:'3',
       0x2C:' ',0x28:'\n',0x2A:'[BS]',0x2B:'\t',0x29:'[ESC]'}
SHIFT = {0x1E:'!',0x1F:'@',0x20:'#'}
out=[]
for line in open('hid.txt'):
    b=bytes.fromhex(line.strip().replace(':',''))
    if len(b)<3: continue
    mod,k=b[0],b[2]
    if k==0: continue
    ch=SHIFT.get(k) if mod&0x02 else KEY.get(k)
    if ch: out.append(ch)
print(''.join(out))
```

## Устройства и дескрипторы

```bash
# Список устройств в дампе
tshark -r usb.pcap -T fields -e usb.device_address | sort -u
# Дескрипторы устройства (idVendor/idProduct/iProduct)
tshark -r usb.pcap -Y 'usb.bDescriptorType==1' -V | grep -iE 'idVendor|idProduct|iProduct'
# Интерфейсы/классы (HID = 3)
tshark -r usb.pcap -Y 'usb.bInterfaceClass' -T fields -e usb.bInterfaceClass | sort -u
```

Класс интерфейса `3` = HID, `8` = Mass Storage, `7` = Printer, `0x0A` = CDC Data.

## Масс-хранилище: SCSI-команды

Флешки поверх USB используют **USB Mass Storage (BOT/UAS)** с SCSI-командами (`READ(10)`, `WRITE(10)`). Данные лежат в bulk-эндпоинтах; логические блоки (512/4096) можно собрать и смонтировать:

```bash
# Собрать все bulk-данные и найти ФС
tshark -r usb.pcap -Y 'usb.transfer_type==0x03' -T fields -e usb.capdata | tr -d ':\n' | xxd -r -p > bulk.bin
binwalk bulk.bin
# Найти ФС и смонтировать образ
file bulk.bin
mount -o loop,ro bulk.bin /mnt/usb 2>/dev/null || echo "нужен carving"
```

## Итоговый чек-лист

- [ ] Определить класс устройства (HID/storage/…)
- [ ] Для HID — выгрузить `usb.capdata` (len=8) и декодировать с модификаторами
- [ ] Для storage — собрать bulk, carving/монтирование
- [ ] Учесть release-пакеты (нули) и Backspace/Enter
- [ ] Проверить несколько эндпоинтов (in/out)

## Что дальше / решение

Дерево решений для USB-задачи:

1. **Определите класс** интерфейса (`usb.bInterfaceClass`): 3 → HID, 8 → storage.
2. **HID** → выгрузите `usb.capdata` с `usb.data_len==8`, декодируйте таблицей HID, примените модификаторы (Shift), обработайте Backspace/Enter. Если получается мусор — возможно, нужно учитывать только пакеты конкретного эндпоинта.
3. **Storage** → соберите bulk (`usb.transfer_type==0x03`), попробуйте `binwalk`/`foremost`/`mount`. Если образ «рваный» — фильтруйте по endpoint и сортируйте по `frame.number`.
4. **Данных нет** → смотрите control-передачу (дескрипторы, строки) — там может быть серийник или скрытая строка.
5. **Мышь/джойстик** → декодируйте координаты как движение, иногда рисуют буквы/флаг.

Решение-эвристика: для «восстанови текст» — HID-клавиатура и таблица HID; для «достань файл» — bulk + carving.

## Резюме

USB в PCAP разбирается по классу устройства: HID (interrupt, 8-байтовые отчёты, таблица HID + модификаторы) и Mass Storage (bulk, carving/монтирование). Главные ловушки — модификаторы, release-пакеты и порядок bulk. Инструменты: `tshark` (`usb.capdata`, `usb.transfer_type`), `binwalk`, `foremost`.

## Consumer Control и мультимедиа-клавиши

Помимо основной клавиатуры (Usage Page 0x07), HID-устройства шлют **Consumer Control**-отчёты (Usage Page 0x0C): громкость, play/pause, «домой». В CTF это редко, но коды отличаются от обычной таблицы, поэтому не путайте страницы. Отчёт обычно 2-3 байта, и его нужно декодировать отдельной таблицей (`0xE9` = Volume Up, `0xCD` = Play/Pause).

```bash
# Разделить отчёты по устройству/эндпоинту
tshark -r usb.pcap -Y 'usb.capdata' -T fields -e usb.device_address -e usb.endpoint_address -e usb.capdata | head
```

## USB 3.x, SuperSpeed и usbmon

USB 3.0 (SuperSpeed) использует дополнительные эндпоинты (burst) и часто захватывается через `usbmon` интерфейсы выше первого. На Linux `usbmon0` агрегирует все шины, а `usbmonN` — конкретную шину N. В Wireshark для USB 3 есть отдельный dissector (`usbll`).

```bash
# Определить шину устройства
lsusb -t
sudo tcpdump -i usbmon0 -w usb.pcap      # все шины
# В дампе: usb.bus_id, usb.device_address, usb.endpoint_address
```

## Сборка storage: BOT против UAS

Масс-хранилище работает по одному из двух транспортов:

- **BOT** (Bulk-Only Transport) — простой: CBW (Command Block Wrapper, 31 байт) + данные + CSW (статус). Легко собирать.
- **UAS** (USB Attached SCSI) — параллельные потоки, сложнее; данные идут в нескольких bulk-эндпоинтах.

```bash
# Признаки CBW: сигнатура USBC (0x55 0x53 0x42 0x43)
tshark -r usb.pcap -Y 'usb.capdata' -T fields -e usb.capdata | grep -i '^55:53:42:43'
# Собрать данные только IN-эндпоинта (нечётный адрес)
tshark -r usb.pcap -Y 'usb.transfer_type==0x03 && usb.endpoint_address==0x81' \
  -T fields -e usb.capdata | tr -d ':' | xxd -r -p > disk_in.raw
```

Если `binwalk` даёт «рваный» образ, разделяйте потоки по `usb.endpoint_address` и склеивайте каждый отдельно — тогда ФС определяется корректно.

## Проверка результата

```bash
file disk_in.raw                       # определить ФС (ext4, FAT32, NTFS)
sudo mount -o loop,ro disk_in.raw /mnt 2>/dev/null || echo "carve"
strings -n 6 disk_in.raw | head        # быстрый взгляд
```

## Квиз

```quiz
- question: "Какой тип передачи используется для нажатий клавиатуры USB?"
  options:
    - "Interrupt"
    - "Bulk"
    - "Isochronous"
    - "Control"
  answer: 0
  explanation: "HID-клавиатура передаёт нажатия в interrupt-эндпоинте."
- question: "Какое поле Wireshark содержит полезные USB-данные?"
  options:
    - "usb.capdata"
    - "usb.src"
    - "frame.len"
    - "ip.id"
  answer: 0
  explanation: "usb.capdata — данные запроса/ответа USB."
- question: "Почему важно учитывать modifier-байт при декодировании?"
  options:
    - "Он задаёт Shift/Ctrl, меняя регистр и символы"
    - "Он задаёт скорость"
    - "Он содержит MAC"
    - "Он определяет порт"
  answer: 0
  explanation: "Без Shift получаются строчные буквы и цифры вместо символов."
- question: "Как восстанавливают данные с USB-накопителя в PCAP?"
  options:
    - "Собирают bulk-payload и ищут сигнатуры файлов / экспортируют объекты"
    - "Смотрят control-эндпоинт"
    - "Ищут DNS-запросы"
    - "Расшифровывают TLS"
  answer: 0
  explanation: "Масс-хранилища используют bulk; данные восстанавливают по сигнатурам или export."
- question: "Какой риск создаёт BadUSB-устройство?"
  options:
    - "Выдаёт себя за клавиатуру и вводит команды"
    - "Шифрует диск"
    - "Меняет DNS"
    - "Отключает IPv6"
  answer: 0
  explanation: "BadUSB эмулирует HID и набирает команды от имени пользователя."
```

## Где пригодится

- **CTF:** восстановление нажатий/файлов из USB-трафика.
- **IR:** анализ физического вектора (USB).
- **Пентест:** оценка рисков USB-политик.
- **Форензика:** связка с USB-артефактами реестра.
- **Защита:** внедрение device control и мониторинга.
