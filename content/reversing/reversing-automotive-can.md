---
id: reversing-automotive-can
title: "Реверс автомобильных сетей: CAN и UDS"
category: reversing
parent: reversing-firmware-hardware
difficulty: expert
order: 2
tags: [reversing, automotive, can, uds, obd, ecu, car-hacking]
prerequisites: [reversing-firmware, reversing-protocols]
useful_for:
  - "CTF Hardware/Automotive"
  - "Car security research"
  - "Automotive pentest"
estimated_minutes: 60
summary: "Реверс CAN-шины и UDS-диагностики: фреймы, arbitration ID, сервисы UDS, seed/key и прошивка ECU."
---
Автомобили общаются по **CAN-шине** (Controller Area Network) — мультимастерной broadcast-сети, где все узлы (ECU) видят все кадры. Диагностика идёт по **UDS** (Unified Diagnostic Services, ISO 14229) поверх CAN, а обновление прошивок — через UDS-сервисы загрузки. Реверс этих протоколов — ключ к car hacking: понять, какие arbitration ID и байты управляют чем (двери, двигатель, тормоза), как устроена seed/key-защита и как читать/писать прошивку ECU. Этот урок — практический разбор CAN/UDS от подключения к шине до обхода SecurityAccess.

## CAN: физика и кадр

CAN — дифференциальная шина (CAN_H/CAN_L), устойчивая к помехам, с арбитражем по приоритету. Классический кадр:

| Поле | Размер | Смысл |
|------|--------|-------|
| Arbitration ID | 11 бит (standard) / 29 бит (extended) | идентификатор **сообщения** (не отправителя!) |
| RTR | 1 бит | remote frame (запрос данных) |
| Control / DLC | 4 бита | длина данных (0–8 в CAN, до 64 в CAN-FD) |
| Data | 0–8 байт (CAN) / до 64 (FD) | полезная нагрузка |
| CRC | 15 бит | контроль целостности кадра (аппаратный) |
| ACK | 1 бит | подтверждение приёма |

Ключевое: **ID определяет назначение сообщения, а не отправителя** — один и тот же ID могут слать разные ECU. Все узлы видят все кадры; фильтрация — по ID. Скорость типично 500 kbit/s (power­train) или 125 kbit/s (comfort); CAN-FD — до 8 Mbit/s.

## Практика: SocketCAN и can-utils

В Linux CAN работает как сетевой интерфейс (SocketCAN):

```bash
# Поднять интерфейс (адаптер: Peak, Kvaser, USB-CAN, или виртуальный vcan)
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# Для стенда без железа — виртуальная шина
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Слушать всё
candump can0
candump -l can0                 # -l: логировать в файл (candump-*.log)
candump can0,123:7FF            # фильтр по ID-диапазону

# Отправить кадр (ID#данные в hex)
cansend can0 123#DEADBEEF
cansend can0 123#R              # remote-запрос

# Отслеживать изменения байт (подсвечивает изменения)
cansniffer can0
cansniffer -c can0              # -c: только изменяющиеся байты

# Воспроизвести лог
canplayer -I candump-2024.log
# Генерировать нагрузку
cangen can0 -g 10 -I 123        # каждые 10 мс, ID 123
```

Полезные флаги `candump`: `-n <count>` (ограничить число кадров), `-t <type>` (timestamp-формат), `-e` (полный кадр с флагами), `-a` (ASCII). Графические: **SavvyCAN** (фильтры, графики, DBC), **CANalyzat0r**, **Wireshark** (с плагином CAN).

## Реверс CAN: методология

Задача — связать кадры с физическими функциями:

- **Периодические сообщения.** Большинство кадров шлются с фиксированной частотой (10/20/100 мс). `candump` + подсчёт покажет цикл.
- **Корреляция с действиями.** Нажать педаль/кнопку/повернуть руль — наблюдать изменение конкретных байт. Это самый прямой метод.
- **Counter/CRC.** Многие современные кадры содержат счётчик (инкремент) и CRC/checksum — защита от replay. Их нужно моделировать, чтобы подделывать кадры.
- **Multiplexed.** Один ID с «субсообщениями»: первый байт (multiplexer) выбирает, что означают остальные.
- **DBC-файл.** Если есть, он прямо описывает сигналы (битовые поля) — но в реверсе его обычно нет, и его восстанавливают.

```bash
# Собрать два лога (фон и после действия), сравнить
candump -l can0                 # фон 10 секунд
# ... выполнить действие (нажать педаль) ...
# найти ID, чьи байты изменились
python3 - <<'EOF'
# грубое сравнение частоты/значений по ID из двух логов
EOF
```

## Корреляция, counter и CRC

Практический приём: сохранить лог, изменить одно воздействие, снять второй лог, вычесть «фон». Изменённые байты в конкретном ID указывают на функцию. Для плавных сигналов (RPM, скорость) значение кодируется в нескольких байтах, часто с масштабом/смещением (little-endian или Motorola-порядок).

Counter/CRC: если байт монотонно растёт с каждым кадром — это счётчик; если меняется «хаотично», но детерминированно — CRC. Пример реверса CRC:

```python
# Проверить гипотезу: CRC8 (poly 0x1D) по первым 7 байтам
def crc8(data, poly=0x1D):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

for frame in frames:                       # кадры из лога
    assert crc8(frame[:7]) == frame[7]     # подтверждение алгоритма
```

Как только counter и CRC воспроизведены, поддельные кадры проходят проверку ECU.

## UDS (ISO 14229): сервисы и сессии

UDS — запрос/ответ по диагностическому ID (обычно запрос `0x7DF`/`0x7E0`, ответ `0x7E8`). Первый байт — SID (Service Identifier):

| SID | Сервис | Назначение |
|-----|--------|------------|
| 0x10 | DiagnosticSessionControl | переключить сессию (default/programming/extended) |
| 0x11 | ECUReset | сброс ECU |
| 0x14 | ClearDiagnosticInformation | очистить DTC |
| 0x19 | ReadDTCInformation | читать коды ошибок |
| 0x22 | ReadDataByIdentifier | читать данные по DID (VIN, версии) |
| 0x23 | ReadMemoryByAddress | читать память |
| 0x27 | SecurityAccess | seed/key-разблокировка |
| 0x2E | WriteDataByIdentifier | писать данные |
| 0x31 | RoutineControl | запуск рутин (erase, self-test) |
| 0x34 | RequestDownload | начать загрузку прошивки |
| 0x36 | TransferData | передать блок прошивки |
| 0x37 | RequestTransferExit | завершить загрузку |
| 0x3E | TesterPresent | держать сессию активной |
| 0x85 | ControlDTCSetting | включить/выключить DTC |

Ответ на успешный запрос: SID+0x40 (`0x10` → `0x50`). Отрицательный ответ начинается с `0x7F` и NRC (negative response code). Пример чтения VIN:

```bash
# ReadDataByIdentifier, DID F190 (VIN) через OBD-запрос
cansend can0 7DF#0322F190
candump can0                 # ответ 7E8#...62 F1 90 <17 байт VIN>
```

## SecurityAccess (0x27): seed/key

Процедура разблокировки:

```text
1) Tester -> ECU: 27 01 (запрос seed, уровень 1)
2) ECU -> Tester: 67 01 <seed bytes>
3) Tester -> ECU: 27 02 <key bytes>   (key = f(seed))
4) ECU -> Tester: 67 02  (успех) или 7F 27 35 (invalid key)
```

```bash
cansend can0 7E0#0227101        # запрос seed
candump can0                    # 7E8# 06 67 01 <seed...>
```

Алгоритм `f(seed)` — в прошивке ECU или в дилерском ПО. Его реверсят (см. уроки по embedded/прошивкам) либо ищут готовый (DBC/утилиты). Часто это простые операции: XOR, ADD, табличные подстановки, CRC. Иногда уровни `0x03/0x04` (уровень 2) имеют другой алгоритм.

## Прошивка ECU через UDS

Обновление прошивки:

```text
1) 10 03  — programming session
2) 27 xx  — SecurityAccess (разблокировка)
3) 31 01 FF00 — RoutineControl (eraseMemory)
4) 34 ... — RequestDownload (адрес, размер)
5) 36 ... — TransferData (блоки прошивки, много раз)
6) 37     — RequestTransferExit
7) 31 01 FF01 — проверка/верификация
8) 11 01  — ECUReset
```

Это самый мощный примитив: при успехе вы управляете прошивкой ECU. Требует стабильного питания и точного формата; ошибка может «окирпичить» блок.

## Инструменты

| Инструмент | Назначение |
|------------|------------|
| `can-utils` | candump/cansend/cansniffer/cangen/canplayer |
| SocketCAN | ядерный CAN-стек Linux |
| SavvyCAN | GUI: фильтры, графики, DBC, отправка |
| CANalyzat0r | анализ CAN, брутфорс |
| Wireshark | разбор pcap с CAN/CAN-FD |
| `udsoncan` (Python) | полноценный UDS-клиент |
| `python-can` | низкоуровневый доступ к шине |
| OBD-II адаптер | физическое подключение (ELM327, PEAK, Kvaser) |

## Разобранный пример: от подключения до разблокировки

```text
1) Подключиться: OBD-II (pin 6=CAN_H, 14=CAN_L) или напрямую к шине.
   ip link set can0 up type can bitrate 500000
2) candump can0 -l — собрать фон; нажать кнопку; собрать второй лог.
3) Найти ID и байты, коррелирующие с функцией (напр., открытие двери).
4) Для диагностики: перейти в extended session (10 03).
5) Запросить seed: cansend can0 7E0#0227101; прочитать 67 01 <seed>.
6) Реверснуть алгоритм seed->key (прошивка/дилерское ПО), посчитать key.
7) Отправить 27 02 <key>; получить 67 02 -> разблокировано.
8) Читать/писать параметры (22/2E), при необходимости — прошивка (34/36/37).
```

## Безопасность и правовые аспекты

Работа с CAN опасна и юридически чувствительна:

- **Физическая опасность.** Запись в ECU (особенно тормоза/рулевое/двигатель) на ходу может привести к аварии. Работайте только на **стенде**, с отключённым приводом, в лаборатории.
- **Правовые ограничения.** Вмешательство в чужие автомобили/устройства без разрешения — противоправно. Тестируйте только свои/разрешённые образцы (CTF-стенды, research-платформы).
- **Постоянное питание.** Во время прошивки прерывание питания «окирпичивает» ECU — используйте стабильный источник.

## Частые ошибки

- **Путать ID отправителя и назначения.** ID — это сообщение, а не ECU; его могут слать несколько узлов.
- **Игнорировать counter/CRC.** Replay не сработает без корректного counter/CRC.
- **Нет физического доступа.** CAN требует подключения к шине (OBD-II или напрямую).
- **Опасность для авто.** Запись в ECU может повредить; только стенд.
- **Забыть про скорость шины.** Неверный bitrate — связи нет.
- **Не учитывать gateway.** Некоторые шины изолированы центральным gateway; напрямую ECU недоступен.
- **Пропуск сессии.** Многие сервисы (0x2E, 0x27, 0x34) требуют extended/programming session.

## Что делать дальше / решение

1. Поднимите интерфейс (`ip link set can0 ...`) и соберите фон через `candump -l`.
2. Коррелируйте кадры с действиями; определите ID и сигналы, восстановите counter/CRC.
3. Перейдите к UDS: extended session, чтение DID (22), DTC (19).
4. Запросите seed (27 01) и реверсните алгоритм keygen из прошивки/ПО.
5. Разблокируйте ECU (27 02) и прочитайте/запишите параметры.
6. Для прошивки — programming session + 34/36/37; только на стенде с надёжным питанием.

## Квиз

```quiz
- question: "Что определяет arbitration ID в CAN?"
  options:
    - "Назначение сообщения (а не отправителя)"
    - "Отправителя"
    - "CRC"
    - "Скорость"
  answer: 0
  explanation: "ID идентифицирует сообщение; его могут слать разные ECU."
- question: "Что такое UDS SecurityAccess (0x27)?"
  options:
    - "Seed/key-процедура разблокировки ECU"
    - "Чтение данных"
    - "Сброс ECU"
    - "Онлайн-обновление"
  answer: 0
  explanation: "ECU отдаёт seed, tester возвращает key для разблокировки."
- question: "Какие утилиты слушают/шлют CAN?"
  options:
    - "candump/cansend (can-utils)"
    - "nmap"
    - "gdb"
    - "objdump"
  answer: 0
  explanation: "can-utils (candump/cansend) — базовые инструменты CAN."
- question: "Зачем нужен counter/CRC в CAN-сообщениях?"
  options:
    - "Защита от replay/повторов"
    - "Ускорение"
    - "Шифрование"
    - "Сжатие"
  answer: 0
  explanation: "Counter/CRC усложняют простой replay."
- question: "Что нужно для реверса seed/key?"
  options:
    - "Найти алгоритм в прошивке ECU/софте дилера"
    - "Отключить ASLR"
    - "Снять canary"
    - "Расширить tcache"
  answer: 0
  explanation: "Алгоритм keygen реверсится из прошивки/дилерского ПО."
```

## Где пригодится

- **CTF:** Hardware/Automotive.
- **Car security research:** анализ шины/ECU.
- **Automotive pentest:** тестирование авто.
- **Работа:** embedded/automotive security.
