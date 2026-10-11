---
id: hardware-can-uds
title: "UDS-диагностика и реверс ECU (ISO 14229)"
category: hardware
parent: hardware-can-bus
difficulty: hard
order: 2
tags: [uds, iso14229, ecu, diagnostic, obd2, seed-key, can, automotive]
prerequisites: [hardware-can-bus]
useful_for:
  - "CTF-задачи категории Hardware/Automotive"
  - "Автомобильная безопасность"
  - "Пентест connected car"
estimated_minutes: 50
summary: "Протокол UDS поверх CAN: сессии, SecurityAccess (seed-key), чтение/запись ECU, прошивка и обход аутентификации — практический реверс диагностики автомобиля."
---

UDS (Unified Diagnostic Services, ISO 14229) — стандарт диагностики, который используется дилерским оборудованием для чтения ошибок, конфигурации и перепрошивки ECU. Поверх CAN он даёт мощный интерфейс к автомобилю. Для атакующего UDS — это «API» автомобиля: если обойти SecurityAccess, можно читать/писать внутренние данные и прошивку.

## Теория

UDS-сообщение отправляется в диагностический CAN-ID (обычно `0x7E0` для запроса, `0x7E8` для ответа). Формат: `[длина][SID][параметры]`.

Основные сервисы (SID):

| SID | Сервис | Назначение |
|-----|--------|-----------|
| 0x10 | DiagnosticSessionControl | переключить сессию (default/programming/extended) |
| 0x27 | SecurityAccess | seed-key аутентификация |
| 0x22 | ReadDataByIdentifier | чтение DID (VIN, версии, калибровки) |
| 0x2E | WriteDataByIdentifier | запись DID |
| 0x31 | RoutineControl | запуск процедур (самотест, сброс) |
| 0x34 | RequestDownload | начать загрузку прошивки |
| 0x36 | TransferData | передача блоков |
| 0x37 | RequestTransferExit | завершить |
| 0x3E | TesterPresent | поддержание сессии |
| 0x11 | ECUReset | сброс ECU |
| 0x19 | ReadDTCInformation | чтение ошибок |

**SecurityAccess (0x27)** — ключевой барьер:
1. Тестер шлёт `27 01` (request seed).
2. ECU отвечает `67 01 <seed>`.
3. Тестер вычисляет key из seed (секретный алгоритм) и шлёт `27 02 <key>`.
4. ECU проверяет; при успехе — `67 02`.

Алгоритм key часто «зашит» в прошивке или в закрытом софте. Реверс алгоритма = полный доступ.

## Инструменты и команды

- **python-uds**, **udsoncan** + **python-can** — отправка UDS.
- **can-utils** (`cansend`, `candump`) — низкоуровнево.
- **Caring Caribou / Vehicle Spy** — коммерческие.
- **CANalyze / SavvyCAN** — анализ.
- **IDA/Ghidra** — реверс алгоритма seed-key из прошивки ECU.

```bash
# Простой UDS-запрос через cansend: 02 = длина, 10 03 = extended session
cansend can0 7E0#0210030000000000
candump can0,7E8:7FF        # смотреть ответы ECU

# python-uds
python - <<'PY'
import udsoncan
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.client import Client
import isotp, can
bus = can.interface.Bus('can0', bustype='socketcan')
tp = isotp.socket(); tp.bind('can0', isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7E8, txid=0x7E0))
conn = PythonIsoTpConnection(tp)
with Client(conn, request_timeout=2) as c:
    c.change_session(udsoncan.services.DiagnosticSessionControl.Session.extendedDiagnosticSession)
    seed = c.request_seed(0x01).service_data['securitySeed']
    print('seed', seed.hex())
    # key = f(seed) — вычисляем и шлём
    # c.send_key(0x02, key_bytes)
PY
```

## Разобранный пример: обход SecurityAccess

**Дано:** ECU, UDS поверх CAN, есть seed, но нет алгоритма key. Есть дамп прошивки ECU.

**Шаг 1 — расширенная сессия.** `10 03` → ответ `50 03` + параметры (P2/P2* тайминги). Теперь доступны защищённые сервисы.

**Шаг 2 — запрос seed.** `27 01` → `67 01 <seed>`. Seed может быть фиксированным (плохо) или случайным.

**Шаг 3 — проверка фиксированного seed.** Если seed одинаков при каждом запросе — возможно, ECU принимает и фиксированный key. Пробуем стандартные ключи.

**Шаг 4 — реверс алгоритма.** В дампе прошивки ищем обработчик SecurityAccess: таблицу SID (`0x27`), вызовы CRC/умножений. Часто key = CRC8(seed) или просто seed XOR константа. Дизассемблируем в Ghidra, находим функцию и восстанавливаем.

**Шаг 5 — отправка key.** Считаем key, шлём `27 02 <key>`, получаем `67 02` — доступ разрешён.

**Шаг 6 — эксплуатация.** Читаем защищённые DID (`22 F1xx` — калибровки, VIN), пишем конфиг (`2E`), при необходимости — загрузка своей прошивки (`34/36/37`). Всё — только на своём авто/стенде.

## Частые ошибки

- **Нет TesterPresent.** UDS-сессия истекает (P2-таймер ~5 с). Шлите `3E 80` периодически.
- **Неверный адрес/CAN-ID.** Разные ECU используют разные ID (0x7E0..0x7E7). Сканируйте.
- **Прямая запись без чтения.** Сначала читайте (`22`), потом пишите (`2E`). Иначе рискуете «окирпичить» ECU.
- **Игнорирование NRC.** Отрицательный ответ `7F <SID> <NRC>` говорит причину (security denied, wrong session). Читайте NRC.
- **Фаззинг вслепую.** Случайные UDS-запросы могут сбросить ECU/авто. Работайте на стенде.
- **Правовые рамки.** Прошивка чужого авто/отключение иммобилайзера — преступление.

## UDS: сервисы

| Сервис | ID | Назначение |
|--------|-----|------------|
| DiagnosticSessionControl | 0x10 | смена сессии |
| ECUReset | 0x11 | перезагрузка |
| ReadDataByIdentifier | 0x22 | чтение данных |
| WriteDataByIdentifier | 0x2E | запись |
| SecurityAccess | 0x27 | seed-key |
| RoutineControl | 0x31 | запуск рутины |
| RequestDownload | 0x34 | загрузка прошивки |
| TransferData | 0x36 | передача |

## SecurityAccess: seed-key

ECU выдаёт seed, клиент возвращает key (обычно производный от seed через секретный алгоритм). Обход: извлечь алгоритм из прошивки (реверс), найти backdoor-ключ, или сбросить счётчик попыток. Часто алгоритм — простая функция (XOR, таблица), и его находят в бинарнике ECU.

```bash
# can-utils + isotp
isotp-send -d can0 -t 0x7E0 02 10 03
isotp-send -d can0 -t 0x7E0 02 27 01     # request seed
# ответ: 67 01 <seed>
isotp-send -d can0 -t 0x7E0 06 27 02 <key>
```

## Инструменты

```bash
ip link set can0 up type can bitrate 500000
candump can0
cansend can0 7DF#020100
isotpscan -d can0
# UDS: python-udsoncan, Caring Caribou
```

## Практика

На тестовом ECU (или симуляторе) запросите seed, восстановите алгоритм key из прошивки и пройдите SecurityAccess. Затем получите доступ к WriteDataByIdentifier. Это стандартный automotive-пентест.

## Диагностические сессии и привилегии

UDS использует сессии: `default`, `programming`, `extended`. Привилегированные операции (запись, загрузка прошивки) доступны только в extended/programming после SecurityAccess. Обход строится на: (1) слабом алгоритме seed-key, (2) отсутствии ограничения попыток, (3) backdoor-ключе, оставленном разработчиком. Проверьте `0x27 0x03/0x04` (suppress positive response) и тайминг (P2/P2*). Часто достаточно извлечь алгоритм из прошивки ECU: ищите таблицы, XOR-константы, вызовы CRC. Затем пройдите SecurityAccess и получите доступ к WriteDataByIdentifier — вплоть до перепрошивки. Это серьёзный риск для автомобиля.

## Итог

UDS даёт диагностический доступ к ECU; SecurityAccess (seed-key) — основной барьер. Обход строится на реверсе алгоритма key, слабых ограничениях или backdoor. Пройдя SecurityAccess, можно читать/писать данные и перепрошивать ECU. Для защиты — сильный seed-key, ограничение попыток, аутентификация диагностики.

## Сводка по инструментам

| Задача | Инструмент |
|--------|-----------|
| мониторинг CAN | candump, SavvyCAN |
| UDS | python-udsoncan, isotp |
| сканирование | isotpscan, Caring Caribou |
| реверс key | Ghidra по прошивке ECU |
| запись кадров | cansend |

## Быстрая проверка

```bash
ip link set can0 up type can bitrate 500000
isotp-send -d can0 -t 0x7E0 02 10 03
isotp-send -d can0 -t 0x7E0 02 27 01
```

Запросите seed (`27 01`), реверсите алгоритм key из прошивки ECU и пройдите SecurityAccess (`27 02`). Затем доступны привилегированные сервисы.

## Квиз

```quiz
- question: "Что делает сервис UDS 0x27?"
  options:
    - "SecurityAccess: seed-key аутентификация"
    - "Чтение ошибок"
    - "Сброс ECU"
    - "Передача прошивки"
  answer: 0
- question: "Какой сервис читает данные по идентификатору (DID)?"
  options:
    - "0x22 ReadDataByIdentifier"
    - "0x27 SecurityAccess"
    - "0x11 ECUReset"
    - "0x3E TesterPresent"
  answer: 0
- question: "Зачем нужен TesterPresent (0x3E)?"
  options:
    - "Поддерживать диагностическую сессию, чтобы она не истекла"
    - "Стереть ошибки"
    - "Прочитать VIN"
    - "Сбросить ключи"
  answer: 0
- question: "Что означает ответ 7F 27 35?"
  options:
    - "Отрицательный ответ на SecurityAccess (invalidKey)"
    - "Успешная аутентификация"
    - "Сброс ECU"
    - "Чтение VIN"
  answer: 0
- question: "Где чаще всего ищут алгоритм seed-key?"
  options:
    - "В прошивке ECU (дизассемблирование) или в закрытом диагностическом софте"
    - "В файле DBC"
    - "В логе CAN"
    - "В SIM-карте"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware/Automotive-задачи с UDS и seed-key.
- **Автомобильная безопасность:** реверс ECU, оценка диагностического доступа.
- **Пентест connected car:** полный контроль над диагностикой.
- **Работа:** разработка диагностических приложений, защита ECU.
- **Дальше по дереву:** `hardware-can-bus`, `hardware-scada`, `hardware-secure-boot`.
