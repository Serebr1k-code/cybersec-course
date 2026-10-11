---
id: hardware-jtag-deep
title: "JTAG/SWD глубоко: boundary scan, debug-lock bypass"
category: hardware
parent: hardware-jtag
difficulty: hard
order: 2
tags: [jtag, swd, boundary-scan, openocd, urjtag, debug-lock, bsdl, idcode]
prerequisites: [hardware-jtag, hardware-logic-analysis]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Реверс встраиваемых устройств"
  - "Аппаратная безопасность"
estimated_minutes: 45
summary: "Глубокое погружение в JTAG: цепочка TAP, boundary scan, определение распиновки, обход debug-lock и чтение памяти через OpenOCD."
---

JTAG — это не только «отладка процессора», но и полноценный стандарт IEEE 1149.1 с цепочкой TAP-контроллеров, boundary scan и возможностью чтения/записи памяти. В этом уроке — продвинутые техники: как найти неизвестный JTAG-разъём, как работать с цепочкой из нескольких устройств и как обходить debug-lock.

## Теория

JTAG-интерфейс состоит из 5 сигналов:

| Сигнал | Полное имя | Назначение |
|--------|-----------|------------|
| TCK | Test Clock | тактирование |
| TMS | Test Mode Select | управление состоянием TAP |
| TDI | Test Data In | вход данных |
| TDO | Test Data Out | выход данных |
| TRST | Test Reset | сброс TAP (опционально) |

TAP-контроллер — конечный автомат из 16 состояний. Через TMS задаётся переход; через TDI/TDO гоняются данные. В цепочке может быть несколько TAP-устройств, соединённых последовательно (TDI→...→TDO).

**Boundary scan** — каждая ножка чипа имеет ячейку, позволяющую «пришпилить» её значение. Это позволяет:
- проверить соединения на плате без доступа к сигналам;
- прочитать состояние входов;
- найти распиновку неизвестного разъёма.

**IDCODE** — 32-битный идентификатор, по которому определяют производителя/модель чипа. Команда `IDCODE` в OpenOCD/urjtag выдаёт его.

**Debug-lock** — производитель может запретить отладку (fuse, регистр). Обходы: найти отладочный режим, снять fuse, использовать boundary scan для обхода, fault injection.

## Инструменты и команды

- **OpenOCD** — универсальный отладчик JTAG/SWD.
- **urjtag** — работа с цепочкой TAP, boundary scan.
- **JTAGulator** — автоматический поиск JTAG-пинов.
- **Black Magic Probe / FTDI + адаптер** — железо.
- **BSDL-файлы** — описание boundary scan для конкретного чипа.

```bash
# --- JTAGulator: найти пины ---
# В его консоли: подключаем каналы к подозрительным пинам и запускаем IDCODE scan.

# --- urjtag: обнаружить цепочку ---
jtag
> cable ft2232
> detect
# Вывод: Found 2 devices, IDCODE 0x... (производитель/модель)

# --- boundary scan через urjtag ---
> bsdl path /path/to/bsdl/
> bsdl
> instruction SAMPLE/PRELOAD
> shift ir
> shift dr
> print

# --- OpenOCD: подключение и чтение ---
openocd -f interface/ftdi/xxx.cfg -f target/stm32f4x.cfg
# в telnet 4444:
# > reset halt
# > flash banks
# > dump_image firmware.bin 0x08000000 0x100000
```

## Разобранный пример: поиск JTAG на неизвестной плате

**Дано:** плата с группой из 12 площадок, документации нет.

**Шаг 1 — JTAGulator.** Подключаем каналы JTAGulator к площадкам, запускаем `IDCODE scan` (по одному биту). Инструмент перебирает комбинации TDI/TDO/TCK/TMS и сообщает, когда находит валидный IDCODE.

```text
JTAGulator> i        # IDCODE scan
# Found IDCODE: 0x4BA00477  -> ARM Cortex (типовой)
```

**Шаг 2 — определить пины.** По результату скана JTAGulator сообщает, какие каналы = TCK/TMS/TDI/TDO. Остальные (Vcc, GND, TRST, RTCK) определяем прозвонкой.

**Шаг 3 — цепочка.** Подключаем OpenOCD:

```bash
openocd -f interface/ftdi/ft2232.cfg \
  -c "adapter speed 1000" \
  -c "jtag newtap auto0 tap -irlen 4 -expected-id 0x4ba00477" \
  -f target/...
```

**Шаг 4 — чтение памяти.** `reset halt`, затем `mdw 0x08000000` для чтения регионов. Если debug-lock включён — получим ошибку.

**Шаг 5 — обход debug-lock.** Варианты:
- проверить, не отключается ли lock определённым паттерном на линии;
- использовать boundary scan для чтения флеш через ножки (в обход CPU-отладки);
- fault injection (см. `hardware-fault-injection`) для пропуска проверки lock.

**Шаг 6 — дамп.** Снимаем флеш через JTAG (если разрешено) или boundary scan, далее `binwalk`.

## Частые ошибки

- **Путаница TCK/TMS.** Неверный TMS = TAP не выходит из reset, IDCODE не читается. JTAGulator решает это автоматически.
- **Нет общей земли.** JTAG без GND не работает. GND — всегда.
- **Низкая/высокая скорость.** Слишком высокая частота TCK на длинных проводах = ошибки. Начните с 100–500 кГц.
- **Ожидание одного TAP.** В цепочке их может быть несколько; IDCODE первого — не всего. Смотрите полный `detect`.
- **Игнорирование debug-lock.** Если чтение памяти всегда 0/FF — вероятно lock. Не считайте чип пустым.
- **Boundary scan без BSDL.** Без BSDL-описания вы не знаете ячейки; используйте `SAMPLE` для базового чтения.

## Теория: boundary scan и TAP

JTAG основан на TAP (Test Access Port) с состояниями и регистрами: IR (instruction), DR (data), IDCODE, BYPASS. Boundary scan позволяет «щупать» пины чипа без физического доступа (через цепочку), читать/писать состояния выводов. IDCODE идентифицирует чип. Debug-доступ (ARM DAP) даёт отладку ядра.

## Инструменты и команды

```bash
# OpenOCD
openocd -f interface/ftdi/... -f target/...
# в telnet
> scan_chain
> irscan
> drscan
# urjtag
jtag
> detect
> cable
> print
# определение IDCODE
openocd -c 'adapter speed 1000; init; scan_chain; shutdown'
```

## Разобранный пример 2: поиск JTAG на неизвестной плате

1. Ищем группу из 4-5 пятачков (TDI, TDO, TCK, TMS, TRST).
2. Прозвонкой/логическим анализатором находим TCK (клок при старте).
3. Подключаем JTAGulator или перебираем комбинации OpenOCD.
4. `scan_chain` показывает IDCODE — чип найден.
5. Читаем память через `dump_image`.

## Debug-lock bypass

Блокировка SWD/JTAG обходится: mass-erase, glitching проверки lock, чтение через boot ROM, альтернативный интерфейс. Иногда lock снимается самим загрузчиком или через специальную последовательность.

## JTAGulator и автоматический поиск

JTAGulator — инструмент, который перебирает комбинации пинов и определяет JTAG/SWD/UART автоматически. Это ускоряет поиск на незнакомой плате. Для JTAG он проверяет TDI/TDO/TCK/TMS/TRST; для UART — TX/RX/baudrate.

```bash
# подключение JTAGulator к пятачкам
> j   # JTAG scan
> u   # UART scan
> s   # SWD scan
# результат: пины и IDCODE/baud
```

## Практика 2

Возьмите плату с неизвестной разводкой, подключите JTAGulator, определите пины JTAG. Затем через OpenOCD `scan_chain` прочитайте IDCODE, идентифицируйте чип и снимите дамп памяти. Если интерфейс заблокирован — попробуйте массовое стирание или glitching проверки lock. Задокументируйте метод обхода.

## Быстрая проверка

```bash
# JTAGulator
> j    # JTAG scan
> s    # SWD scan
# OpenOCD
openocd -c 'adapter speed 1000; init; scan_chain; shutdown'
# urjtag
jtag -c detect
```

Найдите пины (JTAGulator), получите IDCODE (`scan_chain`), идентифицируйте чип. Затем читайте память через `dump_image`. При debug-lock — mass-erase или glitching.

## Итог

JTAG/SWD дают доступ к ядру и памяти. Boundary scan «щупает» пины, DAP отлаживает, ETM/SWO дают трассировку. Debug-lock обходится mass-erase или glitching. Начинайте с JTAGulator для поиска пинов, затем OpenOCD для чтения памяти.

## Сводка

| Интерфейс | Пины | Инструмент |
|-----------|------|-----------|
| JTAG | TCK/TMS/TDI/TDO | OpenOCD, urjtag |
| SWD | SWCLK/SWDIO | OpenOCD, pyOCD |
| SWO | SWO | pyOCD, JLink |

## Квиз

```quiz
- question: "Сколько основных сигналов у JTAG (без опциональных)?"
  options:
    - "Четыре: TCK, TMS, TDI, TDO (TRST опционален)"
    - "Один: только TCK"
    - "Восемь: DAT0-DAT7"
    - "Два: TX и RX"
  answer: 0
- question: "Что такое IDCODE?"
  options:
    - "32-битный идентификатор чипа в цепочке TAP"
    - "Пароль от отладчика"
    - "Номер версии прошивки"
    - "Адрес флеш-памяти"
  answer: 0
- question: "Зачем нужен boundary scan?"
  options:
    - "Проверять соединения и читать состояние ножек чипа без доступа к сигналам"
    - "Ускорять работу процессора"
    - "Шифровать прошивку"
    - "Питать плату"
  answer: 0
- question: "Что означает постоянное чтение 0x00000000/0xFFFFFFFF при попытке дампа по JTAG?"
  options:
    - "Вероятно, включён debug-lock или неверная цепочка TAP"
    - "Флеш пустая и исправна"
    - "Питание слишком высокое"
    - "Нужно сменить USB-кабель"
  answer: 0
- question: "Какой инструмент автоматически ищет JTAG-пины?"
  options:
    - "JTAGulator"
    - "Nmap"
    - "Ghidra"
    - "Wireshark"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware-задачи с поиском JTAG и чтением памяти.
- **Реверс:** извлечение прошивки и отладка процессора.
- **Аппаратная безопасность:** оценка защищённости отладочных интерфейсов.
- **Работа:** производственный тест плат, разработка встраиваемых систем.
- **Дальше по дереву:** `hardware-swd-advanced`, `hardware-embedded-debug`, `hardware-secure-boot`.
