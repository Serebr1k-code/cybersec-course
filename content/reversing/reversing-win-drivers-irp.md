---
id: reversing-win-drivers-irp
title: "Реверс Windows-драйверов: IRP, dispatch, IOCTL-фаззинг"
category: reversing
parent: reversing-mod-win2
difficulty: hard
order: 2
tags: [reversing, windows, driver, kernel, irp, ioctl, fuzzing, privesc]
prerequisites: [reversing-mod-win]
useful_for:
  - "Поиск локального повышения привилегий"
  - "Анализ EDR и rootkit-компонентов"
  - "Реверс драйверов"
estimated_minutes: 60
summary: "Реверс драйвера ядра Windows: DriverEntry, MajorFunction, обработка IRP, разбор IOCTL-кодов и подход к IOCTL-фаззингу для поиска privesc."
lab:
  kind: shell
  title: "Практика: разбор драйвера"
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md, vulndrv.sys]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Драйвер — это PE-файл; `DriverEntry` и `IoCreateDevice` — признаки драйвера."
    - "IOCTL-коды задаются макросом CTL_CODE и видны как hex-константы."
    - "`strings -n 5 vulndrv.sys` покажет имена функций и артефакт."
    - "`strings -n 5 vulndrv.sys | grep nto > found.txt`, затем `check`."
---

## Вопрос, с которого всё начинается

Ты нашёл `vulndrv.sys` — сторонний драйвер, установленный в системе. Известно, что такие драйверы часто содержат уязвимые IOCTL-обработчики, позволяющие обычному пользователю выполнить код в ядре. Как разобрать драйвер и найти уязвимый IOCTL?

## Наш пример

Возьмём `vulndrv.sys`. Смотрим строки:

```
$ strings -n 5 vulndrv.sys | grep -iE 'driver|device|ioctl|create'
DriverEntry
IoCreateDevice
IoCreateSymbolicLink
\\Device\\VulnDrv
\\DosDevices\\VulnDrv
IRP_MJ_DEVICE_CONTROL
```

Это классический драйвер: создаёт устройство `\Device\VulnDrv` и символьную ссылку, доступную из user-mode как `\\.\VulnDrv`, и обрабатывает `IRP_MJ_DEVICE_CONTROL`. Разберём, что это значит.

## Шаг 1: точка входа и создание устройства

Драйвер — это PE-файл, но с точкой входа `DriverEntry` (аналог `main`), которую вызывает ядро при загрузке. В `DriverEntry` драйвер обычно: создаёт объект устройства (`IoCreateDevice`), создаёт символическую ссылку (`IoCreateSymbolicLink`), чтобы user-mode мог к нему обратиться, и заполняет таблицу обработчиков `MajorFunction`.

`MajorFunction` — массив указателей на функции, по одному на каждый тип IRP: `IRP_MJ_CREATE` (открытие), `IRP_MJ_CLOSE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_DEVICE_CONTROL` (IOCTL). Для поиска уязвимостей интересен последний.

## Шаг 2: IRP — что это такое

**IRP** (I/O Request Packet) — структура, через которую ядро передаёт драйверу запросы ввода-вывода. Когда user-mode программа вызывает `DeviceIoControl`, ядро создаёт IRP с кодом `IRP_MJ_DEVICE_CONTROL` и передаёт его драйверу. Драйвер разбирает IRP: достаёт код IOCTL (`Parameters.DeviceIoControl.IoControlCode`), буферы входа/выхода и их размеры.

Для реверса это означает: обработчик `IRP_MJ_DEVICE_CONTROL` — центральная функция. Именно она решает, что делать с запросом, и именно в ней обычно кроется ошибка.

## Шаг 3: IOCTL-коды и макрос CTL_CODE

IOCTL-код — 32-битное число, собранное макросом `CTL_CODE(DeviceType, Function, Method, Access)`. Верхние биты кодируют тип устройства и метод доступа к буферу (buffered, direct, neither), нижние — номер функции.

В дизассемблере IOCTL-коды видны как сравнения: обработчик делает `switch` по `IoControlCode` и вызывает разные функции. Например:

```
cmp  [ebp+IoControlCode], 0x222003
je   handler_0x222003
cmp  [ebp+IoControlCode], 0x222007
je   handler_0x222007
```

Каждая ветка — отдельная команда драйвера. Это и есть точки для фаззинга.

## Шаг 4: как выглядит уязвимый IOCTL

Классические уязвимости драйверов:

- **Произвольная запись**: IOCTL принимает адрес и значение из user-mode и пишет по этому адресу без проверки — позволяет перезаписать ядро.
- **Переполнение буфера**: `memcpy` входных данных в фиксированный буфер ядра без проверки длины.
- **Вызов по указателю**: драйвер вызывает функцию по адресу, переданному из user-mode.
- **Отсутствие проверки прав**: обработчик доступен любому пользователю, хотя должен быть только для админа.

Для реверса: смотри обработчики, которые берут адрес/размер из входного буфера IRP (`Irp->AssociatedIrp.SystemBuffer`, `Parameters.DeviceIoControl.InputBufferLength`) и передают их в `memcpy`/`write`. Если проверок длины или прав нет — это цель.

## Шаг 5: IOCTL-фаззинг

Найдя подозрительный IOCTL-код, его проверяют фаззингом: пишут маленькую user-mode программу, которая открывает `\\.\VulnDrv` и шлёт случайные данные с этим кодом. Если драйвер падает (BSOD) или ведёт себя некорректно — есть баг. Дальше подбирают вход, дающий контролируемый эффект.

Инструменты вроде `ioctlbf` или самописные fuzzer'ы на Python/C автоматизируют перебор: перебирают коды, длины и содержимое буферов. Важно делать это на изолированной виртуалке — BSOD реален.

## Шаг 6: находим артефакт практики

Среди строк драйвера — артефакт. Достанем его:

```
$ strings -n 5 vulndrv.sys | grep nto
nto{10ctl_d1sp4tch_arb1tr4ry_wr1t3}
```

## Что мы теперь знаем

- Драйвер — PE с точкой входа `DriverEntry`; создаёт устройство и символьную ссылку.
- `MajorFunction` — таблица обработчиков IRP; ключевой для атак — `IRP_MJ_DEVICE_CONTROL`.
- IOCTL-код собирается `CTL_CODE`; в коде — `switch` по нему.
- Уязвимости: произвольная запись/чтение, переполнение буфера, вызов по указателю, слабые проверки прав.
- IOCTL-фаззинг: посылать случайные данные с кодом и искать падение/эффект.

## Квиз

Проверь себя.

```quiz
- question: "Как называется точка входа драйвера Windows?"
  options:
    - "DriverEntry"
    - "DllMain"
    - "WinMain"
    - "main"
  answer: 0
- question: "Что такое IRP?"
  options:
    - "Структура запроса ввода-вывода, которую ядро передаёт драйверу"
    - "Тип сетевого пакета"
    - "Формат картинки"
    - "Регистр процессора"
  answer: 0
- question: "Какой обработчик IRP отвечает за IOCTL?"
  options:
    - "IRP_MJ_DEVICE_CONTROL"
    - "IRP_MJ_CREATE"
    - "IRP_MJ_CLOSE"
    - "IRP_MJ_READ"
  answer: 0
- question: "Почему IOCTL-фаззинг делают на изолированной виртуалке?"
  options:
    - "Ошибка драйвера приводит к BSOD (синий экран), а не к безопасному сбою"
    - "Так быстрее"
    - "На реальной машине нет IOCTL"
    - "Виртуалка нужна для сети"
  answer: 0
```

## Куда дальше

Дальше — другие области Windows internals: реестр, службы, автозапуск и подписанный код. Пока главное запомни: **драйвер — это таблица обработчиков IRP; найди `IRP_MJ_DEVICE_CONTROL`, разбери `switch` по IOCTL-кодам и проверь каждый на доверие к входу**.

## Где пригодится

- **Локальный privesc:** уязвимые драйверы — частая дорога до SYSTEM.
- **Анализ EDR/rootkit:** драйверы — низкоуровневая часть защиты и атак.
- **Bug bounty:** поиск уязвимостей в драйверах антивирусов и утилит.
