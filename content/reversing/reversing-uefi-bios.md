---
id: reversing-uefi-bios
title: "Реверс UEFI/BIOS"
category: reversing
parent: reversing-firmware-basics
difficulty: expert
order: 4
tags: [reversing, uefi, bios, firmware, spi, dxe, pei, secure-boot]
prerequisites: [reversing-firmware, reversing-file-formats]
useful_for:
  - "CTF Reversing (expert)"
  - "Firmware security"
  - "Bootkit analysis"
estimated_minutes: 70
summary: "Разбор UEFI-прошивок: структура PI/PEI/DXE, UEFITool, модули, SMM и анализ bootkit-техник."
---
UEFI/BIOS — это прошивка, которая запускается **до** операционной системы и инициализирует железо, а затем передаёт управление загрузчику. Её реверс критичен для анализа **bootkit**'ов (UEFI-имплантов вроде LoJax/BlackLotus), уязвимостей прошивки (SMM, Secure Boot bypass) и для firmware security в целом. Структура UEFI сильно отличается от обычных бинарей: это набор модулей PI/PEI/DXE внутри Firmware Volume, каждый — PE-подобный файл с GUID вместо имени. Этот урок — практический разбор UEFI от дампа SPI-флеша до анализа DXE-модуля и bootkit-техник.

## Что такое UEFI/BIOS и зачем реверс

Исторически BIOS был 16-битным legacy-кодом. Современный **UEFI** — это 32/64-битная среда с драйверами, протоколами и файловой системой внутри прошивки. Реверс UEFI нужен, чтобы:

- Понять механику **bootkit**'ов: как имплант переживает переустановку ОС (он в SPI flash).
- Найти уязвимости **SMM** (ring -2): переполнения в SMI-handler'ах дают высший привилегированный доступ.
- Разобрать **Secure Boot** и его обход: как проверяются подписи загрузчиков.
- Провести аудит прошивки вендора: скрытые бэкдоры, слабые проверки, небезопасная обработка NVRAM.

## Структура прошивки: SPI, дескриптор, регионы

Прошивка физически лежит в **SPI NOR flash** на материнской плате. Полный образ начинается с **Flash Descriptor**:

```text
+---------------------------+
| Flash Descriptor (0x0)    | регионы: Descriptor/BIOS/ME/GbE/EC
+---------------------------+
| ME region                 | Management Engine (часто отдельный)
+---------------------------+
| GbE region                | сетевой конфиг
+---------------------------+
| BIOS region               | основной UEFI-код (FV с модулями)
+---------------------------+
| EC region                 | embedded controller
+---------------------------+
```

Важно снимать **полный** дамп (включая дескриптор), иначе структура не разберётся. Многие исследователи работают только с BIOS-регионом, но для понимания layout нужен весь образ.

## Firmware Volume, FFS и модули

Внутри BIOS-региона — **Firmware Volume (FV)**: контейнеры с файлами **FFS** (Firmware File System). Каждый FFS-файл — модуль с GUID и типом:

- **PEI** (Pre-EFI Initialization) — самая ранняя инициализация (память, чипсет).
- **DXE** (Driver Execution Environment) — основная фаза: драйверы, протоколы, сервисы (`gBS`, `gRT`).
- **SMM** (System Management Mode) — код в ring -2, обрабатывающий SMI.
- **SEC** — Security phase (первый код после reset).
- **NVRAM** — переменные (в т.ч. `SecureBoot`, `PK`/`KEK`/`db`).

Иерархия: **Flash -> Region -> Firmware Volume -> FFS file -> Section -> PE image**. Понимание этой вложенности — половина успеха разбора.

## Извлечение и разбор: инструменты

```bash
# Дамп SPI-флеша (аппаратно через CH341A/программатор)
flashrom -p ch341a_spi -r firmware.bin
# или из дампа ОС (если разрешено): чтение /dev/mem / win flash tool

# Разбор структуры (CLI + GUI)
UEFITool firmware.bin                    # GUI: дерево FV -> FFS -> секции
UEFIExtract firmware.bin                 # CLI: извлечь всё в out/
uefi-firmware-parser -e firmware.bin -o out/
binwalk -e firmware.bin                  # быстрый поиск вложенных образов

# Прошивка/поиск
chipsec_main.py                          # CHIPSEC: аудит платформы
```

`UEFITool` — стандарт де-факто: он показывает дерево и позволяет извлечь любой модуль в виде `.efi` (PE-подобный образ). `UEFIExtract` делает то же из командной строки, что удобно для скриптов.

## Разбор модуля DXE в Ghidra

EFI-модули — это PE-образы (архитектура x86-64, подтип EFI). Ghidra/IDA загружают их как PE:

```bash
# Извлечь модуль и открыть
UEFIExtract firmware.bin
strings -a module.efi | grep -iE "Protocol|Guid|Boot|SecureBoot|gBS"
# В Ghidra: File -> Import -> module.efi (Auto-detect PE), Auto Analyze
```

Что искать в модуле:

- **Entry point**: `_ModuleEntryPoint` / `EFI_DRIVER_ENTRY_POINT` — точка входа драйвера.
- **Протоколы**: `gBS->LocateProtocol`, `InstallProtocolInterface`, `OpenProtocol` — взаимодействие с сервисами.
- **NVRAM**: `GetVariable`/`SetVariable`/`GetNextVariableName` — чтение/запись переменных (частая зона уязвимостей).
- **Строки**: GUID'ы, имена протоколов, сообщения об ошибках (`ASSERT`).

GUID модуля можно сопоставить с известными (например, `EFI_SECURE_BOOT_...`) — это сразу называет назначение.

## SMM: ring -2

**SMM (System Management Mode)** — режим с самой высокой привилегией, недоступный ОС и гипервизору. Код SMM выполняется по **SMI** (System Management Interrupt):

- **SMI handlers** — обработчики; ОС не видит их выполнение (прозрачны для всех остальных уровней).
- Уязвимости SMM (переполнения буферов, доверие данным из ОС) — крайне опасны: эксплуатация даёт ring -2 и полный обход защит ОС.
- Анализ сложнее: нужны дампы SMRAM, инструменты вроде `chipsec`, Ghidra с ручной разметкой. Модули SMM имеют тип `EFI_SMM_...`.
- Типовые баги: неверная валидация `CommBuffer` из `EFI_SMM_COMMUNICATE`, целочисленные переполнения при расчёте размеров.

## Secure Boot и NVRAM

Secure Boot проверяет подписи загрузчиков по цепочке доверия из NVRAM:

| Переменная | Роль |
|------------|------|
| `PK` | Platform Key (корень доверия) |
| `KEK` | Key Exchange Key |
| `db` | разрешённые подписи (whitelist) |
| `dbx` | запрещённые (blacklist) |
| `SetupMode` | режим настройки (без PK) |

Реверс Secure Boot — это анализ DXE-драйвера, который проверяет `db`/`dbx` при загрузке образа (`LoadImage`). Bootkit обходит это, патча формулировки проверки или сам модуль (что ломает подпись прошивки — детектируется измерением PCR/TXT).

## Bootkit-техники

- **Патч DXE-модуля.** Модификация модуля проверки Secure Boot прямо в прошивке для обхода подписи.
- **UEFI-имплант (LoJax-класс).** Персистентный код в SPI, переживает переустановку ОС; может пропатчить загрузчик ОС на лету.
- **Перехват `ExitBootServices`.** Вмешательство в момент передачи управления ОС — идеальная точка для инжекции в загрузчик/ядро.
- **SPI write protection.** Обход/отключение аппаратной защиты от записи (BIOS Write Enable, PRR) — иначе прошивку не изменить.
- **Bootkit в NVRAM.** Хранение полезной нагрузки в неиспользуемых переменных NVRAM.

## Разобранный пример: анализ DXE-модуля end-to-end

**Шаг 1. Дамп прошивки.**

```bash
flashrom -p ch341a_spi -r firmware.bin
```

**Шаг 2. Разбор структуры.**

```bash
UEFIExtract firmware.bin          # извлечь все модули в firmware.bin.dump/
UEFITool firmware.bin             # GUI: дерево FV/FFS/модули
```

**Шаг 3. Найти интересующий модуль.** Ищите по строкам `SecureBoot`, `Setup`, GUID'ам.

```bash
strings -a firmware.bin.dump/*/*.efi | grep -iE "SecureBoot|dbx|LoadImage"
```

**Шаг 4. Анализ в Ghidra.** EFI-модули — PE-подобные (x86-64); загрузите как PE, найдите entry point.

```bash
strings -a module.efi | grep -iE "Protocol|Guid|Boot|SecureBoot"
```

**Шаг 5. Искать уязвимости.** Проверьте обработку NVRAM-переменных (`GetVariable`), границы буферов, доверие к данным из ОС.

```text
1) flashrom -> полный дамп SPI.
2) UEFIExtract -> дерево FV/FFS.
3) Выбрать DXE-модуль (Secure Boot / Setup / драйвер ввода).
4) Ghidra (PE x86-64) -> entry point, протоколы, GetVariable.
5) Найти переполнение/доверие NVRAM -> сопоставить с bootkit-техникой.
```

## Инструменты

| Инструмент | Назначение |
|------------|------------|
| `flashrom` | дамп/запись SPI |
| `UEFITool`/`UEFIExtract` | разбор FV/FFS, извлечение модулей |
| `uefi-firmware-parser` | парсинг прошивок (Python) |
| `binwalk` | поиск вложенных образов |
| Ghidra/IDA | дизасм/декомпиляция EFI-модулей |
| `CHIPSEC` | аудит платформы, SPI, SMM |
| `chipsec_util smm` | анализ SMM |

## Безопасность: не «окирпичить» устройство

- Работайте с **дампом/копией**, а не с реальной прошивкой. Запись неверного образа делает плату неработоспособной.
- Если нужно прошить — используйте программатор с возможностью восстановления (внешний CH341A + бэкап), а не только software flash.
- Проверяйте целостность дампа (полный размер, дескриптор) до любых модификаций.
- Для SMM/SPI-тестов — только специальные стенды/платформы с recovery.

## Частые ошибки

- **Неверный/неполный дамп.** Нужен полный образ SPI (с дескриптором), иначе структура не разберётся.
- **Путать FV/FFS/PE.** Это разные уровни вложенности: Volume -> File -> Section -> PE.
- **Игнорировать SMM.** Самый привилегированный код и частая зона уязвимостей.
- **Ожидать обычный PE.** EFI-модули имеют свои конвенции (entry point, сервисы `gBS`/`gRT`).
- **Не учитывать Secure Boot.** Модификация прошивки ломает подпись/загрузку — детектируется.
- **Опасность брика.** Не пишите в реальную прошивку без recovery.
- **Забыть про ME/EC-регионы.** Часть логики и бэкдоров может быть вне BIOS-региона.

## Что делать дальше / решение

1. Снимите полный дамп SPI (`flashrom -r`) и сохраните бэкап.
2. Разберите структуру (`UEFIExtract`/`UEFITool`): регионы -> FV -> FFS -> модули.
3. Определите назначение модулей по GUID и строкам; выберите цели (Secure Boot, Setup, SMM).
4. Загрузите модуль в Ghidra как PE, разберите entry point, протоколы, работу с NVRAM.
5. Ищите уязвимости (переполнения, доверие данным) и сопоставляйте с bootkit-техниками.
6. Для SMM — используйте CHIPSEC и дампы SMRAM; для записи — только с recovery-планом.

## Квиз

```quiz
- question: "Что такое DXE в UEFI?"
  options:
    - "Driver Execution Environment — фаза драйверов/сервисов"
    - "Формат файла"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "DXE — фаза инициализации драйверов/протоколов."
- question: "Какой инструмент разбирает UEFI-прошивки?"
  options:
    - "UEFITool"
    - "nm"
    - "ldd"
    - "gdb"
  answer: 0
  explanation: "UEFITool отображает FV/модули прошивки."
- question: "В каком режиме работает SMM?"
  options:
    - "Ring -2 (System Management Mode)"
    - "Ring 3"
    - "Ring 0"
    - "Ring -1"
  answer: 0
  explanation: "SMM — привилегированный режим ниже гипервизора."
- question: "Что делает UEFI-bootkit?"
  options:
    - "Персистентно патчит прошивку/обходит Secure Boot"
    - "Сканирует порты"
    - "Шифрует сеть"
    - "Сжимает данные"
  answer: 0
  explanation: "Bootkit живёт в прошивке и влияет на загрузку ОС."
- question: "Почему опасно писать в реальную прошивку?"
  options:
    - "Можно 'окирпичить' устройство"
    - "Это медленно"
    - "Это не влияет"
    - "Это необратимо только для ОС"
  answer: 0
  explanation: "Неверная запись в SPI делает устройство неработоспособным."
```

## Где пригодится

- **CTF:** Reversing (expert) — firmware-задачи.
- **Firmware security:** анализ прошивок.
- **Bootkit analysis:** UEFI-импланты.
- **Работа:** hardware security.
