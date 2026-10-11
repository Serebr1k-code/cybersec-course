---
id: reversing-pe-deep
title: "PE изнутри: RVA, импорты и ресурсы"
category: reversing
parent: reversing-mod-file-formats
difficulty: medium
order: 4
tags: [reversing, pe, windows, pefile, imports, rva]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: Windows crackme"
  - "Malware analysis: анализ PE-образцов"
  - "Vuln research: экспорт, релокации, TLS-колбэки"
estimated_minutes: 55
summary: "Полный разбор Portable Executable: DOS/COFF/optional-заголовки, RVA, таблицы импорта/экспорта, ресурсы, TLS-колбэки, релокации и практический анализ через pefile и dumpbin."
---

Portable Executable (PE) — формат исполняемых файлов, объектных модулей и DLL в Windows. Он
наследует идеи COFF и заметно отличается от ELF: вместо сегментов здесь секции, вместо виртуальных
адресов — RVA, а точка входа и база образа задаются в «optional»-заголовке (который на самом деле
обязателен для образов). Понимание PE — обязательный навык для анализа Windows-малвари и crackme.

## Общая структура PE

PE-файл начинается с DOS-заголовка (`IMAGE_DOS_HEADER`), который ради совместимости содержит
магию `MZ` и поле `e_lfanew` — смещение до настоящего PE-заголовка. Дальше идут: сигнатура `PE\0\0`,
COFF-заголовок (`IMAGE_FILE_HEADER`), optional-заголовок (`IMAGE_OPTIONAL_HEADER`, 32/64-битный),
таблица секций (`IMAGE_SECTION_HEADER`) и сами секции. Такой «DOS-стаб» в начале — историческое
наследие: если запустить PE под DOS, он печатает «This program cannot be run in DOS mode».

COFF-заголовок содержит число секций, временную метку компиляции, размер optional-заголовка и
характеристики (например, `IMAGE_FILE_DLL` для библиотек, `IMAGE_FILE_EXECUTABLE_IMAGE`). Временная
метка (`TimeDateStamp`) — важная зацепка в malware-анализе: она часто выдаёт дату сборки, а
некоторые упаковщики оставляют её нулевой.

## Optional-заголовок: RVA, база, точка входа

Несмотря на название, optional-заголовок обязателен для образов. Ключевые поля:

- **AddressOfEntryPoint** — RVA точки входа (для DLL это `DllMain`, для EXE — CRT-стаб).
- **ImageBase** — предпочтительная база загрузки (для EXE обычно `0x400000` или `0x140000000`).
- **SectionAlignment / FileAlignment** — выравнивание в памяти и в файле.
- **Subsystem** — GUI (`2`) или консоль (`3`).
- **DllCharacteristics** — флаги защиты: ASLR (`DYNAMIC_BASE`), DEP (`NX_COMPAT`), CFG, высокие
  энтропийные адреса.

**RVA (Relative Virtual Address)** — смещение относительно базы образа. Чтобы получить абсолютный
адрес, нужно прибавить фактическую базу (`ImageBase` при отсутствии ASLR или реальную базу после
загрузки). Это ключевое отличие от ELF: в PE вы почти всегда работаете с RVA, а не с файловыми
смещениями. Пересчёт RVA в файловое смещение делается через таблицу секций: находим секцию, в чей
диапазон `[VirtualAddress, VirtualAddress+VirtualSize)` попадает RVA, и прибавляем `PointerToRawData
- VirtualAddress`.

## Секции PE

Типовые секции: `.text` (код), `.rdata` (read-only данные, в т.ч. импорты), `.data` (данные),
`.rsrc` (ресурсы), `.reloc` (релокации), `.tls` (TLS). Права секции кодируются в
`Characteristics` (`IMAGE_SCN_MEM_READ/WRITE/EXECUTE`). Подозрительно, когда `.text` одновременно
writable и executable, или когда имя секции нестандартно (`.upx0`, `.vmp0`, случайный мусор) —
признак упаковки.

Важное отличие от ELF: в PE секции в файле выровнены по `FileAlignment` (обычно 512 байт), а в
памяти — по `SectionAlignment` (обычно 4096). Поэтому размеры в файле и в памяти различаются, и при
ручном чтении нельзя просто «умножить RVA на 1».

## Таблицы импорта и экспорта

Таблица импорта (`IMAGE_DIRECTORY_ENTRY_IMPORT`) описывает, какие функции из каких DLL использует
модуль. Для каждой DLL есть `IMAGE_IMPORT_DESCRIPTOR` с указателями на массив `OriginalFirstThunk`
(имена) и `FirstThunk` (адреса, заполняемые загрузчиком). Это PE-аналог GOT: `FirstThunk` — массив
указателей, которые загрузчик перезаписывает адресами функций. Именно поэтому перезапись IAT
(Import Address Table) — классическая техника перехвата.

Таблица экспорта (`IMAGE_DIRECTORY_ENTRY_EXPORT`) есть у DLL: перечисляет имена функций, их
ordinals и RVA. При анализе важно смотреть на имена импортируемых функций: `VirtualAllocEx`,
`WriteProcessMemory`, `CreateRemoteThread`, `InternetOpenUrl` — характерные индикаторы инъекций и
сетевой активности.

## Ресурсы, TLS и отладочные данные

Ресурсы (`IMAGE_DIRECTORY_ENTRY_RESOURCE`) — дерево директорий с иконками, манифестами, строками и
произвольными бинарными данными. Малварь часто прячет в ресурсах вторую стадию или конфигурацию:
проверяйте `RT_RCDATA`-записи. TLS-директория (`.tls`) позволяет задавать колбэки, исполняемые до
точки входа — тот же трюк, что `.init_array` в ELF, и частое место сокрытия анти-отладочных
проверок. Отладочная директория хранит путь к PDB; иногда там остаётся информация о среде сборки.

## Практический разбор: pefile и dumpbin

Идентификация:

```
$ python3 -c "import pefile; pe=pefile.PE('sample.exe'); print(hex(pe.OPTIONAL_HEADER.ImageBase), hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), pe.FILE_HEADER.NumberOfSections)"
0x140000000 0x1a4b0 6

$ python3 -c "import pefile; pe=pefile.PE('sample.exe'); [print(s.Name.decode().rstrip(chr(0)), hex(s.VirtualAddress), s.Characteristics) for s in pe.sections]"
.text 0x1000 1610612768
.rdata 0xb000 1073741888
.data 0xc000 3221225536
.rsrc 0xe000 1073741888
```

`Characteristics` 0x60000020 = `CODE|EXECUTE|READ`, а 0xC0000040 = `INITIALIZED_DATA|READ|WRITE`.
Если увидите `WRITE|EXECUTE` вместе — это красный флаг.

Импорты:

```
$ python3 -c "import pefile; pe=pefile.PE('sample.exe'); [print(e.dll.decode()) or [print('  ', i.name) for i in e.imports if i.name] for e in pe.DIRECTORY_ENTRY_IMPORT]"
KERNEL32.dll
   VirtualAllocEx
   WriteProcessMemory
   CreateRemoteThread
ADVAPI32.dll
   RegOpenKeyExW
```

Такой набор импортов почти наверняка означает инъекцию в чужой процесс. Если PE собран как DLL,
смотрим экспорты:

```
$ python3 -c "import pefile; pe=pefile.PE('lib.dll'); [print(hex(e.address), e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]"
0x1230 DllRegisterServer
0x1400 RunPayload
```

## Типичные CTF-сценарии и краевые случаи

- **Упакованные PE**: `UPX!` в имени секции, `AddressOfEntryPoint` указывает в `.upx1`; лечится
  `upx -d`.
- **Испорченный `e_lfanew`**: некоторые инструменты падают; pefile обычно справляется.
- **Обфусцированные импорты**: имена функций скрыты, резолвятся вручную через `GetProcAddress` по
  хешам. Ищите `LoadLibrary`/`GetProcAddress` и хеш-константы.
- **Delphi/C++ сборки**: тысячи маленьких функций, RTTI-строки, свои соглашения вызова.
- **.NET**: PE с заголовком `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` — анализируется в dnSpy, а не в
  IDA.

## Инструменты и флаги

| Задача | Инструмент |
|---|---|
| Общий разбор | `pefile` (Python), `dumpbin /headers`, `rabin2 -I` |
| Импорты | `dumpbin /imports`, `pefile.DIRECTORY_ENTRY_IMPORT` |
| Экспорты | `dumpbin /exports`, `pefile.DIRECTORY_ENTRY_EXPORT` |
| Ресурсы | `Resource Hacker`, `pefile.DIRECTORY_ENTRY_RESOURCE` |
| Дизассемблер | IDA, Ghidra, x64dbg, `objdump -d` (MinGW) |
| Строки | `strings -el`, FLOSS |
| Упаковка | `Detect It Easy (DIE)`, PEiD |

## Ручной разбор: RVA → файловое смещение

Предположим, вы нашли в дизассемблере строку по RVA `0x2A10` и хотите увидеть её в файле. Сначала
определите, в какую секцию попадает RVA. Пусть таблица секций такая:

| Секция | VirtualAddress | VirtualSize | PointerToRawData | SizeOfRawData |
|---|---|---|---|---|
| .text | 0x1000 | 0x8000 | 0x400 | 0x8000 |
| .rdata | 0x9000 | 0x2000 | 0x8400 | 0x2000 |
| .data | 0xB000 | 0x1000 | 0xA400 | 0x1000 |

RVA `0x2A10` лежит в диапазоне `.text` (`0x1000..0x9000`). Файловое смещение считается как
`PointerToRawData + (RVA - VirtualAddress)` = `0x400 + (0x2A10 - 0x1000)` = `0x400 + 0x1A10` =
`0x1E10`. Именно по этому смещению строка лежит в файле. Если же RVA попадает в диапазон, которого
нет ни в одной секции, значит ссылка битая или указывает в неинициализированную память — это
само по себе интересный сигнал.

Обратный пересчёт (из файлового смещения в RVA) используется при патчинге: вы находите нужный байт
в hex-редакторе и должны понять, какой RVA ему соответствует, чтобы IDA показала то же место.

## Обфускация импортов и API-хеши

Простой список импортов — золотая жила для аналитика, поэтому злоумышленники его прячут. Типовые
приёмы:

- **Динамический резолв**: в импортах есть только `LoadLibraryA` и `GetProcAddress`, а имена
  нужных функций передаются строками (иногда зашифрованными). Ищите вызовы этих двух функций и
  трассируйте их аргументы.
- **API-хеши**: имя функции превращают в хеш (CRC32, djb2, ROR13) и сравнивают с константой, а
  адрес получают перебором экспортов. Восстановить соответствие можно таблицей хешей или скриптом.
- **Строковое шифрование**: строки зашифрованы и расшифровываются на лету; помогает FLOSS или
  эмуляция участка расшифровки.
- **Разбор PEB**: через `fs:[0x30]` (32-bit) или `gs:[0x60]` (64-bit) находят `PEB->Ldr` и вручную
  обходят список загруженных модулей, не используя `GetModuleHandle`. Это продвинутая техника, и
  её наличие — сильный индикатор вредоносности.

## Сравнение PE и ELF

Полезно держать в голове соответствия, чтобы быстро переносить знания между платформами. Точка
входа в ELF — `e_entry`, в PE — `AddressOfEntryPoint`. Адресация в ELF идёт через виртуальные
адреса, в PE — через RVA. Таблица внешних вызовов в ELF — GOT/PLT, в PE — IAT. Инициализаторы в
ELF — `.init_array`, в PE — TLS-колбэки. Загрузчик в ELF — `ld-linux`, в PE — `ntdll` + loader.
Защита адресного пространства — ASLR (флаг `DYNAMIC_BASE`), защита стека — NX (`NX_COMPAT`).

| Понятие | ELF | PE |
|---|---|---|
| Точка входа | `e_entry` (`_start`) | `AddressOfEntryPoint` |
| Адресация | виртуальный адрес | RVA + ImageBase |
| Внешние вызовы | GOT/PLT | IAT |
| Инициализаторы | `.init_array` | TLS callbacks |
| Релокации | `.rela.*` | `.reloc` |
| Символы | `.symtab`/`.dynsym` | COFF symbols / PDB |

## Подводные камни

Первое: RVA ≠ файловое смещение; путать их — самая частая ошибка. Второе: `SizeOfImage` не равен
сумме размеров секций из-за выравнивания. Третье: в 64-битных PE `ImageBase` по умолчанию
`0x140000000`, и младшие адреса недействительны. Четвёртое: `AddressOfEntryPoint` для DLL — это
`DllMain`, который может вызываться многократно. Пятое: импорты могут быть «зашиты» (bound imports)
или разрешаться вручную, и тогда таблица пуста.

## Что дальше / решение

Практика: возьмите любой системный `notepad.exe`, разберите его pefile-скриптом, найдите точку
входа, список DLL, экспорты (если DLL). Затем откройте образец с `Detect It Easy` и определите,
упакован ли он. Для закрепления сравните PE и ELF по понятиям: RVA против виртуального адреса,
IAT против GOT, TLS-колбэки против `.init_array`. Дальше — `reversing-sections-segments` и
`reversing-windows-debuggers` для практической отладки.

## Квиз

```quiz
- question: "Что хранит поле e_lfanew в DOS-заголовке?"
  options:
    - "Смещение до PE-заголовка"
    - "Размер образа"
    - "Точку входа"
    - "Число секций"
  answer: 0
- question: "Что такое RVA?"
  options:
    - "Смещение относительно базы образа"
    - "Абсолютный виртуальный адрес"
    - "Файловое смещение"
    - "Индекс секции"
  answer: 0
- question: "Какую структуру перезаписывает загрузчик адресами импортируемых функций?"
  options:
    - "IAT (FirstThunk)"
    - "DOS-заголовок"
    - ".reloc"
    - ".rsrc"
  answer: 0
- question: "Что может означать секция с правами WRITE+EXECUTE?"
  options:
    - "Признак упаковки или самомодифицирующегося кода"
    - "Нормальное состояние любой секции"
    - "Отладочные символы"
    - "Ресурсы"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** Windows crackme, обфусцированные импорты, скрытые ресурсы.
- **Malware analysis:** определение упаковщика, характерных импортов, второй стадии в ресурсах.
- **Vuln research:** анализ экспортов, TLS-колбэков, перезаписи IAT.
