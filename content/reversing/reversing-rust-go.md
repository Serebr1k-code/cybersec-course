---
id: reversing-rust-go
title: "Реверс Rust и Go бинарников"
category: reversing
parent: reversing-static-tools
difficulty: hard
order: 4
tags: [reversing, rust, golang, symbols, goroutines, monomorphization]
prerequisites: [reversing-static-analysis]
useful_for:
  - "CTF Reversing (hard)"
  - "Malware analysis (Go/Rust)"
  - "Анализ современного ПО"
estimated_minutes: 50
summary: "Особенности компиляции Rust и Go: мономорфизация, статическая линковка, Go-символы и goroutines."
---
**Реверс Rust и Go бинарников** — отдельная дисциплина: эти языки компилируются в нативный код, но с богатыми метаданными, мономорфизацией и необычным ABI. Обычный IDA/Ghidra без подготовки тонет в «мусоре» из std-библиотеки. Урок даёт полный workflow: как восстанавливать имена Go-функций (pclntab), как разбирать Rust-мономорфизацию и mangling, какие инструменты использовать и два разобранных примера.

## Особенности Rust/Go

- **Статическая линковка std.** Огромный объём кода из std/runtime «разбавляет» вашу функцию.
- **Мономорфизация (Rust).** Дженерики разворачиваются в отдельные функции с манглированными именами.
- **Go runtime.** Goroutines, scheduler, GC — своя модель исполнения и ABI (регистры + стек).
- **Богатые метаданные.** Go хранит `pclntab` с именами функций; Rust — mangling (`_ZN...`/`_R...`).
- **Паники.** Обработка ошибок через `panic!`/`unwrap` — видны по строкам.

## Go: символика и pclntab

Go-бинарники обычно **не стриппятся полностью**: в секции `pclntab` лежит таблица с именами функций, файлов и строк. Именно её используют инструменты для восстановления имён.

```bash
file ./gobin
go version ./gobin        # определить версию Go
strings -a ./gobin | grep -m5 'go1\.'
```

Инструменты:

| Инструмент | Назначение | Команда |
|---|---|---|
| `go tool nm` | символы (если есть) | `go tool nm ./gobin` |
| `redress` | анализ Go-бинарников | `redress info ./gobin` |
| `GoReSym` | восстановление имён | `GoReSym -t ./gobin` |
| `golang_loader_assist` | IDA-плагин | GUI |
| `GoReSym`/`redress` | функции/типы | CLI |

```bash
redress info ./gobin
redress funcs ./gobin | grep -i main
GoReSym -t -d ./gobin -o gore.json
```

## Go: восстановление имён и анализ

```bash
# список функций main.*
redress funcs ./gobin | grep 'main\.'
# декомпиляция конкретной функции (через GoReSym + Ghidra loader)
GoReSym -t ./gobin > syms.txt
# затем в Ghidra: скрипт, применяющий syms.txt
```

Ghidra-плагин `golang` (или `GoReSym` loader) применяет имена автоматически. В IDA — `golang_loader_assist`. После этого виден реальный `main.main`, `main.checkFlag` и т.д.

## Rust: mangling и мономорфизация

Rust использует mangling в стиле Itanium (`_ZN...E`) или новый v0 (`_R...`). Деманглинг даёт полные пути с типами и дженериками.

```bash
nm ./rustbin | grep '_ZN' | head
echo '_ZN4core3fmt9Formatter3pad17h...E' | rustfilt
# или
c++filt -t _ZN4core3fmt9Formatter3pad17h...E
```

Инструменты: `rustfilt`, `rust-demangle`, в Ghidra — плагин для Rust-деманглинга. Мономорфизация означает, что `Vec<u8>::push` и `Vec<i32>::push` — **разные** функции с разными именами; ищите по префиксу типа.

## Rust: восстановление типов и паники

- **Паники**: строки `called \`Option::unwrap()\` on a \`None\`` и `index out of bounds` указывают на места проверок.
- **Типы**: деманглированные имена содержат полные типы (`alloc::vec::Vec<u8>`).
- **Trait-объекты**: динамическая диспетчеризация через vtable.
- **`Result`/`Option`**: разворачиваются в теги (discriminant) + union.

```bash
strings -a ./rustbin | grep -iE 'unwrap|panic|index out of bounds|RUST_BACKTRACE'
```

Установите `RUST_BACKTRACE=1` при запуске — получите имена функций в стеке, что ускоряет сопоставление.

## Разобранный пример: Go crackme

**Шаг 1. Определить Go.**

```bash
strings -a crackme | grep -m1 'go1\.'
redress info crackme | head
```

**Шаг 2. Найти main.**

```bash
redress funcs crackme | grep 'main\.'
# main.main, main.checkPassword
```

**Шаг 3. Применить имена в Ghidra** (GoReSym loader) и открыть `main.checkPassword`.

**Шаг 4. Разобрать логику.** Видим сравнение ввода с константой (или XOR-декодирование строки). Go-строки — это пары (ptr, len); читайте обе части.

**Шаг 5. Восстановить флаг.**

```bash
strings -a crackme | grep -iE 'flag\{|wrong|correct'
```

## Разобранный пример: Rust keycheck

**Шаг 1. Деманглировать символы.**

```bash
nm rustcheck | grep '_ZN' | rustfilt | grep -i main
# rustcheck::main
# rustcheck::verify
```

**Шаг 2. Открыть `verify`** в Ghidra/IDA, посмотреть сравнение байтов.

**Шаг 3. Найти панику** (маркер близости проверки).

```bash
strings -a rustcheck | grep -iE 'unwrap|assert'
```

**Шаг 4. Восстановить алгоритм** (XOR/сдвиги над вводом) и написать решатель на Python.

## Строки и goroutines

- **Go-строки** не null-terminated; это структура `{data *byte, len int}`. В дизассемблере ищите два подряд значения (указатель + длина).
- **Goroutines** видны как вызовы `runtime.newproc`/`runtime.goexit`; их анализ даёт параллельную логику.
- **Интерфейсы** — пара (type, data); вызовы через itab.

```bash
# найти имена горутин/функций
redress funcs ./gobin | grep -iE 'goroutine|runtime\.'
```

## Таблица инструментов

| Инструмент | Язык | Назначение |
|---|---|---|
| `redress` | Go | info/funcs/types/strings |
| `GoReSym` | Go | восстановление имён из pclntab |
| `golang_loader_assist` | Go | IDA-плагин |
| `rustfilt` | Rust | деманглинг |
| `Ghidra + rust plugin` | Rust | деманглинг/типы |
| `go tool nm` | Go | символы |

## Частые ошибки и подводные камни

- **Стриппинг.** Полностью стриппленный Go теряет часть метаданных; используйте GoReSym (работает по pclntab).
- **Мономорфизация.** Не путайте одинаковые по имени, но разные по типу функции.
- **Go ABI.** Аргументы передаются не только через регистры — учитывайте стековую модель Go.
- **Rust v0 mangling.** Старые инструменты не понимают `_R`-схему; обновляйте `rustfilt`/плагины.
- **Объём std.** Не анализируйте std целиком — фильтруйте по `main`/вашим символам.
- **Паника как подсказка.** Строки `unwrap`/`index out of bounds` часто отмечают проверки.

## Что дальше / решение

Маршрут: **определить язык/версию → восстановить имена (redress/GoReSym/rustfilt) → применить в Ghidra/IDA → разобрать main-логику → написать решатель**. Для Go ключ — `pclntab`; для Rust — mangling и мономорфизация. Дальше — `reversing-go-advanced`, `reversing-rust-advanced` и `reversing-keygen`.

## Go: разбор типов, интерфейсов и структур

Go-типы описаны в метаданных (`runtime._type`, `runtime.itab`), что позволяет восстанавливать структуры.

- **Интерфейс** — пара (itab, data); `itab` содержит указатель на тип и таблицу методов.
- **Структуры** — из метаданных видно поля и смещения; `redress types` выводит определения.
- **Срезы** — `{ptr, len, cap}` (три слова).
- **Мапы** — `runtime.hmap`.

```bash
redress types ./gobin | head -40
redress interfaces ./gobin
```

Зная раскладку, вы читаете поля структуры в дизассемблере как смещения (`[rbx+0x18]`), а не как «магию». Для функций, работающих с интерфейсами, ищите косвенные вызовы через itab.

## Rust: мономорфизация и размер бинарника

Дженерики Rust разворачиваются в отдельные функции для каждого конкретного типа. Это раздувает бинарник и создаёт «клоны» логики.

```bash
nm ./rustbin | rustfilt | grep 'Vec<u8>::push'
nm ./rustbin | rustfilt | grep 'Vec<i32>::push'
# разные символы — разные функции
```

При анализе ищите **ваш** тип; остальное — std. Для ускорения: применяйте деманглинг-плагин и фильтруйте по префиксу модуля (`myapp::`).

## Практика: решатель на Python для Go/Rust

После восстановления алгоритма напишите решатель независимо от языка.

```python
# пример: XOR-декодирование строки Go-бинарника
enc = bytes.fromhex("0e1a1a0d")   # из дампа
key = 0x6d
print(bytes(b ^ key for b in enc))
# b'flag'
```

Для Rust — воспроизведите логику из `verify` (сдвиги, сравнения) на Python и подберите вход. Проверяйте на реальном бинарнике.

## Стриппинг и восстановление после него

- **Go**: даже стриппленный бинарник часто сохраняет `pclntab` (GoReSym работает).
- **Rust**: при стриппинге теряются имена — ориентируйтесь на паники, строки, размеры функций.
- **Восстановление**: сопоставляйте функции по вызываемым API/строкам/константам.
- **Отладочная информация**: если есть `.debug_info` (DWARF) — используйте её напрямую.

```bash
readelf -S ./bin | grep -i debug     # есть ли DWARF
```

## Чеклист реверса Rust/Go

1. Определить язык и версию (`go version`, строки).
2. Восстановить имена (redress/GoReSym/rustfilt) и применить в Ghidra/IDA.
3. Отфильтровать `main`/ваш модуль от std.
4. Разобрать ключевую функцию (Go: строки-пары; Rust: типы из mangling).
5. Найти проверки по строкам паник/ошибок.
6. Написать решатель на Python и проверить.

## Go: goroutines, каналы и параллельная логика

Go-бинарники активно используют горутины; логика может быть размазана по нескольким.

- **`runtime.newproc`/`runtime.goexit`** — создание/завершение горутины.
- **Каналы** — `runtime.chansend`/`chanrecv`; синхронизация.
- **`sync.Mutex`** — блокировки.

```bash
redress funcs ./gobin | grep -iE 'runtime\.(newproc|goexit|chansend)'
```

Если main-функция запускает горутину, которая и делает проверку, статический анализ `main.main` её не покажет — идите по `newproc` к целевой функции.

## Rust: обработка ошибок как карта логики

Rust-код пронизан `Result`/`Option`, и паники отмечают границы проверок. Каждый `unwrap()` — потенциальное место, где ожидается корректное значение; `assert!`/`assert_eq!` — явные проверки.

```bash
strings -a ./rustbin | grep -iE 'assert|unwrap|expect'
```

Сопоставив строку паники с функцией (через xref), вы быстро находите условия, которые нужно удовлетворить для «успеха».

## Сравнение инструментов Go и Rust

| Задача | Go | Rust |
|---|---|---|
| Восстановление имён | GoReSym/redress | rustfilt + плагин |
| Типы | `redress types` | mangling + DWARF |
| Паники | строки runtime | `panic!`/`unwrap` |
| ABI | регистры+стек | System V/ARM64 |
| Runtime | goroutines/GC | no GC, но std большой |

## Итоговый маршрут

Определите язык → восстановите имена → отфильтруйте `main`/ваш модуль → разберите проверку → напишите решатель на Python → проверьте на бинарнике. Для Go опирайтесь на `pclntab`; для Rust — на mangling и паники.

## Квиз

```quiz
- question: "Как определить, что бинарник написан на Go?"
  options:
    - "По секции `.rodata`"
    - "По `Go BuildID` / `gopclntab` / строкам `runtime.`"
    - "По наличию `main`"
    - "По `checksec`"
  answer: 1
  explanation: "`Go BuildID`, `gopclntab`, `runtime.*` — признаки Go."
- question: "Как восстановить имена функций в stripped Go-бинаре?"
  options:
    - "`strings` недостаточно — нужен GoReSym/redress"
    - "`nm` покажет всё"
    - "`upx -d`"
    - "`readelf -s`"
  answer: 0
  explanation: "Символы восстанавливаются из `gopclntab` инструментами вроде GoReSym."
- question: "Как деманглить Rust-имена?"
  options:
    - "`rustfilt`"
    - "`strings`"
    - "`upx`"
    - "`javap`"
  answer: 0
  explanation: "`rustfilt` деманглирует `_ZN`/`_R` имена."
- question: "Где точка входа Rust-программы?"
  options:
    - "`main`"
    - "`std::rt::lang_start`, который вызывает `main`"
    - "`_start` без рантайма"
    - "`rust_init`"
  answer: 1
  explanation: "Рантайм Rust стартует через `lang_start`."
- question: "Что такое мономорфизация в Rust?"
  options:
    - "Шифрование строк"
    - "Разворачивание дженериков в отдельные функции под каждый тип"
    - "Упаковка бинарника"
    - "Обфускация потока"
  answer: 1
  explanation: "Дженерики компилируются в специализированные копии."
```

## Где пригодится

- **CTF Reversing (hard):** Rust/Go-задачи всё чаще встречаются; нужны специфичные инструменты.
- **Malware analysis:** современные образцы (RAT, ransomware) пишут на Go/Rust ради обхода
  сигнатур; анализ требует Go-плагинов.
- **Аудит современного ПО:** CLI-утилиты и сервисы на Rust/Go — частый объект анализа.
- **Bug bounty:** поиск логических багов в Go/Rust-сервисах.
- **Собес:** вопросы про Go-символы, Rust demangling, мономорфизацию — маркер современного RE.
