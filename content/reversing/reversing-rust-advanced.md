---
id: reversing-rust-advanced
title: "Rust advanced: мономорфизация, panic и runtime"
category: reversing
parent: reversing-rust-go
difficulty: hard
order: 2
tags: [reversing, rust, monomorphization, panic, llvm, mangling]
prerequisites: [reversing-rust-go, reversing-static-analysis]
useful_for:
  - "CTF Reversing"
  - "Анализ Rust-малвари"
  - "Bug bounty (Rust-сервисы)"
estimated_minutes: 60
summary: "Глубокий реверс Rust: демаглинг, мономорфизация, обработка panic, распознавание идиом std/core."
---
Rust-бинари сложны для реверса по нескольким причинам: **мономорфизация** (generic-функции дублируются под каждый конкретный тип), **манглинг** имён с хеш-суффиксами, развёрнутая обработка `panic`/`Result`, агрессивный inline, и большой объём кода рантайма (`core`, `alloc`, `std`). Понимание этих особенностей резко ускоряет анализ и превращает «нечитаемую кашу» в структурированную картину. Этот урок — практические приёмы реверса Rust от демаглинга до распознавания идиом стандартной библиотеки.

## Манглинг и демаглинг

Rust применяет **v0-манглинг** (современный, с префиксом `_R`) или legacy (`_ZN...E`, как у C++ Itanium ABI). Имена выглядят так:

```text
_ZN4core3fmt9Formatter3pad17h8b4a3c1d2e5f6a7bE
_RNvCs8f...  (v0)
```

Демаглинг раскрывает путь модуля, тип и хеш:

```bash
nm -C ./binary | head                    # -C автоматически демаглит (если nm поддерживает Rust)
c++filt _ZN4core3fmt9Formatter3pad17h8b4a3c1d2e5f6a7bE
# rustfilt — надёжнее для v0 и legacy
nm ./binary | rustfilt | head
rustfilt -i symbols.txt
```

Если `rustfilt` не установлен: `cargo install rustfilt`. В Ghidra есть встроенный Rust-демаглер (`Demangler` → Rust) и плагины вроде `ghidra-rust`; IDA использует `rust`-демаглер из коробки (Alt+F1 после выделения).

## Мономорфизация: почему функций так много

Generic-функции компилируются **отдельно для каждого типа**:

```rust
fn max<T: Ord>(a: T, b: T) -> T { if a > b { a } else { b } }
// В бинаре появятся: max::<i32>, max::<u64>, max::<String>, max::<&str> ...
```

Следствия для реверса:

- Много **почти идентичных** функций — это не разные алгоритмы, а копии одного generic-кода под разные типы.
- Размер бинаря растёт, `main` «размазан» по вызовам.
- Приём: найдите «семейство» по похожей структуре (тот же CFG, отличия только в размере элемента), разберите **одну** и распространите понимание на остальные.

Иногда мономорфы различимы по константам: копия для `u64` использует 8-байтовые операции, для `String` — вызовы `alloc::string`.

## Panic, unwind и Result

Обработка ошибок в Rust порождает много «шумового» кода:

- **`panic!`** разворачивает стек (`unwind`, через `core::panicking::panic_fmt`) либо мгновенно завершает процесс (`abort`). В release часто `panic=abort` — тогда нет таблиц разворачивания.
- **`Result<T,E>` и оператор `?`** — на каждом шаге ветвление «успех/ошибка» и ранний `return`.
- **`unwrap()`/`expect()`** — точка «жёсткого» падения при `None`/`Err`; часто содержит строку с именем файла и номером строки.
- **`assert!`/`debug_assert!`** — проверки; в release `debug_assert` вырезается.

Приём: `panic`/`Result`-ветки — это **шум**. Ищите «happy path»: основную логику, где значения обрабатываются при корректном вводе. Строки panic-сообщений (`panicked at src/main.rs:42`) бесценны — они прямо указывают исходный файл и строку.

## Идиомы std/core, которые надо узнавать

| Конструкция | Представление в памяти | Как узнать |
|-------------|------------------------|------------|
| `Option<T>` | `enum`: дискриминант + payload; для `&T`/`Box` — niche-оптимизация (null = None) | проверка указателя на 0, условный jump |
| `Vec<T>` | трёхсловный дескриптор: `ptr`, `len`, `cap` | `alloc::vec::Vec`, три поля рядом, realloc при росте |
| `String` | как `Vec<u8>`, гарантированно UTF-8 | `alloc::string::String`, вызовы `push_str` |
| `&str`/`&[T]` | пара `ptr` + `len` (fat pointer) | два регистра на аргумент |
| `Iterator` | цепочки `map`/`filter` инлайнятся в цикл | развёрнутые циклы без явных вызовов |
| `format!`/`Display` | вызовы `core::fmt::write`/`Formatter` | ссылки на `core::fmt::*` |
| `drop` | деструкторы в конце scope и при unwind | вызовы `drop_in_place` |
| `Box<T>` | единственный указатель | `alloc::boxed` |

Bounds-check у `Vec`/срезов генерирует проверку и `panic_bounds_check` — это не «проверка пароля», а защита памяти. Не путайте её с логикой валидации.

## Практический workflow

```text
1) Демаглинг: nm -C / rustfilt -> осмысленные имена (если не stripped).
2) Поиск main: panic-строки, env::args, std::rt::lang_start, ссылки на main.
3) Игнорируйте panic/Result-ветки — фокус на happy path.
4) Распознавайте std-идиомы (Vec/Option/Iterator/format).
5) Для stripped — по строкам: panic-сообщения содержат имена файлов/функций.
6) Динамика (gdb) для проверки гипотез о проверках ввода.
```

```bash
# Найти main и ключевые функции
nm -C ./binary | grep -E "::main|::run|::new|::check"
# Строки с именами типов/функций (panic-сообщения)
strings -a ./binary | grep -E "panicked at|src/|\.rs:"
# Точка входа рантайма
nm -C ./binary | grep -E "lang_start|std::rt"
```

## Разобранный пример: stripped Rust-crackme

```bash
# 1) Бинарь stripped — символов нет
file ./crackme && nm ./crackme 2>&1 | head
# nm: ./crackme: no symbols

# 2) Ищем panic-строки — они переживают strip
strings -a ./crackme | grep -iE "panicked|assert|invalid|password|flag"
# panicked at src/main.rs:57:
# Invalid password

# 3) В Ghidra: Search -> For Strings -> "Invalid password"
#    XREF на строку -> функция check_password; рядом ветвление
# 4) Демаглим ближайшие функции (Ghidra Rust demangler)
# 5) Восстанавливаем алгоритм: видим цикл с XOR константой и сравнение
```

В Ghidra ориентируйтесь по `core::fmt`/`alloc::vec` для навигации по рантайму и по `std::io::stdio` для точек ввода. Проверка пароля почти всегда стоит **между** чтением ввода (`stdin`) и строкой успеха/ошибки.

## Строки, форматы и аргументы

- `env::args()` — доступ к аргументам командной строки; ищите `std::env::args`.
- `format!`-строки лежат в `.rodata` в виде `{}`-шаблонов — рядом с ними ищите логику подстановки.
- `String::from`, `to_string`, `parse::<i32>()` — точки преобразования ввода; `parse` возвращает `Result` (часто `unwrap`).
- Для Go-подобной ориентации: Rust-бинарники не содержат Go runtime-строк, но содержат много `core::fmt` — это отличительный признак.

## Сравнение с C++ и Go: как отличить Rust на глаз

Определить, что бинарь собран на Rust, можно по ряду признаков ещё до демаглинга:

- Символы вида `_ZN4core...`, `_ZN5alloc...`, `_ZN3std...` (legacy) или `_R...` (v0).
- Множество функций с суффиксом-хешем `17h<16 hex>` — маркер Rust-манглинга.
- Строки `panicked at <path>:<line>:<col>` и `called \`Option::unwrap()\` on a \`None\` value`.
- Секции `.rustc`, наличие `core::fmt::write`, `alloc::alloc::__rust_alloc`.
- Точка входа, вызывающая `std::rt::lang_start` (аналог `__libc_start_main`).
- В отличие от C++, нет исключений и `typeinfo`/vtable-таблиц в том же виде; вместо RTTI — ограниченный набор `TypeId`.
- В отличие от Go, нет гигантского `runtime.*` и `go.buildinfo`, зато есть `lang_start` и `core::fmt`.

Быстрая проверка:

```bash
strings -a ./binary | grep -cE 'panicked at|__rust_alloc|lang_start'
nm ./binary 2>/dev/null | grep -cE '_ZN4core|_ZN5alloc|17h'
```

Если оба счётчика ненулевые — почти наверняка Rust. Это помогает выбрать правильную стратегию (демаглер + поиск panic-строк) вместо «слепого» разбора.

## Оптимизации, которые ломают картину

Компилятор Rust с `-O`/release применяет:

- **Inlining** — маленькие функции встраиваются в вызывающие, `main` раздувается, отдельные функции исчезают.
- **Devirtualization** — статические вызовы вместо динамических; vtable исчезает.
- **Loop unrolling / vectorization** — циклы превращаются в развёрнутые последовательности, сложнее восстановить исходный цикл.
- **Constant folding** — вычисленные на этапе компиляции значения попадают в `.rodata` как готовые константы (иногда это «сливает» секреты).
- **Drop elaboration** — множество вызовов `drop_in_place` в конце scope.

Приём против inline: ищите по строкам/константам и `xref`, а не по границам функций; в IDA/Ghidra включайте определение функций заново после удаления ложных.

## Справочник команд

| Задача | Команда |
|--------|---------|
| Демаглинг (nm) | `nm -C ./binary` |
| Демаглинг (rustfilt) | `nm ./binary \| rustfilt` |
| Установка rustfilt | `cargo install rustfilt` |
| Поиск main | `nm -C ./binary \| grep '::main'` |
| Panic-строки | `strings -a ./binary \| grep 'panicked at'` |
| Точка входа рантайма | `nm -C ./binary \| grep lang_start` |
| Определить Rust | `strings ./binary \| grep -c __rust_alloc` |
| Дизасм функции | `objdump -d -M intel ./binary` |

## Частые ошибки

- **Игнорировать манглинг.** Без демаглинга имена `_ZN4core...` бессмысленны; потратите время на «слепой» реверс.
- **Анализировать panic-пути.** Они раздувают код; фокусируйтесь на happy path.
- **Путать мономорфы.** Похожие функции — копии generic; не считайте их разными алгоритмами.
- **Ожидать простой `main`.** Rust-рантайм (`lang_start`) добавляет код до и после вашей логики.
- **Забыть про `abort`.** Некоторые сборки паникуют без unwind — нет таблиц `.eh_frame`, и это норма.
- **Не использовать panic-строки.** В stripped-бинаре это лучший якорь для локализации логики.
- **Путать bounds-check с валидацией.** Паника на границах — защита памяти, а не проверка пароля.

## Что делать дальше / решение

1. Проверьте, stripped ли бинарь (`nm`, `file`), и прогоните `nm -C`/`rustfilt`.
2. Извлеките panic-строки и имена `.rs`-файлов — это карта исходников.
3. Локализуйте `main`/`lang_start` и точку ввода.
4. Отбросьте panic/Result-ветки, разберите happy path.
5. Распознайте std-идиомы (Vec/Option/Iterator) и восстановите алгоритм.
6. Подтвердите гипотезы в gdb (точки останова на проверках) и/или напишите keygen.

## Квиз

```quiz
- question: "Что такое мономорфизация в Rust?"
  options:
    - "Компиляция generic-функции отдельно для каждого типа"
    - "Сжатие кода"
    - "Шифрование строк"
    - "Удаление символов"
  answer: 0
  explanation: "Generic-функции дублируются под каждый тип, растёт объём кода."
- question: "Как демаглить Rust-символы?"
  options:
    - "nm -C или rustfilt/c++filt"
    - "ldd"
    - "strace"
    - "objdump -h"
  answer: 0
  explanation: "nm -C и rustfilt раскрывают Rust-манглинг."
- question: "Что делать с panic/Result-ветками при реверсе?"
  options:
    - "Игнорировать их, фокусируясь на основной логике"
    - "Анализировать все до одной"
    - "Удалить их из бинаря"
    - "Запустить"
  answer: 0
  explanation: "Panic-пути — шум; основная логика в happy path."
- question: "Как найти функции в stripped Rust-бинаре?"
  options:
    - "По panic-строкам и именам файлов/типов"
    - "По GOT"
    - "По секциям"
    - "По ASLR"
  answer: 0
  explanation: "Строки panic содержат имена, помогающие локализовать код."
- question: "Чем Vec в Rust отличается от C-массива?"
  options:
    - "Это трёхсловный дескриптор (ptr/len/cap) с bounds-check"
    - "Он статический"
    - "Он без длины"
    - "Он в стеке"
  answer: 0
  explanation: "Vec хранит ptr/len/cap и проверяет границы (паникует)."
```

## Где пригодится

- **CTF:** Reversing — Rust-задачи.
- **Malware analysis:** Rust-малварь.
- **Bug bounty:** Rust-сервисы.
- **Работа:** реверс современных бинарей.
