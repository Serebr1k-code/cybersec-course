---
id: mobile-libfuzzer
title: 'libFuzzer: фаззинг native-функции через harness'
category: mobile
parent: mobile-native-fuzzing
difficulty: hard
order: 1
tags: [fuzzing, libfuzzer, harness, native, clang, sanitizer]
prerequisites: [mobile-reverse-native]
useful_for:
  - 'Поиск уязвимостей'
  - 'Пентест мобильных приложений'
  - 'Bug bounty'
estimated_minutes: 40
summary: 'Как написать harness для libFuzzer, собрать его с ASan под arm64 и запустить фаззинг функции разбора в нативной библиотеке Android.'
lab:
  kind: shell
  title: 'Практика: разобрать отчёт ASan'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, asan_report.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`asan_report.txt` — отчёт санитайзера из фаззинг-прогона.'
    - 'Определи тип ошибки и функцию, где она возникла.'
    - 'В отчёте спрятан флаг `nto{...}` — запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

В приложении есть нативная библиотека `libparser.so`, которая разбирает входной формат. Мы
подозреваем, что на кривом вводе она выходит за границы буфера, но руками такой ввод не
придумать. Как заставить компьютер **сам** перебирать миллионы вариантов и находить падение?

## Наш пример: точка входа парсера

Заглянем в библиотеку и найдём функцию разбора:

```bash
$ nm -D --defined-only libparser.so | grep -i parse
0000000000012a40 T parse_record
```

`nm` показывает таблицу символов; `T` — определённая (экспортируемая) функция. Значит, есть
`parse_record`, которая принимает буфер и длину. Фаззеру нужна ровно такая функция.

## Шаг 1: что такое harness

Фаззер не знает, что вызывать. Мы пишем **harness** — маленькую обёртку, которая берёт
случайные байты и передаёт их в нашу функцию:

```c
extern int parse_record(const uint8_t *buf, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_record(data, size);
    return 0;
}
```

`LLVMFuzzerTestOneInput` — точка входа, которую libFuzzer вызывает сам. Каждый вызов — это
одна попытка с новым набором байтов. `return 0` означает «всё нормально, продолжай».

## Шаг 2: сборка

Компилируем harness вместе с библиотекой под нужную архитектуру, включая санитайзер адресов
(`-fsanitize=address`) и сам фаззер (`-fsanitize=fuzzer`):

```bash
$ clang --target=aarch64-linux-android -fsanitize=fuzzer,address \
    -o fuzz_parser harness.c -L. -lparser
$ file fuzz_parser
fuzz_parser: ELF 64-bit LSB shared object, ARM aarch64
```

`--target` задаёт архитектуру Android. `-fsanitize=fuzzer` добавляет движок фаззинга,
`-fsanitize=address` — детектор выхода за границы памяти. Без ASan ошибка может пройти
«тихо», не уронив процесс.

## Шаг 3: запуск и словарь

Запускаем на устройстве (или эмуляторе) и смотрим статистику:

```bash
$ adb push fuzz_parser /data/local/tmp/ && adb shell /data/local/tmp/fuzz_parser
INFO: Seed: 3829104
#2  INITED cov: 214 ft: 388 corp: 3/21b exec/s: 0
#1024 NEW  cov: 421 ft: 902 corp: 11/150b
```

`cov` — покрытие кода (сколько ветвей достигнуто), `exec/s` — сколько запусков в секунду,
`corp` — размер «корпуса», то есть набора интересных входов. Фаззер хранит их и мутирует.

## Шаг 4: словарь для форматов

Если формат начинается с «магических» байтов, фаззеру трудно их угадать. Словарь подсказывает:

```bash
$ cat parser.dict
hdr="REC0"
len="\x00\x00"
$ adb shell /data/local/tmp/fuzz_parser -dict=/data/local/tmp/parser.dict
```

Словарь — файл с токенами в формате `имя="значение"`. Это резко ускоряет прохождение
проверок формата.

## Шаг 5: читаем краш

Когда ASan ловит ошибку, он печатает отчёт:

```bash
==3110==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... 
READ of size 1 at 0x... thread T0
    #0 0x... in parse_record parser.c:57
```

`heap-buffer-overflow` — чтение за границей кучи. Указан файл и строка. libFuzzer сохраняет
вход, вызвавший краш, в файл `crash-<hash>` — его можно воспроизвести:

```bash
$ adb shell /data/local/tmp/fuzz_parser crash-abc123
```

## Шаг 6: ограничения

libFuzzer требует, чтобы функцию можно было вызвать напрямую и собрать библиотеку. Если
логика спрятана в статической сборке без символов или в обфусцированном коде, придётся
сначала восстановить точку входа (см. `mobile-reverse-native`). Тогда на помощь приходит
AFL (`mobile-afl-native`).

## Что мы теперь знаем

- Harness — обёртка с `LLVMFuzzerTestOneInput`.
- Сборка: `-fsanitize=fuzzer,address` под arm64 Android.
- `cov` и `exec/s` — покрытие и скорость фаззинга.
- Словарь ускоряет прохождение проверок формата.
- ASan-отчёт и файл `crash-*` дают воспроизводимый вход.

## Квиз

Проверь себя.

```quiz
- question: "Что такое harness?"
  options:
    - "Обёртка, которая передаёт случайные байты в тестируемую функцию"
    - "Скрипт сборки"
    - "Файл словаря"
    - "Отчёт ASan"
  answer: 0
  explanation: "Harness — точка входа LLVMFuzzerTestOneInput."
- question: "Зачем включать -fsanitize=address?"
  options:
    - "Чтобы тихие ошибки памяти становились явными крашами"
    - "Чтобы ускорить фаззинг"
    - "Чтобы уменьшить размер бинарника"
    - "Чтобы включить сеть"
  answer: 0
  explanation: "ASan превращает выход за границы в падение, которое ловит фаззер."
- question: "Что показывает метрика cov?"
  options:
    - "Покрытие кода"
    - "Скорость сети"
    - "Размер файла"
    - "Число утечек"
  answer: 0
  explanation: "cov — сколько ветвей кода достигнуто."
- question: "Зачем нужен словарь (dict)?"
  options:
    - "Подсказать фаззеру магические байты формата"
    - "Хранить пароли"
    - "Ускорить сборку"
    - "Сжимать корпус"
  answer: 0
  explanation: "Словарь помогает пройти проверки формата."
```
## Куда дальше

В следующем уроке — `mobile-afl-native`: фаззер, который работает с программой как с
процессом, когда harness написать нельзя. А пока запомни: libFuzzer + ASan + словарь — это
базовый набор для поиска memory-safety багов в native-коде.

## Где пригодится

- **Пентест:** переполнения в парсерах форматов.
- **Bug bounty:** падения в native-библиотеках.
- **Разработка:** фаззинг собственных парсеров.
- **CTF:** автоматический поиск падения.
