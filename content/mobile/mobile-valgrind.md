---
id: mobile-valgrind
title: 'Valgrind на Android: утечки памяти без пересборки'
category: mobile
parent: mobile-native-fuzzing
difficulty: medium
order: 4
tags: [valgrind, memory, leak, android, native, analysis]
prerequisites: [mobile-sanitizers]
useful_for:
  - 'Пентест мобильных приложений'
  - 'Разработка native'
  - 'Анализ стабильности'
estimated_minutes: 32
summary: 'Как запустить Valgrind на Android, чем Memcheck отличается от ASan, как читать отчёты об утечках и ошибках доступа и когда Valgrind незаменим.'
lab:
  kind: shell
  title: 'Практика: найти утечку по отчёту Valgrind'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, valgrind_out.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`valgrind_out.txt` — вывод Valgrind с `--leak-check=full`.'
    - 'Найди запись definitely lost и функцию-виновника.'
    - 'В трассе утечки спрятан флаг `nto{...}` — запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Приложение работает часами и постепенно съедает память. Санитайзеры мы включать не можем —
сборка чужая, исходников нет. Есть ли инструмент, который найдёт утечку в **готовом**
бинарнике, не требуя его пересобирать?

## Наш пример: сервис, который течёт

Нативный сервис обрабатывает запросы и должен освобождать буферы:

```bash
$ adb shell /data/local/tmp/netsvc --once
request handled
```

Память растёт с каждым запросом. Запустим Valgrind — динамический анализатор, который
исполняет программу под своим контролем и наблюдает за каждым обращением к памяти.

## Шаг 1: что такое Valgrind

Valgrind — это **виртуальная машина**: программа выполняется не напрямую на процессоре, а
под управлением Valgrind, который перехватывает все операции с памятью. Главный инструмент
внутри — **Memcheck**: он отмечает, что выделено, что освобождено и что прочитано без
инициализации. Отсюда две вещи: Valgrind ничего не надо пересобирать, но он замедляет
программу в 10–50 раз.

## Шаг 2: запуск на Android

Valgrind для Android ставят на устройство вместе с программой:

```bash
$ adb push valgrind /data/local/tmp/
$ adb push netsvc /data/local/tmp/
$ adb shell /data/local/tmp/valgrind --leak-check=full /data/local/tmp/netsvc --once
```

`--leak-check=full` включает подробный разбор утечек. Вывод идёт в `logcat` или в файл.

## Шаг 3: читаем отчёт об утечке

```bash
==4211== HEAP SUMMARY:
==4211==     in use at exit: 8,192 bytes in 2 blocks
==4211==   total heap usage: 128 allocs, 126 frees
==4211== 8,192 (8,192 direct) bytes in 1 blocks are definitely lost in loss record 1 of 1
==4211==    at 0x...: malloc (in /system/lib64/libc.so)
==4211==    by 0x...: handle_request (netsvc.c:88)
```

`definitely lost` — точно потерянная память: указатель на выделенный блок утерян, освободить
его уже некому. Строка `handle_request (netsvc.c:88)` указывает место. Это и есть искомая
утечка.

## Шаг 4: категории утечек

Valgrind различает: `definitely lost` (точно утеряно), `indirectly lost` (потеряно вместе с
родителем), `possibly lost` (указатель на середину блока — часто ложное срабатывание),
`still reachable` (память ещё доступна, но не освобождена — часто норма). Важно не
паниковать из-за `possibly lost` и смотреть на `definitely lost`.

## Шаг 5: ошибки доступа

Memcheck ловит не только утечки, но и неверные обращения:

```bash
==4211== Invalid read of size 4
==4211==    at 0x...: parse_header (netsvc.c:41)
==4211==  Address 0x... is 0 bytes after a block of size 32 alloc'd
```

`Invalid read` — чтение по адресу, который не выделен. Это тот же класс ошибок, что ловит
ASan, но без пересборки.

## Шаг 6: когда Valgrind лучше санитайзеров

Valgrind незаменим, когда: исходников нет; нельзя пересобрать; нужно проверить именно
готовый релизный бинарник; или нужно посмотреть на реальное поведение под длительной
нагрузкой. Его цена — скорость. Поэтому Valgrind гоняют на коротких сценариях, а фаззинг —
под санитайзерами.

## Что мы теперь знаем

- Valgrind — динамический анализатор, работает без пересборки.
- Memcheck находит утечки и неверные обращения к памяти.
- `definitely lost` — настоящая утечка; `still reachable` — часто норма.
- `Invalid read/write` — ошибки доступа, как у ASan.
- Valgrind медленный: для коротких сценариев, не для фаззинга.

## Квиз

Проверь себя.

```quiz
- question: "Чем Valgrind отличается от ASan?"
  options:
    - "Не требует пересборки, работает с готовым бинарником"
    - "Он быстрее ASan"
    - "Он только для iOS"
    - "Он не ищет утечки"
  answer: 0
  explanation: "Valgrind исполняет программу под своим контролем."
- question: "Какая категория утечки самая серьёзная?"
  options:
    - "definitely lost"
    - "still reachable"
    - "possibly lost"
    - "indirectly lost"
  answer: 0
  explanation: "definitely lost — указатель утерян, освободить некому."
- question: "Почему Valgrind медленный?"
  options:
    - "Программа выполняется под эмуляцией, а не напрямую"
    - "Он качает данные из сети"
    - "Он пересобирает бинарник"
    - "Он шифрует память"
  answer: 0
  explanation: "Виртуальная машина замедляет выполнение в 10-50 раз."
- question: "Что означает Invalid read у Memcheck?"
  options:
    - "Чтение по невыделенному адресу"
    - "Утечку памяти"
    - "Медленный запрос"
    - "Обрыв соединения"
  answer: 0
  explanation: "Неверное обращение к памяти, как у ASan."
```
## Куда дальше

На этом модуль фаззинга и санитайзеров завершён. Мы прошли путь от harness для libFuzzer до
Valgrind на готовом бинарнике. Дальше можно вернуться к `mobile-native-fuzzing` и собрать
полный конвейер: ASan-сборка, фаззинг, Valgrind на коротких сценариях. Главное запомни:
инструмент выбирается по тому, есть ли исходники и можно ли пересобрать.

## Где пригодится

- **Пентест:** утечки и ошибки памяти в готовых библиотеках.
- **Разработка:** поиск утечек в долгоживущих сервисах.
- **Bug bounty:** доказательство утечки памяти.
- **CTF:** анализ чужого бинарника.
