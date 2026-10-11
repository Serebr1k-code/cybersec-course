---
id: reversing-elf-instrumentation
title: "Инструментация ELF: e9patch и frida-gadget"
category: reversing
parent: reversing-frida-advanced
difficulty: hard
order: 1
tags: [reversing, elf, instrumentation, e9patch, frida-gadget, binary-rewriting]
prerequisites: [reversing-patching, reversing-frida-advanced]
useful_for:
  - "CTF Reversing"
  - "Bug bounty"
  - "Tooling"
estimated_minutes: 55
summary: "Инструментация и перезапись ELF: e9patch для статического трейсинга, frida-gadget для инъекции без root."
---
**Инструментация ELF** — это изменение поведения готового бинарника без пересборки: вставка трамплинов, подмена вызовов, перехват функций, сбор трасс. В реверсе это нужно для динамического анализа закрытых программ, трассировки конкретных функций, обхода анти-отладки и генерации fuzzing-обвязок. Урок разбирает два основных подхода — **статическую бинарную перезапись** (`e9patch`/`e9tool`) и **инъекцию рантайм-библиотеки** (`frida-gadget`, `LD_PRELOAD`) — с полными командами и разбором вывода.

## Зачем инструментировать бинарник

Мотивации в реверсе и безопасноти:

- **Трассировка**: узнать аргументы и возвраты конкретной функции (`malloc`, `strcmp`, `send`).
- **Перехват**: подменить результат проверки (`strcmp → 0`, `IsDebuggerPresent → 0`).
- **Fuzzing-обвязка**: подавать вход в функцию и ловить падения (AFL++/libFuzzer через e9afl).
- **Обход анти-отладки/анти-VM**: нейтрализовать проверки, не патча вручную в IDA.
- **Сбор данных**: логировать обращения к памяти, индексы, значения.

Важно различать: **статическая инструментация** (патч на диске, `e9patch`) и **динамическая** (библиотека грузится в процесс, `frida`, `LD_PRELOAD`, ptrace-DBI). У каждой — свои компромиссы по надёжности и скрытности.

## e9patch / e9tool: бинарная перезапись

`e9patch` — это статический бинарный переписыватель: он разбирает ELF, вставляет в код «трамплины» (hooks) и корректирует все относительные переходы. `e9tool` — фронтенд, задающий, куда и какие хуки ставить.

```bash
# установка (сборка из исходников)
git clone https://github.com/GJDuck/e9patch && cd e9patch && ./build.sh
export PATH="$PWD/build:$PATH"
# базовое использование: перехватить все вызовы malloc и залогировать
e9tool -M 'mnemonic=call' -P 'printf("call at %p\n", addr)' a.out -o a.out.patched
# трамплин с вызовом функции (extern) для конкретной функции
e9tool -M 'function=main' -P 'printpc' a.out -o a.out.inst
```

Полезные опции `e9tool`:

| Опция | Смысл |
|---|---|
| `-M <matcher>` | какие инструкции/функции матчить (`function=`, `mnemonic=`, `addr=`, `symbol=`) |
| `-P <patch>` | что вставить (`printpc`, `printf(...)`, `trace`, вызов extern-функции) |
| `-o <file>` | выходной пропатченный ELF |
| `--mem` | инъекция в память, без записи файла |
| `--exec` | сразу запустить результат |
| `-c` | сохранить исходный код без изменений (только трамплины) |

Пример с extern-функцией и логом аргументов:

```bash
cat > hook.c <<'EOF'
#include <stdio.h>
void my_hook(void *addr, long a0, long a1) {
    fprintf(stderr, "hook addr=%p a0=%ld a1=%ld\n", addr, a0, a1);
}
EOF
gcc -shared -fPIC -o hook.so hook.c
e9tool -M 'symbol=strcmp' -P 'my_hook($addr, $arg0, $arg1)' \
       -l hook.so ./check -o ./check.inst
./check.inst
```

Вывод покажет реальные аргументы `strcmp` — то, что вам нужно для восстановления пароля.

## e9afl: инструментация для fuzzing

`e9afl` строит из бинарника fuzz-цель с покрытием (edge coverage), совместимую с AFL++:

```bash
e9afl ./target -o ./target.inst      # добавить инструментацию покрытия
afl-fuzz -i seeds/ -o out/ -- ./target.inst @@
```

Это позволяет фаззить **закрытый бинарник без исходников** — распространённая задача в реверсе протоколов и парсеров.

## frida-gadget: инъекция библиотеки

`frida-gadget` — это разделяемая библиотека, которую можно «подсунуть» приложению, чтобы получить полноценный Frida-хукинг без запуска через `frida -f`. Особенно полезно на Android и в embedded.

```bash
# 1) положить библиотеку рядом с бинарником/в LD_LIBRARY_PATH
cp frida-gadget.so ./libfrida-gadget.so
# 2) заставить приложение её загрузить: LD_PRELOAD
LD_PRELOAD=$PWD/libfrida-gadget.so ./target
# 3) gadget создаёт конфиг-файл рядом (frida-gadget.config) — отредактировать
cat > libfrida-gadget.config <<'EOF'
{
  "interaction": {
    "type": "script",
    "path": "./hook.js",
    "on_change": "reload"
  }
}
EOF
```

`hook.js` на стороне Frida:

```javascript
Interceptor.attach(Module.getExportByName(null, "strcmp"), {
  onEnter(args) {
    this.a = args[0].readUtf8String();
    this.b = args[1].readUtf8String();
  },
  onLeave(retval) {
    console.log(`strcmp("${this.a}", "${this.b}") = ${retval}`);
  }
});
```

На Android gadget обычно добавляют через `patchelf --add-needed` или переупаковкой APK:

```bash
patchelf --add-needed libfrida-gadget.so ./lib/arm64-v8a/libtarget.so
```

## LD_PRELOAD: простейшая подмена функций

Без Frida и e9patch — перехват через `LD_PRELOAD` собственной `.so`:

```bash
cat > preload.c <<'EOF'
#define _GNU_SOURCE
#include <string.h>
int strcmp(const char *a, const char *b) {
    fprintf(stderr, "strcmp: %s vs %s\n", a, b);
    return 0;   // всегда «равны» — обход проверки
}
EOF
gcc -shared -fPIC -ldl -o preload.so preload.c
LD_PRELOAD=$PWD/preload.so ./check
```

Работает только для **динамически слинкованных** вызовов PLT. Если бинарник статический или вызывает `strcmp` внутренне (`-O2` инлайнит) — `LD_PRELOAD` не поможет, нужен `e9patch` или DBI.

## Динамическая инструментация: DBI и ptrace

Полноценные DBI-фреймворки (Intel PIN, DynamoRIO, QBDI) инструментируют **каждую инструкцию** во время исполнения и не требуют патча файла. Они перехватывают `ptrace`, что может конфликтовать с анти-отладкой. Для лёгких задач хватает `ptrace`-хуков через `gdb` или `ltrace`:

```bash
ltrace -e 'strcmp+strcpy+malloc' ./check
# перехват конкретной функции и печать аргументов/результата
gdb -q -batch -ex 'break strcmp' -ex 'run' -ex 'x/s $rdi' -ex 'x/s $rsi' ./check
```

## Разобранный пример: восстановление пароля через инструментацию

Дано: `check` просит пароль и печатает `wrong`/`correct`. Нужно узнать пароль.

**Шаг 1. Разведка.**

```bash
file check && checksec --file=check
ltrace -e 'strcmp+strncmp+memcmp' ./check <<< "AAAA"
```

**Шаг 2. Трассировка `strcmp`.**

```bash
ltrace -s 128 -e strcmp ./check <<< "AAAA"
# вывод: strcmp("AAAA", "s3cr3t_pw") = -1
```

**Шаг 3. Проверка.**

```bash
./check <<< "s3cr3t_pw"
# correct
```

Если `ltrace` не показывает (статический бинарник или инлайн) — используем e9tool:

```bash
e9tool -M 'symbol=strcmp' -P 'my_hook($addr,$arg0,$arg1)' -l hook.so ./check -o check.inst
./check.inst <<< "AAAA"
```

## Сравнение подходов

| Подход | Патч файла | Работает со статикой | Заметность | Типичный инструмент |
|---|---|---|---|---|
| `LD_PRELOAD` | нет | нет (только PLT) | низкая | libc |
| `e9patch`/`e9tool` | да | да | средняя (меняет файл) | e9patch |
| `frida-gadget` | нет (инъекция) | да | средняя | Frida |
| DBI (PIN/QBDI) | нет | да | высокая | PIN, QBDI |
| `ptrace`/gdb | нет | да | высокая | gdb, ltrace |

## Частые ошибки и подводные камни

- **`LD_PRELOAD` на статическом бинарнике** — молча не работает. Проверьте `ldd`/`file`.
- **Инлайн-функции.** `-O2` часто инлайнит `strcmp`/`memcpy`; перехвата на уровне символа не будет.
- **PIE и ASLR.** e9patch корректно работает с PIE, но самодельные патчи по абсолютным адресам — нет.
- **Конфликт ptrace.** DBI/отладчик и анти-отладка в бинарнике будут драться за `ptrace` — используйте `prctl`-хуки или e9patch.
- **Порча ELF.** После `e9patch` проверяйте `readelf -h`/`ldd` и запускайте; при сбое — не тот матчер/патч.
- **Gadget config.** Если `frida-gadget.config` не рядом с `.so` — gadget не загрузится; следите за `on_change`.
- **Архитектура.** `frida-gadget.so` должен совпадать с arch бинарника (x86_64/arm64).

## Что дальше / решение

Выберите инструмент по ситуации: **быстрая проверка гипотезы** — `ltrace`/`gdb`; **подмена в рантайме без патча файла** — `LD_PRELOAD` (если динамика) или `frida-gadget`; **статический бинарник / fuzzing / надёжный патч на диске** — `e9patch`/`e9afl`. Комбинируйте: e9patch для нейтрализации анти-отладки, frida для интерактивного хукинга. Дальше логично перейти к `reversing-pin-dbi` (полноценные DBI) и `reversing-frida-advanced` (сложные хуки, ObjC/Java).

## Сборка и развёртывание frida-gadget по платформам

Gadget — не универсальный: под каждую архитектуру и ОС нужен свой бинарник. Скачивать надо именно `frida-gadget-<version>-<os>-<arch>.so`/`.dylib`.

```bash
# Linux x86_64
wget https://github.com/frida/frida/releases/download/16.4.0/frida-gadget-16.4.0-linux-x86_64.so.xz
unxz frida-gadget-16.4.0-linux-x86_64.so.xz
mv frida-gadget-16.4.0-linux-x86_64.so libfrida-gadget.so
# Android arm64 — кладём в APK/lib
wget .../frida-gadget-16.4.0-android-arm64.so.xz
# iOS arm64 — кладём через патч Mach-O load command
```

Тип взаимодействия задаётся в конфиге: `"listen"` (TCP-порт, подключаемся `frida -H`), `"script"` (заранее заданный JS), `"connect"` (обратный коннект на C2). Для удалённых таргетов удобен `listen`:

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "resume"
  }
}
```

```bash
LD_PRELOAD=./libfrida-gadget.so ./target &
frida -H 127.0.0.1:27042 Gadget -l hook.js
```

## Обход анти-отладки инструментацией

Частая задача — нейтрализовать `ptrace(PTRACE_TRACEME)`, `IsDebuggerPresent`, чтение `/proc/self/status`. Вместо ручного патча в дизассемблере можно поставить хук e9patch, который подменяет возврат:

```bash
# перехватить ptrace и вернуть 0 (как будто успех)
e9tool -M 'symbol=ptrace' -P 'ret0' ./target -o ./target.clean
# где ret0 — встроенный патч e9patch, возвращающий 0 из функции
```

Аналогично для `getppid`/`readlink("/proc/self/exe")` при анти-VM. Frida-вариант:

```javascript
Interceptor.replace(Module.getExportByName(null, "ptrace"),
  new NativeCallback((req, pid, addr, data) => 0, "long", ["int","int","pointer","pointer"]));
```

## Трассировка аргументов и памяти: практический шаблон

Универсальный e9tool-патч для логирования всех аргументов вызова:

```bash
e9tool -M 'mnemonic=call' \
  -P 'printf("CALL %p target=%p a0=%ld a1=%ld a2=%ld\n", $addr, $target, $arg0, $arg1, $arg2)' \
  ./target -o ./target.trace
./target.trace 2>trace.log
head trace.log
```

Сопоставив `target` с именами символов (`nm -D ./target`), вы получаете полную карту вызовов с аргументами — фактически трассу исполнения без отладчика.

## Ограничения: когда инструментация не сработает

- **Самомодифицирующийся код** и распаковщики: патч на диске затирается при распаковке — нужен рантайм-хук после unpack.
- **Packed/UPX** бинарники: инструментировать нужно уже распакованный образ в памяти.
- **Анти-хукинг**: проверка целостности кода (CRC) обнаружит трамплины e9patch.
- **Статические бинарники + inline** — единственный выход DBI (PIN/QBDI) или символьное исполнение.
- **Kernel-space / SGX** — инструментация из user-space невозможна.

## Квиз

```quiz
- question: "Чем e9patch отличается от отладчика?"
  options:
    - "Статически переписывает бинарь, не требует ptrace/root"
    - "Запускает процесс"
    - "Сканирует порты"
    - "Шифрует файл"
  answer: 0
  explanation: "e9patch вставляет hook-и в файл, обходя ptrace-анти-отладку."
- question: "Что такое frida-gadget?"
  options:
    - "Встраиваемая библиотека Frida для инъекции без root"
    - "Отладчик ядра"
    - "Формат ELF"
    - "Пакер"
  answer: 0
  explanation: "Gadget подгружается процессом и исполняет JS-скрипт."
- question: "Как запустить frida-gadget без патча файла?"
  options:
    - "LD_PRELOAD=./frida-gadget.so ./target"
    - "gdb ./target"
    - "strace ./target"
    - "objdump ./target"
  answer: 0
  explanation: "LD_PRELOAD подгружает gadget при старте."
- question: "Почему LD_PRELOAD может быть замечен анти-анализом?"
  options:
    - "Переменная видна в /proc/self/environ"
    - "Он меняет ELF"
    - "Он требует root"
    - "Он замедляет CPU"
  answer: 0
  explanation: "Проверка окружения раскрывает LD_PRELOAD."
- question: "Что делает Interceptor.replace?"
  options:
    - "Полностью заменяет функцию на ваш код"
    - "Только логирует вызов"
    - "Отключает ASLR"
    - "Перезапускает процесс"
  answer: 0
  explanation: "replace подменяет реализацию функции (например, возвращает успех)."
```

## Где пригодится

- **CTF:** Reversing — обход анти-отладки.
- **Bug bounty:** перехват в чужих процессах.
- **Tooling:** трассировка/покрытие.
- **Работа:** динамический анализ без отладчика.
