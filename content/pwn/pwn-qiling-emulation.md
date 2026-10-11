---
id: pwn-qiling-emulation
title: "Qiling: эмуляция ОС и syscall для анализа бинарей"
category: pwn
parent: pwn-emulation
difficulty: hard
order: 2
tags: [qiling, emulation, syscall, rootfs, elf, pe]
prerequisites: [pwn-unicorn-emulation]
useful_for:
  - "CTF Pwn категория"
  - "Malware analysis"
  - "Firmware/IoT"
estimated_minutes: 50
summary: "Разбираем Qiling: эмуляция ОС поверх Unicorn, rootfs, syscall-хуки, запуск ELF/PE и анализ чужой архитектуры."
---

Unicorn эмулирует процессор, но не операционную систему: `syscall` он не обрабатывает. Qiling закрывает этот пробел — это фреймворк эмуляции, который поверх Unicorn добавляет эмуляцию ОС: загрузчик ELF/PE, виртуальную файловую систему (`rootfs`), реализацию системных вызовов, эмуляцию Windows API и даже сетевых сокетов. Для pwn это означает, что вы можете запустить бинарь целиком в песочнице — без риска, без реального ядра, на любой архитектуре.

В этом уроке — установка, структура `rootfs`, базовый запуск, syscall-хуки и практические примеры. Материал продолжает `pwn-unicorn-emulation`.

## Что такое Qiling и чем отличается от Unicorn

Qiling = Unicorn + ОС. Он умеет:

- загружать ELF, PE, Mach-O, shellcode;
- эмулировать Linux, Windows, macOS, FreeBSD, UEFI, EVM;
- предоставлять `rootfs` — виртуальную ФС, из которой программа «видит» файлы;
- реализовывать системные вызовы (частично) и перехватывать их;
- эмулировать API Windows (`kernel32.dll` и др.).

Отличие в уровне абстракции: Unicorn даёт вам «голый CPU», Qiling — почти готовую ОС. Если задача — «запустить бинарь и посмотреть, что он делает», берите Qiling. Если нужно «вызвать одну функцию» — хватит Unicorn.

Есть и третий путь — `qemu-user`, который запускает бинарь чужой архитектуры почти нативно (см. `pwn-qemu-user`). Он быстрее Qiling и точнее воспроизводит поведение, но не даёт хуков уровня памяти/инструкций и требует, чтобы бинарь реально работал. Выбор такой: Qiling — для анализа и обхода анти-анализа, qemu-user — для эксплуатации и точного поведения, Unicorn — для эмуляции отдельных функций.

## Установка и структура rootfs

```bash
pip install qiling
python3 -c "import qiling; print(qiling.__version__)"
# 1.4.6

# для Linux-эмуляции нужен rootfs (набор библиотек и утилит)
git clone https://github.com/qilingframework/qiling.git
# rootfs лежат в qiling/examples/rootfs/x86_64_linux
```

`rootfs` — это дерево каталогов, которое программа видит как свою ФС: `/lib`, `/usr/lib`, `/etc`, `/bin`. Qiling загружает из него динамический линкер и разделяемые библиотеки. Если `rootfs` нет, программа не найдёт `ld-linux` и упадёт.

## Базовый запуск ELF/PE

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["./chall", "arg1"],
            rootfs="qiling/examples/rootfs/x86_64_linux",
            verbose=QL_VERBOSE.DEFAULT)
ql.run()
```

Для PE (Windows):

```python
ql = Qiling([r"examples/rootfs/x86_windows/bin/hello.exe"],
            rootfs=r"examples/rootfs/x86_windows")
ql.run()
```

Qiling сам определит формат и архитектуру, загрузит зависимости из `rootfs` и начнёт исполнение. `verbose=QL_VERBOSE.DEFAULT` печатает выполняемые API/syscall — удобно для быстрого понимания поведения.

## Эмуляция syscall и hooking

Хуки в Qiling ставятся на адреса и на syscall:

```python
def hook_syscall(ql, intno):
    if intno == 0:                 # read
        # вернуть 1 вместо реального чтения
        ql.os.ret(1)

ql.hook_intno(hook_syscall, 0x80)   # int 0x80
# или через hook_syscall для syscall-инструкции
```

Более удобный высокоуровневый API:

```python
ql.os.set_syscall("read", my_read)
ql.os.set_api("ptrace", my_ptrace, QL_INTERCEPT.CALL)
```

`set_syscall` подменяет реализацию syscall, `set_api` — функцию. Для Windows API: `ql.os.set_api("CreateFileW", ...)`.

Хуки можно ставить и на конкретные адреса кода: `ql.hook_address(cb, addr)` вызывает `cb` при достижении адреса, а `ql.hook_code(cb)` — на каждую инструкцию (медленно). Для практики чаще всего достаточно `hook_address` на функцию проверки и `set_syscall` на ввод-вывод. Комбинируя их, можно «раскрутить» программу: подсовывать данные на `read`, логировать ветвления и постепенно восстанавливать алгоритм, не прибегая к статическому анализу целиком.

## Инструменты и команды

```bash
# установка и проверка
pip show qiling

# список доступных rootfs
ls qiling/examples/rootfs/
# x86_64_linux  x86_linux  arm_linux  mips_linux  x86_windows  ...

# запуск примера
python3 -m qiling.examples.hello_x86_64_linux

# трассировка всех syscall
# в коде: verbose=QL_VERBOSE.DEBUG
```

`QL_VERBOSE.DEBUG` печатает каждый syscall и API-вызов — это заменяет `strace` и даёт мгновенную картину поведения. Для больших программ вывод огромен, поэтому перенаправляйте в файл.

## Разобранный пример: запуск Linux ELF

Пусть у нас MIPS-бинарь из прошивки роутера, и мы хотим понять, как он проверяет пароль. Запускаем под Qiling:

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["./router_check", "admin"],
            rootfs="./rootfs/mips_linux",
            verbose=QL_VERBOSE.DEBUG)
ql.run()
```

Ожидаемый вывод:

```
[=]     write(fd = 1, buf = 0x...("Enter password: "), count = 15) = 15
[=]     read(fd = 0, buf = 0x..., count = 64) = 6
[=]     write(fd = 1, buf = 0x...("wrong\n"), count = 6) = 6
```

Из трассы видно, какие syscall делает программа, куда пишет и откуда читает. Если программа использует `strcmp` со встроенной строкой, трасса покажет её содержимое — пароль может «утечь» прямо из вывода.

## Разобранный пример: обход анти-отладки и anti-VM

Анти-анализ часто проверяет `ptrace`, наличие файлов `/proc`, `cpuid`, время. Под Qiling всё это можно перехватить:

```python
from qiling.const import QL_INTERCEPT

def fake_ptrace(ql, *args):
    return 0                    # «трассировки нет»

ql.os.set_api("ptrace", fake_ptrace, QL_INTERCEPT.CALL)

def fake_read(ql, fd, buf, count):
    data = b"..."               # подсунуть «правильные» данные
    ql.mem.write(buf, data)
    return len(data)
ql.os.set_syscall("read", fake_read)
```

Так вы проходите проверки и наблюдаете за дальнейшей логикой. Это безопаснее, чем запускать malware на хосте, и работает для любой архитектуры.

## Qiling для Windows PE и API-хуки

Отдельная сильная сторона Qiling — эмуляция Windows PE без Windows. Он загружает `kernel32.dll`, `ntdll.dll` и другие библиотеки из Windows-`rootfs` и реализует большую часть API. Для pwn это позволяет разбирать Windows-эксплойты и malware на Linux-хосте. Хуки ставятся на API по имени:

```python
from qiling.const import QL_INTERCEPT

def fake_isdebugger(ql, *args):
    return 0                       # «отладчика нет»
ql.os.set_api("IsDebuggerPresent", fake_isdebugger, QL_INTERCEPT.CALL)

def fake_virtualalloc(ql, addr, size, alloc_type, protect):
    return ql.mem.map_anywhere(size)   # вернуть валидный адрес
ql.os.set_api("VirtualAlloc", fake_virtualalloc, QL_INTERCEPT.CALL)
```

Так обходятся анти-отладочные проверки и эмулируется выделение памяти. Трасса API (`QL_VERBOSE.DEBUG`) показывает, какие функции вызывает образ, — это фактически автоматический «API-монитор», родственный тому, что даёт Cuckoo/Speakeasy.

## Практика: трассировка и восстановление логики

Qiling удобен для восстановления логики проверок. Включите подробный вывод и посмотрите, где программа ветвится:

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["./chall"], rootfs="./rootfs/x86_64_linux",
            verbose=QL_VERBOSE.DEBUG)
ql.run()
```

Вывод покажет последовательность syscall/API и аргументы. Если программа вызывает `strcmp` со встроенной строкой, трасса выдаст её. Если проверка реализована вручную (побайтовое сравнение), трасса покажет адреса чтения — их можно скоррелировать с дизассемблером и восстановить ожидаемый ввод. В отличие от статического анализа, здесь вы видите **фактический** путь исполнения.

Дополнительно можно вешать хук на адрес в коде: `ql.hook_address(callback, addr)` — он вызовется при достижении адреса, что позволяет логировать состояние или подменять регистры в интересной точке.

## Эмуляция чужой архитектуры (MIPS/ARM)

Qiling поддерживает MIPS, ARM, ARM64, PPC «из коробки» — нужен лишь подходящий `rootfs`. Для IoT это бесценно: вы запускаете бинарь прошивки на x86-хосте. Учитывайте endianness: для big-endian MIPS нужен соответствующий `rootfs` и настройки Qiling (`ql.archtype`).

## Ограничения Qiling и когда он не подходит

Qiling — мощный, но не универсальный инструмент. Понимание ограничений экономит часы:

- **Неполная реализация syscall.** Многие системные вызовы реализованы частично или заглушками. Сложные программы (с `epoll`, `io_uring`, потоками) могут падать, и тогда нужны хуки.
- **Производительность.** Эмуляция в десятки раз медленнее нативного исполнения. Для крипто-брутфорса Qiling не подойдёт — там лучше Unicorn на конкретной функции.
- **Динамические зависимости.** Если программа подгружает библиотеки, которых нет в `rootfs`, эмуляция прервётся. Приходится докладывать их в `rootfs` вручную.
- **Анти-эмуляция.** Продвинутый malware проверяет окружение (наличие эмулятора, аномалии `cpuid`, тайминги). Qiling это не скрывает по умолчанию — нужны хуки, чтобы «притвориться» реальной системой.
- **Отсутствие реального ядра.** Всё, что требует ядерных интерфейсов (`ioctl` к специфичным устройствам, `perf`), эмулируется ограниченно.

Поэтому рабочая стратегия такая: сначала попробовать запустить бинарь целиком под Qiling с `QL_VERBOSE.DEFAULT` и посмотреть, доходит ли он до интересной логики. Если да — хукайте нужное. Если нет — переходите на Unicorn и эмулируйте отдельные функции, где вы контролируете всё. Не тратьте время на «заставление» Qiling запустить то, что он принципиально не тянет.

## Частые ошибки

- **Нет `rootfs`.** Программа не найдёт `ld-linux` и упадёт — всегда указывайте `rootfs`.
- **Неверная архитектура rootfs.** MIPS-бинарь с x86-rootfs не запустится.
- **Ожидание полной эмуляции syscall.** Часть syscall реализована частично; сложные программы требуют хуков.
- **Слишком подробный вывод.** `QL_VERBOSE.DEBUG` на большой программе печатает мегабайты — пишите в файл.
- **Игнорирование эмуляции сети.** Сетевые вызовы Qiling эмулирует; для реального взаимодействия нужен собственный хук.

## Что дальше / решение

- Изучите `pwn-emulation-hooks` для продвинутой подмены состояния.
- Для firmware-задач свяжите с `pwn-mips` и `pwn-arm64-basics`.
- Для обхода anti-debug используйте связку Qiling + Unicorn-хуки.
- Помните про `pwn-qemu-user` — альтернативный путь запуска чужой архитектуры.

## Справочные таблицы

| Формат | Поддержка |
|---|---|
| ELF | да |
| PE | да |
| Mach-O | да |
| shellcode | да |

| API | Назначение |
|---|---|
| hook_intno | перехват прерывания |
| set_syscall | подмена syscall |
| set_api | подмена функции |

## Квиз

```quiz
- question: "Что добавляет Qiling поверх Unicorn?"
  options:
    - "Эмуляцию ОС: загрузчик, rootfs и syscall"
    - "Только графический интерфейс"
    - "Компилятор"
    - "Ничего"
  answer: 0
  explanation: "Qiling эмулирует ОС, включая syscall и файловую систему."
- question: "Зачем нужен rootfs в Qiling?"
  options:
    - "Чтобы ускорить эмуляцию"
    - "Чтобы программа нашла линкер и библиотеки"
    - "Чтобы отключить ASLR"
    - "Чтобы создать поток"
  answer: 1
  explanation: "Без rootfs динамический линкер и библиотеки недоступны."
- question: "Как подменить реализацию системного вызова в Qiling?"
  options:
    - "Через set_syscall"
    - "Через mem_map"
    - "Через hook_code"
    - "Через emu_start"
  answer: 0
  explanation: "set_syscall заменяет реализацию конкретного syscall."
```

## Где пригодится

- **CTF:** задачи с анти-отладкой и чужой архитектурой.
- **Bug bounty:** безопасный запуск подозрительных бинарей.
- **Пентест:** анализ прошивок IoT без устройства.
- **Работа:** malware analysis и DFIR.
