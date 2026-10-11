---
id: pwn-race-widening
title: "Расширение окна гонки: userfaultfd, FUSE и планировщик"
category: pwn
parent: pwn-race-conditions
difficulty: expert
order: 3
tags: [userfaultfd, fuse, race, mprotect, kernel, ctf]
prerequisites: [pwn-thread-races]
useful_for:
  - "CTF Pwn категория"
  - "Kernel exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Учимся детерминированно расширять окно гонки: userfaultfd, FUSE, mprotect, ptrace и планировщик — от идеи до полного эксплойта."
---

Самая большая проблема гонок — их нестабильность. Окно между двумя операциями измеряется микросекундами, и «правильный» порядок выпадает редко. Но окно можно **расширить детерминированно**: заставить один поток застрять ровно в нужной точке, пока другой готовит состояние. Лучший инструмент для этого — `userfaultfd`, который позволяет перехватить обращение к странице памяти и удерживать поток в обработчике сколько угодно.

В этом уроке мы разберём `userfaultfd` и FUSE, научимся замораживать поток в критической точке, соберём полный эксплойт и рассмотрим более простые альтернативы. Материал опирается на `pwn-thread-races` и `pwn-toctou` и напрямую связан с `pwn-kernel-userfaultfd`.

## Зачем расширять окно гонки

Наивный подход — крутить racer в цикле и надеяться. Он работает для широких окон, но бесполезен, когда между check и use всего пара инструкций. Расширение окна переводит гонку из «вероятностной» в «детерминированную»: вы точно знаете, что поток A стоит в точке X, а поток B в это время меняет данные.

Три источника «застревания»:

- **Page fault** — поток обращается к странице, которой нет в памяти; `userfaultfd` перехватывает это событие.
- **Файловая операция** — FUSE-ФС может отвечать медленно, удерживая поток на `read`/`open`.
- **Явная приостановка** — `SIGSTOP`, `ptrace`, `mprotect` (заставить segfault и обработать).

## userfaultfd: механика и режимы

`userfaultfd` — системный вызов, создающий дескриптор, через который пользовательский процесс получает уведомления о page fault на **своей** памяти. Идея: вы регистрируете диапазон, и когда поток обращается к незаполненной странице, ядро не обрабатывает fault само, а кладёт событие в очередь `userfaultfd`. Пока ваш обработчик не сделает `UFFDIO_COPY`, поток-нарушитель висит в ядре.

Режимы:

| Режим | Что перехватывает |
|---|---|
| `UFFDIO_REGISTER_MODE_MISSING` | обращение к отсутствующей странице |
| `UFFDIO_REGISTER_MODE_WP` | запись в защищённую страницу |
| `UFFDIO_REGISTER_MODE_MINOR` | minor fault (для live-migration) |

Для гонок обычно нужен `MISSING`: вы `mmap`-ите регион `PROT_READ|PROT_WRITE`, регистрируете его и намеренно не заполняете. Первое же обращение даёт событие.

## Реализация userfaultfd-хендлера

```c
int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api ua = { .api = UFFD_API };
ioctl(uffd, UFFDIO_API, &ua);

char *region = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
struct uffdio_register ur = { .range = { .start = (unsigned long)region,
                                          .len = 0x1000 },
                              .mode = UFFDIO_REGISTER_MODE_MISSING };
ioctl(uffd, UFFDIO_REGISTER, &ur);

// поток-обработчик: ждём событие и удерживаем нарушителя
struct uffd_msg msg;
read(uffd, &msg, sizeof(msg));   // <- нарушитель застрял ЗДЕСЬ
// ... готовим состояние, потом:
struct uffdio_copy uc = { .dst = msg.arg.pagefault.address,
                          .src = (unsigned long)page, .len = 0x1000 };
ioctl(uffd, UFFDIO_COPY, &uc);   // отпускаем поток
```

Пока `read(uffd, ...)` не вернётся и `UFFDIO_COPY` не выполнится, поток-нарушитель стоит в page fault. Это окно неограниченной длительности.

## FUSE: медленные файловые операции

Если цель работает с файлами, вместо `userfaultfd` можно использовать FUSE-файловую систему: ваш обработчик отвечает на `read` с произвольной задержкой. Поток цели висит в `read`, пока вы готовите подмену. Это удобно для TOCTOU на файлах: вы точно знаете, что цель выполнила `access`, и держите её на следующем шаге.

Минус — FUSE требует `/dev/fuse` и привилегий в некоторых окружениях, а также сложнее в настройке. Зато работает там, где `userfaultfd` отключён (см. ниже). На практике FUSE отлично подходит для задач, где цель читает конфиг или загружает плагин: вы подсовываете свою ФС и управляете содержимым в момент чтения, одновременно удерживая поток на медленном ответе.

## Инструменты и команды

```bash
# проверить, доступен ли userfaultfd
sysctl vm.unprivileged_userfaultfd
# vm.unprivileged_userfaultfd = 0  -> непривилегированным нельзя

# проверить, включён ли userfaultfd вообще
grep -i userfault /boot/config-$(uname -r)
# CONFIG_USERFAULTFD=y

# посмотреть сигнатуру syscall
grep userfaultfd /usr/include/asm-generic/unistd.h

# при работе под kernel-задачей — убедиться в наличии
ls -l /dev/fuse
```

С ядра 5.11 `vm.unprivileged_userfaultfd=0` по умолчанию в многих дистрибутивах, поэтому в CTF часто нужно сначала получить CAP_SYS_PTRACE или запускать под root. Проверяйте это до того, как строить план на `userfaultfd`.

## Разобранный пример: заморозка на page fault

Классика kernel-pwn и сложных user-space гонок: объект, который цель читает дважды (double-fetch). Первый раз — проверка, второй — использование. Мы замораживаем поток на втором чтении и подменяем данные.

```c
// 1. Регистрируем userspace-буфер под userfaultfd (MISSING).
// 2. Запускаем syscall/операцию, которая копирует данные из буфера.
// 3. На page fault обработчик видит адрес и может:
//    - записать "безопасное" значение,
//    - затем, при повторном обращении, подменить на опасное.
```

Практический сценарий для ядра: `write(fd, userbuf, len)` копирует `len` из userbuf; мы держим fault, меняем `len` в буфере и отпускаем. Если драйвер читает `len` дважды, второе значение уже больше — переполнение.

## Полный эксплойт с userfaultfd

```python
import ctypes, os, sys, threading, time

UFFDIO_API     = 0xc018aa3f
UFFDIO_REGISTER= 0xc020aa00
UFFDIO_COPY    = 0xc028aa03
UFFD_API       = 0xAA

libc = ctypes.CDLL("libc.so.6", use_errno=True)
UFFD_USER_MODE_ONLY = 1

def uffd_setup(size=0x1000):
    uffd = libc.syscall(323, UFFD_USER_MODE_ONLY | os.O_NONBLOCK)  # __NR_userfaultfd
    if uffd < 0:
        raise OSError(ctypes.get_errno(), "userfaultfd")
    region = libc.mmap(None, size, 3, 0x22, -1, 0)   # PROT_READ|WRITE, MAP_PRIVATE|ANON
    return uffd, region, size

def handler(uffd, region, size, page_to_copy):
    # ждём fault, затем копируем страницу -> отпускаем поток
    buf = ctypes.create_string_buffer(64)
    if libc.read(uffd, buf, 64) > 0:
        addr = int.from_bytes(buf[16:24], "little")   # pagefault.address
        dst = ctypes.c_void_p(addr)
        src = ctypes.c_char_p(page_to_copy)
        # ... ioctl(UFFDIO_COPY) ...
        print(f"[+] releasing fault at {hex(addr)}")
```

В реальном эксплойте обработчик вызывается в отдельном потоке, а основной готовит подмену. Ключевое — `UFFDIO_COPY` выполняется **только когда** нужное состояние уже создано. Это делает гонку детерминированной.

Ожидаемый вывод:

```
[+] userfaultfd registered at 0x7f...
[*] target thread frozen on page fault
[+] state prepared, releasing
[+] race won deterministically
```

## Альтернативы: mprotect, nanosleep, ptrace, SIGSTOP

Если `userfaultfd` недоступен:

- **`mprotect`.** Снимите `PROT_READ` с региона; обращение даст `SIGSEGV`, обработчик которого удерживает поток и восстанавливает права. Проще, чем uffd, но менее гибко.
- **`nanosleep`/`usleep`.** Если цель сама спит между check и use — окно уже широкое.
- **`ptrace`.** Приостановить поток в нужной точке через `PTRACE_SEIZE`/`PTRACE_INTERRUPT`; но это требует прав и не работает при anti-debug.
- **`SIGSTOP`/`SIGCONT`.** Послать потоку `SIGSTOP` в момент X и продолжить позже.
- **`sched_yield`/affinity.** Иногда достаточно привязать потоки к одному ядру и играть планировщиком.

Комбинируйте приёмы: `mprotect` для простого окна, `userfaultfd` для точного контроля, FUSE для файловых операций. В одной задаче может понадобиться связка — например, FUSE удерживает поток на `read`, а `userfaultfd` замораживает второй поток в момент, когда он готовит подмену.

## Стабилизация и измерение надёжности

Даже с расширенным окном полезно измерить, насколько надёжен ваш эксплойт. Практика такая: оберните запуск в цикл и считайте долю успехов.

```python
success = 0
for i in range(100):
    io = process('./chall')
    try:
        exploit(io)
        success += 1
    except Exception:
        pass
    finally:
        io.close()
print(f"reliability: {success}%")
```

Если надёжность ниже 50%, ищите узкое место: возможно, вы удерживаете поток не в той точке, или второй поток не успевает подготовить состояние. Иногда помогает добавить ещё один fault (два последовательных `UFFDIO_COPY`), чтобы получить два независимых окна. Для kernel-эксплойтов надёжность особенно важна: нестабильный эксплойт может паниковать ядро и убить вашу единственную точку входа. Поэтому перед «боевым» запуском прогоняйте десятки попыток на изолированной копии.

Помните и об ограничениях: `userfaultfd` — тяжёлый механизм, и некоторые песочницы его блокируют через seccomp. Всегда проверяйте доступность заранее, чтобы не строить весь план на недоступном примитиве.

## Частые ошибки

- **`vm.unprivileged_userfaultfd=0`.** Частая причина «не работает» — проверьте `sysctl`.
- **Гонка в самом обработчике.** Пока вы держите fault, не давайте нарушителю уйти: не выполняйте долгих операций в основном потоке.
- **FUSE без `/dev/fuse`.** Проверьте наличие устройства и прав.
- **Забыть `UFFDIO_COPY`.** Поток-нарушитель останется висеть вечно.
- **Один fault на всю гонку.** Иногда нужно несколько последовательных fault'ов — планируйте их заранее.

## Что дальше / решение

- Освойте `userfaultfd` на простом double-fetch — это базовый навык modern kernel-pwn.
- Смотрите `pwn-kernel-userfaultfd` для kernel-контекста и обхода `unprivileged_userfaultfd=0`.
- Для файловых гонок изучите FUSE на практике.
- Комбинируйте с `pwn-thread-races` для многопоточных целей.

## Справочные таблицы

| Приём | Сложность | Требования |
|---|---|---|
| userfaultfd | высокая | sysctl/CAP |
| FUSE | высокая | /dev/fuse |
| mprotect | средняя | — |
| ptrace | средняя | права |
| SIGSTOP | низкая | — |

| ioctl | Назначение |
|---|---|
| UFFDIO_API | инициализация |
| UFFDIO_REGISTER | регистрация региона |
| UFFDIO_COPY | заполнить и отпустить |

## Квиз

```quiz
- question: "Что делает userfaultfd при обращении к незаполненной странице?"
  options:
    - "Игнорирует обращение"
    - "Кладёт событие в очередь и удерживает поток до UFFDIO_COPY"
    - "Перезагружает страницу с диска"
    - "Отключает ASLR"
  answer: 1
  explanation: "Поток-нарушитель застревает, пока обработчик не отпустит его."
- question: "Зачем расширять окно гонки?"
  options:
    - "Чтобы ускорить программу"
    - "Чтобы сделать гонку детерминированной и воспроизводимой"
    - "Чтобы обойти NX"
    - "Чтобы создать поток"
  answer: 1
  explanation: "Точное удержание потока в критической точке убирает нестабильность."
- question: "Какая альтернатива userfaultfd использует SIGSEGV?"
  options:
    - "mprotect со снятием PROT_READ"
    - "nanosleep"
    - "sched_yield"
    - "fork"
  answer: 0
  explanation: "mprotect провоцирует segfault, который обрабатывает ваш сигнальный обработчик."
```

## Где пригодится

- **CTF:** задачи на гонки, где без расширения окна не обойтись.
- **Bug bounty:** эксплуатация double-fetch в драйверах.
- **Пентест:** kernel LPE с узким окном гонки.
- **Работа:** понимание userfaultfd и его влияния на безопасность.
