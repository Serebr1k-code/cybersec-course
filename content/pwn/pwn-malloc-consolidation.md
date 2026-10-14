---
id: pwn-malloc-consolidation
title: "Консолидация malloc: unlink, слияние и произвольная запись"
category: pwn
parent: pwn-heap-primitives
difficulty: expert
order: 3
tags: [heap, consolidation, unlink, unsorted-bin, top-chunk, glibc]
prerequisites: [pwn-chunk-overlap]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Разбираем консолидацию чанков: unlink и его проверки, слияние с top chunk и unsorted bin, и как превратить это в произвольную запись."
lab:
  kind: shell
  title: "Практика: размер слитого чанка"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, consol.c, consol, run.txt]
  check: "grep -q 'merged=0x841' answer.txt"
  hints:
    - "`cat run.txt` — размеры до и после free(B)."
    - "A и B по 0x420; backward consolidation сливает их."
    - "0x420 + 0x420 = 0x840, плюс флаг prev_inuse = 0x841."
    - "Запиши `merged=0x841`."
---
## Вопрос, с которого всё начинается

Когда мы освобождаем чанк, он попадает в список свободных. Но что произойдёт, если рядом освободить ещё один? Аллокатор не оставит их лежать по отдельности — он **сливает** соседей в один большой чанк. Этот процесс называется **консолидация**, и он — источник одной из самых старых и самых красивых атак на кучу.

Разберём, как работает слияние и как из него получить контролируемую запись.

## Наш пример

Возьмём три чанка по `0x410` байт данных и проследим, что происходит при освобождении:

```
A=0x129c8010 size=0x421
B=0x129c8430 size=0x421
G=0x129c8850 size=0x421
free(A): A -> unsorted (size 0x421)
free(B): backward consolidation B+A -> size 0x841 at 0x129c8010
malloc(0x830) -> 0x129c8010  (== A? yes)  size now 0x841
```

Смотри: после `free(A)` в `unsorted bin` лежит чанк `0x421`. После `free(B)` два соседних чанка слились в один размером `0x841` — и он начинается там же, где `A`. Запрос `malloc(0x830)` вернул этот слитый чанк.

## Шаг 1. Почему размеры такие

`malloc(0x410)` возвращает чанк размером `0x420` (запрос округляется вверх и прибавляется заголовок `0x10`). Младший бит в `size` — флаг `prev_inuse` («предыдущий чанк занят»). Мы берём `0x410`, а не `0x50`, по важной причине: чанки размером больше `0x410` **не попадают в tcache**, а значит свободно идут в `unsorted bin` и участвуют в консолидации. Маленькие чанки застряли бы в tcache и не слились.

## Шаг 2. Backward consolidation: слияние с предыдущим

Когда освобождают `B`, glibc смотрит на поле `prev_size` чанка `B` и на флаг `prev_inuse`. Если предыдущий чанк (`A`) свободен, происходит **слияние с предыдущим** (backward consolidation): `A` «поглощает» `B`, и в списке остаётся один чанк размером `A.size + B.size = 0x420 + 0x420 = 0x840`, начинающийся по адресу `A`. Именно это и показывает вывод: `size 0x841` (плюс флаг `prev_inuse`).

## Шаг 3. Unlink: как чанк покидает список

Свободные чанки в `unsorted bin` связаны двусвязным списком: у каждого есть `fd` (forward — вперёд) и `bk` (backward — назад). Когда чанк выбывает из списка (сливается или выдаётся), его надо «выцепить» из цепочки — эта операция называется **unlink**. Упрощённо она делает:

```c
next->bk = prev;    /* обходим удаляемый чанк */
prev->fd = next;
```

Если злоумышленник контролирует `fd` и `bk` чанка, который вот-вот выцепят, то эти две записи превращаются в **запись по двум произвольным адресам**. Классика: указать `fd = target - 0x18` и `bk = target - 0x10`, чтобы после unlink по адресу `target` оказался указатель на сам чанк. Так `unlink` даёт примитив «запиши адрес чанка в произвольное место».

## Шаг 4. Safe-unlink: проверка, которую добавили

Классический unlink-эксплойт работал, пока glibc не добавила проверку. Теперь перед unlink аллокатор сверяет:

```c
if (fd->bk != p || bk->fd != p)   /* p — удаляемый чанк */
    malloc_printerr ("corrupted double-linked list");
```

Смысл: `fd` должен указывать на чанк, у которого `bk` равен нашему чанку, и наоборот. Просто подставить произвольные адреса нельзя. Обход: найти в памяти **уже существующий** указатель на наш чанк `p` (например, в глобальном массиве указателей, который ведёт сама программа) и использовать его как «легального» соседа. Тогда проверка проходит, а запись идёт в тот адрес, который мы выбрали.

## Шаг 5. Из консолидации — в перекрытие

Консолидация — это ещё и способ сделать **overlap** больше, чем мы просили. Сценарий:

1. Выделяем `A`, `B`, `C` подряд.
2. Через off-by-one или UAF портим метаданные так, чтобы `B` считал `A` свободным.
3. Освобождаем `B` — срабатывает backward consolidation, и `A` (который на самом деле занят) втягивается в свободный чанк.
4. Аллоцируем большой кусок — он возвращает `A` и перекрывает всё, что было между.

Так консолидация усиливает перекрытие, полученное из прошлого урока.

## Шаг 6. Forward consolidation и слияние с top

Слияние бывает в обе стороны. **Forward consolidation** — когда освобождают `A`, а свободен `B` справа: тогда `A` втягивает `B`. Кроме того, если свободный чанк примыкает к **top chunk** (остатку арены), он сливается с ним и возвращается в кучу. Это нужно учитывать: слишком крупный свободный чанк может «раствориться» в top и исчезнуть из списка раньше, чем мы им воспользуемся.

## Шаг 7. Как консолидацию вызывают принудительно

Иногда нужно заставить glibc слить fastbin-чанки немедленно. Для этого запрашивают размер, не входящий в fastbin — например, большой блок. Тогда вызывается `malloc_consolidate`, которая обходит fastbin, сливает соседей и переносит результат в `unsorted bin`:

```python
alloc(0x500)   # провоцирует malloc_consolidate
```

Приём «fastbin dup + consolidate» часто используют, когда цель требует записи через `unsorted bin`.

## Шаг 8. Что смотреть при отладке

В отладчике с heap-плагином проверяй `bins` до и после `free`: увидишь, как два соседних чанка превращаются в один, и убедишься, что `fd`/`bk` указывают туда, куда ты ожидал. Полезно смотреть на флаг `prev_inuse` у правого соседа — именно он решает, будет ли backward consolidation.

## Если не сработало

Консолидация — операция, чувствительная к деталям раскладки. Если задуманное слияние не происходит, проверь по порядку.

Во-первых, размер. Маленькие чанки (до `0x410`) уходят в tcache и не сливаются. Если тебе нужен unlink в `unsorted bin`, работай с размером больше `0x410` либо сначала наполни tcache, чтобы освобождение прошло мимо него.

Во-вторых, флаг `prev_inuse`. Backward consolidation срабатывает только если у правого чанка сброшен младший бит `size`. Через off-by-one или UAF его надо обнулить — иначе `free` посчитает левого соседа занятым и просто положит чанк в bin отдельно.

В-третьих, `prev_size`. Если ты сбрасываешь `prev_inuse`, glibc начнёт доверять полю `prev_size` левого чанка. Оно должно быть корректным, иначе получишь `corrupted size vs. prev_size`. Иногда `prev_size` надо подделать вместе с флагом.

В-четвёртых, safe-unlink. На современной glibc наивная подстановка `fd`/`bk` падает с `corrupted double-linked list`. Ищи в памяти программы реальный указатель на твой чанк — глобальный массив, список объектов, указатель на «следующий свободный» — и строй `fd`/`bk` так, чтобы проверка `fd->bk == p && bk->fd == p` прошла.

В-пятых, top chunk. Если свободный чанк примыкает к вершине кучи, он сливается с top и исчезает из `unsorted bin`. Держи между рабочими чанками «сторожа» — маленькие занятые чанки, которые не дают слиянию дойти до top.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d consol

src/consol:     file format elf64-x86-64


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

0000000000001040 <setbuf@plt>:
    1040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 4008 <setbuf@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	push   $0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001050 <printf@plt>:
    1050:	ff 25 ba 2f 00 00    	jmp    *0x2fba(%rip)        # 4010 <printf@GLIBC_2.2.5>
    1056:	68 02 00 00 00       	push   $0x2
    105b:	e9 c0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001060 <malloc@plt>:
    1060:	ff 25 b2 2f 00 00    	jmp    *0x2fb2(%rip)        # 4018 <malloc@GLIBC_2.2.5>
    1066:	68 03 00 00 00       	push   $0x3
    106b:	e9 b0 ff ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .text:

0000000000001070 <_start>:
    1070:	f3 0f 1e fa          	endbr64
    1074:	31 ed                	xor    %ebp,%ebp
    1076:	49 89 d1             	mov    %rdx,%r9
    1079:	5e                   	pop    %rsi
    107a:	48 89 e2             	mov    %rsp,%rdx
    107d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1081:	50                   	push   %rax
    1082:	54                   	push   %rsp
    1083:	45 31 c0             	xor    %r8d,%r8d
    1086:	31 c9                	xor    %ecx,%ecx
    1088:	48 8d 3d da 00 00 00 	lea    0xda(%rip),%rdi        # 1169 <main>
    108f:	ff 15 2b 2f 00 00    	call   *0x2f2b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
    1095:	f4                   	hlt
    1096:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    109d:	00 00 00 

00000000000010a0 <deregister_tm_clones>:
    10a0:	48 8d 3d 89 2f 00 00 	lea    0x2f89(%rip),%rdi        # 4030 <stdout@GLIBC_2.2.5>
    10a7:	48 8d 05 82 2f 00 00 	lea    0x2f82(%rip),%rax        # 4030 <stdout@GLIBC_2.2.5>
    10ae:	48 39 f8             	cmp    %rdi,%rax
    10b1:	74 15                	je     10c8 <deregister_tm_clones+0x28>
    10b3:	48 8b 05 0e 2f 00 00 	mov    0x2f0e(%rip),%rax        # 3fc8 <_ITM_deregisterTMCloneTable>
    10ba:	48 85 c0             	test   %rax,%rax
    10bd:	74 09                	je     10c8 <deregister_tm_clones+0x28>
    10bf:	ff e0                	jmp    *%rax
    10c1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10c8:	c3                   	ret
    10c9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010d0 <register_tm_clones>:
    10d0:	48 8d 3d 59 2f 00 00 	lea    0x2f59(%rip),%rdi        # 4030 <stdout@GLIBC_2.2.5>
    10d7:	48 8d 35 52 2f 00 00 	lea    0x2f52(%rip),%rsi        # 4030 <stdout@GLIBC_2.2.5>
    10de:	48 29 fe             	sub    %rdi,%rsi
    10e1:	48 89 f0             	mov    %rsi,%rax
    10e4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10e8:	48 c1 f8 03          	sar    $0x3,%rax
    10ec:	48 01 c6             	add    %rax,%rsi
    10ef:	48 d1 fe             	sar    $1,%rsi
    10f2:	74 14                	je     1108 <register_tm_clones+0x38>
    10f4:	48 8b 05 dd 2e 00 00 	mov    0x2edd(%rip),%rax        # 3fd8 <_ITM_registerTMCloneTable>
    10fb:	48 85 c0             	test   %rax,%rax
    10fe:	74 08                	je     1108 <register_tm_clones+0x38>
    1100:	ff e0                	jmp    *%rax
    1102:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1108:	c3                   	ret
    1109:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001110 <__do_global_dtors_aux>:
    1110:	f3 0f 1e fa          	endbr64
    1114:	80 3d 1d 2f 00 00 00 	cmpb   $0x0,0x2f1d(%rip)        # 4038 <completed.0>
    111b:	75 33                	jne    1150 <__do_global_dtors_aux+0x40>
    111d:	55                   	push   %rbp
    111e:	48 83 3d ba 2e 00 00 	cmpq   $0x0,0x2eba(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1125:	00 
    1126:	48 89 e5             	mov    %rsp,%rbp
    1129:	74 0d                	je     1138 <__do_global_dtors_aux+0x28>
    112b:	48 8b 3d f6 2e 00 00 	mov    0x2ef6(%rip),%rdi        # 4028 <__dso_handle>
    1132:	ff 15 a8 2e 00 00    	call   *0x2ea8(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1138:	e8 63 ff ff ff       	call   10a0 <deregister_tm_clones>
    113d:	c6 05 f4 2e 00 00 01 	movb   $0x1,0x2ef4(%rip)        # 4038 <completed.0>
    1144:	5d                   	pop    %rbp
    1145:	c3                   	ret
    1146:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    114d:	00 00 00 
    1150:	c3                   	ret
    1151:	0f 1f 40 00          	nopl   0x0(%rax)
    1155:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    115c:	00 00 00 00 

0000000000001160 <frame_dummy>:
    1160:	f3 0f 1e fa          	endbr64
    1164:	e9 67 ff ff ff       	jmp    10d0 <register_tm_clones>

0000000000001169 <main>:
    1169:	55                   	push   %rbp
    116a:	48 89 e5             	mov    %rsp,%rbp
    116d:	48 83 ec 20          	sub    $0x20,%rsp
    1171:	48 8b 05 b8 2e 00 00 	mov    0x2eb8(%rip),%rax        # 4030 <stdout@GLIBC_2.2.5>
    1178:	be 00 00 00 00       	mov    $0x0,%esi
    117d:	48 89 c7             	mov    %rax,%rdi
    1180:	e8 bb fe ff ff       	call   1040 <setbuf@plt>
    1185:	bf 10 04 00 00       	mov    $0x410,%edi
    118a:	e8 d1 fe ff ff       	call   1060 <malloc@plt>
    118f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1193:	bf 10 04 00 00       	mov    $0x410,%edi
    1198:	e8 c3 fe ff ff       	call   1060 <malloc@plt>
    119d:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    11a1:	bf 10 04 00 00       	mov    $0x410,%edi
    11a6:	e8 b5 fe ff ff       	call   1060 <malloc@plt>
    11ab:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    11af:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11b3:	48 83 e8 08          	sub    $0x8,%rax
    11b7:	48 8b 10             	mov    (%rax),%rdx
    11ba:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11be:	48 8d 0d 43 0e 00 00 	lea    0xe43(%rip),%rcx        # 2008 <_IO_stdin_used+0x8>
    11c5:	48 89 c6             	mov    %rax,%rsi
    11c8:	48 89 cf             	mov    %rcx,%rdi
    11cb:	b8 00 00 00 00       	mov    $0x0,%eax
    11d0:	e8 7b fe ff ff       	call   1050 <printf@plt>
    11d5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11d9:	48 83 e8 08          	sub    $0x8,%rax
    11dd:	48 8b 10             	mov    (%rax),%rdx
    11e0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11e4:	48 8d 0d 2e 0e 00 00 	lea    0xe2e(%rip),%rcx        # 2019 <_IO_stdin_used+0x19>
    11eb:	48 89 c6             	mov    %rax,%rsi
    11ee:	48 89 cf             	mov    %rcx,%rdi
    11f1:	b8 00 00 00 00       	mov    $0x0,%eax
    11f6:	e8 55 fe ff ff       	call   1050 <printf@plt>
    11fb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11ff:	48 83 e8 08          	sub    $0x8,%rax
    1203:	48 8b 10             	mov    (%rax),%rdx
    1206:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    120a:	48 8d 0d 19 0e 00 00 	lea    0xe19(%rip),%rcx        # 202a <_IO_stdin_used+0x2a>
    1211:	48 89 c6             	mov    %rax,%rsi
    1214:	48 89 cf             	mov    %rcx,%rdi
    1217:	b8 00 00 00 00       	mov    $0x0,%eax
    121c:	e8 2f fe ff ff       	call   1050 <printf@plt>
    1221:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1225:	48 89 c7             	mov    %rax,%rdi
    1228:	e8 03 fe ff ff       	call   1030 <free@plt>
    122d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1231:	48 83 e8 08          	sub    $0x8,%rax
    1235:	48 8b 00             	mov    (%rax),%rax
    1238:	48 8d 15 01 0e 00 00 	lea    0xe01(%rip),%rdx        # 2040 <_IO_stdin_used+0x40>
    123f:	48 89 c6             	mov    %rax,%rsi
    1242:	48 89 d7             	mov    %rdx,%rdi
    1245:	b8 00 00 00 00       	mov    $0x0,%eax
    124a:	e8 01 fe ff ff       	call   1050 <printf@plt>
    124f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1253:	48 89 c7             	mov    %rax,%rdi
    1256:	e8 d5 fd ff ff       	call   1030 <free@plt>
    125b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    125f:	48 83 e8 08          	sub    $0x8,%rax
    1263:	48 8b 00             	mov    (%rax),%rax
    1266:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    126a:	48 8d 0d f7 0d 00 00 	lea    0xdf7(%rip),%rcx        # 2068 <_IO_stdin_used+0x68>
    1271:	48 89 c6             	mov    %rax,%rsi
    1274:	48 89 cf             	mov    %rcx,%rdi
    1277:	b8 00 00 00 00       	mov    $0x0,%eax
    127c:	e8 cf fd ff ff       	call   1050 <printf@plt>
    1281:	bf 30 08 00 00       	mov    $0x830,%edi
    1286:	e8 d5 fd ff ff       	call   1060 <malloc@plt>
    128b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    128f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1293:	48 83 e8 08          	sub    $0x8,%rax
    1297:	48 8b 10             	mov    (%rax),%rdx
    129a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    129e:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
    12a2:	75 09                	jne    12ad <main+0x144>
    12a4:	48 8d 05 f6 0d 00 00 	lea    0xdf6(%rip),%rax        # 20a1 <_IO_stdin_used+0xa1>
    12ab:	eb 07                	jmp    12b4 <main+0x14b>
    12ad:	48 8d 05 f1 0d 00 00 	lea    0xdf1(%rip),%rax        # 20a5 <_IO_stdin_used+0xa5>
    12b4:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
    12b8:	48 8d 3d e9 0d 00 00 	lea    0xde9(%rip),%rdi        # 20a8 <_IO_stdin_used+0xa8>
    12bf:	48 89 d1             	mov    %rdx,%rcx
    12c2:	48 89 c2             	mov    %rax,%rdx
    12c5:	b8 00 00 00 00       	mov    $0x0,%eax
    12ca:	e8 81 fd ff ff       	call   1050 <printf@plt>
    12cf:	b8 00 00 00 00       	mov    $0x0,%eax
    12d4:	c9                   	leave
    12d5:	c3                   	ret

Disassembly of section .fini:

00000000000012d8 <_fini>:
    12d8:	f3 0f 1e fa          	endbr64
    12dc:	48 83 ec 08          	sub    $0x8,%rsp
    12e0:	48 83 c4 08          	add    $0x8,%rsp
    12e4:	c3                   	ret
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Что мы теперь знаем

- Консолидация — слияние соседних свободных чанков в один большой.
- Backward — с предыдущим (`prev_size` + `prev_inuse`), forward — со следующим, плюс слияние с `top`.
- Свободные чанки связаны `fd`/`bk`; удаление из списка — это `unlink`.
- Контроль над `fd`/`bk` при unlink даёт запись по произвольному адресу.
- Safe-unlink сверяет `fd->bk == p` и `bk->fd == p`, поэтому нужен «легальный» указатель на чанк.
- Консолидация может усилить перекрытие, втянув занятый чанк в свободный.

## Квиз

Проверь себя.

```quiz
- question: "Что такое консолидация в glibc?"
  options:
    - "Слияние соседних свободных чанков в один большой"
    - "Шифрование указателей"
    - "Удаление canary"
    - "Сжатие кучи"
  answer: 0
  explanation: "Освобождённые соседние чанки сливаются, чтобы уменьшить фрагментацию."
- question: "Когда происходит backward consolidation?"
  options:
    - "Когда предыдущий чанк свободен (prev_inuse = 0)"
    - "Когда включён PIE"
    - "Когда tcache полон"
    - "Когда стек исполняемый"
  answer: 0
  explanation: "Слияние с предыдущим чанком идёт по prev_size при сброшенном prev_inuse."
- question: "Что делает unlink?"
  options:
    - "Выцепляет чанк из двусвязного списка: next->bk = prev; prev->fd = next"
    - "Шифрует чанк"
    - "Увеличивает tcache"
    - "Ставит canary"
  answer: 0
  explanation: "unlink связывает соседей, минуя удаляемый чанк."
- question: "Какую проверку добавила safe-unlink?"
  options:
    - "fd->bk == p && bk->fd == p"
    - "size > 0x410"
    - "prev_inuse == 1"
    - "key == tcache"
  answer: 0
  explanation: "Проверка не даёт подставить произвольные fd/bk без легального указателя на чанк."
- question: "Зачем используют malloc_consolidate?"
  options:
    - "Чтобы принудительно слить fastbin-чанки и перенести их в unsorted bin"
    - "Чтобы отключить ASLR"
    - "Чтобы убрать canary"
    - "Чтобы включить PIE"
  answer: 0
  explanation: "Запрос большого размера провоцирует слияние fastbin в unsorted bin."
```

## Куда дальше

В следующем уроке — `pwn-heap-tcache` — мы вернёмся к tcache и разберём **tcache poisoning**: самый короткий путь от UAF к произвольной аллокации в modern glibc. А пока главное: **консолидация сливает соседей, unlink выцепляет чанк из списка — и если контролировать `fd`/`bk`, это превращается в запись по произвольному адресу.**

## Где пригодится

- **CTF:** heap-задачи на консолидацию и unlink.
- **Bug bounty:** heap-баги в large-объектах.
- **Пентест:** эксплуатация heap-уязвимостей.
- **Работа:** глубокое понимание glibc-аллокатора.
