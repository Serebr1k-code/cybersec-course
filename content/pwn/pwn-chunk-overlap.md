---
id: pwn-chunk-overlap
title: "Перекрытие чанков: overlap и двойная аллокация"
category: pwn
parent: pwn-heap-primitives
difficulty: expert
order: 2
tags: [heap, overlap, off-by-one, uaf, tcache, glibc]
prerequisites: [pwn-partial-overwrite]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 50
summary: "Разбираем перекрытие чанков: как получить два аллоцированных региона на одной памяти, через off-by-one, UAF и подделку size, и как это превратить в arbitrary write."
lab:
  kind: shell
  title: "Практика: corrupted size"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, overlap.c, overlap, run.txt]
  check: "grep -q 'size=0xe1' answer.txt"
  hints:
    - "`cat overlap.c` — какой байт и куда пишется (off-by-one)."
    - "`cat run.txt` — размеры A/B/C и результат порчи."
    - "Было 0x61, младший байт заменяется на 0xe1."
    - "Запиши `size=0xe1`."
---
## Вопрос, с которого всё начинается

Мы уже умеем писать по произвольному адресу и переезжать внутри страницы. Но есть приём, который даёт почти всемогущество на куче: заставить аллокатор выдать **два разных указателя на одну и ту же память**. Тогда мы читаем и пишем одни байты двумя разными «ручками» — а значит, можем незаметно портить служебные поля объекта, который считаем целым.

Приём называется **перекрытие чанков** (chunk overlap). Разберём, как его получают и зачем.

## Наш пример

Соберём стенд из трёх чанков `A`, `B`, `C` по `0x50` байт данных каждый и посмотрим их заголовки:

```
A=0x1f5d6010 size=0x61
B=0x1f5d6070 size=0x61
C=0x1f5d60d0 size=0x61
```

Адреса идут с шагом `0x60`: `A` — на `...010`, `B` — на `...070`, `C` — на `...0d0`. Размер `0x61` — это `0x60` плюс младший бит `1` (флаг «предыдущий чанк занят», `prev_inuse`). Термин простой: у каждого чанка есть поле `size`, где хранится его длина, а последний бит говорит, свободен ли сосед слева.

## Шаг 1. Заголовок чанка

Каждый чанк в glibc начинается с **заголовка** из двух машинных слов (по 8 байт на amd64):

| Поле | Смещение | Смысл |
|---|---|---|
| `prev_size` | `-0x10` от данных | размер предыдущего чанка, если он свободен |
| `size` | `-0x8` от данных | размер этого чанка + флаги |

`malloc` возвращает указатель **на данные**, то есть на `+0x10` от начала чанка. Поэтому `size` лежит на 8 байт **перед** выданным указателем.

## Шаг 2. Портим размер на один байт

Теперь ключевой трюк. Пусть у нас есть уязвимость, позволяющая записать **один байт за границей** буфера `A` — это называется off-by-one. Мы пишем этот байт в поле `size` чанка `A`:

```c
((unsigned char*)A)[-8] = 0xe1;   /* было 0x61, стало 0xe1 */
```

Вывод программы подтверждает:

```
corrupted A.size -> 0xe1  (covers A and B)
```

Теперь аллокатор думает, что чанк `A` имеет размер `0xe0`, а не `0x60`. То есть «охватывает» не только себя, но и `B` (и кусочек `C`).

## Шаг 3. Освобождаем A и получаем увеличенный чанк

Освобождаем `A`. Аллокатор верит подделанному размеру и кладёт в `unsorted bin` (корзину свободных чанков) кусок размером `0xe0`:

```c
free(A);   /* A -> unsorted bin, size 0xe0 */
```

## Шаг 4. Аллоцируем — и получаем перекрытие

Просим у `malloc` большой кусок, ровно под этот размер:

```c
void *D = malloc(0xd0);   /* возвращает A, но охватывает A и B */
```

Вывод:

```
D = malloc(0xd0) = 0x1f5d6010  (== A? yes)
```

`D` равен `A`. Но теперь `D` простирается на `0xe0` байт — то есть **накрывает `B`**, который всё ещё считается выделенным. Проверим, что `D` и `B` делят память: пишем байты в `B`, читаем их через `D`:

```
wrote 'B' bytes to B[0..15]:  D[0x60..0x6f] now = 42 42 ...
wrote 0x99 via D[0x60..]:       B[0..1] now  = 99 99
```

Два указателя, одна память. Изменение через `D` видно в `B`, и наоборот.

## Шаг 5. Зачем это нужно

Перекрытие — универсальный усилитель. Что оно даёт:

1. **Подмена служебных полей.** Через один чанк правим `fd`/`bk` другого, готовя tcache poisoning или unsorted bin attack.
2. **Чтение чужих данных.** Перекрыв объект, читаем его указатели и утекаем адреса.
3. **Обход проверок.** Аллокатор «не видит» порчи, потому что смотрит на подделанный размер.
4. **Управление объектом с указателем функции.** Перекрываем C++-объект или структуру с `callback` и подменяем указатель.

## Шаг 6. Как ещё получают перекрытие

Кроме off-by-one размера есть и другие пути:

| Приём | Как работает |
|---|---|
| off-by-one / off-by-null | порча поля `size` соседа |
| UAF + fastbin/tcache dup | один чанк выдаётся дважды (см. прошлый урок) |
| double-free | цикл в списке свободных |
| largebin attack | подмена `bk_nextsize` даёт overlap больших чанков |

Все они ведут к одному: два указателя на одну память.

## Полный прогон от начала до конца

Соберём всю историю в один сценарий. У нас есть меню-программа: `alloc(size)`, `edit(idx, data)` — и `edit` на один байт выходит за границу. Задача — перекрыть два объекта и подменить указатель одного из них.

1. `alloc(0x50)` -> `A`; `alloc(0x50)` -> `B`; `alloc(0x50)` -> `C`.
2. `edit(A, b'A'*0x50 + b'\xe1')` — off-by-one меняет `A.size` с `0x61` на `0xe1`.
3. `free(A)` — в `unsorted bin` ложится чанк `0xe0`.
4. `alloc(0xd0)` -> `D`, перекрывающий `B`.
5. Теперь `edit(D, ...)` на смещении `0x60` пишет в **данные `B`**, хотя `B` считается выделенным. Подменяем в `B` нужный указатель (например, `callback` или `fd` следующего чанка) и пользуемся.

На каждом шаге мы не знаем полных адресов — всё держится на относительной раскладке чанков.

## Шаг 7. Что мешает

На modern glibc есть проверки, ловящие грубую порчу:

- **`prev_inuse`.** При освобождении glibc сверяет размер предыдущего чанка; неверный `prev_size` даёт `corrupted size vs. prev_size`.
- **Проверка `size` следующего чанка.** `free()` смотрит на `nextchunk->size` — если он выходит за границы арены, падает `invalid next size`.
- **`safe-linking`** шифрует указатели в списках, усложняя подмену.
- **Консолидация.** Большие запросы сливают чанки — нужно аккуратно подбирать размеры.

Поэтому перекрытие обычно строят не «в один ход», а комбинируя: сначала UAF/off-by-one, потом нужный размер, потом операция, которая превращает overlap в примитив чтения/записи.

## Если не сработало

Перекрытие редко получается «в лоб», потому что современные проверки glibc ловят грубые ошибки. Если программа падает на `free`, разбирайся по шагам.

Первое: проверь, не попал ли чанк в `tcache`. Освобождения маленьких чанков (до `0x410`) сначала идут в tcache, а не в `unsorted bin`, и там не сливаются. Чтобы дойти до консолидации, размер должен быть больше `0x410` либо tcache нужного размера должен быть полон.

Второе: убедись, что `prev_inuse` соседа действительно сброшен. Для backward consolidation glibc смотрит на младший бит `size` следующего чанка. Если он равен `1`, слияния не будет — чанк просто встанет в bin отдельно.

Третье: не выходи за пределы арены. Если подделанный `size` уводит «следующий чанк» за границу выделенной кучей памяти, `free` напечатает `invalid next size` и упадёт. Подбирай размер так, чтобы следующий чанк оставался внутри арены.

Четвёртое: safe-linking. На glibc 2.32+ указатели в tcache и fastbin зашифрованы; прямая запись «сырого» адреса в `fd` не сработает без знания heap-базы. Для обхода либо утекай базу, либо используй частичную перезапись (см. прошлый урок).

Наконец, помни: цель — не сам overlap, а примитив. Задай себе вопрос: что я сделаю с двумя ручками на одну память? Подменю указатель функции, испорчу `fd` соседа или прочитаю чужой указатель? От ответа зависит, какой именно объект надо перекрыть.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d overlap

src/overlap:     file format elf64-x86-64


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

0000000000001040 <putchar@plt>:
    1040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 4008 <putchar@GLIBC_2.2.5>
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
    1098:	48 8d 3d da 00 00 00 	lea    0xda(%rip),%rdi        # 1179 <main>
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

0000000000001179 <main>:
    1179:	55                   	push   %rbp
    117a:	48 89 e5             	mov    %rsp,%rbp
    117d:	48 83 ec 30          	sub    $0x30,%rsp
    1181:	48 8b 05 b0 2e 00 00 	mov    0x2eb0(%rip),%rax        # 4038 <stdout@GLIBC_2.2.5>
    1188:	be 00 00 00 00       	mov    $0x0,%esi
    118d:	48 89 c7             	mov    %rax,%rdi
    1190:	e8 bb fe ff ff       	call   1050 <setbuf@plt>
    1195:	bf 50 00 00 00       	mov    $0x50,%edi
    119a:	e8 d1 fe ff ff       	call   1070 <malloc@plt>
    119f:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    11a3:	bf 50 00 00 00       	mov    $0x50,%edi
    11a8:	e8 c3 fe ff ff       	call   1070 <malloc@plt>
    11ad:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    11b1:	bf 50 00 00 00       	mov    $0x50,%edi
    11b6:	e8 b5 fe ff ff       	call   1070 <malloc@plt>
    11bb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    11bf:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11c3:	48 83 e8 08          	sub    $0x8,%rax
    11c7:	48 8b 10             	mov    (%rax),%rdx
    11ca:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    11ce:	48 8d 0d 33 0e 00 00 	lea    0xe33(%rip),%rcx        # 2008 <_IO_stdin_used+0x8>
    11d5:	48 89 c6             	mov    %rax,%rsi
    11d8:	48 89 cf             	mov    %rcx,%rdi
    11db:	b8 00 00 00 00       	mov    $0x0,%eax
    11e0:	e8 7b fe ff ff       	call   1060 <printf@plt>
    11e5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11e9:	48 83 e8 08          	sub    $0x8,%rax
    11ed:	48 8b 10             	mov    (%rax),%rdx
    11f0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11f4:	48 8d 0d 1e 0e 00 00 	lea    0xe1e(%rip),%rcx        # 2019 <_IO_stdin_used+0x19>
    11fb:	48 89 c6             	mov    %rax,%rsi
    11fe:	48 89 cf             	mov    %rcx,%rdi
    1201:	b8 00 00 00 00       	mov    $0x0,%eax
    1206:	e8 55 fe ff ff       	call   1060 <printf@plt>
    120b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    120f:	48 83 e8 08          	sub    $0x8,%rax
    1213:	48 8b 10             	mov    (%rax),%rdx
    1216:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    121a:	48 8d 0d 09 0e 00 00 	lea    0xe09(%rip),%rcx        # 202a <_IO_stdin_used+0x2a>
    1221:	48 89 c6             	mov    %rax,%rsi
    1224:	48 89 cf             	mov    %rcx,%rdi
    1227:	b8 00 00 00 00       	mov    $0x0,%eax
    122c:	e8 2f fe ff ff       	call   1060 <printf@plt>
    1231:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1235:	48 83 e8 08          	sub    $0x8,%rax
    1239:	c6 00 e1             	movb   $0xe1,(%rax)
    123c:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1240:	48 83 e8 08          	sub    $0x8,%rax
    1244:	48 8b 00             	mov    (%rax),%rax
    1247:	48 8d 15 f2 0d 00 00 	lea    0xdf2(%rip),%rdx        # 2040 <_IO_stdin_used+0x40>
    124e:	48 89 c6             	mov    %rax,%rsi
    1251:	48 89 d7             	mov    %rdx,%rdi
    1254:	b8 00 00 00 00       	mov    $0x0,%eax
    1259:	e8 02 fe ff ff       	call   1060 <printf@plt>
    125e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1262:	48 89 c7             	mov    %rax,%rdi
    1265:	e8 c6 fd ff ff       	call   1030 <free@plt>
    126a:	bf d0 00 00 00       	mov    $0xd0,%edi
    126f:	e8 fc fd ff ff       	call   1070 <malloc@plt>
    1274:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    1278:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    127c:	48 3b 45 f0          	cmp    -0x10(%rbp),%rax
    1280:	75 09                	jne    128b <main+0x112>
    1282:	48 8d 05 e4 0d 00 00 	lea    0xde4(%rip),%rax        # 206d <_IO_stdin_used+0x6d>
    1289:	eb 07                	jmp    1292 <main+0x119>
    128b:	48 8d 05 df 0d 00 00 	lea    0xddf(%rip),%rax        # 2071 <_IO_stdin_used+0x71>
    1292:	48 8b 4d d8          	mov    -0x28(%rbp),%rcx
    1296:	48 8d 3d db 0d 00 00 	lea    0xddb(%rip),%rdi        # 2078 <_IO_stdin_used+0x78>
    129d:	48 89 c2             	mov    %rax,%rdx
    12a0:	48 89 ce             	mov    %rcx,%rsi
    12a3:	b8 00 00 00 00       	mov    $0x0,%eax
    12a8:	e8 b3 fd ff ff       	call   1060 <printf@plt>
    12ad:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    12b4:	eb 14                	jmp    12ca <main+0x151>
    12b6:	8b 45 fc             	mov    -0x4(%rbp),%eax
    12b9:	48 63 d0             	movslq %eax,%rdx
    12bc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    12c0:	48 01 d0             	add    %rdx,%rax
    12c3:	c6 00 42             	movb   $0x42,(%rax)
    12c6:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    12ca:	83 7d fc 0f          	cmpl   $0xf,-0x4(%rbp)
    12ce:	7e e6                	jle    12b6 <main+0x13d>
    12d0:	48 8d 05 c9 0d 00 00 	lea    0xdc9(%rip),%rax        # 20a0 <_IO_stdin_used+0xa0>
    12d7:	48 89 c7             	mov    %rax,%rdi
    12da:	b8 00 00 00 00       	mov    $0x0,%eax
    12df:	e8 7c fd ff ff       	call   1060 <printf@plt>
    12e4:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    12eb:	eb 30                	jmp    131d <main+0x1a4>
    12ed:	8b 45 f8             	mov    -0x8(%rbp),%eax
    12f0:	83 c0 60             	add    $0x60,%eax
    12f3:	48 63 d0             	movslq %eax,%rdx
    12f6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    12fa:	48 01 d0             	add    %rdx,%rax
    12fd:	0f b6 00             	movzbl (%rax),%eax
    1300:	0f b6 c0             	movzbl %al,%eax
    1303:	48 8d 15 c9 0d 00 00 	lea    0xdc9(%rip),%rdx        # 20d3 <_IO_stdin_used+0xd3>
    130a:	89 c6                	mov    %eax,%esi
    130c:	48 89 d7             	mov    %rdx,%rdi
    130f:	b8 00 00 00 00       	mov    $0x0,%eax
    1314:	e8 47 fd ff ff       	call   1060 <printf@plt>
    1319:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    131d:	83 7d f8 03          	cmpl   $0x3,-0x8(%rbp)
    1321:	7e ca                	jle    12ed <main+0x174>
    1323:	bf 0a 00 00 00       	mov    $0xa,%edi
    1328:	e8 13 fd ff ff       	call   1040 <putchar@plt>
    132d:	b8 00 00 00 00       	mov    $0x0,%eax
    1332:	c9                   	leave
    1333:	c3                   	ret

Disassembly of section .fini:

0000000000001334 <_fini>:
    1334:	f3 0f 1e fa          	endbr64
    1338:	48 83 ec 08          	sub    $0x8,%rsp
    133c:	48 83 c4 08          	add    $0x8,%rsp
    1340:	c3                   	ret
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Что мы теперь знаем

- Заголовок чанка — `prev_size` и `size`; `malloc` возвращает данные на `+0x10`.
- Порча одного байта `size` заставляет аллокатор считать чанк больше, чем он есть.
- `free` подделанного чанка кладёт в `unsorted bin` увеличенный кусок.
- Последующий `malloc` возвращает его, перекрывая соседний выделенный чанк.
- Перекрытие даёт две «ручки» на одну память — усилитель для любой heap-атаки.
- Modern glibc ловит грубую порчу проверками `prev_inuse` и `next size`.

## Квиз

Проверь себя.

```quiz
- question: "Что хранится в поле size чанка?"
  options:
    - "Размер чанка и флаги (например, prev_inuse)"
    - "Только адрес следующего чанка"
    - "Canary"
    - "Указатель на vtable"
  answer: 0
  explanation: "size хранит длину чанка, младший бит — флаг prev_inuse."
- question: "Где лежит size относительно указателя, который вернул malloc?"
  options:
    - "На 8 байт перед указателем"
    - "На 8 байт после указателя"
    - "В GOT"
    - "В tcache"
  answer: 0
  explanation: "malloc возвращает данные на +0x10 от начала чанка, значит size на -0x8."
- question: "Что делает порча одного байта size?"
  options:
    - "Аллокатор начинает считать чанк больше, чем он есть"
    - "Отключает ASLR"
    - "Снимает canary"
    - "Шифрует чанк"
  answer: 0
  explanation: "Подделанный размер заставляет free положить в bin увеличенный кусок."
- question: "Как получить перекрытие после порчи размера?"
  options:
    - "Освободить чанк и снова аллоцировать кусок под увеличенный размер"
    - "Вызвать printf"
    - "Включить PIE"
    - "Перезапустить программу"
  answer: 0
  explanation: "free кладёт увеличенный чанк в bin, malloc возвращает его поверх соседа."
- question: "Какая проверка glibc ловит неверный prev_size?"
  options:
    - "corrupted size vs. prev_size"
    - "unaligned chunk"
    - "double free in tcache"
    - "stack smashing"
  answer: 0
  explanation: "При освобождении glibc сверяет prev_size с размером предыдущего чанка."
```

## Куда дальше

В следующем уроке — `pwn-malloc-consolidation` — мы разберём, что происходит, когда освобождённые чанки **сливаются**: как работает `unlink` связанных списков и как из слияния получить контролируемую запись. А пока запомни: **перекрытие — это две ручки на одну память, и почти любая серьёзная heap-атака начинается именно с него.**

## Где пригодится

- **CTF:** heap-задачи с off-by-one, UAF и double-free.
- **Bug bounty:** heap-баги в парсерах и браузерах.
- **Пентест:** эксплуатация heap-уязвимостей в сервисах.
- **Работа:** понимание современного heap-эксплойта.
