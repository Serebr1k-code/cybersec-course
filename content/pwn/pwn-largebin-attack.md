---
id: pwn-largebin-attack
title: "Large bin attack: произвольная запись через большие чанки"
category: pwn
parent: pwn-heap-bin-attacks
difficulty: expert
order: 2
tags: [pwn, heap, glibc, largebin, malloc]
prerequisites: [pwn-heap-basics, pwn-heap-uaf]
useful_for:
  - "CTF Pwn — heap-задачи"
  - "Разработка эксплойтов"
estimated_minutes: 45
summary: "Устройство large bin в glibc, почему вставка чанка даёт запись указателя по контролируемому адресу и как применять примитив на современном glibc."
lab:
  kind: shell
  title: "Практика: граница large bin"
  toolset: [core, objdump]
  workdir: /home/student/task
  files: [task.md, largebin.c, largebin, run.txt]
  check: "grep -q 'threshold=0x400' answer.txt"
  hints:
    - "`cat largebin.c` — размер чанка 0x420."
    - "`cat run.txt` — чанк сортируется в large bin."
    - "Граница между small и large bins — 0x400."
    - "Запиши `threshold=0x400`."
---

## Вопрос, с которого всё начинается

Unsorted bin attack умела писать адрес libc, но на glibc 2.29 её закрыли проверкой. Как же тогда в современных задачах получают **произвольную запись**, да ещё и без double-free? Ответ — в другом списке: large bin. Чанки там отсортированы по размеру и связаны дополнительными указателями `fd_nextsize`/`bk_nextsize`. Подделав один из них, можно заставить `malloc` записать адрес чанка по выбранному адресу. Это **large bin attack**.

## Наш пример: два больших чанка

Возьмём программу, которая освобождает большой чанк и показывает его связи в large bin:

```c
#include "common.h"
int main(void){
    char *a = malloc(0x418);          /* чанк 0x420 -> largebin (>= 0x400) */
    char *b = malloc(0x418);
    char *guard = malloc(0x20);
    printf("a=%p b=%p\n", a, b);
    free(a);                          /* a -> unsorted bin */
    char *big = malloc(0x500);        /* триггерит сортировку: a уходит в largebin */
    unsigned long *c = (unsigned long*)a;
    printf("  fd=%p  bk=%p\n", (void*)c[0], (void*)c[1]);
    printf("  fd_nextsize=%p  bk_nextsize=%p\n", (void*)c[2], (void*)c[3]);
    ...
}
```

Почему `0x420`? Граница между small и large bins — `0x400`: чанки размером `≥ 0x400` идут в large bin. А `guard` не даёт чанку `a` слиться с top chunk, чтобы он остался отдельным.

## Шаг 1. Устройство large bin

В отличие от small bin, чанки в large bin **отсортированы по размеру**, и каждый чанк дополнительно связан с соседями *другого* размера через `fd_nextsize`/`bk_nextsize`. Смещения полей от начала чанка:

| Поле | Смещение | Смысл |
|---|---|---|
| `fd` | `0x10` | сосед в списке (тот же размер) |
| `bk` | `0x18` | сосед в списке (тот же размер) |
| `fd_nextsize` | `0x20` | следующий чанк другого размера |
| `bk_nextsize` | `0x28` | предыдущий чанк другого размера |

## Шаг 2. Смотрим реальные указатели

Компилируем и запускаем:

```
$ gcc -fno-pie -no-pie -O0 -o largebin largebin.c
$ ./largebin
a=0x127e9020 b=0x127e9440
a в largebin:
  fd=0x7f0eb79a6eb8  bk=0x7f0eb79a6eb8
  fd_nextsize=0x127e9010  bk_nextsize=0x127e9010
```

Читаем:

- `fd`/`bk` равны `0x7f…` — адрес в libc. Это голова large bin (внутри `main_arena`). Значит, чанк `a` — единственный, и оба указателя смотрят на список.
- `fd_nextsize`/`bk_nextsize` равны `0x127e9010` — это адрес **самого чанка** `a` минус `0x10` (шапка). Когда чанк в списке один, его `nextsize`-связи замкнуты на себя.

Почему «минус `0x10`»? Потому что `nextsize`-указатели тоже ссылаются на **начало шапки** чанка, а не на данные. Наш указатель `a` — это данные, то есть шапка на `0x10` раньше. Поэтому `fd_nextsize`/`bk_nextsize` и показывают `a - 0x10`. Это важно запомнить: все указатели в бинах адресуют шапку чанка.

Заметь, что `fd`/`bk` указывают в libc, а `nextsize` — в кучу. Когда чанков разного размера несколько, `nextsize` связывают их в отсортированную цепочку. Именно по этой цепочке и «проедет» запись при вставке нового чанка.

## Шаг 3. Механика атаки

Когда `malloc` вставляет новый чанк `victim` в large bin, выполняется такая последовательность:

```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;   /* ЗАПИСЬ */
```

Последняя строка пишет адрес `victim` в поле `fd_nextsize` чанка, лежащего по адресу `victim->bk_nextsize`. Поле `fd_nextsize` — на смещении `0x20`, значит запись идёт по `victim->bk_nextsize + 0x20`. Если подделать `victim->bk_nextsize = target - 0x20`, то по адресу `target` ляжет адрес `victim`. Произвольная запись **адреса чанка**.

Важно: записывается именно адрес чанка, а не произвольное значение. Поэтому цель должна быть указателем на структуру, которую вы контролируете (например, `_IO_list_all`), чтобы дальше подсунуть туда поддельный `_IO_FILE`.

## Шаг 4. Пробуем на современной glibc

Подделываем `bk_nextsize` у чанка `a` и триггерим вставку маленького чанка в large bin:

```c
unsigned long target = 0x4040a0;
c[3] = target - 0x20;                 /* a->bk_nextsize = target - 0x20 */
char *sm = malloc(0x100);
free(sm);                             /* sm -> unsorted */
char *t = malloc(0x500);              /* вставка sm в largebin */
printf("*(target)=%p\n", *(void**)target);
```

Запускаем:

```
$ ./largebin
подделываем a->bk_nextsize = 0x404080 (target-0x20)
corrupted double-linked list (not small)
Aborted (core dumped)
```

Атака **не проходит**: glibc падает с `corrupted double-linked list (not small)`. Это проверка, добавленная в 2.30: перед записью `malloc` сверяет, что `bck->fd == victim` и связи `nextsize` согласованы. Наивная подделка одного `bk_nextsize` ломает целостность — и аллокатор обрывается.

## Шаг 5. Как обходят проверку

Проверка требует, чтобы цель `target` уже содержала ожидаемый указатель, и чтобы связи large bin оставались согласованными. На практике это делают так:

1. **Два чанка разного размера в large bin.** Вставляют `victim` так, чтобы ветка кода с записью выполнилась при уже согласованных `fwd->bk`. Тогда проверка проходит, а запись всё равно происходит по `victim->bk_nextsize + 0x20`.
2. **House of God / House of Apple.** Large bin attack — их первый шаг: записать адрес контролируемого чанка в `_IO_list_all`, затем подделать `_IO_FILE` и вызвать `exit`. На glibc 2.34+ (где удалены `__free_hook`/`__malloc_hook`) это основной путь к исполнению.
3. **Другие цели.** `global_max_fast` (расширить fastbin), `mp_.tcache_bins` (расширить tcache), `__exit_funcs`.

Ключевое преимущество large bin attack: указатели в large bin **не маскируются safe-linking**, поэтому атака работает и на glibc 2.32+.

## Если не сработало

- **`corrupted double-linked list (not small)`.** Наивная подделка `bk_nextsize` не проходит проверку. Нужны согласованные связи — вставляйте так, чтобы выполнялось предусловие.
- **Чанк не в large bin.** Размер < `0x400` уходит в small bin. Берите ≥ `0x400`.
- **Чанк не отсортирован.** Пока чанк в unsorted bin, он не в large bin; нужен дополнительный `malloc` для сортировки.
- **Неверная цель.** Записывается адрес чанка — цель обязана быть указателем на контролируемую структуру.
- **Версия glibc.** Проверки в largebin path менялись; сверяйтесь с исходником `_int_malloc` для своей версии.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d largebin

src/largebin:     file format elf64-x86-64


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
    1195:	bf 18 04 00 00       	mov    $0x418,%edi
    119a:	e8 d1 fe ff ff       	call   1070 <malloc@plt>
    119f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    11a3:	bf 18 04 00 00       	mov    $0x418,%edi
    11a8:	e8 c3 fe ff ff       	call   1070 <malloc@plt>
    11ad:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    11b1:	bf 20 00 00 00       	mov    $0x20,%edi
    11b6:	e8 b5 fe ff ff       	call   1070 <malloc@plt>
    11bb:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    11bf:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    11c3:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    11c7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11cb:	48 8d 3d 36 0e 00 00 	lea    0xe36(%rip),%rdi        # 2008 <_IO_stdin_used+0x8>
    11d2:	48 89 c6             	mov    %rax,%rsi
    11d5:	b8 00 00 00 00       	mov    $0x0,%eax
    11da:	e8 81 fe ff ff       	call   1060 <printf@plt>
    11df:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    11e3:	48 83 e8 08          	sub    $0x8,%rax
    11e7:	48 8b 00             	mov    (%rax),%rax
    11ea:	48 8d 15 2f 0e 00 00 	lea    0xe2f(%rip),%rdx        # 2020 <_IO_stdin_used+0x20>
    11f1:	48 89 c6             	mov    %rax,%rsi
    11f4:	48 89 d7             	mov    %rdx,%rdi
    11f7:	b8 00 00 00 00       	mov    $0x0,%eax
    11fc:	e8 5f fe ff ff       	call   1060 <printf@plt>
    1201:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1205:	48 89 c7             	mov    %rax,%rdi
    1208:	e8 23 fe ff ff       	call   1030 <free@plt>
    120d:	48 8d 05 33 0e 00 00 	lea    0xe33(%rip),%rax        # 2047 <_IO_stdin_used+0x47>
    1214:	48 89 c7             	mov    %rax,%rdi
    1217:	e8 24 fe ff ff       	call   1040 <puts@plt>
    121c:	bf 00 05 00 00       	mov    $0x500,%edi
    1221:	e8 4a fe ff ff       	call   1070 <malloc@plt>
    1226:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    122a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    122e:	48 8d 15 33 0e 00 00 	lea    0xe33(%rip),%rdx        # 2068 <_IO_stdin_used+0x68>
    1235:	48 89 c6             	mov    %rax,%rsi
    1238:	48 89 d7             	mov    %rdx,%rdi
    123b:	b8 00 00 00 00       	mov    $0x0,%eax
    1240:	e8 1b fe ff ff       	call   1060 <printf@plt>
    1245:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1249:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    124d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1251:	48 83 c0 08          	add    $0x8,%rax
    1255:	48 8b 00             	mov    (%rax),%rax
    1258:	48 89 c2             	mov    %rax,%rdx
    125b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    125f:	48 8b 00             	mov    (%rax),%rax
    1262:	48 89 c1             	mov    %rax,%rcx
    1265:	48 8d 05 37 0e 00 00 	lea    0xe37(%rip),%rax        # 20a3 <_IO_stdin_used+0xa3>
    126c:	48 89 ce             	mov    %rcx,%rsi
    126f:	48 89 c7             	mov    %rax,%rdi
    1272:	b8 00 00 00 00       	mov    $0x0,%eax
    1277:	e8 e4 fd ff ff       	call   1060 <printf@plt>
    127c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1280:	48 83 c0 18          	add    $0x18,%rax
    1284:	48 8b 00             	mov    (%rax),%rax
    1287:	48 89 c2             	mov    %rax,%rdx
    128a:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    128e:	48 83 c0 10          	add    $0x10,%rax
    1292:	48 8b 00             	mov    (%rax),%rax
    1295:	48 89 c1             	mov    %rax,%rcx
    1298:	48 8d 05 11 0e 00 00 	lea    0xe11(%rip),%rax        # 20b0 <_IO_stdin_used+0xb0>
    129f:	48 89 ce             	mov    %rcx,%rsi
    12a2:	48 89 c7             	mov    %rax,%rdi
    12a5:	b8 00 00 00 00       	mov    $0x0,%eax
    12aa:	e8 b1 fd ff ff       	call   1060 <printf@plt>
    12af:	48 8d 05 1a 0e 00 00 	lea    0xe1a(%rip),%rax        # 20d0 <_IO_stdin_used+0xd0>
    12b6:	48 89 c7             	mov    %rax,%rdi
    12b9:	e8 82 fd ff ff       	call   1040 <puts@plt>
    12be:	b8 00 00 00 00       	mov    $0x0,%eax
    12c3:	c9                   	leave
    12c4:	c3                   	ret

Disassembly of section .fini:

00000000000012c8 <_fini>:
    12c8:	f3 0f 1e fa          	endbr64
    12cc:	48 83 ec 08          	sub    $0x8,%rsp
    12d0:	48 83 c4 08          	add    $0x8,%rsp
    12d4:	c3                   	ret
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Что мы теперь знаем

- Large bin — список чанков ≥ `0x400`, отсортированный по размеру.
- У чанков есть дополнительные поля `fd_nextsize`/`bk_nextsize` (смещения `0x20`/`0x28`).
- При вставке `malloc` пишет адрес `victim` по `victim->bk_nextsize + 0x20`.
- Подделав `bk_nextsize`, получаем запись адреса чанка по выбранному адресу.
- С glibc 2.30 проверка целостности блокирует наивный вариант.
- Safe-linking на large bin не действует — техника живёт на всех версиях.

## На что смотреть дальше

- **Предусловие проверки.** Цель должна содержать ожидаемый указатель.
- **Выбор цели.** `_IO_list_all` (FSOP), `global_max_fast`, `mp_.tcache_bins`.
- **Порядок операций.** Сначала подготовьте large bin, затем вставляйте `victim`.
- **Отладка.** `bins` и `x/8gx <addr>` в pwndbg показывают связи `nextsize`.
- **Цепочка целиком.** Large bin — только шаг; планируйте FSOP наперёд.

## Квиз

Проверь себя.

```quiz
- question: "Какой минимальный размер (на 64-бит) нужен чанку, чтобы попасть в large bin?"
  options:
    - "0x80"
    - "0x400"
    - "0x20"
    - "0x10000"
  answer: 1
  explanation: "MIN_LARGE_SIZE = 0x400 на 64-бит; меньшие уходят в small bins."
- question: "Какое значение записывается примитивом large bin attack?"
  options:
    - "Адрес вставляемого чанка victim"
    - "Адрес main_arena"
    - "Ноль"
    - "Указатель на стек"
  answer: 0
  explanation: "Выполняется victim->bk_nextsize->fd_nextsize = victim, где victim — heap-адрес."
- question: "Какая проверка мешает наивной атаке с glibc 2.30+?"
  options:
    - "Сверка целостности связей nextsize (иначе corrupted double-linked list)"
    - "Шифрование safe-linking"
    - "Запрет чанков > 0x1000"
    - "Полное отключение large bins"
  answer: 0
  explanation: "Аллокатор проверяет согласованность bck->fd и nextsize-связей."
- question: "Почему нужен дополнительный malloc после free большого чанка?"
  options:
    - "Чтобы чанк отсортировался из unsorted bin в large bin"
    - "Чтобы сбросить кэш процессора"
    - "Чтобы увеличить энтропию ASLR"
    - "Чтобы очистить tcache"
  answer: 0
  explanation: "Пока чанк в unsorted bin, он не в large bin; сортировка — при следующем malloc."
- question: "Почему large bin attack работает и на glibc 2.32+?"
  options:
    - "Указатели large bin не маскируются safe-linking"
    - "safe-linking отключается автоматически"
    - "Она использует tcache"
    - "Она не пишет по адресу"
  answer: 0
  explanation: "safe-linking защищает только fastbin/tcache, а не nextsize-связи large bin."
```

## Куда дальше

В `pwn-mmap-exploitation` мы разберём чанки, которые glibc создаёт через `mmap`, и атаки вроде House of Muney. А пока главное: **large bin даёт запись адреса чанка через `bk_nextsize`, и это работает даже на новых glibc.**

## Где пригодится

- **CTF:** категория Pwn — heap-задачи уровня expert, где нужен write-primitive без утечки libc.
- **Bug bounty:** понимание внутренностей malloc помогает в задачах на real-world heap-уязвимости в сервисах.
- **Пентест:** эксплуатация heap-багов в нативных сервисах (парсеры, демоны).
- **Работа:** разработка эксплойтов, анализ glibc-митигаций, security research.
