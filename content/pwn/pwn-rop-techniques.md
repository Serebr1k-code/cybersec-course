---
id: pwn-rop-techniques
title: "ROP: базовые техники (GOT/PLT, поиск гаджетов, ret2csu, stack pivot)"
category: pwn
parent: pwn-rop
difficulty: medium
order: 2
tags: [pwn, rop, got, plt, gadgets, ret2csu, stack-pivot]
prerequisites: [pwn-rop]
useful_for:
  - "CTF Pwn: построение ROP-цепочек"
  - "Обход NX без libc"
estimated_minutes: 10
summary: "Первый ROP-этап: базовый арсенал return-oriented programming — GOT/PLT, поиск гаджетов, ret2csu и stack pivot."
lab:
  kind: shell
  title: "Практика: поиск гаджета pop rdi; ret"
  toolset: [core, objdump, nm]
  workdir: /home/student/task
  files: [task.md, rop, rop.objdump.txt, rop.ropgadget.txt]
  check: "grep -q 'pop_rdi=0x401111' answer.txt"
  hints:
    - "Гаджет `pop rdi; ret` в x86-64 ставит первый аргумент функции."
    - "Байты гаджета: `5f c3` (`pop rdi` = `5f`, `ret` = `c3`)."
    - "`rop.objdump.txt` содержит метку `<g_pop_rdi>` с адресом."
    - "`rop.ropgadget.txt` подтверждает: `0x401111 : pop rdi ; ret`."
---
Первый из двух ROP-модулей. Здесь базовый арсенал return-oriented programming: как получить управление, как искать гаджеты и как строить цепочки вызовов, когда удобных примитивов не хватает.

## Что покрывает этап

**pwn-got-plt** — GOT/PLT: как работает отложенное связывание и как через него вызывать функции.
**pwn-gadget-hunting** — поиск гаджетов (ROPgadget, ropper, pwntools) и построение цепочки.
**pwn-ret2csu** — ret2csu: вызов функций с нужными аргументами через __libc_csu_init.
**pwn-stack-pivot** — stack pivot: перенос стека, когда места под цепочку мало.

## Почему такой порядок

GOT/PLT — фундамент, без него непонятно, куда возвращаться и как вызывать функции. Затем поиск гаджетов — практический навык, который используется постоянно. ret2csu решает проблему установки аргументов в x86-64, а stack pivot нужен, когда цепочка не помещается в доступное место.

## Что вы сможете после этапа

- Читать GOT/PLT и использовать их в ROP-цепочке.
- Искать гаджеты и собирать из них вызов функции.
- Применять ret2csu для установки аргументов.
- Делать stack pivot при нехватке места под цепочку.

## Инструмент: nm — таблица символов

`nm` перечисляет символы бинарника: имена функций и глобальных переменных с их адресами. Если символы не срезаны, это самый быстрый способ найти нужную функцию.

Ключи, которые пригодятся:
* `nm <файл>` — все символы с адресами;
* `nm -C <файл>` — демутируй C++-имена (читаемые сигнатуры);
* `T`/`t` — код (глобальный/локальный), `R`/`r` — только чтение (`.rodata`), `D`/`B` — данные;
* нижний регистр = локальный символ, верхний = глобальный/экспортируемый.

### Рабочий пример (как в лаборатории)

```
$ nm rop
0000000000403e38 d _DYNAMIC
0000000000403fe8 d _GLOBAL_OFFSET_TABLE_
0000000000402000 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
0000000000402088 r __FRAME_END__
0000000000402004 r __GNU_EH_FRAME_HDR
0000000000404028 D __TMC_END__
00000000004020d0 r __abi_tag
0000000000404028 B __bss_start
0000000000404000 D __data_start
00000000004010d0 t __do_global_dtors_aux
0000000000403e30 d __do_global_dtors_aux_fini_array_entry
0000000000404008 D __dso_handle
0000000000403e28 d __frame_dummy_init_array_entry
                 w __gmon_start__
                 U __libc_start_main@GLIBC_2.34
0000000000401050 T _dl_relocate_static_pie
0000000000404028 D _edata
0000000000404030 B _end
0000000000401118 T _fini
0000000000401000 T _init
0000000000401020 T _start
0000000000404028 b completed.0
0000000000404000 W data_start
0000000000401060 t deregister_tm_clones
0000000000401100 t frame_dummy
0000000000401111 T g_pop_rdi
0000000000401113 T g_pop_rsi
0000000000401115 T g_syscall
0000000000404010 D gadgets
0000000000401106 T main
0000000000401090 t register_tm_clones
```

Подсказка из лаборатории: `nm <файл>`.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump -d rop

rop:     file format elf64-x86-64


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

Disassembly of section .text:

0000000000401020 <_start>:
  401020:	f3 0f 1e fa          	endbr64
  401024:	31 ed                	xor    %ebp,%ebp
  401026:	49 89 d1             	mov    %rdx,%r9
  401029:	5e                   	pop    %rsi
  40102a:	48 89 e2             	mov    %rsp,%rdx
  40102d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  401031:	50                   	push   %rax
  401032:	54                   	push   %rsp
  401033:	45 31 c0             	xor    %r8d,%r8d
  401036:	31 c9                	xor    %ecx,%ecx
  401038:	48 c7 c7 06 11 40 00 	mov    $0x401106,%rdi
  40103f:	ff 15 83 2f 00 00    	call   *0x2f83(%rip)        # 403fc8 <__libc_start_main@GLIBC_2.34>
  401045:	f4                   	hlt
  401046:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40104d:	00 00 00 

0000000000401050 <_dl_relocate_static_pie>:
  401050:	f3 0f 1e fa          	endbr64
  401054:	c3                   	ret
  401055:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40105c:	00 00 00 
  40105f:	90                   	nop

0000000000401060 <deregister_tm_clones>:
  401060:	b8 28 40 40 00       	mov    $0x404028,%eax
  401065:	48 3d 28 40 40 00    	cmp    $0x404028,%rax
  40106b:	74 13                	je     401080 <deregister_tm_clones+0x20>
  40106d:	48 8b 05 5c 2f 00 00 	mov    0x2f5c(%rip),%rax        # 403fd0 <_ITM_deregisterTMCloneTable>
  401074:	48 85 c0             	test   %rax,%rax
  401077:	74 07                	je     401080 <deregister_tm_clones+0x20>
  401079:	bf 28 40 40 00       	mov    $0x404028,%edi
  40107e:	ff e0                	jmp    *%rax
  401080:	c3                   	ret
  401081:	0f 1f 40 00          	nopl   0x0(%rax)
  401085:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  40108c:	00 00 00 00 

0000000000401090 <register_tm_clones>:
  401090:	be 28 40 40 00       	mov    $0x404028,%esi
  401095:	48 81 ee 28 40 40 00 	sub    $0x404028,%rsi
  40109c:	48 89 f0             	mov    %rsi,%rax
  40109f:	48 c1 ee 3f          	shr    $0x3f,%rsi
  4010a3:	48 c1 f8 03          	sar    $0x3,%rax
  4010a7:	48 01 c6             	add    %rax,%rsi
  4010aa:	48 d1 fe             	sar    $1,%rsi
  4010ad:	74 19                	je     4010c8 <register_tm_clones+0x38>
  4010af:	48 8b 05 2a 2f 00 00 	mov    0x2f2a(%rip),%rax        # 403fe0 <_ITM_registerTMCloneTable>
  4010b6:	48 85 c0             	test   %rax,%rax
  4010b9:	74 0d                	je     4010c8 <register_tm_clones+0x38>
  4010bb:	bf 28 40 40 00       	mov    $0x404028,%edi
  4010c0:	ff e0                	jmp    *%rax
  4010c2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4010c8:	c3                   	ret
  4010c9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000004010d0 <__do_global_dtors_aux>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	80 3d 4d 2f 00 00 00 	cmpb   $0x0,0x2f4d(%rip)        # 404028 <__TMC_END__>
  4010db:	75 13                	jne    4010f0 <__do_global_dtors_aux+0x20>
  4010dd:	55                   	push   %rbp
  4010de:	48 89 e5             	mov    %rsp,%rbp
  4010e1:	e8 7a ff ff ff       	call   401060 <deregister_tm_clones>
  4010e6:	c6 05 3b 2f 00 00 01 	movb   $0x1,0x2f3b(%rip)        # 404028 <__TMC_END__>
  4010ed:	5d                   	pop    %rbp
  4010ee:	c3                   	ret
  4010ef:	90                   	nop
  4010f0:	c3                   	ret
  4010f1:	0f 1f 40 00          	nopl   0x0(%rax)
  4010f5:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  4010fc:	00 00 00 00 

0000000000401100 <frame_dummy>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	eb 8a                	jmp    401090 <register_tm_clones>

0000000000401106 <main>:
  401106:	55                   	push   %rbp
  401107:	48 89 e5             	mov    %rsp,%rbp
  40110a:	b8 00 00 00 00       	mov    $0x0,%eax
  40110f:	5d                   	pop    %rbp
  401110:	c3                   	ret

0000000000401111 <g_pop_rdi>:
  401111:	5f                   	pop    %rdi
  401112:	c3                   	ret

0000000000401113 <g_pop_rsi>:
  401113:	5e                   	pop    %rsi
  401114:	c3                   	ret

0000000000401115 <g_syscall>:
  401115:	0f 05                	syscall
  401117:	c3                   	ret

Disassembly of section .fini:

0000000000401118 <_fini>:
  401118:	f3 0f 1e fa          	endbr64
  40111c:	48 83 ec 08          	sub    $0x8,%rsp
  401120:	48 83 c4 08          	add    $0x8,%rsp
  401124:	c3                   	ret
```

Подсказка из лаборатории: `objdump [-d] <файл>`.

## Квиз

```quiz
- question: "Зачем нужен ret2csu?"
  options:
    - "Для вызова функций с аргументами, когда нет удобных гаджетов pop rdi/rsi/rdx"
    - "Для шифрования трафика"
    - "Для обхода ASLR"
    - "Для отладки ядра"
  answer: 0
  explanation: "ret2csu использует __libc_csu_init для загрузки аргументов."
- question: "Когда применяют stack pivot?"
  options:
    - "Когда нет GOT"
    - "Когда цепочка ROP не помещается в доступное место стека"
    - "Когда отключён ASLR"
    - "Только в ядре"
  answer: 1
  explanation: "Pivot переносит стек туда, где есть место."
- question: "Что даёт знание GOT/PLT при построении ROP?"
  options:
    - "Понимание, куда возвращаться и как вызывать функции"
    - "Ускорение компиляции"
    - "Шифрование гаджетов"
    - "Обход seccomp"
  answer: 0
  explanation: "GOT/PLT — это точки вызова и адреса функций."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
