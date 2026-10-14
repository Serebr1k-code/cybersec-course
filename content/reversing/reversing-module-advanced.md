---
id: reversing-module-advanced
title: "Модуль: Продвинутая отладка и защита кода"
category: reversing
parent: reversing-dynamic-debug
difficulty: hard
order: 3
tags: [reversing, debuggers, unpacking, protectors, roadmap]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: упакованные и защищённые бинарники"
  - "Malware analysis: обход протекторов и анти-анализа"
  - "Vuln research: точная отладка сложных целей"
estimated_minutes: 8
summary: "Навигационный модуль по продвинутой отладке и защите кода: современные отладчики, точки наблюдения, распаковка, коммерческие протекторы и обход анти-анализа."
lab:
  kind: shell
  title: 'Практика: анти-отладка и распаковка'
  toolset: [core, hex, rev]
  workdir: /home/student/task
  files: [task.md, adv, enc.bin, unpack.py]
  check: 'grep -q ''nto{4nt1_d3bug_then_unp4ck}'' found.txt'
  hints:
    - '`objdump -d adv | grep ptrace` — вызов `ptrace(PTRACE_TRACEME,...)`.'
    - '`strings adv` — маркер анти-отладки в секции `.note.stub`.'
    - 'Полезная нагрузка XOR-зашифрована: `python3 unpack.py enc.bin`.'
---

Когда бинарник упакован UPX, защищён VMProtect или Themida, отказывается отлаживаться и проверяет
целостность собственного кода — обычного «запустил в gdb и посмотрел» недостаточно. Этот модуль
собирает техники, которые превращают чёрный ящик в управляемый объект: правильные отладчики под
каждую платформу, аппаратные точки наблюдения, автоматическую и ручную распаковку, а также
методологию обхода защит.

## Что покрывает модуль

- **reversing-mod-debuggers** — современный инструментарий отладки: rizin/Cutter, LLDB,
  Windows-отладчики (x64dbg, WinDbg), а также аппаратные точки останова и watchpoints, без которых
  невозможно поймать обращение к памяти в упакованном коде.
- **reversing-mod-protection** — защита кода и её снятие: распаковка UPX и кастомных упаковщиков,
  коммерческие протекторы (VMProtect, Themida), обход анти-отладочных и анти-VM приёмов, проверки
  целостности и защита от патчинга.

## Почему такой порядок

Отладка идёт первой: распаковка и обход протекторов почти всегда выполняются под отладчиком или
трассировщиком, поэтому уверенное владение инструментом — предпосылка. Затем защита: она требует
не только инструмента, но и понимания, как устроены анти-анализ и упаковщики, и как их нейтрализовать
на каждом уровне (скрипт, патч, эмуляция).

## Что вы будете уметь

- Выбирать отладчик под задачу и платформу и настраивать его для работы с защищёнными бинарниками.
- Ставить аппаратные точки останова и watchpoints там, где программные breakpoints бесполезны
  (самомодифицирующийся код, самодешифровка).
- Распаковывать UPX и кастомные упаковщики, находить OEP и дампить образ из памяти.
- Распознавать и обходить типовые анти-отладочные проверки и определять коммерческий протектор.

## Как пользоваться модулем

Если вы ещё не работали с чем-то кроме gdb/Ghidra — начните с **reversing-mod-debuggers**, раздел
про rizin/Cutter и Windows-отладчики. Если отладка для вас привычна, переходите к
**reversing-mod-protection** и тренируйтесь на CTF-бинарниках, упакованных UPX и защищённых
протекторами. Уроки внутри каждого подмодуля упорядочены по возрастанию сложности.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -d adv

adv:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 c9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fc9]        # 403fd8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <puts@plt-0x10>:
  401020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 403ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 403ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401030 <puts@plt>:
  401030:	ff 25 ca 2f 00 00    	jmp    QWORD PTR [rip+0x2fca]        # 404000 <puts@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	push   0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401040 <ptrace@plt>:
  401040:	ff 25 c2 2f 00 00    	jmp    QWORD PTR [rip+0x2fc2]        # 404008 <ptrace@GLIBC_2.2.5>
  401046:	68 01 00 00 00       	push   0x1
  40104b:	e9 d0 ff ff ff       	jmp    401020 <_init+0x20>

Disassembly of section .text:

0000000000401050 <_start>:
  401050:	f3 0f 1e fa          	endbr64
  401054:	31 ed                	xor    ebp,ebp
  401056:	49 89 d1             	mov    r9,rdx
  401059:	5e                   	pop    rsi
  40105a:	48 89 e2             	mov    rdx,rsp
  40105d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401061:	50                   	push   rax
  401062:	54                   	push   rsp
  401063:	45 31 c0             	xor    r8d,r8d
  401066:	31 c9                	xor    ecx,ecx
  401068:	48 c7 c7 36 11 40 00 	mov    rdi,0x401136
  40106f:	ff 15 53 2f 00 00    	call   QWORD PTR [rip+0x2f53]        # 403fc8 <__libc_start_main@GLIBC_2.34>
  401075:	f4                   	hlt
  401076:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40107d:	00 00 00 

0000000000401080 <_dl_relocate_static_pie>:
  401080:	f3 0f 1e fa          	endbr64
  401084:	c3                   	ret
  401085:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40108c:	00 00 00 
  40108f:	90                   	nop

0000000000401090 <deregister_tm_clones>:
  401090:	b8 20 40 40 00       	mov    eax,0x404020
  401095:	48 3d 20 40 40 00    	cmp    rax,0x404020
  40109b:	74 13                	je     4010b0 <deregister_tm_clones+0x20>
  40109d:	48 8b 05 2c 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f2c]        # 403fd0 <_ITM_deregisterTMCloneTable>
  4010a4:	48 85 c0             	test   rax,rax
  4010a7:	74 07                	je     4010b0 <deregister_tm_clones+0x20>
  4010a9:	bf 20 40 40 00       	mov    edi,0x404020
  4010ae:	ff e0                	jmp    rax
  4010b0:	c3                   	ret
  4010b1:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  4010b5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4010bc:	00 00 00 00 

00000000004010c0 <register_tm_clones>:
  4010c0:	be 20 40 40 00       	mov    esi,0x404020
  4010c5:	48 81 ee 20 40 40 00 	sub    rsi,0x404020
  4010cc:	48 89 f0             	mov    rax,rsi
  4010cf:	48 c1 ee 3f          	shr    rsi,0x3f
  4010d3:	48 c1 f8 03          	sar    rax,0x3
  4010d7:	48 01 c6             	add    rsi,rax
  4010da:	48 d1 fe             	sar    rsi,1
  4010dd:	74 19                	je     4010f8 <register_tm_clones+0x38>
  4010df:	48 8b 05 fa 2e 00 00 	mov    rax,QWORD PTR [rip+0x2efa]        # 403fe0 <_ITM_registerTMCloneTable>
  4010e6:	48 85 c0             	test   rax,rax
  4010e9:	74 0d                	je     4010f8 <register_tm_clones+0x38>
  4010eb:	bf 20 40 40 00       	mov    edi,0x404020
  4010f0:	ff e0                	jmp    rax
  4010f2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4010f8:	c3                   	ret
  4010f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000401100 <__do_global_dtors_aux>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	80 3d 15 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f15],0x0        # 404020 <__TMC_END__>
  40110b:	75 13                	jne    401120 <__do_global_dtors_aux+0x20>
  40110d:	55                   	push   rbp
  40110e:	48 89 e5             	mov    rbp,rsp
  401111:	e8 7a ff ff ff       	call   401090 <deregister_tm_clones>
  401116:	c6 05 03 2f 00 00 01 	mov    BYTE PTR [rip+0x2f03],0x1        # 404020 <__TMC_END__>
  40111d:	5d                   	pop    rbp
  40111e:	c3                   	ret
  40111f:	90                   	nop
  401120:	c3                   	ret
  401121:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401125:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40112c:	00 00 00 00 

0000000000401130 <frame_dummy>:
  401130:	f3 0f 1e fa          	endbr64
  401134:	eb 8a                	jmp    4010c0 <register_tm_clones>

0000000000401136 <main>:
  401136:	55                   	push   rbp
  401137:	48 89 e5             	mov    rbp,rsp
  40113a:	b9 00 00 00 00       	mov    ecx,0x0
  40113f:	ba 00 00 00 00       	mov    edx,0x0
  401144:	be 00 00 00 00       	mov    esi,0x0
  401149:	bf 00 00 00 00       	mov    edi,0x0
  40114e:	b8 00 00 00 00       	mov    eax,0x0
  401153:	e8 e8 fe ff ff       	call   401040 <ptrace@plt>
  401158:	48 85 c0             	test   rax,rax
  40115b:	79 16                	jns    401173 <main+0x3d>
  40115d:	48 8d 05 a0 0e 00 00 	lea    rax,[rip+0xea0]        # 402004 <_IO_stdin_used+0x4>
  401164:	48 89 c7             	mov    rdi,rax
  401167:	e8 c4 fe ff ff       	call   401030 <puts@plt>
  40116c:	b8 01 00 00 00       	mov    eax,0x1
  401171:	eb 14                	jmp    401187 <main+0x51>
  401173:	48 8d 05 9c 0e 00 00 	lea    rax,[rip+0xe9c]        # 402016 <_IO_stdin_used+0x16>
  40117a:	48 89 c7             	mov    rdi,rax
  40117d:	e8 ae fe ff ff       	call   401030 <puts@plt>
  401182:	b8 00 00 00 00       	mov    eax,0x0
  401187:	5d                   	pop    rbp
  401188:	c3                   	ret

Disassembly of section .fini:

000000000040118c <_fini>:
  40118c:	f3 0f 1e fa          	endbr64
  401190:	48 83 ec 08          	sub    rsp,0x8
  401194:	48 83 c4 08          	add    rsp,0x8
  401198:	c3                   	ret
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Квиз

```quiz
- question: "Почему в упакованном бинарнике программный breakpoint может не сработать?"
  options:
    - "Код расшифровывается во время выполнения, адреса и байты меняются"
    - "Отладчик не умеет ставить breakpoints"
    - "Упакованный код не выполняется"
    - "Нужно всегда использовать только hardware breakpoints"
  answer: 0
- question: "Что такое OEP при распаковке?"
  options:
    - "Original Entry Point — точка входа распакованной программы"
    - "Оптимизированный формат PE"
    - "Таблица импортов"
    - "Секция с ресурсами"
  answer: 0
- question: "Какой приём типичен для анти-отладки?"
  options:
    - "Вызов ptrace(PTRACE_TRACEME) и проверка результата"
    - "Использование malloc"
    - "Вызов printf"
    - "Чтение argv"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** упакованные и обфусцированные бинарники, crackme с защитой.
- **Malware analysis:** снятие протекторов, обход анти-анализа, дамп полезной нагрузки.
- **Vuln research:** отладка сложных целей с проверками целостности.
- **Работа (RE-команда):** построение методики разбора защищённого коммерческого ПО.
