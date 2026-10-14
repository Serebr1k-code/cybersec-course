---
id: reversing-mod-debuggers
title: "Модуль: Современные отладчики и точки наблюдения"
category: reversing
parent: reversing-module-advanced
difficulty: medium
order: 1
tags: [reversing, rizin, lldb, x64dbg, windbg, watchpoints, roadmap]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: точная отладка сложных бинарников"
  - "Malware analysis: отладка под Windows и macOS"
estimated_minutes: 6
summary: "Подмодуль об отладочном инструментарии: rizin/Cutter, LLDB, Windows-отладчики (x64dbg/WinDbg), аппаратные breakpoints и watchpoints."
lab:
  kind: shell
  title: 'Практика: аппаратный watchpoint в gdb'
  toolset: [core, hex, rev]
  workdir: /home/student/task
  files: [task.md, wp]
  check: 'grep -q ''nto{hw_w4tchp01nt_c4tch3s_wr1t3}'' found.txt'
  hints:
    - '`file wp` — ELF. Отладчик: `gdb ./wp`.'
    - 'Поставь точку на `decode`, затем watchpoint на `unlocked`.'
    - '`gdb -batch -ex ''b decode'' -ex run -ex ''watch unlocked'' -ex continue -ex ''x/s &flagbuf'' wp`.'
---

GDB — не единственный отладчик, и часто не лучший. Для Windows это x64dbg и WinDbg, для macOS —
LLDB, для быстрого интерактивного разбора — rizin/Cutter. А когда программные breakpoints
бесполезны (код расшифровывается на лету), на первый план выходят аппаратные точки останова и
watchpoints, следящие за чтением/записью памяти.

## Что покрывает подмодуль

- **reversing-rizin-cutter** — rizin (форк radare2) и графический Cutter: анализ, эмуляция,
  скрипты на r2pipe/Python, визуальный граф функций.
- **reversing-lldb** — LLDB: команды, Python-скриптинг, отладка Mach-O и ядра, интеграция с Xcode.
- **reversing-windows-debuggers** — x64dbg и WinDbg: скрипты, плагины, расширения `!analyze`,
  анализ дампов и структур Windows.
- **reversing-watchpoints-hwbp** — аппаратные точки останова (DR0–DR7), watchpoints на
  чтение/запись, ограничения (4 точки), применение к самомодифицирующемуся коду.

## Почему такой порядок

Инструменты идут от кроссплатформенного и лёгкого (rizin/Cutter) к платформенным (LLDB, Windows).
Аппаратные точки наблюдения — отдельный навык поверх любого отладчика, поэтому замыкают подмодуль:
они нужны, когда обычные средства не работают.

## Что вы будете уметь

- Выбирать отладчик под платформу и задачу и уверенно им пользоваться.
- Писать скрипты автоматизации для rizin/LLDB/WinDbg.
- Ставить аппаратные watchpoints на адрес памяти и ловить момент расшифровки/записи.
- Отлаживать бинарники там, где программные breakpoints неэффективны.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -d wp

wp:     file format elf64-x86-64


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

Disassembly of section .text:

0000000000401020 <_start>:
  401020:	f3 0f 1e fa          	endbr64
  401024:	31 ed                	xor    ebp,ebp
  401026:	49 89 d1             	mov    r9,rdx
  401029:	5e                   	pop    rsi
  40102a:	48 89 e2             	mov    rdx,rsp
  40102d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401031:	50                   	push   rax
  401032:	54                   	push   rsp
  401033:	45 31 c0             	xor    r8d,r8d
  401036:	31 c9                	xor    ecx,ecx
  401038:	48 c7 c7 51 11 40 00 	mov    rdi,0x401151
  40103f:	ff 15 83 2f 00 00    	call   QWORD PTR [rip+0x2f83]        # 403fc8 <__libc_start_main@GLIBC_2.34>
  401045:	f4                   	hlt
  401046:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40104d:	00 00 00 

0000000000401050 <_dl_relocate_static_pie>:
  401050:	f3 0f 1e fa          	endbr64
  401054:	c3                   	ret
  401055:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40105c:	00 00 00 
  40105f:	90                   	nop

0000000000401060 <deregister_tm_clones>:
  401060:	b8 10 40 40 00       	mov    eax,0x404010
  401065:	48 3d 10 40 40 00    	cmp    rax,0x404010
  40106b:	74 13                	je     401080 <deregister_tm_clones+0x20>
  40106d:	48 8b 05 5c 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f5c]        # 403fd0 <_ITM_deregisterTMCloneTable>
  401074:	48 85 c0             	test   rax,rax
  401077:	74 07                	je     401080 <deregister_tm_clones+0x20>
  401079:	bf 10 40 40 00       	mov    edi,0x404010
  40107e:	ff e0                	jmp    rax
  401080:	c3                   	ret
  401081:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401085:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40108c:	00 00 00 00 

0000000000401090 <register_tm_clones>:
  401090:	be 10 40 40 00       	mov    esi,0x404010
  401095:	48 81 ee 10 40 40 00 	sub    rsi,0x404010
  40109c:	48 89 f0             	mov    rax,rsi
  40109f:	48 c1 ee 3f          	shr    rsi,0x3f
  4010a3:	48 c1 f8 03          	sar    rax,0x3
  4010a7:	48 01 c6             	add    rsi,rax
  4010aa:	48 d1 fe             	sar    rsi,1
  4010ad:	74 19                	je     4010c8 <register_tm_clones+0x38>
  4010af:	48 8b 05 2a 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f2a]        # 403fe0 <_ITM_registerTMCloneTable>
  4010b6:	48 85 c0             	test   rax,rax
  4010b9:	74 0d                	je     4010c8 <register_tm_clones+0x38>
  4010bb:	bf 10 40 40 00       	mov    edi,0x404010
  4010c0:	ff e0                	jmp    rax
  4010c2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4010c8:	c3                   	ret
  4010c9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000004010d0 <__do_global_dtors_aux>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	80 3d 45 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f45],0x0        # 404020 <completed.0>
  4010db:	75 13                	jne    4010f0 <__do_global_dtors_aux+0x20>
  4010dd:	55                   	push   rbp
  4010de:	48 89 e5             	mov    rbp,rsp
  4010e1:	e8 7a ff ff ff       	call   401060 <deregister_tm_clones>
  4010e6:	c6 05 33 2f 00 00 01 	mov    BYTE PTR [rip+0x2f33],0x1        # 404020 <completed.0>
  4010ed:	5d                   	pop    rbp
  4010ee:	c3                   	ret
  4010ef:	90                   	nop
  4010f0:	c3                   	ret
  4010f1:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  4010f5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4010fc:	00 00 00 00 

0000000000401100 <frame_dummy>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	eb 8a                	jmp    401090 <register_tm_clones>

0000000000401106 <decode>:
  401106:	55                   	push   rbp
  401107:	48 89 e5             	mov    rbp,rsp
  40110a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  401111:	eb 24                	jmp    401137 <decode+0x31>
  401113:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  401116:	48 8d 15 03 0f 00 00 	lea    rdx,[rip+0xf03]        # 402020 <enc>
  40111d:	0f b6 04 10          	movzx  eax,BYTE PTR [rax+rdx*1]
  401121:	83 f0 33             	xor    eax,0x33
  401124:	89 c1                	mov    ecx,eax
  401126:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  401129:	48 8d 15 30 2f 00 00 	lea    rdx,[rip+0x2f30]        # 404060 <flagbuf>
  401130:	88 0c 10             	mov    BYTE PTR [rax+rdx*1],cl
  401133:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
  401137:	83 7d fc 1f          	cmp    DWORD PTR [rbp-0x4],0x1f
  40113b:	76 d6                	jbe    401113 <decode+0xd>
  40113d:	c6 05 3c 2f 00 00 00 	mov    BYTE PTR [rip+0x2f3c],0x0        # 404080 <flagbuf+0x20>
  401144:	c7 05 f2 2e 00 00 01 	mov    DWORD PTR [rip+0x2ef2],0x1        # 404040 <unlocked>
  40114b:	00 00 00 
  40114e:	90                   	nop
  40114f:	5d                   	pop    rbp
  401150:	c3                   	ret

0000000000401151 <main>:
  401151:	55                   	push   rbp
  401152:	48 89 e5             	mov    rbp,rsp
  401155:	e8 ac ff ff ff       	call   401106 <decode>
  40115a:	b8 00 00 00 00       	mov    eax,0x0
  40115f:	5d                   	pop    rbp
  401160:	c3                   	ret

Disassembly of section .fini:

0000000000401164 <_fini>:
  401164:	f3 0f 1e fa          	endbr64
  401168:	48 83 ec 08          	sub    rsp,0x8
  40116c:	48 83 c4 08          	add    rsp,0x8
  401170:	c3                   	ret
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf readelf --file-header wp
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401020
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14920 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         14
  Size of section headers:           64 (bytes)
  Number of section headers:         34
  Section header string table index: 33
```

Подсказка из лаборатории: `readelf <опция> <файл>`.

## Квиз

```quiz
- question: "Сколько аппаратных точек останова доступно на x86-64 обычно?"
  options:
    - "4"
    - "1"
    - "16"
    - "Неограниченно"
  answer: 0
- question: "Для чего используют watchpoint?"
  options:
    - "Остановиться при чтении/записи по адресу памяти"
    - "Ускорить выполнение"
    - "Подменить библиотеку"
    - "Распаковать бинарник"
  answer: 0
- question: "Какой отладчик штатный для macOS?"
  options:
    - "LLDB"
    - "WinDbg"
    - "x64dbg"
    - "OllyDbg"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** crackme с самомодифицирующимся кодом, упакованные бинарники.
- **Malware analysis:** отладка Windows-образцов, анализ дампов.
- **Vuln research:** точное наблюдение за доступом к памяти при эксплуатации.
