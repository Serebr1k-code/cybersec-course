---
id: pwn-buffer-overflow-core
title: "Переполнение буфера: format string, shellcode, integer overflow, stack clash"
category: pwn
parent: pwn-buffer-overflow
difficulty: medium
order: 1
tags: [pwn, buffer-overflow, format-string, shellcode, integer-overflow, stack-clash]
prerequisites: [pwn-buffer-overflow]
useful_for:
  - "CTF Pwn: классические stack-задачи"
  - "Аудит C/C++ кода"
estimated_minutes: 10
summary: "Модуль классического переполнения буфера: format string, shellcode, integer overflow и stack clash."
lab:
  kind: shell
  title: "Практика: смещение format string"
  toolset: [core, objdump, readelf]
  workdir: /home/student/task
  files: [task.md, fmt.c, fmt, out.txt]
  check: "grep -q 'offset=6' answer.txt"
  hints:
    - "`out.txt` — реальный вывод `printf(buf)`; аргументы идут через `.`."
    - "Позиция — это номер `%p` по порядку (первый `%p` = позиция 1)."
    - "Найди `%p`, который напечатал `0x4242424241414141` (это байты `AAAABBBB`)."
    - "Это шестой `%p`, значит буфер начинается с 6-го аргумента."
---
Этот модуль собирает классические разновидности переполнения буфера и связанных с ними уязвимостей стека — от format string до integer overflow и stack clash. Вместе они покрывают основу CTF-задач начального и среднего уровня.

## Что покрывает этап

**pwn-format-string** — format string: чтение и запись памяти через управляемый форматный спецификатор.
**pwn-shellcode** — shellcode: написание и размещение полезной нагрузки.
**pwn-integer-overflow** — integer overflow и type confusion как путь к переполнению буфера.
**pwn-stack-clash** — stack clash: атака на обработку больших стековых аллокаций.

## Почему такой порядок

Format string идёт первым: это отдельный и очень наглядный класс баг, не требующий переполнения. Shellcode — практический навык размещения полезной нагрузки. Integer overflow и stack clash замыкают модуль как менее очевидные, но важные пути к порче памяти.

## Что вы сможете после этапа

- Читать и записывать память через format string.
- Писать и размещать shellcode.
- Использовать integer overflow для достижения переполнения.
- Понимать механику stack clash и способы защиты от неё.

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
  40113a:	48 83 c4 80          	add    $0xffffffffffffff80,%rsp
  40113e:	48 8d 45 80          	lea    -0x80(%rbp),%rax
  401142:	ba 80 00 00 00       	mov    $0x80,%edx
  401147:	48 89 c6             	mov    %rax,%rsi
  40114a:	bf 00 00 00 00       	mov    $0x0,%edi
  40114f:	e8 ec fe ff ff       	call   401040 <read@plt>
  401154:	48 8d 45 80          	lea    -0x80(%rbp),%rax
  401158:	48 89 c7             	mov    %rax,%rdi
  40115b:	e8 d0 fe ff ff       	call   401030 <printf@plt>
  401160:	b8 00 00 00 00       	mov    $0x0,%eax
  401165:	c9                   	leave
  401166:	c3                   	ret

Disassembly of section .fini:

0000000000401168 <_fini>:
  401168:	f3 0f 1e fa          	endbr64
  40116c:	48 83 ec 08          	sub    $0x8,%rsp
  401170:	48 83 c4 08          	add    $0x8,%rsp
  401174:	c3                   	ret
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
$ readelf -s fmt

Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _[...]@GLIBC_2.34 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (3)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.2.5 (3)
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]

Symbol table '.symtab' contains 37 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crt1.o
     2: 0000000000402100    32 OBJECT  LOCAL  DEFAULT   18 __abi_tag
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtbegin.o
     4: 0000000000401090     0 FUNC    LOCAL  DEFAULT   12 deregister_tm_clones
     5: 00000000004010c0     0 FUNC    LOCAL  DEFAULT   12 register_tm_clones
     6: 0000000000401100     0 FUNC    LOCAL  DEFAULT   12 __do_global_dtors_aux
     7: 0000000000404020     1 OBJECT  LOCAL  DEFAULT   25 completed.0
     8: 0000000000403df0     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtor[...]
     9: 0000000000401130     0 FUNC    LOCAL  DEFAULT   12 frame_dummy
    10: 0000000000403de8     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_in[...]
    11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS fmt.c
    12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtend.o
    13: 00000000004020b8     0 OBJECT  LOCAL  DEFAULT   16 __FRAME_END__
    14: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    15: 0000000000403df8     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC
    16: 0000000000402004     0 NOTYPE  LOCAL  DEFAULT   15 __GNU_EH_FRAME_HDR
    17: 0000000000403fe8     0 OBJECT  LOCAL  DEFAULT   23 _GLOBAL_OFFSET_TABLE_
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    19: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
    20: 0000000000404010     0 NOTYPE  WEAK   DEFAULT   24 data_start
    21: 0000000000404020     0 NOTYPE  GLOBAL DEFAULT   24 _edata
    22: 0000000000401168     0 FUNC    GLOBAL HIDDEN    13 _fini
    23: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5
    24: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.2.5
    25: 0000000000404010     0 NOTYPE  GLOBAL DEFAULT   24 __data_start
    26: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    27: 0000000000404018     0 OBJECT  GLOBAL HIDDEN    24 __dso_handle
    28: 0000000000402000     4 OBJECT  GLOBAL DEFAULT   14 _IO_stdin_used
    29: 0000000000404028     0 NOTYPE  GLOBAL DEFAULT   25 _end
    30: 0000000000401080     5 FUNC    GLOBAL HIDDEN    12 _dl_relocate_sta[...]
    31: 0000000000401050    38 FUNC    GLOBAL DEFAULT   12 _start
    32: 0000000000404020     0 NOTYPE  GLOBAL DEFAULT   25 __bss_start
    33: 0000000000401136    49 FUNC    GLOBAL DEFAULT   12 main
    34: 0000000000404020     0 OBJECT  GLOBAL HIDDEN    24 __TMC_END__
    35: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    36: 0000000000401000     0 FUNC    GLOBAL HIDDEN    10 _init
```

Подсказка из лаборатории: `readelf [-s|--file-header] <файл>`.

<!-- lab -->

## Квиз

```quiz
- question: "Чем format string отличается от классического переполнения буфера?"
  options:
    - "Это отдельный класс баг, не требующий переполнения"
    - "Это то же самое"
    - "Он работает только в ядре"
    - "Он требует GPU"
  answer: 0
  explanation: "Format string использует управляемые спецификаторы формата."
- question: "Что нужно уметь делать с shellcode?"
  options:
    - "Писать и размещать полезную нагрузку"
    - "Только компилировать"
    - "Только шифровать"
    - "Только декомпилировать"
  answer: 0
  explanation: "Shellcode — это полезная нагрузка эксплойта."
- question: "Почему integer overflow и stack clash идут последними?"
  options:
    - "Это менее очевидные, но важные пути к порче памяти"
    - "Они проще остальных"
    - "Они не связаны с переполнением"
    - "Они устарели"
  answer: 0
  explanation: "Они требуют более глубокого понимания семантики."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
