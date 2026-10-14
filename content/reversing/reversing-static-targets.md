---
id: reversing-static-targets
title: "Статический анализ: цели (прошивки, malware, shellcode)"
category: reversing
parent: reversing-static-analysis
difficulty: hard
order: 3
tags: [reversing, static-analysis, firmware, malware, shellcode]
prerequisites: [reversing-static-analysis]
useful_for:
  - "Анализ malware и прошивок"
  - "CTF Reversing: shellcode-задачи"
estimated_minutes: 10
summary: "Второй модуль статического анализа: специфические цели — прошивки, статический анализ malware и shellcode."
lab:
  kind: shell
  title: 'Практика: stripped-бинарь без символов'
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, target]
  check: 'grep -q ''nto{str1pp3d_b1n4ry_n0_sym6ols}'' found.txt'
  hints:
    - '`nm target` скажет `no symbols` — это ожидаемо.'
    - 'Ищи строки: `strings target`.'
    - '`strings target | grep nto`.'
---
Второй модуль статического анализа посвящён специфическим целям, где «обычный» разбор не работает: прошивки с чужой архитектурой, malware без символов и позиционно-независимый shellcode.

## Что покрывает этап

**reversing-firmware** — статический анализ прошивок: распаковка образов, архитектуры, поиск точек входа.
**reversing-malware-static** — статический анализ malware: строки, импорты, YARA, устойчивость к обфускации.
**reversing-shellcode-analysis** — анализ shellcode: позиционно-независимый код, декодирование, эмуляция.

## Почему такой порядок

Прошивки идут первыми: там статический анализ часто единственный доступный метод. Malware-static второй — он опирается на инструменты из первого модуля и добавляет специфику вредоносного кода. Shellcode замыкает модуль как самый низкоуровневый и неструктурированный объект анализа.

## Что вы сможете после этапа

- Распаковывать и анализировать образы прошивок.
- Проводить статический анализ malware и писать YARA-правила.
- Разбирать позиционно-независимый shellcode и эмулировать его.

## Инструмент: nm — таблица символов

`nm` перечисляет символы бинарника: имена функций и глобальных переменных с их адресами. Если символы не срезаны, это самый быстрый способ найти нужную функцию.

Ключи, которые пригодятся:
* `nm <файл>` — все символы с адресами;
* `nm -C <файл>` — демутируй C++-имена (читаемые сигнатуры);
* `T`/`t` — код (глобальный/локальный), `R`/`r` — только чтение (`.rodata`), `D`/`B` — данные;
* нижний регистр = локальный символ, верхний = глобальный/экспортируемый.

### Рабочий пример (как в лаборатории)

```
$ nm nm target
nm: target: no symbols
```

Подсказка из лаборатории: `nm <файл> — таблица символов`.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -d target

target:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <.text>:
  401000:	31 c0                	xor    %eax,%eax
  401002:	0f b6 0f             	movzbl (%rdi),%ecx
  401005:	0f b6 16             	movzbl (%rsi),%edx
  401008:	38 d1                	cmp    %dl,%cl
  40100a:	75 0c                	jne    0x401018
  40100c:	84 c9                	test   %cl,%cl
  40100e:	74 0e                	je     0x40101e
  401010:	48 ff c7             	inc    %rdi
  401013:	48 ff c6             	inc    %rsi
  401016:	eb ea                	jmp    0x401002
  401018:	b8 01 00 00 00       	mov    $0x1,%eax
  40101d:	c3                   	ret
  40101e:	31 c0                	xor    %eax,%eax
  401020:	c3                   	ret
  401021:	48 8b 04 24          	mov    (%rsp),%rax
  401025:	48 83 f8 02          	cmp    $0x2,%rax
  401029:	7c 25                	jl     0x401050
  40102b:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
  401030:	48 8d 3d c9 0f 00 00 	lea    0xfc9(%rip),%rdi        # 0x402000
  401037:	e8 c4 ff ff ff       	call   0x401000
  40103c:	85 c0                	test   %eax,%eax
  40103e:	75 10                	jne    0x401050
  401040:	48 8d 35 c1 0f 00 00 	lea    0xfc1(%rip),%rsi        # 0x402008
  401047:	48 c7 c2 20 00 00 00 	mov    $0x20,%rdx
  40104e:	eb 0e                	jmp    0x40105e
  401050:	48 8d 35 d2 0f 00 00 	lea    0xfd2(%rip),%rsi        # 0x402029
  401057:	48 c7 c2 05 00 00 00 	mov    $0x5,%rdx
  40105e:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  401065:	48 c7 c7 01 00 00 00 	mov    $0x1,%rdi
  40106c:	0f 05                	syscall
  40106e:	48 c7 c0 3c 00 00 00 	mov    $0x3c,%rax
  401075:	48 31 ff             	xor    %rdi,%rdi
  401078:	0f 05                	syscall
```

Подсказка из лаборатории: `objdump -d <файл> — дизассемблер`.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf readelf -h target
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
  Entry point address:               0x401021
  Start of program headers:          64 (bytes into file)
  Start of section headers:          8352 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         6
  Size of section headers:           64 (bytes)
  Number of section headers:         6
  Section header string table index: 5
```

Подсказка из лаборатории: `readelf -h <файл> — заголовок ELF`.

## Квиз

```quiz
- question: "Почему прошивки идут первыми в этом модуле?"
  options:
    - "Там статический анализ часто единственный доступный метод"
    - "Они самые простые"
    - "Они не имеют архитектуры"
    - "Они всегда на x86"
  answer: 0
  explanation: "Прошивку неудобно запускать, поэтому важен статический подход."
- question: "Что добавляет malware-static к обычному статическому анализу?"
  options:
    - "Специфику вредоносного кода и устойчивость к обфускации"
    - "Только HTML"
    - "Сетевой протокол"
    - "Синтаксис SQL"
  answer: 0
  explanation: "Malware анализируется с учётом противодействия анализу."
- question: "Чем shellcode сложен для анализа?"
  options:
    - "Это позиционно-независимый неструктурированный код"
    - "Он всегда подписан"
    - "Он имеет символы"
    - "Он на языке Python"
  answer: 0
  explanation: "Shellcode не имеет заголовков и часто самодекодируется."
```

## Где пригодится

- **CTF:** задачи категории reversing и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
