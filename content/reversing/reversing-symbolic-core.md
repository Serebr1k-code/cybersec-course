---
id: reversing-symbolic-core
title: "Символьное исполнение: ядро (taint, concolic, angr)"
category: reversing
parent: reversing-symbolic-execution
difficulty: expert
order: 2
tags: [reversing, symbolic, taint, concolic, angr]
prerequisites: [reversing-symbolic-execution]
useful_for:
  - "CTF Reversing: обход проверок автоматически"
  - "Автоматический поиск путей"
estimated_minutes: 10
summary: "Первый модуль символьного исполнения: taint-анализ, concolic-исполнение и angr."
lab:
  kind: shell
  title: 'Практика: символическое решение (z3)'
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, crackme15]
  check: 'grep -q ''nto{z3_symb0l1c_s0lv3r_c0r3}'' found.txt'
  hints:
    - 'Проверка: `(b*3) ^ 0x11 == target` для каждого байта.'
    - 'Реши ограничения: `python3 solve.py`.'
    - 'Затем `crackme15 cQNW]`.'
---
Первый из двух модулей символьного исполнения. Здесь ядро подхода: как отслеживать влияние входов, как комбинировать конкретное и символьное исполнение и как применять angr для автоматического поиска пути.

## Что покрывает этап

**reversing-taint-analysis** — taint-анализ: отслеживание распространения пользовательских данных.
**reversing-concolic** — concolic-исполнение: сочетание конкретного запуска и решателя ограничений.
**reversing-angr-advanced** — angr: продвинутые сценарии автоматического поиска пути и обхода проверок.

## Почему такой порядок

Taint-анализ идёт первым: он объясняет, какие данные вообще влияют на поведение. Concolic вторым — он соединяет конкретное исполнение с решателем. angr замыкает модуль как практический фреймворк, вобравший оба подхода.

## Что вы сможете после этапа

- Проводить taint-анализ и находить источники влияния на ветвление.
- Применять concolic-исполнение для обхода проверок.
- Писать angr-скрипты для автоматического достижения цели.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -d crackme15

crackme15:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <strcmp>:
  401000:	31 c0                	xor    %eax,%eax
  401002:	0f b6 0f             	movzbl (%rdi),%ecx
  401005:	0f b6 16             	movzbl (%rsi),%edx
  401008:	38 d1                	cmp    %dl,%cl
  40100a:	75 0c                	jne    401018 <strcmp+0x18>
  40100c:	84 c9                	test   %cl,%cl
  40100e:	74 0e                	je     40101e <strcmp+0x1e>
  401010:	48 ff c7             	inc    %rdi
  401013:	48 ff c6             	inc    %rsi
  401016:	eb ea                	jmp    401002 <strcmp+0x2>
  401018:	b8 01 00 00 00       	mov    $0x1,%eax
  40101d:	c3                   	ret
  40101e:	31 c0                	xor    %eax,%eax
  401020:	c3                   	ret

0000000000401021 <decode>:
  401021:	48 31 c0             	xor    %rax,%rax
  401024:	0f b6 06             	movzbl (%rsi),%eax
  401027:	30 d0                	xor    %dl,%al
  401029:	88 07                	mov    %al,(%rdi)
  40102b:	48 ff c6             	inc    %rsi
  40102e:	48 ff c7             	inc    %rdi
  401031:	e2 f1                	loop   401024 <decode+0x3>
  401033:	c3                   	ret

0000000000401034 <_start>:
  401034:	48 8d 35 cb 0f 00 00 	lea    0xfcb(%rip),%rsi        # 402006 <enc_flag>
  40103b:	48 8d 3d 1e 20 00 00 	lea    0x201e(%rip),%rdi        # 403060 <__bss_start>
  401042:	48 c7 c1 1d 00 00 00 	mov    $0x1d,%rcx
  401049:	b2 2a                	mov    $0x2a,%dl
  40104b:	e8 d1 ff ff ff       	call   401021 <decode>
  401050:	48 8b 04 24          	mov    (%rsp),%rax
  401054:	48 83 f8 02          	cmp    $0x2,%rax
  401058:	7c 25                	jl     40107f <.nope>
  40105a:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
  40105f:	48 8d 3d 9a 0f 00 00 	lea    0xf9a(%rip),%rdi        # 402000 <password>
  401066:	e8 95 ff ff ff       	call   401000 <strcmp>
  40106b:	85 c0                	test   %eax,%eax
  40106d:	75 10                	jne    40107f <.nope>
  40106f:	48 8d 35 ea 1f 00 00 	lea    0x1fea(%rip),%rsi        # 403060 <__bss_start>
  401076:	48 c7 c2 1d 00 00 00 	mov    $0x1d,%rdx
  40107d:	eb 0e                	jmp    40108d <.pr>

000000000040107f <.nope>:
  40107f:	48 8d 35 9d 0f 00 00 	lea    0xf9d(%rip),%rsi        # 402023 <nope>
  401086:	48 c7 c2 05 00 00 00 	mov    $0x5,%rdx

000000000040108d <.pr>:
  40108d:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  401094:	48 c7 c7 01 00 00 00 	mov    $0x1,%rdi
  40109b:	0f 05                	syscall
  40109d:	48 c7 c0 3c 00 00 00 	mov    $0x3c,%rax
  4010a4:	48 31 ff             	xor    %rdi,%rdi
  4010a7:	0f 05                	syscall
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Квиз

```quiz
- question: "Почему taint-анализ идёт первым?"
  options:
    - "Он объясняет, какие данные влияют на поведение программы"
    - "Он самый сложный"
    - "Он не связан с символьным исполнением"
    - "Он требует GPU"
  answer: 0
  explanation: "Без понимания влияния данных нет смысла искать путь."
- question: "Что такое concolic-исполнение?"
  options:
    - "Сочетание конкретного запуска и решателя ограничений"
    - "Только статический анализ"
    - "Только фаззинг"
    - "Шифрование трафика"
  answer: 0
  explanation: "Concolic смешивает конкретные значения с символьными."
- question: "Почему angr замыкает модуль?"
  options:
    - "Это практический фреймворк, вобравший taint и concolic-подходы"
    - "Он проще всех"
    - "Он не использует решатель"
    - "Он только для веба"
  answer: 0
  explanation: "angr автоматизирует поиск пути поверх этих идей."
```

## Где пригодится

- **CTF:** задачи категории reversing и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
