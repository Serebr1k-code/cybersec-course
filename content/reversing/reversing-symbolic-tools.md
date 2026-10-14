---
id: reversing-symbolic-tools
title: "Символьное исполнение: инструменты (Z3, binary lifting)"
category: reversing
parent: reversing-symbolic-execution
difficulty: hard
order: 1
tags: [reversing, symbolic, z3, binary-lifting, smt]
prerequisites: [reversing-symbolic-execution]
useful_for:
  - "CTF Reversing: решение ограничений"
  - "Подъём бинаря в IR"
estimated_minutes: 10
summary: "Второй модуль символьного исполнения: SMT-решатель Z3 и подъём бинаря (binary lifting) в промежуточное представление."
lab:
  kind: shell
  title: 'Практика: capstone + z3 в связке'
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, crackme16]
  check: 'grep -q ''nto{z3_symb0l1c_t00lch41n}'' found.txt'
  hints:
    - '`sym.py` дизассемблирует стуб (capstone) и решает его (z3).'
    - 'Пароль: `cQNW]`.'
    - 'Запусти `crackme16 cQNW]`.'
---
Второй модуль символьного исполнения — про инструменты нижнего уровня. Здесь вы учитесь формулировать задачи для SMT-решателя Z3 и переводить машинный код в промежуточное представление (binary lifting), на котором работает символьный анализ.

## Что покрывает этап

**reversing-z3-advanced** — Z3: формулировка ограничений, продвинутые теории, решение крипто- и логических задач.
**reversing-binary-lifting** — binary lifting: перевод бинаря в IR (например, VEX) для дальнейшего анализа.

## Почему такой порядок

Z3 идёт первым: это универсальный инструмент, нужный в самых разных задачах. Binary lifting замыкает модуль, потому что он лежит в основе инструментов символьного исполнения и объясняет, как машинный код превращается в формулы.

## Что вы сможете после этапа

- Формулировать и решать задачи в Z3.
- Поднимать бинарь в промежуточное представление для анализа.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -d crackme16

crackme16:     file format elf64-x86-64


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
  40103b:	48 8d 3d 16 20 00 00 	lea    0x2016(%rip),%rdi        # 403058 <__bss_start>
  401042:	48 c7 c1 1b 00 00 00 	mov    $0x1b,%rcx
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
  40106f:	48 8d 35 e2 1f 00 00 	lea    0x1fe2(%rip),%rsi        # 403058 <__bss_start>
  401076:	48 c7 c2 1b 00 00 00 	mov    $0x1b,%rdx
  40107d:	eb 0e                	jmp    40108d <.pr>

000000000040107f <.nope>:
  40107f:	48 8d 35 9b 0f 00 00 	lea    0xf9b(%rip),%rsi        # 402021 <nope>
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
- question: "Зачем нужен Z3 в реверсе?"
  options:
    - "Для решения логических и крипто-ограничений"
    - "Для компиляции"
    - "Для отладки ядра"
    - "Для сканирования сети"
  answer: 0
  explanation: "Z3 — SMT-решатель, используемый во множестве задач."
- question: "Что делает binary lifting?"
  options:
    - "Переводит бинарь в промежуточное представление"
    - "Шифрует файл"
    - "Запускает программу"
    - "Собирает статистику сети"
  answer: 0
  explanation: "Lifting даёт IR, удобный для символьного анализа."
- question: "Почему Z3 идёт перед binary lifting?"
  options:
    - "Это универсальный инструмент, нужный в разных задачах"
    - "Lifting проще"
    - "Они не связаны"
    - "Lifting не использует IR"
  answer: 0
  explanation: "Решатель применим шире, чем один метод анализа."
```

## Где пригодится

- **CTF:** задачи категории reversing и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
