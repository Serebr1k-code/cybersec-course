---
id: reversing-time-travel
title: "Time-travel debugging: rr и WinDbg TTD"
category: reversing
parent: reversing-advanced-debugging
difficulty: hard
order: 1
tags: [reversing, time-travel, rr, windbg, ttd, debugging, record-replay]
prerequisites: [reversing-advanced-debugging, reversing-dynamic-debug]
useful_for:
  - "CTF Reversing"
  - "Vulnerability research"
  - "Malware analysis"
estimated_minutes: 55
summary: "Запись и обратное исполнение: rr (Linux), WinDbg TTD (Windows), reverse-continue и анализ багов/малвари."
lab:
  kind: shell
  title: 'Практика: восстановление по записям в память'
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, tt]
  check: 'grep -q ''nto{t1m3_tr4v3l_r3v3rs3_d3bug}'' found.txt'
  hints:
    - 'Функция `build` пишет байты в `ttbuf` через `movb`.'
    - 'Остановись после `build` и прочитай буфер.'
    - '`x/s &ttbuf` покажет собранный флаг.'
---
## Вопрос, с которого всё начинается

Программа падает с `SIGSEGV`, но нестабильно: иногда сразу, иногда через пару секунд. Обычный
отладчик умеет идти **только вперёд** — чтобы понять, откуда взялось «плохое» значение, приходится
перезапускать программу десятки раз. Как остановиться на причине, а не на симптоме?

Ответ — **time-travel debugging (TTD)**: запись исполнения целиком с возможностью «отмотать»
назад. Вы записываете один прогон и исследуете его интерактивно: обратные шаги, точки останова
«назад во времени», watchpoints. Разберём это на конкретном краше.

Опираемся на прошлые уроки: ты умеешь работать в отладчике (точки останова, стек, регистры).
TTD — это надстройка над теми же командами, плюс движение назад.

## Наш пример

Возьмём маленькую программу `ttd_demo`, которая портит указатель и затем разыменовывает его:

```c
int *g;
void corrupt(void) { g = 0; }        // обнуляет указатель
int main(void) {
    int x = 42;
    g = &x;                          // сначала g указывает на x
    puts("before corrupt");
    corrupt();
    puts("after corrupt");
    return *g;                       // разыменование NULL -> SIGSEGV
}
```

Запуск падает:

```
$ ./ttd_demo
before corrupt
after corrupt
Segmentation fault (core dumped)
```

Вопрос: где именно `g` стал нулём? В коде видно `corrupt()`, но в реальной программе всё сложнее —
указатель могли испортить глубоко в вызовах. Поймаем причину, **не перезапуская** программу.

## Шаг 1: записываем исполнение

Обычный отладчик хранит только текущее состояние. TTD же записывает **детерминированную трассу**:
регистры, память, порядок потоков. В gdb запись включается командой `record` (вариант
`record full` — программная запись):

```
$ gdb ./ttd_demo
(gdb) break main
(gdb) run
(gdb) record full                # начали запись трассы
```

Термин: **детерминированная трасса** означает, что прогон можно воспроизвести байт-в-байт
сколько угодно раз. Внешние события (ввод, время, системные вызовы) берутся из записи, а не
происходят заново.

## Шаг 2: воспроизводим до краха

Записав трассу, гоняем программу до падения и смотрим состояние в момент краха:

```
(gdb) break corrupt
(gdb) continue
Breakpoint 2, corrupt () at ttd_demo.c:3
3	void corrupt(void) { g = 0; }
(gdb) printf "g before corrupt = %p\n", g
g before corrupt = 0x7fffffffe16c     # указатель ещё валиден

(gdb) continue
Program received signal SIGSEGV, Segmentation fault.
0x000055555555518f in main () at ttd_demo.c:10
10	    return *g;
(gdb) printf "after crash, g = %p\n", g
after crash, g = (nil)                # теперь g = NULL
```

Мы видим симптом: в момент краха `g` равен `(nil)`. Но **кто** его обнулил? Обычный отладчик
здесь бессилен: назад он не идёт.

## Шаг 3: идём назад во времени

Вот главная команда — `reverse-continue`. Она откатывает исполнение назад до предыдущего
события останова (в нашем случае — до точки останова в `corrupt`):

```
(gdb) reverse-continue
Breakpoint 2, corrupt () at ttd_demo.c:3
3	void corrupt(void) { g = 0; }
(gdb) bt
#0  corrupt () at ttd_demo.c:3
#1  0x0000555555555179 in main () at ttd_demo.c:8
(gdb) printf "back in time, g = %p\n", g
back in time, g = 0x7fffffffe16c
```

Мы **отмотали** программу от краха назад и оказались в `corrupt()` — функции, которая испортила
указатель. Обрати внимание: `g` снова валиден (`0x7fffffffe16c`) — это состояние **до** порчи.
Один прогон вместо десятков перезапусков.

## Шаг 4: watchpoints назад — «кто записал это значение?»

Ещё сильнее приём — **watchpoint** (точка наблюдения на адрес/переменную) вместе с обратным
ходом. Он останавливает исполнение, когда значение меняется. В обычном отладчике watchpoint
ловит только **будущие** записи; в TTD — и прошедшие:

```
(gdb) watch g
Hardware watchpoint 3: g
(gdb) reverse-continue
Old value = (int *) 0x0
New value = (int *) 0x7fffffffe16c
corrupt () at ttd_demo.c:3
```

Такой приём («поставь watchpoint и иди назад») за один прогон находит, где именно переменная была
испорчена, — то, что в обычном отладчике требовало бы десятков перезапусков.

## Шаг 5: инструменты TTD

На Linux основной инструмент — **rr** (Mozilla): он специализирован для записи/воспроизведения и
работает с многопоточностью лучше, чем `record` в gdb.

```
$ rr record ./target              # записать прогон в трассу
$ rr replay                       # воспроизвести (открывает gdb)
(rr) continue
(rr) reverse-continue             # откат к предыдущей точке останова
(rr) reverse-stepi                # шаг назад по инструкциям
(rr) when                         # текущая позиция в трассе
```

Ключевые флаги `rr record`: `-o <dir>` (каталог трассы), `--chaos` (случайный порядок
планирования — чтобы поймать **race condition**), `-h` (записывать только потоки, трогающие heap).
Поскольку `rr replay` открывает настоящий gdb, работают расширения вроде pwndbg (`vmmap`, `heap`).

На Windows TTD встроен в современный **WinDbg**:

| Команда | Действие |
|---|---|
| `!tt 0` / `!tt 100` | в начало / в конец трассы |
| `g-` / `p-` | обратный continue / шаг |
| `ba w4 0xADDR` + `g-` | обратный watchpoint |
| `.time` | текущая позиция трассы |

Трасса сохраняется в `.run`-файл и открывается на другой машине.

## Ограничения

- **Размер трассы** растёт быстро (гигабайты) — храните на быстром диске и записывайте только
  нужное окно.
- **Производительность**: активно пишется один поток, остальные «приостанавливаются»
  детерминированно.
- **Не для ядра**: rr работает в user-space; для kernel-space другие инструменты (drgn, kprobes).
- **WinDbg TTD** требует Windows 10 (1809+) и подходящего режима записи (Intel PT или программный).
- Без `--chaos` нестабильную гонку не поймать.

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -d tt

tt:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <build>:
  401000:	c6 05 29 20 00 00 6e 	movb   $0x6e,0x2029(%rip)        # 403030 <__bss_start>
  401007:	c6 05 23 20 00 00 74 	movb   $0x74,0x2023(%rip)        # 403031 <__bss_start+0x1>
  40100e:	c6 05 1d 20 00 00 6f 	movb   $0x6f,0x201d(%rip)        # 403032 <__bss_start+0x2>
  401015:	c6 05 17 20 00 00 7b 	movb   $0x7b,0x2017(%rip)        # 403033 <__bss_start+0x3>
  40101c:	c6 05 11 20 00 00 74 	movb   $0x74,0x2011(%rip)        # 403034 <__bss_start+0x4>
  401023:	c6 05 0b 20 00 00 31 	movb   $0x31,0x200b(%rip)        # 403035 <__bss_start+0x5>
  40102a:	c6 05 05 20 00 00 6d 	movb   $0x6d,0x2005(%rip)        # 403036 <__bss_start+0x6>
  401031:	c6 05 ff 1f 00 00 33 	movb   $0x33,0x1fff(%rip)        # 403037 <__bss_start+0x7>
  401038:	c6 05 f9 1f 00 00 5f 	movb   $0x5f,0x1ff9(%rip)        # 403038 <__bss_start+0x8>
  40103f:	c6 05 f3 1f 00 00 74 	movb   $0x74,0x1ff3(%rip)        # 403039 <__bss_start+0x9>
  401046:	c6 05 ed 1f 00 00 72 	movb   $0x72,0x1fed(%rip)        # 40303a <__bss_start+0xa>
  40104d:	c6 05 e7 1f 00 00 34 	movb   $0x34,0x1fe7(%rip)        # 40303b <__bss_start+0xb>
  401054:	c6 05 e1 1f 00 00 76 	movb   $0x76,0x1fe1(%rip)        # 40303c <__bss_start+0xc>
  40105b:	c6 05 db 1f 00 00 33 	movb   $0x33,0x1fdb(%rip)        # 40303d <__bss_start+0xd>
  401062:	c6 05 d5 1f 00 00 6c 	movb   $0x6c,0x1fd5(%rip)        # 40303e <__bss_start+0xe>
  401069:	c6 05 cf 1f 00 00 5f 	movb   $0x5f,0x1fcf(%rip)        # 40303f <__bss_start+0xf>
  401070:	c6 05 c9 1f 00 00 72 	movb   $0x72,0x1fc9(%rip)        # 403040 <__bss_start+0x10>
  401077:	c6 05 c3 1f 00 00 33 	movb   $0x33,0x1fc3(%rip)        # 403041 <__bss_start+0x11>
  40107e:	c6 05 bd 1f 00 00 76 	movb   $0x76,0x1fbd(%rip)        # 403042 <__bss_start+0x12>
  401085:	c6 05 b7 1f 00 00 33 	movb   $0x33,0x1fb7(%rip)        # 403043 <__bss_start+0x13>
  40108c:	c6 05 b1 1f 00 00 72 	movb   $0x72,0x1fb1(%rip)        # 403044 <__bss_start+0x14>
  401093:	c6 05 ab 1f 00 00 73 	movb   $0x73,0x1fab(%rip)        # 403045 <__bss_start+0x15>
  40109a:	c6 05 a5 1f 00 00 33 	movb   $0x33,0x1fa5(%rip)        # 403046 <__bss_start+0x16>
  4010a1:	c6 05 9f 1f 00 00 5f 	movb   $0x5f,0x1f9f(%rip)        # 403047 <__bss_start+0x17>
  4010a8:	c6 05 99 1f 00 00 64 	movb   $0x64,0x1f99(%rip)        # 403048 <__bss_start+0x18>
  4010af:	c6 05 93 1f 00 00 33 	movb   $0x33,0x1f93(%rip)        # 403049 <__bss_start+0x19>
  4010b6:	c6 05 8d 1f 00 00 62 	movb   $0x62,0x1f8d(%rip)        # 40304a <__bss_start+0x1a>
  4010bd:	c6 05 87 1f 00 00 75 	movb   $0x75,0x1f87(%rip)        # 40304b <__bss_start+0x1b>
  4010c4:	c6 05 81 1f 00 00 67 	movb   $0x67,0x1f81(%rip)        # 40304c <__bss_start+0x1c>
  4010cb:	c6 05 7b 1f 00 00 7d 	movb   $0x7d,0x1f7b(%rip)        # 40304d <__bss_start+0x1d>
  4010d2:	c3                   	ret

00000000004010d3 <_start>:
  4010d3:	e8 28 ff ff ff       	call   401000 <build>
  4010d8:	48 c7 c0 3c 00 00 00 	mov    $0x3c,%rax
  4010df:	48 31 ff             	xor    %rdi,%rdi
  4010e2:	0f 05                	syscall
```

Подсказка из лаборатории: `objdump -d <файл>`.

## Что мы теперь знаем

- **TTD** записывает прогон и позволяет исполнять программу **назад**.
- `record`/`rr record` включает запись; `reverse-continue`/`reverse-stepi` — обратный ход.
- После краха `reverse-continue` откатывает к причине, а не к симптому.
- **Watchpoint + reverse** находит, кто записал «плохое» значение в память.
- `rr` (Linux) и **WinDbg TTD** (Windows) — основные инструменты; `--chaos` помогает ловить гонки.

## На что смотреть дальше

- Сначала воспроизведи баг **детерминированно**, потом анализируй — иначе выводы случайны.
- Не путай `stepi` (вперёд) и `reverse-stepi` (назад); после `reverse-continue` стек — на момент
  остановки.
- Записывай только нужное окно: длинные трассы съедают диск.
- Для многопоточных багов комбинируй `--chaos` с несколькими записями, пока гонка не
  воспроизведётся.
- Для анализа use-after-free ставь watchpoint на адрес объекта и иди назад к вызову `free`.

## Квиз

Проверь себя.

```quiz
- question: "Что даёт time-travel debugging?"
  options:
    - "Возможность исполнять программу назад (reverse-continue/step)"
    - "Ускорение программы"
    - "Шифрование трассы"
    - "Сканирование портов"
  answer: 0
  explanation: "TTD записывает исполнение и позволяет откатываться назад."
- question: "Какой инструмент TTD для Linux?"
  options:
    - "rr"
    - "gdb без record"
    - "strace"
    - "ltrace"
  answer: 0
  explanation: "rr записывает и воспроизводит исполнение на Linux."
- question: "Какая команда gdb в rr идёт назад до брейкпоинта?"
  options:
    - "reverse-continue"
    - "reverse-stepi"
    - "continue"
    - "next"
  answer: 0
  explanation: "reverse-continue откатывает исполнение до предыдущего события."
- question: "Какой инструмент TTD для Windows?"
  options:
    - "WinDbg TTD"
    - "x64dbg"
    - "IDA"
    - "OllyDbg"
  answer: 0
  explanation: "WinDbg TTD записывает и воспроизводит трассы на Windows."
- question: "Почему replay детерминирован?"
  options:
    - "Запись фиксирует один прогон; внешние события воспроизводятся из трассы"
    - "Он ускоряет CPU"
    - "Он отключает ASLR"
    - "Он использует символы"
  answer: 0
  explanation: "Трасса воспроизводит ровно тот прогон, что был записан."
```

## Куда дальше

Мы научились откатывать исполнение назад — это меняет подход к нестабильным багам. Дальше возьмём
формат Protobuf и gRPC, которые часто прячут логику обмена в бинарных сообщениях. А пока главное
запомни: **TTD превращает «нестабильный баг» в детерминированную задачу** — один прогон вместо
десятков перезапусков.

## Где пригодится

- **CTF:** Reversing — анализ сложной логики и нестабильных проверок.
- **Vulnerability research:** поиск первопричины багов (corruption, UAF, гонки).
- **Malware analysis:** разбор поведения, зависящего от условий.
- **Работа:** debugging, incident response.
