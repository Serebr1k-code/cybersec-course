---
id: pwn-house-of-force
title: "House of Force / Spirit / Orange"
category: pwn
parent: pwn-heap-house
difficulty: hard
order: 3
tags: [heap, house-of-force, house-of-spirit, house-of-orange, top-chunk]
prerequisites: [pwn-heap-basics, pwn-fastbin-dup]
useful_for:
  - "CTF Pwn категория"
  - "Эксплуатация heap-уязвимостей"
  - "Vulnerability research"
estimated_minutes: 70
summary: "Разбираем три классические heap-техники: House of Force (перезапись top chunk), House of Spirit (поддельный fastbin) и House of Orange (unsorted bin -> FSOP) с полным разбором каждой."
---
House of Force — это техника эксплуатации переполнения top-чанка, позволяющая получить аллокацию по произвольному адресу. Идея: top chunk (вершина кучи) имеет поле `size`, описывающее, сколько памяти осталось. Если переполнить это поле огромным значением (например, `0xffffffffffffffff`), то при следующей аллокации glibc решит, что доступно «бесконечно» много памяти, и выдаст указатель по адресу `top + запрошенный_размер`. Управляя размером запроса, вы получаете аллокацию в произвольной точке памяти. Техника работает на glibc без проверки размера top (примерно до 2.29 включительно) и требует переполнения в чанк, смежный с top. В этом уроке — House of Force, а также родственные House of Spirit и House of Orange.

## Устройство top chunk

Top chunk — последний чанк в куче, его `size` равен оставшемуся пространству (по умолчанию около 0x20000 при первом расширении). При `malloc`, если ни один бин не подходит, glibc «отрезает» от top нужный размер. Проверка в `_int_malloc`:

```c
if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
    remainder_size = size - nb;
    remainder = chunk_at_offset(victim, nb);
    ...
    set_head(victim, nb | PREV_INUSE);
    ...
}
```

Если `size` подделать на `SIZE_MAX` (0xffffffffffffffff), проверка всегда проходит, и `remainder` вычисляется за пределами кучи.

## Механика атаки

```text
1) Переполнить чанк, смежный с top, записав в top->size значение 0xffffffffffffffff.
2) Вычислить target_addr — куда хотите получить аллокацию (например, __malloc_hook
   или .bss).
3) Запросить malloc(offset), где offset = target_addr - top_addr - 0x10.
4) glibc выдаст чанк по адресу target_addr.
5) Следующим malloc записать туда полезные данные.
```

Формула критична: `target = top + 0x10 (заголовок) + запрошенный_размер`. Отсюда `запрошенный_размер = target - top - 0x10`. Если запросить слишком много (больше `SIZE_MAX`), будет ошибка — поэтому target должен быть **выше** top (или используйте вычитание через отрицательные значения при переполнении знакового поля).

## Разобранный пример

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')

def alloc(sz, data=b''):
    p.sendlineafter(b'> ', b'1'); p.sendline(str(sz).encode()); p.sendafter(b'data: ', data)

# 1) выделить чанк, смежный с top, и переполнить top->size
alloc(0x18, b'A'*0x18 + p64(0) + p64(0xffffffffffffffff))

# 2) вычислить target (например, __malloc_hook)
libc.address = leak - libc.sym['...']
target = libc.address + libc.sym['__malloc_hook']

# 3) узнать адрес top (из утечки heap)
top = heap_base + 0x...   # адрес top-чанка
distance = target - top - 0x10
alloc(distance)           # «прыжок» к target

# 4) теперь следующий alloc вернёт target
alloc(0x18, p64(system))  # запись system в __malloc_hook
```

Точный адрес top получают из heap-утечки; distance должен быть положительным и корректным.

## House of Spirit

House of Spirit — атака через подделку чанка в контролируемой памяти (например, на стеке) и последующий `free` этого «чанка». glibc проверит `size` и (при определённых условиях) поместит поддельный чанк в fastbin/tcache. Затем аллокация вернёт указатель в контролируемую область. Условия: корректный `size` (в пределах fastbin), выровненный адрес, а также (для fastbin) проверка `next`-чанка. Полезно, когда есть `free` указателя, который вы контролируете.

## House of Orange

House of Orange использует переполнение top-чанка, чтобы заставить glibc «освободить» top в unsortedbin (подделав `prev_inuse` и размер), получить утечку libc и затем перейти к FSOP. Техника нужна, когда в программе нет функции `free` — освобождение эмулируется через переполнение top. Подробнее — в `pwn-fsop`.

## Условия применимости и митигации

House of Force работает на glibc, где нет проверки `size` top-чанка на «разумность». Начиная с glibc 2.29 добавлена проверка `if (__glibc_unlikely (size > av->system_mem)) malloc_printerr("malloc(): corrupted top size")`, что закрывает технику. Поэтому:

| Версия glibc | House of Force |
|---|---|
| < 2.29 | работает |
| ≥ 2.29 | заблокирована проверкой top size |

Проверяйте версию перед применением; на новых glibc используйте другие техники (largebin, FSOP).

## Проверка в gdb

```bash
gdb ./chall
(gdb) heap
(gdb) p main_arena.top
(gdb) x/4gx main_arena.top
(gdb) p/x main_arena.system_mem
```

Смотрите `top` и его `size` до и после переполнения. Убедитесь, что `size` действительно стал огромным и что `malloc` не выдаёт ошибку.

## Частые ошибки

- **Неверный target.** target должен быть выше top; иначе distance отрицательный.
- **Переполнение не доходит до top.** Нужен чанк, смежный с top, и достаточная длина записи.
- **Проверка top size (≥2.29).** Техника не сработает — проверьте версию.
- **Неверный адрес top.** Требуется heap-утечка; без неё distance не посчитать.
- **Слишком большой запрос.** Приводит к abort.

## Справочные таблицы

| Техника | Идея | Версия |
|---|---|---|
| House of Force | переполнение top size | < 2.29 |
| House of Spirit | поддельный чанк + free | любая |
| House of Orange | top → unsortedbin → FSOP | любая |
| House of Einherjar | off-by-null | любая |

| Символ | Роль |
|---|---|
| `main_arena.top` | указатель на top |
| `main_arena.system_mem` | размер арены |
| `MINSIZE` | минимальный размер чанка |

## Что дальше / решение

Дальше: `pwn-house-modern`, `pwn-house-lore`, `pwn-house-einherjar`, `pwn-fsop`, `pwn-largebin-attack`, `pwn-glibc-mitigations`. Практический алгоритм: (1) проверьте версию glibc (< 2.29 для Force); (2) найдите чанк, смежный с top, и переполните `top->size`; (3) вычислите `distance = target - top - 0x10`; (4) запросите `malloc(distance)`; (5) следующей аллокацией запишите полезные данные. House of Force — элегантный пример того, как одна переполненная метаданная превращается в аллокацию по произвольному адресу; но помните, что современные glibc её закрыли.
## Сквозной разбор House of Force на glibc 2.23

Разберём классическую задачу: 64-битный бинарь, glibc 2.23, есть переполнение в чанк, смежный с top, нет проверки top size. Цель — перезаписать `__malloc_hook` на one-gadget. Шаги: (1) выделяем чанк A, смежный с top, и переполняем его, записывая в `top->size` значение `0xffffffffffffffff`; (2) получаем heap-утечку, чтобы узнать адрес top; (3) вычисляем `distance = (__malloc_hook - 0x10) - top` (с учётом заголовка); (4) запрашиваем `malloc(distance)` — glibc «отрезает» кусок от поддельного top и возвращает указатель рядом с `__malloc_hook`; (5) следующей аллокацией записываем адрес one-gadget в `__malloc_hook`; (6) вызываем `malloc` — срабатывает хук. Формула расстояния критична: `target = top + 0x10 + requested`, поэтому `requested = target - top - 0x10`. Если `requested` получается отрицательным, используйте другой target выше top.

## Формулы и вычисления

Разберём аккуратно. `top` — это адрес заголовка top-чанка (первые 8 байт — `prev_size`, следующие 8 — `size`). Полезная нагрузка top начинается с `top + 0x10`. При `malloc(n)` glibc отдаёт `chunk = top`, а новый top становится `top + n + 0x10` (с учётом округления до 0x10). Значит, чтобы получить чанк, чьи данные начинаются в `target`, нужно `n = target - (top + 0x10)`, и `n` должно быть кратно 0x10 (иначе выравнивание сдвинет адрес). Если `target < top`, `n` отрицателен, что при передаче в `malloc` как `size_t` даст огромное число и abort — поэтому выбирайте target выше top либо переполняйте top так, чтобы поддельный top «съехал» ниже. Всегда проверяйте выравнивание: `(target - top - 0x10) % 0x10 == 0`.

## House of Spirit подробно

House of Spirit обходит необходимость переполнения top: вы подделываете чанк в контролируемой памяти и освобождаете его. Условия для fastbin: `size` должен попадать в диапазон fastbin (0x20–0x80 на 64-бит), адрес выровнен на 0x10, а `prev_size`/следующий чанк должны «проходить» проверки. Схема: (1) в контролируемой области (стек/`bss`) размещаем `size`; (2) вызываем `free` на указателе, указывающем на наш поддельный чанк; (3) glibc помещает его в fastbin; (4) следующая `malloc` возвращает указатель в контролируемую область. Это даёт запись по адресам, которые вы выбрали. Уязвимость возникает, когда программа позволяет `free` произвольный указатель (например, введённый пользователем).

## Сравнение и когда что применять

House of Force нужен, когда есть переполнение в чанк у top и старая glibc. House of Spirit — когда есть `free` произвольного указателя и контролируемая память. House of Orange — когда есть переполнение top, но нет `free`, и цель — FSOP. House of Einherjar — когда есть off-by-null. Выбор определяется доступным примитивом и версией glibc. Все четыре — «классика» heap-эксплуатации, которую стоит знать, даже если современные версии закрыли часть из них: понимание их устройства помогает адаптироваться к новым митигациям и находить свежие варианты.

## Чек-лист

1. Определите версию glibc и митигации.
2. Проверьте, есть ли переполнение в чанк у top / `free` произвольного указателя.
3. Для Force: подделайте `top->size`, вычислите `distance`, запросите `malloc`.
4. Для Spirit: разместите поддельный чанк, вызовите `free`, затем `malloc`.
5. Для Orange: переполните top, получите unsortedbin-утечку, перейдите к FSOP.
6. Проверьте в gdb (`heap`, `bins`, `p main_arena.top`).

## Квиз

```quiz
- question: "Что перезаписывает House of Force?"
  options:
    - "Размер top chunk (для смещения top)"
    - "Canary"
    - "GOT"
    - "tcache"
  answer: 0
  explanation: "House of Force меняет size top chunk, чтобы malloc вернул нужный адрес."
- question: "Что использует House of Spirit?"
  options:
    - "Поддельный fastbin-чанк, освобождаемый через free"
    - "Unsorted bin"
    - "GOT"
    - "vtable"
  answer: 0
  explanation: "Spirit заставляет free освободить поддельный чанк в контролируемой памяти."
- question: "Что делает House of Orange?"
  options:
    - "Через unsorted bin и переполнение top добирается до FSOP"
    - "Перезаписывает GOT"
    - "Снимает canary"
    - "Обходит ASLR"
  answer: 0
  explanation: "Orange создаёт unsorted-чанк без free и перекрывает _IO_list_all."
- question: "С какой версии glibc House of Force в основном заблокирован?"
  options:
    - "2.29 (проверка top->size)"
    - "2.23"
    - "2.40"
    - "1.0"
  answer: 0
  explanation: "Проверка размера top добавлена в 2.29, ломая классическую Force."
- question: "Какой триггер нужен для FSOP в House of Orange?"
  options:
    - "exit/return (вызывает _IO_flush_all_lockp)"
    - "malloc"
    - "free"
    - "read"
  answer: 0
  explanation: "FSOP срабатывает при обходе _IO_list_all на exit/flush."
```

## Где пригодится

- **CTF:** Pwn — heap-задачи с top/fastbin/unsorted.
- **Bug bounty:** понимание glibc-примитивов.
- **Пентест:** эксплуатация heap-багов.
- **Работа:** security research glibc.
