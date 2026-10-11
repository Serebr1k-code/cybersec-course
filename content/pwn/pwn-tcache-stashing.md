---
id: pwn-tcache-stashing
title: "Tcache stashing unlink attack"
category: pwn
parent: pwn-house-lore
difficulty: expert
order: 1
tags: [pwn, heap, glibc, tcache, smallbin, stashing]
prerequisites: [pwn-heap-tcache, pwn-house-lore]
useful_for:
  - "CTF Pwn — modern glibc"
  - "Разработка эксплойтов"
estimated_minutes: 60
summary: "Как функция tcache_stashing_unlink переносит чанки из small bin в tcache и почему это даёт произвольную запись/аллокацию на glibc 2.29–2.3x."
---
Tcache stashing unlink attack — это атака на glibc ≥ 2.29, эксплуатирующая механизм `tcache_stashing_unlink`, который glibc применяет при выделении из smallbin: если tcache соответствующего размера не полон, glibc «перекладывает» в него до 7 чанков из smallbin. При этом используются операции unlink без полной проверки в определённом контексте, что позволяет записать произвольный указатель в tcache. Эта техника не требует double-free и работает там, где safe-linking ещё не включён (2.29–2.31), а на 2.32+ требует учёта маскировки. В этом уроке — механика stashing, пошаговый эксплойт, цели и обход safe-linking.

## Механизм tcache stashing

Когда `_int_malloc` не находит чанк в tcache, fastbin или unsortedbin, он идёт в smallbin. Если бин не пуст и tcache этого размера не полон, glibc выполняет:

```c
// _int_malloc, smallbin path
if (tcache != NULL && tc_idx < mp_.tcache_bins) {
    ...
    // перекладываем чанки из smallbin в tcache
    while ((tc_victim = bck->bk) != bin) {
        // для каждого чанка делаем unlink и кладём в tcache
        ...
    }
}
```

Ключевое: при этом цикле glibc берёт `bck->bk` и записывает его в tcache, вызывая unlink. Если подделать `bk` чанка в smallbin, можно заставить glibc записать в tcache указатель на произвольный адрес.

## Пошаговая механика

```text
1) Заполнить tcache одного размера частично (например, оставить 1 свободный слот).
2) Поместить в smallbin два чанка: первый (target) и второй, чей bk подделан.
3) Подделать bk второго чанка так, чтобы он указывал на адрес-цель (target).
4) Вызвать malloc этого размера -> glibc перекладывает чанки в tcache,
   записывая target в tcache->entries.
5) Следующая malloc вернёт target -> arbitrary write.
```

Точнее: подделывается `bk` первого чанка в smallbin, чтобы при обходе `bck->bk` glibc взял наш адрес.

## Разобранный пример

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')

def alloc(sz, data=b''):
    p.sendlineafter(b'> ', b'1'); p.sendline(str(sz).encode()); p.sendafter(b'data: ', data)
def free(i):
    p.sendlineafter(b'> ', b'2'); p.sendline(str(i).encode())
def edit(i, data):
    p.sendlineafter(b'> ', b'3'); p.sendline(str(i).encode()); p.sendafter(b'data: ', data)

S = 0x100
# 1) заполнить tcache: 7 чанков размера S, освободить 6 (оставив 1 слот)
tc = [alloc(S) for _ in range(7)]
for i in range(6):
    free(i)                      # tcache почти полон
# 2) поместить 2 чанка в smallbin
A = alloc(S); B = alloc(S)
free(A); free(B)                 # в smallbin (tcache полон)
# 3) подделать bk чанка A -> target
target = elf.got['free'] - 0x10
edit(A, p64(0) + p64(0) + p64(B) + p64(target))
# 4) вызвать malloc -> stashing -> target в tcache
alloc(S)                         # заполняет последний слот, тянет из smallbin
# 5) следующая malloc вернёт target
victim = alloc(S)
```

Детали зависят от версии; ключевое — подделка `bk`.

## Цели атаки

Обычные цели: `__free_hook`/`__malloc_hook` (на 2.29–2.31 записать `system`), `_IO_list_all`/`_IO_2_1_stdout_` (FSOP), `.fini_array`, `__exit_funcs`. Выбрав target, вы получаете аллокацию по этому адресу и записываете туда нужное значение.

## Обход safe-linking (glibc 2.32+)

С 2.32 tcache-указатели маскируются (`ptr ^ (pos >> 12)`). При stashing glibc тоже маскирует записываемый указатель, поэтому для корректного target нужно знать heap-базу и вычислить `target ^ (pos >> 12)`. Это усложняет атаку, но не отменяет её: сначала добудьте heap-утечку, затем подделайте `bk` с учётом маскировки.

## Проверка в gdb

```bash
gdb ./chall
(gdb) bins
(gdb) p *(struct malloc_chunk*)<addr_A>
(gdb) x/8gx <addr_A>
(gdb) b _int_malloc
```

Смотрите состояние smallbin и tcache до и после stashing. Убедитесь, что target попал в tcache entries.

## Частые ошибки

- **tcache полон.** Stashing происходит только при свободных слотах — оставьте место.
- **Неверная подделка `bk`.** Цепочка не сработает.
- **safe-linking (2.32+).** Нужна маскировка с heap-базой.
- **Версия glibc.** Механика менялась; сверяйтесь.
- **Не тот размер.** tcache-бин должен совпадать с размером чанков.

## Справочные таблицы

| Версия | safe-linking | stashing |
|---|---|---|
| 2.29–2.31 | нет | работает напрямую |
| 2.32+ | да | нужна heap-утечка |

| Цель | Запись |
|---|---|
| `__free_hook` | `system` |
| `_IO_list_all` | поддельный поток |
| `.fini_array` | адрес функции |

## Что дальше / решение

Дальше: `pwn-tcache-mechanics`, `pwn-house-botcake`, `pwn-glibc-mitigations`, `pwn-fsop`, `pwn-largebin-attack`. Практический алгоритм: (1) определите версию glibc и наличие safe-linking; (2) частично заполните tcache; (3) поместите два чанка в smallbin; (4) подделайте `bk` (с маскировкой при необходимости); (5) вызовите `malloc`, чтобы сработало stashing; (6) получите аллокацию по target. Tcache stashing — элегантная техника, обходящая отсутствие double-free и работающая на широком диапазоне версий.
## Сквозной разбор stashing на glibc 2.31

Разберём задачу: glibc 2.31, есть UAF и edit, tcache включён, safe-linking нет. Цель — получить аллокацию по `__free_hook`, записать `system`. Шаги: (1) выделяем 7 чанков размера S и освобождаем 6 из них — tcache почти полон (1 слот свободен); (2) выделяем два чанка A и B размера S и освобождаем их: из-за почти полного tcache один уходит в smallbin (или оба, если tcache заполнился); (3) через UAF/edit подделываем `bk` чанка в smallbin так, чтобы он указывал на `__free_hook - 0x10` (или другой target); (4) вызываем `malloc(S)`: glibc, обнаружив свободный слот в tcache и непустой smallbin, выполняет stashing — перекладывает чанки из smallbin в tcache, записывая наш поддельный указатель; (5) следующая `malloc(S)` возвращает target; (6) записываем `system` в `__free_hook`. Проверяем в gdb: `bins` покажет tcache entries с target, `b _int_malloc` — момент stashing.

## Почему это обходит отсутствие double-free

Классический tcache poisoning требует UAF или double-free, чтобы записать подделанный `next`. Stashing использует другой путь: glibc сам «перекладывает» чанки из smallbin в tcache, вызывая unlink и записывая указатели. Подделав `bk` чанка в smallbin, вы влияете на то, что окажется в tcache. Это не требует double-free — достаточно возможности редактировать освобождённый чанк (UAF) или подделать связи. Поэтому stashing применяют там, где double-free заблокирован (проверка `key`).

## Учёт safe-linking на 2.32+

На glibc 2.32+ указатели в tcache маскируются как `ptr ^ (pos >> 12)`. При stashing glibc тоже маскирует записываемый указатель. Значит, чтобы target оказался корректным, нужно записать `target ^ (pos >> 12)`, где `pos` — адрес ячейки в tcache. Для этого требуется **утечка heap-базы** (чтобы вычислить `pos`). Схема: (1) сначала добудьте heap-утечку (через show освобождённого чанка или overlap); (2) вычислите `pos`; (3) подделайте `bk` как `target ^ (pos >> 12)`; (4) выполните stashing. Без heap-утечки poisoning под safe-linking невозможен, поэтому она — обязательный первый шаг.

## Чек-лист применения

1. Определите версию glibc и наличие safe-linking.
2. Частично заполните tcache (оставьте свободный слот).
3. Поместите два чанка в smallbin.
4. Подделайте `bk` (с маскировкой при safe-linking).
5. Вызовите `malloc`, чтобы сработало stashing.
6. Проверьте в gdb, что target попал в tcache.
7. Следующей `malloc` получите target и запишите нужное.

## Итог

Tcache stashing unlink — мощная техника, которая обходит отсутствие double-free и работает на широком диапазоне версий. Она требует понимания взаимодействия tcache и smallbin, а на новых glibc — учёта safe-linking. Отработайте её на задаче glibc 2.31, и вы получите ещё один инструмент для heap-эксплуатации, дополняющий House of Botcake и largebin attack.

## Замечание о порядке и количестве чанков

Stashing перекладывает до семи чанков, поэтому количество и порядок чанков в smallbin важны. Если в smallbin больше чанков, чем свободных слотов в tcache, glibc остановится, заполнив tcache, и оставшиеся останутся в smallbin. Подбирайте число чанков так, чтобы ваш подделанный `bk` обрабатывался в нужный момент. Проверяйте в gdb `bins` после каждого шага: там видно, какие чанки перешли в tcache. Не забывайте, что при safe-linking маскируется каждый записываемый указатель, поэтому маскировка должна быть корректной для всех чанков, а не только для целевого.

## Замечание о совместимости

Перед применением убедитесь, что в вашей версии glibc действительно реализован путь stashing (2.29+). Проверьте в gdb: поставьте точку останова на `_int_malloc`, подайте подходящую последовательность и посмотрите, вызывается ли код перекладывания чанков в tcache. Если да — подделка `bk` сработает. Если нет — используйте другой примитив (House of Botcake, largebin). Не полагайтесь на writeup для другой версии: сверяйте поведение с целевой библиотекой.

Практический совет: проверяйте число свободных слотов tcache перед stashing командой `tcache` в pwndbg — если слотов нет, перекладывание не произойдёт, и атаку нужно планировать иначе.

И наконец, не забывайте сверять поведение с исходниками конкретной версии glibc: реализация stashing менялась, и универсального рецепта, работающего на всех сборках, не существует.

## Квиз

```quiz
- question: "Что делает tcache_stashing_unlink?"
  options:
    - "Переносит чанки из small bin в tcache при malloc"
    - "Шифрует кучу"
    - "Снимает canary"
    - "Обнуляет GOT"
  answer: 0
  explanation: "При malloc из small bin glibc дозаполняет tcache оставшимися чанками."
- question: "Сколько чанков нужно в small bin для техники?"
  options:
    - "Как минимум два (чтобы был перенос)"
    - "Один"
    - "Ноль"
    - "Сто"
  answer: 0
  explanation: "Перенос идёт, пока tcache не заполнен и есть следующий чанк."
- question: "Какое поле подделывают, чтобы получить запись?"
  options:
    - "bk small-чанка"
    - "canary"
    - "GOT"
    - "vtable"
  answer: 0
  explanation: "Подмена bk направляет перенос/записи по контролируемому адресу."
- question: "Почему на glibc 2.32+ нужна heap-утечка?"
  options:
    - "Из-за safe-linking указатели нужно маскировать"
    - "Из-за ASLR"
    - "Из-за canary"
    - "Из-за tcache key"
  answer: 0
  explanation: "safe-linking кодирует fd/next, для корректной подделки нужен адрес."
- question: "Что нужно, чтобы перенос сработал?"
  options:
    - "tcache по этому классу не заполнен (< 7)"
    - "tcache заполнен полностью"
    - "Отключённый NX"
    - "Снятая canary"
  answer: 0
  explanation: "Если бакет tcache полон, stashing не выполняется."
```

## Где пригодится

- **CTF:** Pwn — modern glibc heap-задачи.
- **Bug bounty:** эксплуатация на актуальных системах.
- **Пентест:** разработка эксплойтов.
- **Работа:** security research glibc.
