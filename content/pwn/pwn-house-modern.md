---
id: pwn-house-modern
title: "Современные House of: Kiwi, Emma, Apple, God"
category: pwn
parent: pwn-tcache-stashing
difficulty: expert
order: 1
tags: [pwn, heap, glibc, house-of, modern]
prerequisites: [pwn-glibc-mitigations, pwn-house-botcake, pwn-tcache-stashing]
useful_for:
  - "CTF Pwn — modern glibc"
  - "Разработка эксплойтов"
estimated_minutes: 65
summary: "Обзор новейших heap-техник glibc 2.31–2.38: House of Kiwi, Emma, Apple, God, Water — условия, примитивы и когда их применять."
---
Современные House of (Kiwi, Emma, Apple, God) — это семейство техник heap-эксплуатации, появившихся после удаления хуков и включения safe-linking в glibc. Они решают задачу получения произвольной записи или исполнения, когда классические приёмы (`__free_hook`, простой tcache poisoning) больше не работают. Каждая техника нацелена на конкретный механизм glibc: `tcache_perthread_struct`, `__exit_funcs`, FSOP, largebin. В этом уроке — обзор и практическое применение Kiwi, Emma, Apple и God, их требования и место в современном арсенале.

## House of Kiwi

House of Kiwi эксплуатирует механизм обработки ошибок glibc: при обнаружении повреждения кучи (например, `malloc_printerr`) glibc вызывает `__libc_message`, который в свою очередь может вызвать `__malloc_assert`/`_IO_file_jumps`-функции. Если подделать соответствующие указатели, вы получаете вызов контролируемой функции. Техника полезна, когда у вас есть возможность испортить кучу так, чтобы сработал обработчик, и подделать vtable/указатель. Требует контроля над памятью, куда смотрит glibc при ошибке.

## House of Emma

House of Emma нацелена на `tcache_perthread_struct` — структуру, управляющую tcache (массив counts и entries). Если получить указатель на неё (или подделать её), можно контролировать, какие чанки возвращаются. Emma использует перекрытие и запись в `tcache_perthread_struct` для создания примитива произвольной аллокации. Актуальна на glibc с safe-linking, где прямой poisoning затруднён: вместо подделки `next` вы подделываете саму структуру tcache.

## House of Apple

House of Apple — техника FSOP через `_IO_wfile_jumps`/`_IO_wfile_overflow`, актуальная на glibc 2.35+ (после ужесточения `_IO_str_overflow`). Она подделывает `_IO_FILE` и `_wide_data`/`_wide_vtable` так, чтобы при `exit`/`fflush` вызвалась контролируемая функция. Это современная замена классическим FSOP-цепочкам. Требует корректных смещений для целевой версии и учёта `_IO_vtable_check`.

## House of God

House of God — обобщение: цепочка, комбинирующая largebin attack для записи указателя на поддельную структуру в `_IO_list_all`/`__exit_funcs` и последующий FSOP. Она показывает, как из одной произвольной записи (largebin) и подделки `_IO_FILE` собрать исполнение на самых новых glibc. Названия техник условны; суть — комбинация примитивов.

## Общая схема современных House of

Современные техники следуют одному шаблону: (1) получить утечки libc/heap; (2) получить примитив произвольной записи (largebin, stashing, overlap); (3) подделать структуру, которую glibc использует в критическом пути (`tcache_perthread_struct`, `_IO_FILE`, `__exit_funcs`); (4) триггернуть вызов. Отличие от старых техник — в целях: вместо хуков атакуются внутренние структуры glibc.

| Техника | Цель | Версия |
|---|---|---|
| House of Kiwi | обработчик ошибок | 2.34+ |
| House of Emma | `tcache_perthread_struct` | 2.32+ |
| House of Apple | `_IO_wfile_jumps` | 2.35+ |
| House of God | largebin + FSOP | 2.34+ |

## Разобранный пример: House of Apple

```python
from pwn import *
libc = ELF('./libc.so.6', checksec=False)
# 1) получить произвольную запись и утечки
# 2) подделать _IO_FILE
fake = FileStructure()
fake.flags = 0
fake.vtable = libc.sym['_IO_wfile_jumps']
fake._wide_data = fake_addr + 0xe0
# 3) подделать wide_vtable
wide = FileStructure()
wide._wide_vtable = fake_addr + 0x100
wide._wide_vtable.__doallocate = libc.sym['system']
# 4) связать с _IO_list_all и вызвать exit
```

Смещения зависят от версии; проверяйте в gdb.

## Проверка в gdb

```bash
gdb ./chall
(gdb) p &tcache_perthread_struct
(gdb) p &_IO_list_all
(gdb) p &_IO_wfile_jumps
(gdb) p &__exit_funcs
(gdb) ptype struct _IO_wide_data
```

Эти адреса и структуры — цели современных техник; изучайте их раскладку для своей версии.

## Частые ошибки

- **Использование устаревших техник.** `__free_hook` на 2.34+ не существует.
- **Неверные смещения.** Структуры менялись — сверяйте с целевой glibc.
- **Забытая проверка vtable.** `_IO_vtable_check` требует vtable в libc.
- **Safe-linking.** Прямой poisoning не сработает без heap-утечки.
- **Не тот триггер.** FSOP требует `exit`/`fflush`.

## Справочные таблицы

| Символ | Роль |
|---|---|
| `tcache_perthread_struct` | управление tcache |
| `_IO_list_all` | список потоков |
| `_IO_wfile_jumps` | vtable wide-файла |
| `__exit_funcs` | обработчики exit |
| `main_arena` | арена |

## Что дальше / решение

Дальше: `pwn-glibc-mitigations`, `pwn-fsop`, `pwn-io-str-overflow`, `pwn-exit-handlers`, `pwn-largebin-attack`. Практический алгоритм: (1) определите версию glibc; (2) добудьте утечки и произвольную запись; (3) выберите технику под версию (Kiwi/Emma/Apple/God); (4) подделайте соответствующую структуру; (5) триггерните вызов. Современные House of — это не отдельные «магические» приёмы, а комбинации примитивов; понимание их общей схемы позволяет адаптироваться к новым митигациям.
## Полный разбор House of Apple на glibc 2.35

Разберём сквозной пример. Дано: glibc 2.35, хуки удалены, safe-linking включён, есть heap UAF и произвольная запись. Цель — исполнение через FSOP. План: (1) через UAF/overlap утекаем libc и heap; (2) вычисляем адреса `_IO_list_all`, `_IO_wfile_jumps`, `system`; (3) в контролируемом чанке конструируем поддельный `_IO_FILE` с `vtable = _IO_wfile_jumps`, `_wide_data = fake + 0xe0`; (4) в wide-данных выставляем `_wide_vtable` на поддельную таблицу, где `__doallocate = system`; (5) связываем поток с `_IO_list_all`; (6) триггерим `exit`. При `_IO_flush_all_lockp` glibc дойдёт до нашего потока, вызовет `_IO_wfile_overflow`, которая через `_IO_wdoallocbuf` обратится к `_wide_vtable->__doallocate`, то есть к `system`. Проверяем в gdb: `b _IO_flush_all_lockp`, `b _IO_wfile_overflow`, `b _IO_wdoallocbuf`, `b system`.

## House of Emma: работа с tcache_perthread_struct

`tcache_perthread_struct` — структура в начале кучи, содержащая массивы `counts[64]` и `entries[64]`. House of Emma атакует её напрямую: если получить указатель на неё (или подделать), можно управлять тем, какие чанки возвращает tcache. Схема: (1) через UAF/overlap получить запись в `tcache_perthread_struct`; (2) выставить `entries[i]` на целевой адрес; (3) `malloc` соответствующего размера вернёт target. Это обходит необходимость подделывать `next` отдельного чанка (и safe-linking), потому что вы работаете с самой структурой управления. Требует знания адреса `tcache_perthread_struct` (обычно heap_base + 0x10).

## House of Kiwi: эксплуатация обработчика ошибок

House of Kiwi использует путь обработки ошибок glibc: при `malloc_printerr`/`__libc_message` glibc обращается к `_IO_2_1_stderr_` и его vtable, а также может вызывать `__malloc_assert`. Если подделать структуру stderr или связанные указатели, вы получите вызов контролируемой функции в момент, когда glibc обнаруживает повреждение кучи. Это «пассивная» техника: вы намеренно портите кучу так, чтобы сработал обработчик, и заранее подготавливаете поддельную структуру. Требует контроля над памятью, куда смотрит обработчик.

## Общие принципы и выбор техники

Все современные House of следуют принципу «атакуем внутренние структуры glibc, а не внешние хуки». Выбор зависит от версии и доступного примитива:

| Условие | Техника |
|---|---|
| есть произвольная запись | House of God / largebin + FSOP |
| есть запись в tcache_perthread | House of Emma |
| есть повреждение кучи | House of Kiwi |
| glibc 2.35+ | House of Apple (`_IO_wfile`) |

Начните с определения версии glibc и доступных примитивов, затем выберите технику. Не пытайтесь применить устаревшую цепочку «по памяти» — сверяйтесь с целевой библиотекой и проверяйте в gdb.

## Чек-лист

1. Определите версию glibc и митигации.
2. Добудьте утечки libc/heap.
3. Добудьте примитив произвольной записи.
4. Выберите технику под версию.
5. Подделайте целевую структуру.
6. Триггерните вызов (`exit`/`fflush`/повреждение кучи).
7. Проверьте цепочку в gdb по шагам.

## Итог

Kiwi, Emma, Apple, God — это современный арсенал heap-эксплуатации, выросший из необходимости обходить safe-linking и отсутствие хуков. Они не заменяют базовые техники, а дополняют их: сначала вы получаете утечки и произвольную запись (через tcache poisoning, stashing, largebin), затем применяете одну из них для финального исполнения. Понимание общей схемы важнее заучивания конкретных смещений.

## Итоговая мысль

Kiwi, Emma, Apple и God — не отдельные «серебряные пули», а семейство техник, решающих одну задачу: исполнение на современных glibc без хуков и с safe-linking. Их объединяет атака на внутренние структуры glibc. Освойте сначала базовые примитивы (poisoning, stashing, largebin), затем применяйте подходящую технику под версию. Всегда сверяйте смещения с целевой библиотекой и проверяйте цепочку в gdb.

## Largebin attack как основа House of God

Largebin attack заслуживает отдельного пояснения, потому что она — фундамент многих современных цепочек. При вставке чанка в largebin glibc записывает указатель на него в поля `bk_nextsize`/`fd_nextsize` соседних чанков. Если подделать эти поля, запись произойдёт по произвольному адресу. Это даёт произвольную запись без double-free и без tcache. Обычно её используют, чтобы записать указатель на поддельную структуру в `_IO_list_all` (House of God), после чего триггерится FSOP. Требуется два больших чанка и контроль над их метаданными. Несмотря на сложность, largebin attack остаётся рабочей на самых новых glibc, что делает её незаменимой.

## Практические заметки по отладке современных техник

Отладка FSOP и largebin-цепочек требует терпения. Ставьте точки останова на ключевые функции (`_IO_flush_all_lockp`, `_IO_wfile_overflow`, `_int_malloc` для largebin), следите за полями структур и указателями. Проверяйте, что поддельный чанк действительно попал в нужный бин и что связи корректны. Если `_IO_vtable_check` срабатывает, убедитесь, что vtable в libc. Логируйте адреса `_IO_list_all`, `main_arena`, heap-базы. Только пошаговая проверка позволяет локализовать ошибку в сложной цепочке.

## Квиз

```quiz
- question: "Какую проблему решают современные House of (Apple, Kiwi, God)?"
  options:
    - "Получение вызова функции на glibc без хуков и старых FSOP-путей"
    - "Обход canary"
    - "Отключение ASLR"
    - "Сжатие указателей"
  answer: 0
  explanation: "После удаления хуков и ужесточения FSOP нужны новые пути к вызову функции."
- question: "На чём основан House of Apple 2?"
  options:
    - "На _IO_wfile_jumps и wide-функциях stdio"
    - "На GOT"
    - "На canary"
    - "На tcache key"
  answer: 0
  explanation: "Apple 2 использует _IO_wfile_jumps/_IO_wfile_overflow для вызова функции."
- question: "Что использует House of Kiwi для триггера?"
  options:
    - "assert/_IO_flush путь через _IO_file_jumps"
    - "malloc"
    - "free"
    - "read"
  answer: 0
  explanation: "Испорченная куча вызывает assert/flush, ведущий к _IO_file_jumps."
- question: "Какая версия glibc удалила __malloc_hook/__free_hook?"
  options:
    - "2.34"
    - "2.23"
    - "2.26"
    - "2.31"
  answer: 0
  explanation: "Хуки удалены в 2.34, что и породило новые техники."
- question: "Что нужно почти для всех современных FSOP-техник?"
  options:
    - "Контроль над fake _IO_FILE и триггер exit/flush"
    - "Отключённый NX"
    - "Снятая canary"
    - "Отключённый ASLR"
  answer: 0
  explanation: "FSOP-цепочки требуют fake-структуры и триггера flush/exit."
```

## Где пригодится

- **CTF:** Pwn — modern glibc heap-задачи.
- **Bug bounty:** эксплуатация на актуальных системах.
- **Пентест:** разработка эксплойтов.
- **Работа:** security research glibc.
