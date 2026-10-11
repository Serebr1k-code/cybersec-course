---
id: pwn-kernel-pipe-buffer
title: "Эксплуатация pipe_buffer"
category: pwn
parent: pwn-kernel-subsystems
difficulty: expert
order: 4
tags: [pwn, kernel, pipe, pipe_buffer, page-cache]
prerequisites: [pwn-kernel-intro, pwn-kernel-heap]
useful_for:
  - "CTF Pwn — kernel"
  - "Разработка эксплойтов"
estimated_minutes: 60
summary: "Как устроены pipe_buffer, примитив Dirty Pipe и захват page cache: перезапись page-cache произвольных файлов и повышение привилегий."
---
Эксплуатация `pipe_buffer` — один из самых востребованных приёмов современного kernel pwn. `pipe_buffer` — массив структур, создаваемый при вызове `pipe()`; каждая структура описывает буфер канала и содержит указатель на `struct page`, смещение и длину. Перезаписав эти поля (через UAF или произвольную запись), можно получить чтение/запись произвольных страниц памяти — примитив, лежащий в основе знаменитой уязвимости Dirty Pipe (CVE-2022-0847). В этом уроке — устройство `pipe_buffer`, техника page-cache overwrite, получение RIP через `ops`, и практические сценарии.

## Устройство pipe_buffer

Структура `pipe_buffer` (в `include/linux/pipe_fs_i.h`):

```c
struct pipe_buffer {
    struct page *page;       // страница с данными
    unsigned int offset;     // смещение в странице
    unsigned int len;        // длина данных
    const struct pipe_buf_operations *ops;  // операции
    unsigned int flags;
    unsigned long private;
};
```

Массив `pipe_buffer` аллоцируется при `pipe()` в кэше `kmalloc-1024` (16 элементов × 0x28 = 0x280, округляется). Это делает его удобной целью для UAF-переиспользования: если уязвимый объект размером ~0x280 освобождён, `pipe_buffer` может занять ту же память.

## Примитив 1: page-cache overwrite (Dirty Pipe)

Идея: указатель `page` в `pipe_buffer` может указывать на страницу page-cache любого файла. Если вы контролируете `page`, `offset` и `len`, то запись в pipe (через `write`) изменит содержимое этой страницы в page-cache — то есть вы получаете запись в произвольный файл, включая read-only (например, `/etc/passwd` или SUID-бинарь). Dirty Pipe эксплуатировала именно это: `flags` не сбрасывались, позволяя записывать в page-cache за пределами допустимого. Схема: (1) подготовить pipe; (2) перезаписать `page` на нужную страницу (например, страницу файла `/etc/passwd`); (3) выставить `offset`/`len`; (4) записать данные — они попадут в page-cache файла.

## Примитив 2: RIP через ops

`pipe_buf_operations` содержит указатели на функции: `release`, `try_steal`, `get`. При закрытии/освобождении pipe вызывается `ops->release`. Если перезаписать `ops` на поддельную таблицу, где `release` указывает на гаджет/функцию, вы получите RIP-контроль:

```c
// перезаписать pipe_buffer->ops на поддельную таблицу
// fake_ops->release = stack_pivot или гаджет
close(pipe_fd);   // вызовет ops->release
```

Это даёт прямой контроль потока выполнения в ядре.

## Разобранный пример: UAF → pipe_buffer → RIP

```python
# эскиз (userland)
# 1) освободить уязвимый объект размером ~0x280
ioctl(fd, FREE, 0)
# 2) создать pipe, чтобы занять память pipe_buffer
r, w = os.pipe()
# 3) записать данные в pipe, чтобы page/offset/len были валидны
os.write(w, b'A'*0x100)
# 4) через UAF перезаписать pipe_buffer->ops на поддельную таблицу
write_uaf(p64(fake_ops_addr))
# 5) закрыть pipe -> вызвать ops->release -> RIP
os.close(r); os.close(w)
```

Для получения root далее строят ROP (`commit_creds`) или используют `modprobe_path`.

## Проверка в gdb

```bash
gdb ./vmlinux
(gdb) target remote :1234
(gdb) b pipe_write
(gdb) p *(struct pipe_buffer*)<addr>
(gdb) p/x *(struct pipe_inode_info*)...
```

Смотрите поля `page`, `offset`, `len`, `ops` до и после перезаписи. Убедитесь, что page указывает на нужную страницу.

## Учёт митигаций

Современные ядра добавили проверки: `pipe_buffer` помечается как `PIPE_BUF_FLAG_CAN_MERGE`, и Dirty Pipe была исправлена сбросом флагов. Также появились hardened freelist, CFI и SMEP/SMAP. Для эксплуатации `pipe_buffer` обычно нужны: UAF/произвольная запись, знание ядерных адресов (KASLR), обход SMEP/SMAP (ROP). Тем не менее `pipe_buffer` остаётся популярной целью из-за удобного размера и мощных примитивов.

## Частые ошибки

- **Неверный размер.** `pipe_buffer` в `kmalloc-1024`; объект должен попадать туда.
- **Не инициализирован pipe.** Запишите данные, чтобы поля были валидны.
- **KASLR.** Адреса `page`/`ops` нужно знать или утечь.
- **Проверки ядра.** Dirty Pipe исправлена — проверяйте версию.
- **Паника.** Неверный `page` приводит к краху.

## Справочные таблицы

| Поле | Смещение | Роль |
|---|---|---|
| `page` | 0x00 | страница |
| `offset` | 0x08 | смещение |
| `len` | 0x0c | длина |
| `ops` | 0x10 | операции |
| `flags` | 0x18 | флаги |
| `private` | 0x20 | приватное |

| Примитив | Поле | Эффект |
|---|---|---|
| page-cache write | `page`/`offset`/`len` | запись в файл |
| RIP | `ops->release` | контроль потока |

## Что дальше / решение

Дальше: `pwn-kernel-heap`, `pwn-kernel-rop`, `pwn-kernel-intro`, `pwn-kernel-smep-smap`. Практический алгоритм: (1) получите UAF/произвольную запись в `kmalloc-1024`; (2) займите память `pipe_buffer`; (3) перезапишите `page` (для page-cache write) или `ops` (для RIP); (4) триггерните операцию; (5) продолжите к root через ROP/`modprobe_path`. `pipe_buffer` — универсальная цель; освоив её, вы получите мощный примитив для большинства современных kernel-задач.
## Полный разбор Dirty Pipe (CVE-2022-0847)

Dirty Pipe — знаменитая уязвимость в `pipe_buffer`, позволявшая записывать в page-cache read-only файлов. Разберём её подробно. Причина: в ядре 5.8+ флаг `PIPE_BUF_FLAG_CAN_MERGE` не сбрасывался при заполнении `pipe_buffer` из user-страниц, из-за чего последующий `write` в pipe «сливался» с предыдущим буфером, записывая данные за пределами разрешённого. Схема эксплойта: (1) заполнить pipe полностью, чтобы все `pipe_buffer` получили флаг `CAN_MERGE`; (2) опустошить pipe (прочитать данные); (3) открыть целевой файл read-only (например, `/etc/passwd`); (4) подготовить `splice` из файла в pipe — `pipe_buffer->page` теперь указывает на страницу page-cache файла; (5) записать в pipe данные с нужным смещением — они попадут в page-cache файла, минуя проверки прав. Так можно изменить `/etc/passwd`, добавив root-пользователя, или модифицировать SUID-бинарь. Проверяем в gdb: `b pipe_write`, смотрим `pipe_buffer->flags` и `page`.

## Примитив записи через splice

`splice` — системный вызов, перемещающий данные между файловым дескриптором и pipe без копирования в userland. Он создаёт `pipe_buffer`, указывающий на страницу page-cache файла. Если вы контролируете `offset`/`len` (через UAF или через баг, как в Dirty Pipe), вы можете записать произвольные данные в произвольное смещение файла. Это очень мощный примитив: изменение SUID-бинаря или `/etc/passwd` даёт root. Даже без Dirty Pipe, при наличии произвольной записи в `pipe_buffer` через UAF, вы можете подделать `page` на нужную страницу (если знаете её адрес) и выполнить `splice`/`write`. Комбинация `pipe_buffer` + page-cache — стандартный путь в современном kernel pwn.

## RIP через ops и последующий ROP

Если цель — исполнение кода, а не запись в файл, используйте поле `ops`. `struct pipe_buf_operations` содержит `release`, `try_steal`, `get`. При закрытии pipe вызывается `ops->release(pipe, buf)`. Перезаписав `ops` на поддельную таблицу, где `release` указывает на stack pivot-гаджет, вы получаете контроль RIP. Далее строите ROP: отключаете SMEP/SMAP (если нужно) и вызываете `commit_creds(prepare_kernel_cred(0))`, возвращаетесь в userland через trampoline. Альтернатива — записать в `modprobe_path` через page-cache-примитив и триггернуть `request_module`, что проще и не требует ROP. Выбор зависит от того, какой примитив у вас есть: page-cache write → `modprobe_path`; RIP → ROP.

## Практические детали и стабильность

`pipe_buffer` в кэше `kmalloc-1024`. Чтобы переиспользовать его после UAF, убедитесь, что размер уязвимого объекта совпадает (округление до 1024). Заполните pipe данными, чтобы `page`/`offset`/`len` были валидны — иначе операции упадут. Привязывайте потоки к CPU. Для page-cache-примитива знайте адрес страницы целевого файла: его можно получить через `/proc/self/pagemap` (при наличии прав) или через утечку. Для RIP-примитива нужны гаджеты и KASLR-утечка. Проверяйте каждый шаг в gdb: `b pipe_write`, `b pipe_release`, `p *(struct pipe_buffer*)addr`. Помните, что современные ядра добавили проверки, и Dirty Pipe исправлена — ищите актуальные баги или используйте UAF.

## Итог

`pipe_buffer` — универсальная цель, дающая и запись в page-cache, и RIP. Она удобна размером (`kmalloc-1024`) и мощными примитивами. Освойте оба сценария: page-cache overwrite (для изменения файлов и `modprobe_path`) и RIP через `ops` (для ROP). Это один из самых ценных навыков современного kernel pwn, и он применяется в большинстве публичных эксплойтов.

## Практические рекомендации

Начните с воспроизведения Dirty Pipe (если версия уязвима) — это лучший учебный пример. Затем перейдите к UAF-сценариям: переиспользование `pipe_buffer` после освобождения объекта. Освойте оба примитива: page-cache write и RIP через `ops`. Проверяйте поля `page`/`offset`/`len`/`ops` в gdb. Помните, что современные ядра добавили проверки, поэтому ищите актуальные баги или комбинируйте с другими примитивами.

## Сравнение с другими объектами-жертвами

`pipe_buffer` удобен размером (1024) и двумя мощными примитивами, но требует создания pipe и заполнения данными. `seq_operations` проще (0x20, прямой RIP), но менее мощный. `msg_msg` гибок по размеру и даёт OOB read/write. `tty_struct` большой и содержит много указателей. На практике комбинируйте: один объект для утечки, другой для RIP. `pipe_buffer` часто выбирают, когда нужна запись в page-cache или когда размер уязвимого объекта попадает в `kmalloc-1024`.

## Типичные ошибки при переиспользовании

Частая ошибка — недостаточно заполнить pipe перед переиспользованием: если `len == 0`, операции не выполняются, и примитив не срабатывает. Другая — неверный размер уязвимого объекта, из-за чего `pipe_buffer` не занимает нужную память. Третья — забыть про KASLR: без адреса страницы page-cache-примитив не работает. Проверяйте все поля `pipe_buffer` в gdb перед триггером и убеждайтесь, что `ops` указывает на валидную таблицу.

## Квиз

```quiz
- question: "Что такое Dirty Pipe?"
  options:
    - "CVE-2022-0847: запись в page cache файла через флаг CAN_MERGE в pipe_buffer"
    - "Атака на tcache"
    - "Отключение ASLR"
    - "Утечка libc"
  answer: 0
  explanation: "Dirty Pipe использует незачищенные флаги pipe_buffer для записи в page cache."
- question: "Какое поле pipe_buffer позволяет захватить поток управления?"
  options:
    - "ops (указатель на pipe_buf_operations)"
    - "offset"
    - "len"
    - "flags"
  answer: 0
  explanation: "Через ops вызываются операции; подмена даёт контроль вызова."
- question: "Почему в Dirty Pipe нельзя писать на границе страницы?"
  options:
    - "splice нужно начинать на offset > 0, иначе не сольётся"
    - "Граница защищена ASLR"
    - "Там нет page cache"
    - "Граница read-only"
  answer: 0
  explanation: "Запись идёт внутрь страницы; offset 0 на границе ломает примитив."
- question: "В каком кэше обычно живёт массив pipe_buffer?"
  options:
    - "kmalloc-1k (16 буферов)"
    - "kmalloc-32"
    - "cred_jar"
    - "dentry"
  answer: 0
  explanation: "Массив из 16 pipe_buffer ~1 КБ, попадает в kmalloc-1k."
- question: "Какой флаг должен присутствовать, чтобы write слился в page cache?"
  options:
    - "PIPE_BUF_FLAG_CAN_MERGE"
    - "IS_MMAPPED"
    - "PREV_INUSE"
    - "SLAB_ACCOUNT"
  answer: 0
  explanation: "CAN_MERGE разрешает дозапись в существующую страницу pipe/page cache."
```

## Где пригодится

- **CTF:** Pwn — kernel-задачи (pipe_buffer, page cache).
- **Bug bounty:** реальные LPE (Dirty Pipe-класс).
- **Пентест:** локальное повышение привилегий.
- **Работа:** security research ядра.
