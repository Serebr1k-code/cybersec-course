#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch MIS-GAP-4a: sandbox runtimes deep — hub + php/java/go/rust escapes."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402
import _labgen  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def spec(lid, title, toolset, files, hints, flag, fs, tools=None):
    return {
        'id': lid, 'category': 'misc', 'title': title, 'toolset': toolset,
        'workdir': WD, 'files': files, 'check': CHECK, 'hints': hints,
        'expect': {'file': WD + '/found.txt', 'contains': flag},
        'fs': fs, 'tools': tools,
    }


def quiz(qs):
    out = ['## Квиз', '', 'Проверь себя.', '', '```quiz']
    for q, opts, a, exp in qs:
        out.append('- question: ' + q)
        out.append('  options:')
        for o in opts:
            out.append('    - ' + o)
        out.append('  answer: ' + str(a))
        if exp:
            out.append('  explanation: ' + exp)
    out.append('```')
    return '\n'.join(out)


# ===========================================================================
# HUB: misc-runtimes-deep
# ===========================================================================
m = dict(
    id='misc-runtimes-deep', title='Модуль: песочницы языковых рантаймов',
    category='misc', parent='misc-sandbox', difficulty='hard', order=5,
    tags=['sandbox', 'php', 'java', 'go', 'rust', 'roadmap'],
    prerequisites=['misc-sandbox'], estimated_minutes=15,
    summary='Этап про побег из песочниц, которые строит сам язык: PHP disable_functions, Java SecurityManager, Go и Rust unsafe.',
    useful_for=['CTF Misc: jail-задачи', 'Аудит песочниц', 'Обход ограничений рантайма'],
)
body = '''Этот модуль продолжает ветку «Песочницы и изоляция». Если раньше мы убегали из чужих песочниц (seccomp, namespaces, контейнеры), то здесь речь о песочницах, которые пытается построить **сам язык**: PHP отключает опасные функции, Java ставит SecurityManager, Go и Rust полагаются на «безопасность» компилятора. Везде одна закономерность: запрет по имени функции не равен запрету возможности.

## Что покрывает модуль

- **PHP sandbox** — `disable_functions`, `open_basedir`, обход через `LD_PRELOAD`, FFI и chankro.
- **Java sandbox** — `SecurityManager`, `AccessController` и почему их обходят через рефлексию.
- **Go sandbox** — `unsafe`, `//go:linkname` и прямой `syscall` в обход вайтлиста.
- **Rust sandbox** — `unsafe`, `transmute` и FFI как мост наружу.

## Почему такой порядок

Начинаем с PHP — самый частый язык «песочниц для кода» в CTF. Затем Java: её модель безопасности формальнее, но исторически дырявая. Дальше Go и Rust — современные языки, где песочницу часто строят «на доверии», и именно это ломается.

## Чему вы научитесь

- Читать конфигурацию песочницы и находить, что реально запрещено.
- Обходить `disable_functions` без прямого вызова `exec`.
- Понимать, почему SecurityManager обходится рефлексией.
- Использовать `unsafe`/FFI для выхода за пределы «безопасного» рантайма.

## Как проходить ступень

Каждый урок — с лабораторией и флагом. Пробуйте не только готовый обход, но и объяснять, почему фильтр его не поймал.

## Связь с другими ветками

После языковых песочниц логично перейти к изоляции на уровне ядра (`misc-runtimes-iso`: gVisor, Firecracker, QEMU) и к ядерным примитивам из `misc-kernel-misc-deep`.
''' + quiz([
    ('Что отключает disable_functions в PHP?',
     ['Функции по именам', 'Файловую систему', 'Сеть', 'Процессор'],
     0, 'Отключение идёт по списку имён, а не по возможностям.'),
    ('Почему SecurityManager в Java исторически обходили?',
     ['Через рефлексию и изменение полей', 'Он не работал', 'Он был медленным',
      'Его не было'], 0, 'Рефлексия ломала инкапсуляцию модели безопасности.'),
    ('Чем опасен Go unsafe для песочницы?',
     ['Даёт произвольный доступ к памяти и syscall', 'Замедляет код',
      'Ломает сборку', 'Ничем'], 0, 'unsafe и linkname обходят вайтлисты.'),
    ('Что общего у всех языковых песочниц?',
     ['Запрет по имени не равен запрету возможности', 'Они непробиваемы',
      'Они работают только в Linux', 'Их пишут на C'], 0,
     'Обход всегда ищет путь в обход списка имён.'),
]) + '''

## Куда дальше

В следующем уроке мы возьмём PHP-песочницу с `disable_functions` и убежим из неё через `LD_PRELOAD`. А пока запомни: песочница на уровне языка защищает от честного кода, а не от атакующего.

## Где пригодится

- CTF Misc: задачи вида «выполни код в песочнице».
- Аудит плагинов и «выполни код» панелей.
- Понимание границ доверия в рантаймах.
'''
write_lesson(m, body)

# ===========================================================================
# misc-php-sandbox
# ===========================================================================
m = dict(
    id='misc-php-sandbox', title='PHP sandbox escape: disable_functions и обход',
    category='misc', parent='misc-runtimes-deep', difficulty='hard', order=1,
    tags=['php', 'sandbox', 'disable_functions', 'ld_preload', 'ffi'],
    prerequisites=['misc-runtimes-deep'], estimated_minutes=40,
    summary='Побег из PHP-песочницы: как читать disable_functions/open_basedir и обходить их через LD_PRELOAD, FFI и chankro.',
    useful_for=['CTF Misc: PHP jail', 'Аудит панелей', 'Обход фильтров функций'],
)
body = '''## Вопрос, с которого всё начинается

Тебе дали веб-приложение, которое исполняет произвольный PHP-код, но с ограничениями: часть опасных функций отключена, а доступ к файлам урезан одним каталогом. Такие «PHP-песочницы» часто встречаются в CTF и в легаси-панелях. Задача — понять, что именно запрещено, и найти путь наружу.

## Наш пример: панель запускает код

```
$ curl -s 'http://sandbox.local/run.php' --data-urlencode 'code=echo 2+2;'
4
```

Код исполняется. Пробуем прочитать флаг:

```
$ curl -s 'http://sandbox.local/run.php' --data-urlencode 'code=echo file_get_contents("/flag.txt");'
Warning: file_get_contents(): open_basedir restriction in effect. File(/flag.txt) is not within the allowed path(s): (/var/www/html)
```

Функция `file_get_contents` существует, но `open_basedir` её блокирует. Значит, изоляция построена на конфигурации PHP, а не на отсутствии функций.

## Шаг 1: как устроена изоляция в PHP

PHP-песочница обычно стоит на трёх опорах:

- **`disable_functions`** — список функций, которые интерпретатор отказывается вызывать.
- **`open_basedir`** — белый список каталогов для файловых функций.
- ограничения ОС (отдельный пользователь, `seccomp`, контейнер).

Ключевой факт: `disable_functions` работает **по именам функций**, а не по возможностям. Если запрещён `system`, это не значит, что запрещён запуск процессов — просто убрали одну дверь.

## Шаг 2: узнаём точную конфигурацию

```
$ curl -s 'http://sandbox.local/run.php' --data-urlencode 'code=var_dump(ini_get("disable_functions"), ini_get("open_basedir"));'
string(58) "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
string(14) "/var/www/html"
```

Читаем: запуск процессов отключён по именам (`exec`, `system`, `proc_open`, …), а файловые операции ограничены `/var/www/html`. Дальше ищем функции, которых в списке нет.

## Шаг 3: обход через переменные окружения и загрузчик

Классический обход — `putenv` (обычно не в списке) плюс динамический загрузчик Linux. `putenv` задаёт переменную окружения текущего процесса. Если среди них есть `LD_PRELOAD`, то **любой новый процесс**, порождённый из PHP, подгрузит нашу библиотеку до `main`. А породить процесс можно функцией, которая формально не «запускает команды»:

```php
<?php
file_put_contents('/tmp/evil.so', base64_decode('...'));
putenv('LD_PRELOAD=/tmp/evil.so');
mail('a@b.c', 'x', 'y');   // форкает и запускает /usr/sbin/sendmail
```

Конструктор нашей `.so` (`__attribute__((constructor))`) исполняется в новом процессе и может сделать что угодно — прочитать флаг, отправить его наружу. Так `exec` обходится **без** `exec`.

## Шаг 4: обход через FFI

Если PHP 7.4+ собран с расширением FFI, доступ к C-функциям идёт напрямую:

```php
<?php
$ffi = FFI::cdef('int system(const char *cmd);', 'libc.so.6');
$ffi->system('cat /flag.txt');
```

FFI не проходит через `disable_functions`: интерпретатор видит вызов метода объекта, а не «запрещённую» функцию. Это тот же принцип — запрет по имени обходится другим путём.

## Шаг 5: инструмент chankro

chankro автоматизирует связку `putenv` + `LD_PRELOAD` + срабатывание. Он генерирует PHP-скрипт, который кладёт `.so`, ставит переменную и вызывает `mail()`/`error_log()` как триггер. В CTF это экономит время, но понимать механизм важнее: инструмент лишь упаковывает шаги 3.

## Полный прогон

1. `var_dump(ini_get('disable_functions'))` — список запрещённого.
2. `phpinfo()` — версия PHP и наличие FFI.
3. Нет FFI → `putenv('LD_PRELOAD=...')` + `mail()`.
4. Есть FFI → `FFI::cdef` + вызов `system`.
5. Читаем `/flag.txt`, пишем содержимое в ответ.

## Что мы теперь знаем

- `disable_functions` — чёрный список имён, а не модель возможностей.
- `open_basedir` ограничивает файлы, но не процессы.
- `LD_PRELOAD` + любой форкающий вызов обходят запрет `exec`.
- FFI даёт прямой доступ к libc в обход списка.
- chankro — просто автоматизация этого обхода.

''' + quiz([
    ('Почему disable_functions не является полноценной песочницей?',
     ['Он фильтрует по именам, а не по возможностям', 'Он медленный',
      'Он не работает в Linux', 'Он требует root'], 0,
     'Запрет имени обходится другим путём.'),
    ('Какую переменную окружения использует обход через загрузчик?',
     ['LD_PRELOAD', 'PATH', 'HOME', 'PHP_INI_SCAN_DIR'], 0,
     'LD_PRELOAD заставляет загрузчик подгрузить нашу библиотеку.'),
    ('Зачем в обходе нужен mail() или error_log()?',
     ['Они форкают новый процесс', 'Они читают файлы', 'Они шифруют данные',
      'Они отключают фильтр'], 0, 'Нужен новый процесс, где сработает LD_PRELOAD.'),
    ('Что даёт расширение FFI?',
     ['Прямой вызов C-функций в обход списка', 'Ускоряет скрипт', 'Сжимает код',
      'Ничего'], 0, 'FFI обходит disable_functions.'),
]) + '''

## Куда дальше

В следующем уроке — Java: там изоляция формальнее (`SecurityManager`), но обходится через рефлексию. А пока запомни: PHP-песочница на конфигурации ломается любым неотключённым мостом к ОС.

## Где пригодится

- CTF Misc: задачи «выполни PHP-код».
- Аудит админ-панелей с «run code».
- Понимание разницы между чёрным и белым списком.
'''
write_lesson(m, body)
_labgen.apply(spec(
    'misc-php-sandbox', 'Практика: побег из PHP-песочницы',
    ['core', 'php', 'file'],
    ['task.md', 'sandbox.php', 'notes.txt', 'flag.txt'],
    ['Изучи `sandbox.php`: какие функции запрещены и куда ограничен доступ.',
     'В `notes.txt` подсказка про LD_PRELOAD и mail().',
     'Флаг лежит в `flag.txt` — прочитай и запиши в `found.txt`.'],
    'nto{php_d1s4bl3_funcs_byp4ss}',
    [_dir(WD),
     _f(WD + '/task.md', '# PHP sandbox\n\n`sandbox.php` имитирует панель «выполни код». Изучи фильтр, найди обход и прочитай `flag.txt`.\n'),
     _f(WD + '/sandbox.php', "<?php\n// Псевдо-песочница: вырезает опасные имена функций\n$code = $_GET['code'] ?? '';\nforeach (['exec','system','shell_exec','passthru','proc_open'] as $f) {\n    if (stripos($code, $f) !== false) die('blocked: '.$f);\n}\nini_set('open_basedir', __DIR__);\neval($code);\n"),
     _f(WD + '/notes.txt', 'Наблюдение: putenv() и mail() не вырезаны. LD_PRELOAD=/tmp/x.so + mail() форкает sendmail и грузит нашу библиотеку до main. FFI тоже подходит, если включён.\n'),
     _f(WD + '/flag.txt', 'nto{php_d1s4bl3_funcs_byp4ss}\n')],
    tools={'php': {'help': 'php <файл.php> — интерпретатор PHP',
                   'cases': [{'match': '--version|^-v$', 'example': 'php --version',
                              'output': 'PHP 8.2.7 (cli) (built: Jun  7 2023 15:37:14) (NTS)'}]}},
))

# ===========================================================================
# misc-java-sandbox
# ===========================================================================
m = dict(
    id='misc-java-sandbox', title='Java sandbox: SecurityManager и обход рефлексией',
    category='misc', parent='misc-runtimes-deep', difficulty='hard', order=2,
    tags=['java', 'sandbox', 'securitymanager', 'reflection', 'unsafe'],
    prerequisites=['misc-runtimes-deep'], estimated_minutes=38,
    summary='Модель безопасности Java (SecurityManager, AccessController, doPrivileged) и её обход через рефлексию, Unsafe и десериализацию.',
    useful_for=['CTF Misc: Java jail', 'Аудит серверов на JVM', 'Разбор десериализации'],
)
body = '''## Вопрос, с которого всё начинается

Java-сервер принимает «безопасный» плагин и ограничивает его права через `SecurityManager`: плагину нельзя читать файлы и завершать JVM. В теории. На практике такие песочницы обходят снова и снова. Разберём, как устроена модель безопасности Java и почему она течёт.

## Наш пример: плагин в песочнице

```
$ java -Djava.security.manager -Djava.security.policy=sandbox.policy Run
> read /etc/passwd
AccessControlException: access denied ("java.io.FilePermission" "/etc/passwd" "read")
```

Плагин получил исключение — механизм работает. Посмотрим, что он запрещает.

## Шаг 1: что такое SecurityManager

`SecurityManager` — объект, который JVM спрашивает перед потенциально опасным действием. Когда код вызывает `new FileInputStream("/etc/passwd")`, JVM дергает менеджер: «можно?». Менеджер смотрит **политику** (`java.policy`) и либо разрешает, либо бросает `AccessControlException`.

Политика задаёт, каким кодам что можно:

```
grant codeBase "file:/opt/plugin/-" {
    permission java.util.PropertyPermission "user.dir", "read";
};
```

Коду из `/opt/plugin` разрешено читать одно свойство — и всё.

## Шаг 2: AccessController и стек

Менеджер проверяет не только текущий кадр, но весь стек вызовов: если наш код вызвал системную библиотеку, а та обратилась к файлу, проверяется и наш кадр. Для «доверенных» мест есть `AccessController.doPrivileged(...)` — он обрезает стек, объявляя участок доверенным.

Именно здесь и живёт классическая ошибка: если доверенный код читает **произвольный** путь, переданный извне, `doPrivileged` пропускает атакующего внутрь.

## Шаг 3: обход через рефлексию

Плагин хочет снять менеджер целиком. Прямой вызов `System.setSecurityManager(null)` бросит `SecurityException`. Но поле, хранящее менеджер, можно достать рефлексией:

```java
Field f = System.class.getDeclaredField("security");
f.setAccessible(true);
f.set(null, null);   // менеджер исчез
```

Если менеджер не запрещает `ReflectPermission("suppressAccessChecks")`, `setAccessible(true)` снимает инкапсуляцию, и мы меняем внутреннее поле. После этого любые проверки проходят «мимо».

## Шаг 4: обход через Unsafe

`sun.misc.Unsafe` даёт доступ к памяти и внутренним структурам в обход виртуальной машины:

```java
Unsafe u = getUnsafe();          // через рефлексию к полю theUnsafe
u.putObject(System.class, offset, null);   // обнуляем поле менеджера
```

Unsafe — «чёрный ход» JVM: он не спрашивает менеджер о большинстве операций.

## Шаг 5: обход через десериализацию

Если песочница ещё и десериализует данные (`ObjectInputStream`), то gadget-цепочки (CommonsCollections и др.) вызывают методы вне проверок или переписывают поля через `readObject`. Менеджер проверяет действия, но не то, что цепочка соберёт `Runtime.exec` из уже доверенных объектов.

## Полный прогон

1. Плагин ловит `AccessControlException` — изучаем политику.
2. Пробуем `System.setSecurityManager(null)` — отказ.
3. Рефлексия: `getDeclaredField("security")` + `setAccessible(true)` + `set(null)`.
4. Менеджер снят → читаем `/flag.txt` через `Files.readString`.
5. Пишем флаг в ответ.

## Что мы теперь знаем

- SecurityManager — точка принятия решений, опирающаяся на политику.
- `doPrivileged` обрезает стек и может стать дырой.
- Рефлексия + `setAccessible` снимает инкапсуляцию полей.
- `Unsafe` обходит проверки на уровне памяти.
- Десериализация позволяет собрать вызов в обход политики.

''' + quiz([
    ('Что проверяет SecurityManager?',
     ['Стек вызовов и политику', 'Только текущий файл', 'Размер памяти',
      'Скорость'], 0, 'Проверяется весь стек против политики.'),
    ('Почему doPrivileged может стать уязвимостью?',
     ['Он обрезает стек и доверяет участку', 'Он шифрует данные',
      'Он замедляет JVM', 'Он удаляет политику'], 0,
     'Доверенный участок может работать с внешними путями.'),
    ('Как снимают SecurityManager рефлексией?',
     ['Через getDeclaredField + setAccessible + set', 'Через new File',
      'Через System.exit', 'Через Thread.stop'], 0,
     'Меняем внутреннее поле security.'),
    ('Почему Unsafe опасен для песочницы?',
     ['Обходит проверки на уровне памяти', 'Он публичный', 'Он медленный',
      'Он не документирован'], 0, 'Unsafe не спрашивает менеджер.'),
]) + '''

## Куда дальше

Дальше — Go: там песочницу часто строят на вайтлистах, и `unsafe` с `//go:linkname` ломают её. А пока запомни: модель безопасности Java сильна ровно настолько, насколько закрыты рефлексия и Unsafe.

## Где пригодится

- CTF Misc: Java jail и десериализация.
- Аудит плагинных систем на JVM.
- Понимание ограничений старых API безопасности.
'''
write_lesson(m, body)
_labgen.apply(spec(
    'misc-java-sandbox', 'Практика: снятие SecurityManager',
    ['core', 'java', 'file'],
    ['task.md', 'Sandbox.java', 'policy.txt', 'flag.txt'],
    ['В `Sandbox.java` менеджер запрещает чтение файлов.',
     'Прямой setSecurityManager(null) не сработает — нужна рефлексия к полю security.',
     'После снятия менеджера прочитай `flag.txt` и запиши в `found.txt`.'],
    'nto{j4v4_r3fl3ct10n_sm_byp4ss}',
    [_dir(WD),
     _f(WD + '/task.md', '# Java sandbox\n\nПлагин ограничен SecurityManager. Найди обход и прочитай `flag.txt`.\n'),
     _f(WD + '/Sandbox.java', "import java.security.*;\npublic class Sandbox {\n  public static void main(String[] a) throws Exception {\n    System.setSecurityManager(new SecurityManager());\n    // плагин: прочитать flag.txt -> AccessControlException\n  }\n}\n"),
     _f(WD + '/policy.txt', "grant { permission java.util.PropertyPermission \"user.dir\", \"read\"; };\n"),
     _f(WD + '/flag.txt', 'nto{j4v4_r3fl3ct10n_sm_byp4ss}\n')],
    tools={'java': {'help': 'java [-Dkey=val] <Класс> — запуск JVM',
                    'cases': [{'match': '--version|^-version$', 'example': 'java -version',
                               'output': 'openjdk version "17.0.7" 2023-04-18\nOpenJDK Runtime Environment (build 17.0.7+7)'}]}},
))

# ===========================================================================
# misc-go-sandbox
# ===========================================================================
m = dict(
    id='misc-go-sandbox', title='Go sandbox: unsafe, linkname и прямой syscall',
    category='misc', parent='misc-runtimes-deep', difficulty='hard', order=3,
    tags=['go', 'sandbox', 'unsafe', 'linkname', 'syscall'],
    prerequisites=['misc-runtimes-deep'], estimated_minutes=36,
    summary='Побег из Go-песочницы: вайтлист функций обходится через unsafe, директиву //go:linkname и прямой вызов syscall.',
    useful_for=['CTF Misc: Go jail', 'Аудит встраиваемых интерпретаторов', 'Разбор Go-бинарей'],
)
body = '''## Вопрос, с которого всё начинается

В CTF всё чаще встречается задание на Go: сервис принимает Go-код (или выражение) и ограничивает его вайтлистом «безопасных» функций. Вайтлист выглядит надёжно, пока не вспомнить, что Go — системный язык с прямым доступом к syscall.

## Наш пример: песочница с вайтлистом

```
$ ./gosandbox 'sum([]int{1,2,3})'
6
$ ./gosandbox 'readFile("/etc/passwd")'
error: function readFile is not allowed
```

Песочница разбирает выражение и разрешает только заранее одобренные функции. Как обойти?

## Шаг 1: как обычно строят такую песочницу

Типовой подход — интерпретатор (например, на `go/parser` + `go/ast`) с таблицей разрешённых имён: `sum`, `len`, `strings.Join` и т.п. Всё, чего нет в таблице, отклоняется. Проблема в том, что интерпретатор исполняет **код на Go**, а Go-код умеет куда больше, чем перечислено.

## Шаг 2: обход через reflect и unsafe

Если интерпретатор вызывает функции по имени, но не изолирует типы, можно дотянуться до `reflect.Value` и `unsafe.Pointer`. Например, получить указатель на произвольную память и прочитать её:

```go
p := unsafe.Pointer(uintptr(0xdeadbeef))
s := *(*string)(p)
```

`unsafe` не спрашивает разрешений. Даже если функция `unsafe.Pointer` не в вайтлисте, интерпретатор может позволить импорт пакета `unsafe` целиком — и тогда песочница пуста.

## Шаг 3: обход через //go:linkname

Директива компилятора `//go:linkname` позволяет привязать символ к внутренней функции рантайма или стандартной библиотеки, даже неэкспортированной:

```go
import _ "unsafe"

//go:linkname osExit os.Exit
func osExit(code int)
```

Так из кода, которому «нельзя» вызывать `os.Exit`, мы всё равно его вызываем. Аналогично достают внутренние функции сети, файловой системы, `runtime`.

## Шаг 4: обход через прямой syscall

Самый прямой путь — вообще не пользоваться стандартной библиотекой, а вызвать ядро:

```go
import "syscall"

fd, _ := syscall.Open("/flag.txt", syscall.O_RDONLY, 0)
buf := make([]byte, 64)
n, _ := syscall.Read(fd, buf)
println(string(buf[:n]))
```

`syscall` — тонкая обёртка над системными вызовами Linux. Любая песочница, не фильтрующая `syscall` и не работающая под `seccomp`, пропускает такой код.

## Полный прогон

1. Песочница отклоняет `readFile`.
2. Пробуем импорт `unsafe` — разрешён?
3. Обходим через `//go:linkname` к нужной функции или через `syscall.Open`.
4. Читаем `/flag.txt`, печатаем.
5. Пишем флаг в ответ.

## Что мы теперь знаем

- Вайтлист имён не изолирует возможности языка.
- `unsafe` даёт доступ к памяти без проверок.
- `//go:linkname` привязывает к внутренним символам.
- Прямой `syscall` обходит любую библиотечную обёртку.
- Настоящая изоляция Go-кода требует отдельного процесса с seccomp/контейнером.

''' + quiz([
    ('Почему вайтлист функций не изолирует Go-код?',
     ['Язык всё равно даёт unsafe и syscall', 'Go медленный', 'Go небезопасен',
      'Вайтлист легко взломать'], 0, 'Возможности языка шире списка имён.'),
    ('Что делает //go:linkname?',
     ['Связывает символ с внутренней функцией', 'Ускоряет сборку',
      'Шифрует строки', 'Удаляет проверки'], 0,
     'Позволяет вызвать неэкспортированную функцию.'),
    ('Почему syscall обходит песочницу?',
     ['Он идёт напрямую в ядро', 'Он быстрый', 'Он документирован',
      'Он в вайтлисте'], 0, 'Обёртка стандартной библиотеки не участвует.'),
    ('Как правильно изолировать Go-код?',
     ['Отдельный процесс + seccomp/контейнер', 'Список имён', 'Компилятор',
      'Reflection'], 0, 'Языковые средства не заменяют ОС.'),
]) + '''

## Куда дальше

Дальше — Rust: там `unsafe` и FFI играют ту же роль. А пока запомни: песочница на вайтлисте ломается о прямые системные вызовы.

## Где пригодится

- CTF Misc: Go-интерпретаторы в песочнице.
- Аудит плагинов на Go.
- Понимание границы между языком и ОС.
'''
write_lesson(m, body)
_labgen.apply(spec(
    'misc-go-sandbox', 'Практика: обход Go-вайтлиста',
    ['core', 'file', 'strings'],
    ['task.md', 'sandbox.go', 'flag.txt'],
    ['В `sandbox.go` вайтлист разрешает только `sum` и `len`.',
     'Вспомни про импорт `syscall` и `//go:linkname`.',
     'Прочитай `flag.txt` и запиши в `found.txt`.'],
    'nto{g0_uns4f3_sysc4ll_3sc4p3}',
    [_dir(WD),
     _f(WD + '/task.md', '# Go sandbox\n\nПесочница разрешает лишь `sum`/`len`. Найди путь к файловой системе и прочитай `flag.txt`.\n'),
     _f(WD + '/sandbox.go', "package main\n\n// allowlist: sum, len\nvar allowed = map[string]bool{\"sum\": true, \"len\": true}\n// eval() отклоняет всё остальное, но импорт syscall/unsafe не фильтруется\n"),
     _f(WD + '/flag.txt', 'nto{g0_uns4f3_sysc4ll_3sc4p3}\n')],
    tools={'strings': {'help': 'strings <файл> — печатаемые строки',
                       'cases': [{'match': 'sandbox\\.go', 'example': 'strings sandbox.go',
                                  'output': 'package main\nallowlist: sum, len\nsyscall\nunsafe'}]}},
))

# ===========================================================================
# misc-rust-sandbox
# ===========================================================================
m = dict(
    id='misc-rust-sandbox', title='Rust sandbox: unsafe, transmute и FFI',
    category='misc', parent='misc-runtimes-deep', difficulty='hard', order=4,
    tags=['rust', 'sandbox', 'unsafe', 'transmute', 'ffi'],
    prerequisites=['misc-runtimes-deep'], estimated_minutes=34,
    summary='Почему «безопасный» Rust не делает песочницу безопасной: unsafe, transmute, FFI и обход проверок компилятора.',
    useful_for=['CTF Misc: Rust jail', 'Аудит Rust-плагинов', 'Понимание unsafe'],
)
body = '''## Вопрос, с которого всё начинается

Rust продают как «безопасный язык»: компилятор не даёт выстрелить в ногу. Но в CTF попадаются песочницы на Rust, которые исполняют чужой код в ограниченном наборе операций. И «безопасность» компилятора тут ни при чём — она про память, а не про доступ к системе.

## Наш пример: выражение на Rust

```
$ ./rssandbox 'calc(2+2)'
4
$ ./rssandbox 'open("/etc/passwd")'
error: unknown function open
```

Песочница разбирает выражение и разрешает только `calc` и похожие чистые функции. Посмотрим, где утекает.

## Шаг 1: что именно гарантирует Rust

Компилятор Rust гарантирует **отсутствие гонок и ошибок владения** в безопасном коде. Он не запрещает:

- блок `unsafe { ... }`;
- вызов внешних C-функций через FFI;
- приведение типов, если оно «выглядит» допустимым.

Значит, песочница на уровне языка должна ограничивать не память, а **возможности**: файлы, процессы, сеть. Если она этого не делает — она декоративна.

## Шаг 2: обход через transmute

`std::mem::transmute` переинтерпретирует байты одного типа как другой, не проверяя ничего:

```rust
let x: u64 = 0x4141414141414141;
let p: *const u8 = unsafe { std::mem::transmute(x) };
```

Так из числа делают указатель и читают произвольную память — в `unsafe`-блоке. Если интерпретатор пропускает `unsafe`-код (или сам его использует), изоляция теряется.

## Шаг 3: обход через FFI

Через `extern "C"` Rust зовёт функции libc:

```rust
extern "C" { fn system(cmd: *const i8) -> i32; }

let cmd = b"cat /flag.txt\\0";
unsafe { system(cmd.as_ptr() as *const i8); }
```

FFI не спрашивает «безопасность» Rust — это прямой мост в ОС. Никакой borrow checker не мешает.

## Шаг 4: обход через std::process

Даже без FFI стандартная библиотека даёт запуск процессов:

```rust
std::process::Command::new("cat").arg("/flag.txt").status().unwrap();
```

Если песочница не блокирует `std::process` и не работает в ограниченном процессе — флаг читается в одну строку.

## Шаг 5: почему «safe Rust» не спасает

Безопасность Rust — про то, что **внутри** языка нельзя выйти за границы памяти. Но песочнице нужно другое: запретить обращение к внешнему миру. Это задача ОС (seccomp, namespaces, отдельный пользователь), а не компилятора.

## Полный прогон

1. Песочница отклоняет `open`.
2. Проверяем, доступен ли `unsafe` и FFI.
3. Через `extern "C" { fn system(...) }` запускаем `cat /flag.txt`.
4. Либо через `std::process::Command`.
5. Пишем флаг в ответ.

## Что мы теперь знаем

- Rust гарантирует безопасность памяти, не безопасность доступа.
- `unsafe` и `transmute` снимают ограничения компилятора.
- FFI — прямой мост к libc.
- `std::process` запускает процессы без всяких трюков.
- Изоляция — задача ОС, а не типа.

''' + quiz([
    ('Что гарантирует безопасный Rust?',
     ['Отсутствие ошибок памяти в safe-коде', 'Запрет файлов', 'Запрет сети',
      'Запрет unsafe'], 0, 'Гарантия про память, не про доступ.'),
    ('Что делает transmute?',
     ['Переинтерпретирует тип без проверок', 'Копирует память', 'Шифрует',
      'Освобождает память'], 0, 'Произвольная переинтерпретация байтов.'),
    ('Почему FFI обходит песочницу Rust?',
     ['Зовёт C-функции напрямую', 'Он безопасен', 'Он медленный',
      'Он в std'], 0, 'FFI не подчиняется borrow checker.'),
    ('Где правильно строить изоляцию?',
     ['В ОС: seccomp, namespaces, пользователь', 'В типах Rust',
      'В компиляторе', 'В borrow checker'], 0, 'Изоляция — задача ОС.'),
]) + '''

## Куда дальше

Дальше — изоляция на уровне ядра: gVisor, Firecracker и QEMU. А пока запомни: «безопасный язык» защищает память, но не мир вокруг процесса.

## Где пригодится

- CTF Misc: Rust-песочницы.
- Аудит встраиваемых рантаймов.
- Понимание, что типовая безопасность не заменяет ОС.
'''
write_lesson(m, body)
_labgen.apply(spec(
    'misc-rust-sandbox', 'Практика: выход из Rust-песочницы',
    ['core', 'file', 'strings'],
    ['task.md', 'sandbox.rs', 'flag.txt'],
    ['Песочница разрешает только чистые функции `calc`/`abs`.',
     'Обрати внимание на `unsafe` и `extern "C"` в `sandbox.rs`.',
     'Прочитай `flag.txt` и запиши в `found.txt`.'],
    'nto{rust_uns4f3_ff1_br1dg3}',
    [_dir(WD),
     _f(WD + '/task.md', '# Rust sandbox\n\nПесочница разрешает только `calc`/`abs`. Найди мост наружу и прочитай `flag.txt`.\n'),
     _f(WD + '/sandbox.rs', "// allowlist: calc, abs\nfn eval(expr: &str) -> i64 { /* ... */ 0 }\n// в интерпретаторе есть unsafe { transmute(...) } и extern \"C\" { fn system(...) }\n"),
     _f(WD + '/flag.txt', 'nto{rust_uns4f3_ff1_br1dg3}\n')],
    tools={'strings': {'help': 'strings <файл> — печатаемые строки',
                       'cases': [{'match': 'sandbox\\.rs', 'example': 'strings sandbox.rs',
                                  'output': 'allowlist: calc, abs\nunsafe\nextern \"C\"\nsystem'}]}},
))

print('batch 4a done')
