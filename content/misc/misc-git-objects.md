---
id: misc-git-objects
title: "Git-объекты: blob, tree, commit вручную"
category: misc
parent: misc-git-forensics
difficulty: hard
order: 3
tags: [git, objects, blob, tree, commit, zlib, forensics, ctf]
prerequisites: [misc-git-forensics]
useful_for:
  - "CTF Forensics/Misc категория"
  - "Восстановление данных из .git"
  - "Анализ репозиториев"
estimated_minutes: 28
summary: "Внутреннее устройство git: blob/tree/commit/tag, zlib-сжатие, ручное чтение объектов, восстановление потерянных данных и работа с packfiles."
---

## Вопрос, с которого всё начинается

Задача даёт каталог `.git` — и больше ничего. Ни файлов, ни веток, ни коммитов, видимых обычным способом. Даже `git` может отказываться открывать репозиторий. Как достать данные, если смотреть не на что?

## Наш пример: осиротевший .git

Смотрим структуру:

```
$ ls .git
HEAD  config  index  objects  refs
$ git log --all --oneline
fatal: your current branch 'main' does not have any commits yet
```

Коммитов нет, но в `objects` что-то лежит. Здесь нужно понять, что git — это база данных объектов, а не просто «система контроля версий». Каждый коммит, файл и каталог — отдельный объект, адресуемый хэшем. Даже без веток объекты живы.

## Шаг 1: четыре типа объектов

| Тип | Что хранит | Ссылается на |
|-----|-----------|--------------|
| **blob** | содержимое файла | — |
| **tree** | список имён и режимов (каталог) | blob/tree |
| **commit** | снимок (tree + родители + метаданные) | tree, commit |
| **tag** | аннотированный тег | commit |

Каждый объект лежит в `.git/objects/` как **zlib-сжатые** данные. Несжатый формат простой: `<type> <size>\0<content>` — тип, размер, нулевой байт и сами данные. Хэш (SHA-1) считается от этих несжатых данных, поэтому одинаковое содержимое даёт один и тот же объект.

## Шаг 2: находим висячие объекты

`git fsck` проверяет целостность базы и показывает объекты, на которые никто не ссылается:

```
$ git fsck --lost-found
dangling blob 3f1a2b4c...
```

Есть висячий blob — кандидат на секрет. Читаем его через высокоуровневую команду:

```
$ git cat-file -t 3f1a2b4c...
blob
$ git cat-file -p 3f1a2b4c...
flag{git_objects_revealed}
```

`-t` печатает тип объекта, `-p` — его содержимое в читаемом виде. Для blob это просто данные файла.

## Шаг 3: читаем объект вручную

Иногда `git` не работает (повреждённый репозиторий или нет самой утилиты). Тогда объект распаковывают zlib-ом напрямую. Файл лежит по пути `.git/objects/ab/cdef...`, где `ab` — первые два символа хэша:

```python
import zlib
data = zlib.decompress(open('.git/objects/3f/1a2b4c...', 'rb').read())
print(data[:60])
```

Вывод начинается с заголовка:

```
b'blob 24\x00flag{git_objects_revealed}\n'
```

Вот и весь секрет: `blob`, размер `24`, нулевой байт, затем содержимое. Однострочником это выглядит так:

```
$ python3 -c "import zlib,sys;print(zlib.decompress(open(sys.argv[1],'rb').read()))" .git/objects/3f/1a2b4c...
```

Понимание этого формата — ключ ко всем задачам, где `.git` повреждён.

## Шаг 4: как устроены commit и tree

Если найден висячий commit, он ссылается на снимок каталога. Смотрим:

```
$ git cat-file -p 1a2b3c...
tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent 8a1b2c...
author Ivan <i@x> 1700000000 +0300

secret commit
```

Поля: `tree` — снимок каталога, `parent` — родительский коммит, автор и сообщение. Если `parent` нет — это первый коммит; несколько `parent` — слияние.

Раскрываем tree:

```
$ git cat-file -p 1a2b3c^{tree}
100644 blob deadbeef...  flag.txt
040000 tree d4e5f6...    src
```

`^{tree}` означает «tree этого коммита». Режимы: `100644` — файл, `100755` — исполняемый, `040000` — каталог, `120000` — symlink. Каталог — это tree, указывающий на другие tree и blob. Так репозиторий образует дерево.

## Шаг 5: packfiles

Объекты часто упакованы в `.git/objects/pack/*.pack` и сжаты дельтами. Они доступны:

```
$ git verify-pack -v .git/objects/pack/pack-*.idx | sort -k3 -n | tail -3
deadbeef... blob 24 33 1234
```

Третья колонка — размер; крупные объекты — кандидаты в секреты. Распаковать всё обратно:

```
$ git unpack-objects < .git/objects/pack/pack-*.pack
```

После этого объекты лежат отдельными файлами и читаются `cat-file` или вручную через zlib.

## Шаг 6: собираем объект вручную

Чтобы по-настоящему понять формат, создадим blob своими руками — без `git add`:

```python
import hashlib, zlib, os
content = b"flag{manual}\n"
header = b"blob " + str(len(content)).encode() + b"\0"
full = header + content
sha = hashlib.sha1(full).hexdigest()
path = f".git/objects/{sha[:2]}/{sha[2:]}"
os.makedirs(os.path.dirname(path), exist_ok=True)
open(path, "wb").write(zlib.compress(full))
print(sha)
```

Мы сформировали заголовок `blob <размер>\0`, посчитали SHA-1 от **несжатых** данных, положили результат в `objects/xx/yyyy...` и сжали zlib-ом. После этого объект виден git-у:

```
$ git cat-file -p <sha>
flag{manual}
```

Это упражнение снимает магию с git: объект — просто сжатый файл с заголовком и хэшем в имени. Так же устроены задачи, где нужно «подделать» объект или восстановить его из сырых байтов.

## Шаг 7: полный прогон

Для каталога `.git` без рабочего дерева:

1. `git fsck --lost-found` — находим висячие объекты.
2. `git cat-file -t <хэш>` — определяем тип (blob/tree/commit).
3. `git cat-file -p <хэш>` — читаем содержимое.
4. Если `git` не работает — распаковываем zlib-ом вручную.
5. Для коммита — `git cat-file -p <commit>^{tree}` и идём по дереву до нужного blob.
6. Объекты только в pack — `git verify-pack -v` и `git unpack-objects`.

Порядок «fsck → cat-file → вручную» покрывает и целые репозитории, и повреждённые каталоги `.git`.

## Что мы теперь знаем

По-простому:

1. Git — база данных объектов, адресуемых хэшем; всего четыре типа: blob, tree, commit, tag.
2. Объекты лежат в `.git/objects/` как zlib-сжатые данные формата `<type> <size>\0<content>`.
3. `git fsck --lost-found` находит висячие объекты; `git cat-file -p` их читает.
4. Если `git` не работает, объект распаковывают zlib-ом вручную.
5. Tree описывает каталог, commit ссылается на tree; packfiles хранят объекты дельтами.

## На что смотреть дальше

- **Забыть про zlib.** `cat .git/objects/...` покажет бинарь — нужен `zlib.decompress`.
- **Считать, что удалённый файл исчез.** Он может быть висячим blob.
- **Игнорировать packfiles.** Объекты могут лежать только там.
- **Путать tree и blob.** Tree — каталог, blob — файл.
- **Не проверять все ветки и теги.** Секрет может быть в неслитой ветке.

## Квиз

Проверь себя.

```quiz
- question: "Как хранятся объекты git в .git/objects?"
  options:
    - "zlib-сжатые, с заголовком `<type> <size>\\0`"
    - "открытым текстом"
    - "в base64"
    - "в JSON"
  answer: 0
  explanation: "SHA-1 считается от несжатых данных с заголовком."
- question: "Что такое tree-объект?"
  options:
    - "содержимое файла"
    - "список имён и режимов каталога (ссылки на blob/tree)"
    - "коммит"
    - "тег"
  answer: 1
  explanation: "tree описывает каталог."
- question: "Как найти потерянные объекты?"
  options:
    - "git fsck --lost-found"
    - "git log"
    - "git status"
    - "git remote"
  answer: 0
  explanation: "fsck показывает dangling и unreachable объекты."
- question: "Как вручную прочитать объект из .git/objects/ab/cdef?"
  options:
    - "base64 -d"
    - "xxd"
    - "zlib.decompress(open(path,'rb').read())"
    - "cat"
  answer: 2
  explanation: "Объекты zlib-сжаты."
- question: "Что означает `^{tree}` в команде `git cat-file -p <commit>^{tree}`?"
  options:
    - "родительский коммит"
    - "tree этого коммита"
    - "тег"
    - "индекс"
  answer: 1
  explanation: "Суффикс `^{tree}` достаёт tree-объект коммита."
```

## Куда дальше

Мы разобрали git до уровня объектов. Дальше — новая тема: **побег из джейлов**. Возьмём Python-песочницу, которая «запрещает» всё лишнее, и попробуем выбраться из неё. А пока главное запомни: git-объект — это zlib-сжатый `<type> <size>\0<content>`, и его всегда можно прочитать вручную.

## Где пригодится

- **CTF:** forensics/misc — восстановление из `.git`.
- **Аудит:** поиск секретов в истории репозиториев.
- **Работа:** понимание git internals, восстановление данных.
- **Bug bounty:** утёкшие `.git` на веб-серверах.
