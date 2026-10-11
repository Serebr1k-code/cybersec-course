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

Git — это база данных объектов, а не просто «система контроля версий». Каждый коммит, файл и каталог — объект, адресуемый SHA-1 хэшем. Понимание этого слоя позволяет вручную восстановить данные, даже когда `git log` ничего не показывает: удалённые файлы, «потерянные» коммиты, содержимое packfiles. В CTF это классическая forensics-задача.

## Четыре типа объектов

| Тип | Что хранит | Ссылается на |
|-----|-----------|--------------|
| **blob** | содержимое файла | — |
| **tree** | список имён и режимов (каталог) | blob/tree |
| **commit** | снимок (tree + родители + метаданные) | tree, commit |
| **tag** | аннотированный тег | commit |

Каждый объект хранится в `.git/objects/` как **zlib-сжатые** данные. Формат: `<type> <size>\0<content>`. SHA-1 считается от несжатых данных.

## Чтение объектов

Высокоуровнево:

```bash
git cat-file -t <hash>     # тип
git cat-file -p <hash>     # содержимое (pretty)
git cat-file -s <hash>     # размер
```

Вручную (без git):

```bash
# объект лежит в .git/objects/ab/cdef...
python3 - <<'EOF'
import zlib
data = zlib.decompress(open('.git/objects/ab/cdef...','rb').read())
print(data[:40])
EOF
```

Или:

```bash
python3 -c "import zlib,sys;print(zlib.decompress(open(sys.argv[1],'rb').read()))" .git/objects/ab/cdef...
```

Первая строка — `blob 1234\0...` — тип, размер и содержимое.

## Как устроен commit

```bash
git cat-file -p HEAD
# tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
# parent 8a1b2c...
# author Ivan <i@x> 1700000000 +0300
# committer Ivan <i@x> 1700000000 +0300
#
# commit message
```

Поля: `tree` (снимок каталога), `parent` (родительский коммит), автор, дата, сообщение. Если у коммита **нет parent** — это первый коммит. Несколько `parent` — merge.

## Как устроен tree

```bash
git cat-file -p HEAD^{tree}
# 100644 blob a1b2c3...    README.md
# 040000 tree d4e5f6...    src
# 100755 blob 123456...    script.sh
```

Режимы: `100644` (файл), `100755` (исполняемый), `040000` (каталог), `120000` (symlink). Каталог — tree, указывающий на другие tree/blob.

## Восстановление потерянного

Даже если файл удалён из всех коммитов, объект может остаться в базе (dangling):

```bash
git fsck --lost-found
# dangling blob a1b2c3...
git cat-file -p a1b2c3...
```

`git fsck --unreachable` и `--dangling` показывают объекты, недостижимые из ссылок. Именно так находят «секреты, удалённые из истории».

## Packfiles

Со временем объекты упаковываются в `.git/objects/pack/*.pack` (со сжатием дельт). `git cat-file` работает и с ними. Для ручного анализа:

```bash
git verify-pack -v .git/objects/pack/pack-*.idx
# перечисляет объекты, размеры, дельты
git unpack-objects < pack-*.pack
```

Инструменты: `git-unpack-objects`, `git verify-pack`, `gitindex`.

## Полный разобранный пример

Дано: каталог `.git`, файлов нет.

```bash
git fsck --lost-found
# dangling commit 1a2b3c...
git cat-file -p 1a2b3c...
# tree ...
# parent ...
# secret commit

git cat-file -p 1a2b3c^{tree}
# 100644 blob deadbeef...  flag.txt
git cat-file -p deadbeef...
# flag{git_objects_revealed}
```

Мы восстановили флаг напрямую из объекта blob.

## Ручное построение объекта

```python
import hashlib, zlib
content = b"flag{manual}\n"
header = b"blob " + str(len(content)).encode() + b"\0"
full = header + content
sha = hashlib.sha1(full).hexdigest()
path = f".git/objects/{sha[:2]}/{sha[2:]}"
import os; os.makedirs(os.path.dirname(path), exist_ok=True)
open(path, "wb").write(zlib.compress(full))
print(sha)
```

Теперь объект доступен как `git cat-file -p <sha>`. Это полезно для понимания и для задач, где надо «подделать» объект.

## Частые ошибки и подводные камни

- Забывать про zlib: `cat .git/objects/...` покажет бинарь.
- Считать, что удалённый файл исчез — он может быть dangling-объектом.
- Игнорировать packfiles: объекты могут лежать только там.
- Путать `tree` (каталог) и `blob` (файл).
- Не проверять все ветки/теги: секрет может быть в неслитой ветке.
- Пропускать `.git/logs/` (reflog) — там пути к «потерянным» коммитам.

## Что дальше / решение

Возьмите репозиторий, удалите файл и коммит, восстановите через `git fsck`. Изучите `misc-git-forensics` и `misc-git-advanced`. Дальше — `misc-archive-tricks` (zlib/архивы) и forensics-ветка.

## Справочная таблица

| Задача | Команда |
|--------|---------|
| Тип объекта | `git cat-file -t <hash>` |
| Содержимое | `git cat-file -p <hash>` |
| Потерянные | `git fsck --lost-found` |
| Pack | `git verify-pack -v ...idx` |
| Распаковать pack | `git unpack-objects < pack` |
| Вручную | `zlib.decompress(...)` |

## Дополнительная теория: SHA-1, дельты и целостность

Git адресует объекты по SHA-1 от несжатого содержимого с заголовком. Это даёт **content-addressing**: одинаковое содержимое = одинаковый хэш, и объект хранится один раз. Именно поэтому в репозитории с сотней почти одинаковых файлов большинство — это дельты к базовому blob. При упаковке (`git gc`) git строит **packfile**, где объекты хранятся как дельты: базовый объект плюс инструкции «скопировать байты X..Y и вставить Z». Это сильно экономит место, но усложняет ручное чтение: чтобы получить blob, нужно применить цепочку дельт.

Важно и то, что SHA-1 известен коллизионными атаками (SHAttered). Хотя для CTF это редко важно, для forensics это означает, что «одинаковый хэш» не гарантирует «одинаковое содержимое» в злонамеренных репозиториях. Современный git поддерживает SHA-256-репозитории, но по умолчанию всё ещё SHA-1.

## .git, HEAD и ссылки

Полная картина репозитория — не только объекты. `.git/HEAD` указывает на текущую ветку (`ref: refs/heads/main`). `.git/refs/heads/*` — ветки, `.git/refs/tags/*` — теги, `.git/packed-refs` — упакованные ссылки. `.git/logs/HEAD` — **reflog**: журнал всех перемещений HEAD, включая «потерянные» коммиты. `.git/index` — staging area (бинарный формат). `.git/config` — remote'ы и настройки, иногда с токенами в URL. При анализе утёкшего `.git` первым делом смотрят именно эти файлы: reflog и config часто содержат больше секретов, чем сами объекты.

Если `.git` утёк на веб-сервере, его можно скачать целиком (`git-dumper`, `dvcs-ripper`) и восстановить репозиторий локально. Тогда `git log --all`, `git fsck`, `git stash list` покажут всю историю. Это стандартная задача bug bounty: `.git` в web-root = утечка исходников и секретов.

## Разбор ошибок и отладка

Если `git fsck` не находит потерянных объектов, возможно, вы в неверной директории или объекты уже собраны сборщиком мусора (`git gc --prune=now`). Попробуйте `git reflog expire --expire=now --all` не выполнять — наоборот, посмотрите reflog. Если объект есть, но `git cat-file` его «не видит», проверьте, не в pack ли он: `git verify-pack -v`. Если файл `.git/objects/ab/cdef` повреждён, попробуйте распаковать zlib вручную — иногда повреждён только индекс, а данные целы. И помните: `git fsck --lost-found` кладёт найденные объекты в `.git/lost-found/` — не теряйте их.

## Частые вопросы

**Можно ли восстановить файл, если он никогда не коммитился?** Обычно нет — git хранит только закоммиченные объекты (плюс проиндексированные blob'ы). Но `git add` создаёт blob в `.git/objects` ещё до коммита, поэтому «добавленный, но не закоммиченный» файл иногда остаётся как dangling blob. `git fsck --lost-found` его найдёт. А вот файл, который никогда не добавлялся, в git отсутствует.

**Почему хэш объекта не совпадает с хэшем файла?** Потому что SHA-1 считается от заголовка `<type> <size>\0` плюс содержимое, а не от содержимого. Это защищает от подмены типа (blob ↔ tree с тем же содержимым дадут разные хэши). Помните об этом, когда строите объект вручную.

**Что делать, если в `.git` нет нужного объекта?** Проверьте packfiles (`git verify-pack -v`), все ветки (`git log --all`), теги, stash (`git stash list`), reflog (`git reflog`), и другие worktrees. Секрет может быть в неслитой ветке или в удалённом stash.

**Как git обрабатывает большие файлы?** Через packfiles с дельтами и, опционально, через Git LFS (Large File Storage), где в репозитории лежит лишь указатель, а сам файл — на сервере LFS. Если репозиторий утёк, но LFS-сервер нет, большие файлы недоступны. Учитывайте это в forensics.

## Практический разбор: восстановление удалённого секрета

Дано: репозиторий, в котором «убрали» файл с секретом. Полный цикл:

```bash
# 1. смотрим всю историю, включая недостижимое
git fsck --lost-found
# dangling blob 1a2b3c...
# dangling commit 4d5e6f...

# 2. содержимое dangling blob
git cat-file -p 1a2b3c...
# DB_PASSWORD=supersecret

# 3. если коммит — смотрим его tree
git cat-file -p 4d5e6f^{tree}
# 100644 blob aabbcc...  .env
git cat-file -p aabbcc...
# SECRET_KEY=...
```

Если секрет в неслитой ветке:

```bash
git log --all --oneline
git show <commit>:path/to/file
```

Если `.git` утёк с сервера — качаем через `git-dumper http://target/.git out/` и повторяем локально. Если объект только в pack — `git verify-pack -v .git/objects/pack/*.idx`. Если ничего не находится — проверьте reflog (`.git/logs/HEAD`) и stash. В CTF секрет почти всегда восстановим, потому что git хранит объекты даже после «удаления» из истории.

## Квиз

```quiz
- question: "Как хранятся объекты git в .git/objects?"
  options:
    - "zlib-сжатые, с заголовком `<type> <size>\\0`"
    - "Открытым текстом"
    - "В base64"
    - "В JSON"
  answer: 0
  explanation: "SHA-1 считается от несжатых данных."
- question: "Что такое tree-объект?"
  options:
    - "Список имён и режимов каталога (ссылки на blob/tree)"
    - "Содержимое файла"
    - "Коммит"
    - "Тег"
  answer: 0
  explanation: "tree описывает каталог."
- question: "Как найти потерянные объекты?"
  options:
    - "git fsck --lost-found / --unreachable"
    - "git log"
    - "git status"
    - "git remote"
  answer: 0
  explanation: "fsck показывает dangling/unreachable объекты."
- question: "Что делать с packfile для ручного анализа?"
  options:
    - "git verify-pack -v и git unpack-objects"
    - "Открыть в блокноте"
    - "Переименовать в .zip"
    - "Удалить"
  answer: 0
  explanation: "Pack хранит сжатые дельтами объекты."
- question: "Как вручную прочитать объект из .git/objects/ab/cdef?"
  options:
    - "zlib.decompress(open(path,'rb').read())"
    - "base64 -d"
    - "xxd"
    - "cat"
  answer: 0
  explanation: "Объекты zlib-сжаты."
```

## Где пригодится

- **CTF:** forensics/misc — восстановление из .git.
- **Аудит:** поиск секретов в истории репозиториев.
- **Работа:** понимание git internals, восстановление данных.
- **Bug bounty:** утёкшие `.git` на веб-серверах.
