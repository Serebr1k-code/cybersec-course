---
id: reversing-container-images
title: "Реверс контейнеров и cloud-бинарников"
category: reversing
parent: reversing-analysis-methodology
difficulty: medium
order: 2
tags: [reversing, docker, container, oci, cloud, serverless, wasm]
prerequisites: [reversing-analysis-methodology, reversing-file-formats]
useful_for:
  - "CTF Reversing / Cloud"
  - "Container security"
  - "Cloud-native analysis"
estimated_minutes: 55
summary: "Разбор образов контейнеров: слои OCI, извлечение бинарников, serverless-артефакты и анализ cloud-кода."
lab:
  kind: shell
  title: 'Практика: разбор слоя docker-образа'
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md, manifest.json, layer.tar]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - '`strings layer.tar` покажет пути (`app/config.json`) и содержимое файлов.'
    - 'Ищи строку с `api_key`.'
    - '`strings layer.tar | grep nto > answer.txt` затем `check`.'
---

## Вопрос, с которого всё начинается

Тебе дали не бинарник, а **Docker-образ**: `docker save revtarget:1 -o revtarget.tar`. Файл
`revtarget.tar` — это архив, внутри которого спрятана программа, но где именно и что она
делает — непонятно. Запускать образ целиком нельзя (нет реестра, да и запускать чужое
небезопасно). Как достать бинарник из образа и проанализировать его?

Образ — это не один файл, а **набор слоёв**. Понимание этой структуры и есть ключ: только
разобрав слои по отдельности, ты найдёшь то, что нужно.

## Наш пример

У нас есть сохранённый образ `revtarget.tar`. Посмотрим, что внутри — обычным `tar`:

```bash
$ tar tf revtarget.tar | head
blobs/
blobs/sha256/
blobs/sha256/24944075e64c5eab63ad4e631e062eb02a76bf8ebd2ee43981b449f0a9df3bc7
blobs/sha256/2e2e6448b76eb19a3a94285b0dcbfaa041ec6c618916c7c1c8bcf67f23b70271
blobs/sha256/fdbc1ef60b69c2e6dd824b719e48c2a47004e147677edecf781672e1c1a43b6b
index.json
manifest.json
oci-layout
```

Это формат **OCI** (Open Container Initiative) — открытый стандарт контейнерных образов.
Файлы с длинными hex-именами в `blobs/sha256/` — это содержимое, а имя файла = его
SHA-256-хеш (так гарантируется целостность). `manifest.json` связывает всё вместе.

Распакуем архив и прочитаем манифест:

```bash
$ mkdir oci && tar xf revtarget.tar -C oci && cd oci
$ cat manifest.json
[{"Config":"blobs/sha256/2e2e6448...","RepoTags":["revtarget:1"],
  "Layers":["blobs/sha256/fdbc1ef6..."]}]
```

Манифест говорит: конфиг — один blob, слой — другой. Слой (layer) — это дельта файловой
системы, то есть архив с файлами, которые добавили поверх базового образа.

## Шаг 1: читаем конфиг — что запускается

Конфиг — это метаданные образа. Смотрим самое важное: `Cmd`, `Env`, `history`.

```bash
$ python3 -m json.tool blobs/sha256/2e2e6448b76eb19a3a94285b0dcbfaa041ec6c618916c7c1c8bcf67f23b70271
{
    "architecture": "amd64",
    "config": {
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "Cmd": ["/xorcheck"],
        "WorkingDir": "/"
    },
    "history": [
        {"created_by": "COPY xorcheck /xorcheck # buildkit", ...},
        {"created_by": "CMD [\"/xorcheck\"]", "empty_layer": true, ...}
    ]
}
```

Два вывода сразу:

- **`Cmd: ["/xorcheck"]`** — контейнер запускает `/xorcheck`. Вот наш целевой бинарник.
- **`history`** — фактически восстановленный `Dockerfile`. Здесь видно команду `COPY xorcheck /xorcheck`.
  В реальных образах в `history` часто утекают пароли, если секрет передавали аргументом в `RUN`.

`Env` в нашем образе чистый, но это **первое место, где проверяют секреты**: токены в
переменных окружения — типовая утечка.

## Шаг 2: распаковываем слой и достаём бинарник

Слой — это gzip-архив. Проверим тип и распакуем его:

```bash
$ file blobs/sha256/fdbc1ef60b69c2e6dd824b719e48c2a47004e147677edecf781672e1c1a43b6b
...: gzip compressed data, original size modulo 2^32 17920

$ tar tvf blobs/sha256/fdbc1ef60b69c2e6dd824b719e48c2a47004e147677edecf781672e1c1a43b6b
-rwxr-xr-x 0/0  16160  2026-10-12 09:08 xorcheck

$ mkdir -p rootfs
$ tar xf blobs/sha256/fdbc1ef6... -C rootfs
$ ls -la rootfs
-rwxr-xr-x 1 ... 16160 ... xorcheck
```

Готово: бинарник `xorcheck` извлечён из слоя. Дальше с ним работаем как с обычным ELF —
`file`, `strings`, `nm`, дизассемблер:

```bash
$ file rootfs/xorcheck
rootfs/xorcheck: ELF 64-bit LSB executable, x86-64, ... not stripped
```

## Шаг 3: почему порядок слоёв и whiteouts важны

В реальном образе слоёв много, и они применяются **строго снизу вверх**: каждый следующий
перекрывает файлы предыдущего. Распаковывать их «как получится» нельзя — получишь неверную ФС.

Особый случай — **whiteouts**: файлы с именем `.wh.<имя>` или `.wh..wh..opq`. Это метки
«удалить файл из нижнего слоя». Файл при этом **физически остаётся** в старом слое — whiteout
лишь скрывает его в собранной ФС. Именно поэтому секрет, «удалённый» в финальном образе,
часто продолжает лежать в нижнем слое и находится при разборе по слоям:

```bash
$ for d in blobs/sha256/*; do
>   tar tf "$d" 2>/dev/null | grep -iE '\.env$|secret|\.key$|\.pem$|token|id_rsa'
> done
```

Плоский экспорт (`docker export`) уже учитывает whiteouts и даёт готовую ФС, но **теряет
удалённые файлы** — а вместе с ними и возможные секреты. Поэтому при реверсе образ всегда
разбирают по слоям, а не только по смонтированной ФС.

То же с **multi-stage build**: в финальный образ попадают только артефакты (`COPY --from=builder`),
а исходники, `.git`, компиляторы и кэш пакетов остаются в промежуточных слоях — если реестр
их хранит, они доступны при прямом разборе.

## Шаг 4: что искать в rootfs

Когда ФС извлечена, обходим её целенаправленно:

- **Entrypoint/Cmd** из конфига — какая программа реально стартует.
- **Бинарники** в `/app`, `/usr/local/bin`, `/opt`, `/srv` — `file`, `strings`, `checksec`.
- **Скрипты** `*.sh`, `*.py`, `*.rb` — вся бизнес-логика часто именно там, а не в скомпилированном коде.
- **Секреты**: `.env`, `*.pem`, `id_rsa`, `credentials`, токены в `Env`.
- **Артефакты сборки**: `.git/`, `Dockerfile`, `go.mod`, `package-lock.json`.

```bash
$ find rootfs -type f \( -name '*.pem' -o -name '*.key' -o -name '.env' -o -name 'id_rsa' \)
$ strings -a -n 6 rootfs/xorcheck | grep -iE "flag|secret|token|/etc/"
```

## Шаг 5: serverless и WASM — та же логика

- **AWS Lambda / GCP Functions**: артефакт — zip или container image. Внутри handler
  (`lambda_function.py`/`main.py`/`index.js`) и зависимости. Распаковать и декомпилировать;
  env-переменные и IAM-роль читаются из конфигурации функции.
- **Cloudflare Workers / WASM**: `.wasm` разбирают своими инструментами (`wasm2wat`, `wasm2c`) —
  подробнее в уроке про WASM.

```bash
$ unzip -o function.zip -d fn/ && file fn/*
```

## Шаг 6: инструменты и кросс-архитектурный запуск

Мы разбирали образ вручную через `docker save` + `tar` — это работает всегда. В реальной
работе удобнее специализированные утилиты:

| Инструмент | Что делает | Пример |
|---|---|---|
| `skopeo` | копирование образа из реестра в каталог без демона Docker | `skopeo copy docker://app:1 dir:./d` |
| `crane` | лёгкая работа с реестром | `crane export app:1 rootfs.tar` |
| `dive` | интерактивный просмотр слоёв | `dive app:1 --ci` |
| `umoci` | корректная распаковка OCI-layout | `umoci unpack --image ./d bundle` |

`skopeo inspect` заодно показывает архитектуру образа:

```bash
$ skopeo inspect docker://app:1 | jq '.Architecture, .Os'
"arm64"
"linux"
```

Если образ собран под ARM64, а ты на x86_64, бинарник **напрямую не запустится** — нужен
эмулятор `qemu-user`:

```bash
$ qemu-aarch64-static -L /usr/aarch64-linux-gnu rootfs/app/server --help
```

Для **статического** анализа архитектура не мешает: `objdump`/Ghidra/r2 разберут ARM64. А вот
для динамического запуска qemu (или нативная ARM-машина) обязателен.

## Что мы теперь знаем

- Контейнерный образ — это **набор слоёв**, а не один файл; `manifest.json` связывает их.
- Конфиг образа (`Cmd`, `Env`, `history`) первым делом говорит, что запускается и где искать секреты.
- Слой — это gzip-архив с файлами; бинарник извлекается обычным `tar xf`.
- Whiteouts и multi-stage **не удаляют** старые файлы — секреты остаются в нижних слоях.
- Serverless/WASM-артефакты разбираются по той же схеме «распакуй → найди точку входа».

## Квиз

Проверь себя.

```quiz
- question: "Что такое слой (layer) OCI-образа?"
  options:
    - "Дельта файловой системы в виде архива"
    - "Скомпилированный бинарник"
    - "Манифест образа"
    - "Конфиг ядра"
  answer: 0
  explanation: "Слой — это дифф ФС; финальная ФС получается применением слоёв по порядку."
- question: "Что в нашем примере сразу показало, какой бинарник запускается?"
  options:
    - "Поле `Cmd` в конфиге образа"
    - "Вывод `nm`"
    - "Манифест"
    - "`docker info`"
  answer: 0
  explanation: '`Cmd: ["/xorcheck"]` в конфиге задаёт команду запуска.'
- question: "Почему секрет может остаться в образе после 'удаления' файла?"
  options:
    - "Файл остаётся в нижнем слое, whiteout лишь скрывает его"
    - "Секрет копируется в ядро"
    - "Он хранится в манифесте"
    - "Он попадает в RAM"
  answer: 0
  explanation: "Слои неизменяемы: whiteout скрывает файл в собранной ФС, но не удаляет из слоя."
- question: "Какой порядок применения слоёв правильный?"
  options:
    - "Строго снизу вверх, как в манифесте"
    - "В случайном порядке"
    - "Сверху вниз"
    - "Только верхний слой"
  answer: 0
  explanation: "Каждый следующий слой перекрывает предыдущий — порядок из манифеста обязателен."
- question: "Что делать с `.wasm`-артефактом из образа?"
  options:
    - "Разбирать инструментами WASM (wasm2wat/wasm2c)"
    - "Запускать как ELF"
    - "Игнорировать"
    - "Открывать в IDA как PE"
  answer: 0
  explanation: "WASM — отдельный формат; ему нужны свои инструменты."
```

## Куда дальше

Мы извлекли бинарник из образа и снова упёрлись в дизассемблер. Но часто нужно не разобрать
**один** бинарник, а понять, что изменилось между **двумя** версиями — именно так находят
исправленную уязвимость по патчу. В следующем уроке мы возьмём два бинарника и сравним их
код. А пока главное запомни: **образ — это слои; секреты живут в нижних.**

## Где пригодится

- **CTF Reversing / Cloud:** задачи с образами и serverless-артефактами.
- **Container security:** аудит образов, поиск утёкших секретов по слоям.
- **Cloud-native analysis:** разбор Lambda/Functions/Workers.
- **Supply-chain:** анализ того, что реально попало в образ.
