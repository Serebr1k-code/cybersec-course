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
---
Современное ПО всё чаще поставляется как **образы контейнеров** (Docker/OCI), serverless-артефакты и WASM-модули. Чтобы реверсить такое приложение, его сначала нужно **извлечь** из слоёв, понять структуру образа и локализовать целевые бинарники. Этот урок — полный практический workflow: от `docker pull`/`skopeo copy` до анализа распакованного rootfs, включая whiteouts, утечки в multi-stage сборке, кросс-архитектурный запуск и разбор serverless/WASM-артефактов.

## Анатомия OCI-образа

Образ по стандарту OCI (Open Container Initiative) — это не один файл, а **набор**: манифест, конфиг и **слои**. Понимание каждого элемента критично, потому что именно в них прячется то, что вы ищете.

- **`manifest.json`** — список слоёв (digest + размер) и ссылка на config. Порядок слоёв важен: они применяются снизу вверх, каждый следующий перекрывает предыдущий.
- **`config.json`** (image config) — метаданные: `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, `Labels`, `History`. В `history` видно, какие команды выполнялись при сборке (`RUN ...`), а иногда — и сами секреты, если они были в аргументах.
- **Слои (`layer.tar`, обычно gzip/zstd)** — дельты файловой системы: только добавленные/изменённые файлы относительно нижнего слоя.
- **Whiteouts** — специальные файлы (`.wh.<name>` и `.wh..wh..opq`), означающие удаление файла или полное затенение каталога из нижнего слоя. Файл **не исчезает** из слоя — он лишь скрыт в смонтированной ФС. Именно поэтому «удалённый» секрет часто остаётся в более раннем слое.
- **Multi-stage build** — в финальный образ копируются только артефакты (`COPY --from=builder`), но исходники, компиляторы, `.git`, кэш пакетов остаются в промежуточных слоях и доступны при прямом разборе.

Ключевой практический вывод: **всегда анализируйте образ по слоям, а не только смонтированную ФС** — иначе потеряете всё, что было удалено.

## Метаданные: что читать в первую очередь

Начните с конфига — он определяет точку входа и окружение.

```bash
# Плоский экспорт образа в каталог
skopeo copy docker://target/app:latest dir:./appimg
cd appimg
# manifest ссылается на config по digest
cat manifest.json | jq '.[0] | {Config, Layers: (.Layers|length)}'
cat config.json | jq '.config | {Entrypoint, Cmd, Env, WorkingDir, User}'
cat config.json | jq '.history[] | {created_by, comment}'
```

Типичный вывод:

```json
{
  "Entrypoint": ["/app/server"],
  "Cmd": ["--config", "/etc/app.yml"],
  "Env": ["PATH=/usr/local/bin", "APP_TOKEN=prod_secret_token_123"],
  "WorkingDir": "/app",
  "User": "app"
}
```

Здесь `Env` уже содержит секрет — это частая утечка. А `history` нередко раскрывает полный `Dockerfile` (какие пакеты ставились, какие файлы копировались).

## Инструменты извлечения и их флаги

| Инструмент | Назначение | Пример |
|---|---|---|
| `skopeo` | копирование между реестрами/форматами | `skopeo copy docker://img:tag dir:./d` |
| `crane` | лёгкая работа с реестром | `crane export img:tag rootfs.tar` |
| `dive` | интерактивный просмотр слоёв | `dive img:tag --ci` |
| `umoci` | разбор OCI-layout | `umoci unpack --image ./img bundle` |
| `docker save/export` | сохранение/плоский экспорт | `docker save img:tag -o i.tar` |
| `ctr`/`nerdctl` | containerd-образы | `nerdctl image export img i.tar` |
| `regctl` | работа с реестром | `regctl image export img out.tar` |

```bash
# 1) через skopeo — самый надёжный способ без демона docker
skopeo copy docker://repo/image:tag dir:./imgdir
# 2) crane — если есть только реестр и креды
crane export repo/image:tag rootfs.tar
# 3) dive — интерактивно понять, что в каком слое
dive repo/image:tag
# 4) umoci — корректная распаковка OCI-layout
umoci unpack --image ./imgdir bundle
```

`dive --ci` удобен для автоматизации: он возвращает код возврата и печатает «wasted space» — какие слои занимают больше всего, что косвенно указывает на интересные артефакты.

## Распаковка слоёв и whiteouts

Слои нужно применять **строго по порядку** из манифеста, иначе получите неверную ФС.

```bash
mkdir -p rootfs && cd appimg
# порядок слоёв — из manifest.json
jq -r '.[0].Layers[]' manifest.json | while read -r layer; do
  echo "== applying $layer"
  tar xf "$layer" -C ../rootfs
done
```

Whiteout-файлы при этом просто распакуются как обычные `.wh.*`. Если хотите получить **истинную** финальную ФС, whiteouts нужно обработать:

```bash
# удалить файлы, помеченные whiteout
find rootfs -name '.wh.*' | while read -r w; do
  base=$(dirname "$w"); name=$(basename "$w")
  [ "$name" = ".wh..wh..opq" ] && continue
  rm -rf "$base/${name#.wh.}"
done
```

Альтернатива — сразу плоская ФС через `docker export`, которая уже учитывает whiteouts, но **теряет удалённые файлы** (и вместе с ними возможные секреты):

```bash
docker export "$(docker create repo/image:tag)" | tar xf - -C rootfs
```

## Что искать внутри rootfs

- **Entrypoint/Cmd** из `config.json` — какая программа реально запускается.
- **Бинарники** в `/app`, `/usr/local/bin`, `/opt`, `/srv` — `file`, `checksec`, `strings`.
- **Скрипты** (`*.sh`, `*.py`, `*.rb`) — часто вся бизнес-логика именно там, а не в скомпилированном коде.
- **Секреты**: `.env`, `*.pem`, `id_rsa`, `credentials`, `*.key`, токены в `config.json`/`Env`. Даже если файл «удалён» — он остался в нижнем слое.
- **Артефакты сборки**: `.git/`, `Dockerfile`, `Makefile`, `go.mod`, `package-lock.json` — раскрывают структуру и зависимости.
- **Языковые артефакты**: `.pyc`/`.pyo` (Python — декомпилируются `uncompyle6`/`decompyle3`), `node_modules`, `*.jar` (Java — `jd-cli`/`cfr`), `.wasm`.

```bash
file rootfs/app/server
checksec --file=rootfs/app/server
strings -a -n 6 rootfs/app/server | grep -iE "flag|secret|token|version|/etc/"
find rootfs -type f \( -name '*.pem' -o -name '*.key' -o -name '.env' -o -name 'id_rsa' \)
```

## Скрипт «всё сразу»: автопоиск секретов по слоям

Самый ценный приём — проверить **каждый слой отдельно**, не распаковывая ФС целиком:

```bash
cd appimg
for d in */; do
  echo "== $d"
  tar tf "$d"* 2>/dev/null | grep -iE '\.env$|secret|\.key$|\.pem$|token|credential|id_rsa'
done
```

Часто секрет лежит в слое, которого нет в финальной ФС, — этот цикл его находит.

## Кросс-архитектурный запуск

Образ может быть собран под ARM64 (Apple Silicon, ARM-серверы), а вы на x86_64. Запустить бинарник напрямую не выйдет — нужен эмулятор.

```bash
# посмотреть архитектуру
skopeo inspect docker://target/app:latest | jq '.Architecture, .Os'
# запуск ARM-бинарника через qemu-user
sudo apt-get install -y qemu-user-static binfmt-support
qemu-aarch64-static -L /usr/aarch64-linux-gnu rootfs/app/server --help
# либо через полноценную эмуляцию контейнера
docker run --rm --platform linux/arm64 -v "$PWD/rootfs:/r" arm64v8/ubuntu /r/app/server
```

Для статического анализа архитектура не мешает (Ghidra/IDA/r2 разберут ARM64), но для **динамического** — нужен qemu или нативная ARM-машина.

## Serverless-артефакты

- **AWS Lambda**: артефакт — zip (или container image). Внутри — handler (например `lambda_function.py`) и `requirements`. Распаковать и декомпилировать; env-переменные и IAM-роль читаются из конфигурации функции.
- **Google Cloud Functions**: тот же zip/container-паттерн; `main.py`/`index.js` + `package.json`/`requirements.txt`.
- **Azure Functions**: `host.json`, `function.json`, бинарники в `bin/`.
- **Cloudflare Workers / WASM**: `.wasm` — отдельная история (см. `reversing-wasm`), конвертировать в WAT через `wasm2wat`, либо в C через `wasm2c`.

```bash
unzip -o function.zip -d fn/
file fn/*
python3 -m dis fn/*.pyc 2>/dev/null | head
```

## Разобранный пример end-to-end

**Шаг 1. Скачать и распаковать.**

```bash
skopeo copy docker://ctf.registry/chal:latest dir:./chal
cd chal && jq -r '.[0].Layers[]' manifest.json | while read l; do tar xf "$l" -C ../rootfs; done
```

**Шаг 2. Определить точку входа.**

```bash
jq '.config | {Entrypoint, Cmd, Env}' config.json
# {"Entrypoint":["/chal/verify"], "Cmd":null, "Env":["FLAG_PATH=/flag"]}
```

**Шаг 3. Проанализировать бинарник.**

```bash
file ../rootfs/chal/verify
checksec --file=../rootfs/chal/verify
strings -a ../rootfs/chal/verify | grep -iE 'flag|wrong|correct|/flag'
```

**Шаг 4. Запустить/отладить.**

```bash
../rootfs/chal/verify    # если не хватает libs — chroot или qemu
ldd ../rootfs/chal/verify | grep 'not found'
```

**Шаг 5. Проверить секреты в слоях, которых нет в финальной ФС.**

```bash
for d in */; do tar tf "$d"* 2>/dev/null | grep -iE 'flag|\.env|secret'; done
```

## Частые ошибки и подводные камни

- **Анализ только смонтированной ФС.** Удалённые whiteout'ом файлы (в т.ч. секреты) остаются в нижних слоях — их нужно смотреть отдельно.
- **Игнорирование порядка слоёв.** Распаковка «как получится» даёт неверную ФС и путает выводы.
- **Забыть про `config.json`.** Entrypoint/Env определяют, что запускать; секрет в `Env` — типовая находка.
- **Не смотреть `history`.** Там может быть весь Dockerfile с паролями в `RUN`-аргументах.
- **Игнорирование архитектуры.** ARM64-бинарник не запустится на x86 без qemu; статический анализ всё равно работает.
- **Пренебрежение `dive`/`crane`.** Без них трудно понять, в каком слое что лежит, и легко пропустить «пустые» слои.
- **Только финальный образ.** В multi-stage полезное (исходники, `.git`) остаётся в промежуточных стадиях — если реестр хранит их, разбирайте все.

## Что дальше / решение

Если задача — **CTF Reversing/Cloud** с образом: примените `skopeo copy → распаковка слоёв по порядку → анализ entrypoint-бинарника → проверка секретов во всех слоях`. В 80% случаев флаг либо в `Env`/`.env` в нижнем слое, либо в логике бинарника, который вы извлекли. Для **container security аудита** — тот же поток плюс `dive` для поиска «мусорных» слоёв и утёкших секретов. Для **serverless** — распакуйте zip/container-артефакт и декомпилируйте handler. Освоив этот workflow, вы закрываете целый класс «облачных» таргетов, которые не видны обычному статическому анализу ELF.

## Квиз

```quiz
- question: "Что такое слой OCI-образа?"
  options:
    - "Дельта файловой системы (tarball)"
    - "Бинарник"
    - "Манифест"
    - "Конфиг ядра"
  answer: 0
  explanation: "Образ состоит из слоёв — диффов ФС."
- question: "Как извлечь полную ФС образа?"
  options:
    - "docker export или распаковка слоёв по порядку"
    - "docker run"
    - "nm"
    - "strings"
  answer: 0
  explanation: "docker export даёт плоскую ФС; либо распаковка layer.tar по порядку."
- question: "Почему секрет может остаться в образе, даже если удалён?"
  options:
    - "Он остаётся в предыдущем слое"
    - "Он в ядре"
    - "Он в RAM"
    - "Он в манифесте"
  answer: 0
  explanation: "Слои не удаляются; белый список лишь скрывает файл в финальной ФС."
- question: "Какой инструмент показывает содержимое по слоям?"
  options:
    - "dive"
    - "gdb"
    - "nm"
    - "ldd"
  answer: 0
  explanation: "dive визуализирует слои и их содержимое."
- question: "Что делать с .wasm-артефактом?"
  options:
    - "Разбирать как WASM (WAT/wasm2c)"
    - "Запускать как ELF"
    - "Игнорировать"
    - "Открывать в IDA как PE"
  answer: 0
  explanation: "WASM требует своих инструментов (см. reversing-wasm)."
```

## Где пригодится

- **CTF:** Reversing/Cloud — задачи с образами.
- **Container security:** аудит образов.
- **Cloud-native:** анализ serverless/WASM.
- **Работа:** supply-chain анализ.
