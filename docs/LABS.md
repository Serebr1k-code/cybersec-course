# Лаборатории (интерактивные практики)

> Спецификация формата `lab:` и движка клиентской лаборатории.
> Версия: Phase 0. Область: **только клиент** — никаких серверных контейнеров.

## Зачем

Урок объясняет, квиз проверяет понимание, но **навык ставится руками**. Лаборатория
даёт уроку настоящий терминал: студент выполняет задачу эмулируемыми инструментами и
сам достаёт результат (флаг), а не читает готовый ответ.

## Как это устроено

```
content/<cat>/<lesson>.md      front-matter: lab: {…}   ← авторский источник истины
content/labs/<id>.json         fixture bundle            ← виртуальная ФС + выводы инструментов
        │
        ▼  GET /api/lessons/{id}      (Go парсит lab-блок → model.Lab)
   LessonView.vue  ── v-if="lesson.lab" ──▶  LabPanel.vue   (ленивый dynamic import)
                                                 │
                                                 ├─ api.lab(id) → GET /api/labs/{id}
                                                 └─ dynamic import → LabShell.js (@xterm) + движок
```

* **Ленивость.** `LabPanel` подключается через `defineAsyncComponent`, `LabShell`
  (тяжёлый `@xterm/xterm`) — через `import()` уже внутри панели. Уроки **без** `lab:`
  не тянут ни `LabPanel`, ни `@xterm` — это отдельные чанки (см. `npm run build`).
* **Фикстуры.** Бандл подгружается по требованию (`GET /api/labs/{id}`), а не вместе с
  уроком. Байты файлов хранятся в бандле (base64), поэтому `xxd`/`strings`/`base64`
  работают над реальным содержимым.

## Front-matter: блок `lab:`

```yaml
lab:
  kind: shell                              # обязателен; пока поддерживается только "shell"
  title: "Практика: разбор подозрительного файла"   # необязательная подпись панели
  toolset: [core, hex, unzip]              # какие группы инструментов включены (информативно)
  workdir: /home/student/task              # стартовый каталог (абсолютный)
  files: [task.md, evidence.dat, notes.txt]  # файлы-семена (валидируются против бандла)
  check: "grep -q 'nto{' found.txt"        # предикат решения (код выхода 0 == решено)
  bundle: forensics-file-magic             # необязательно; по умолчанию = id урока
  hints:                                   # прогрессивные подсказки: слабая → сильнее
    - "Начни с `ls -la` и `file evidence.dat`."
    - "Сравни первые байты (`xxd -l 16`) с сигнатурой PNG из урока."
```

Поля парсит `internal/content` (см. `parseLabBlock`) в `model.Lab`; блок виден в
`GET /api/lessons/{id}` как объект `lab`.

## Bundle: `content/labs/<id>.json`

```jsonc
{
  "id": "forensics-file-magic",
  "workdir": "/home/student/task",     // должен совпадать с lab.workdir
  "hostname": "lab",                   // для приглашения shell
  "vars": { "target": "10.10.10.5" },  // подстановка {{target}} в match/output
  "expect": {                          // СКРЫТАЯ проверка точного ответа (без спойлера в уроке)
    "file": "/home/student/task/found.txt",
    "contains": "nto{m4g1c_byt3s_d0nt_l13}"
  },
  "fs": [                              // виртуальная ФС (сид)
    { "path": "/home/student/task", "type": "dir" },
    { "path": "/home/student/task/task.md", "text": "…" },
    { "path": "/home/student/task/evidence.dat", "b64": "iVBORw0KGgo…", "mode": "644" }
  ],
  "tools": {                           // эмуляция внешних инструментов (replay реального вывода)
    "unzip": {
      "help": "unzip [-l | -p <файл>] <архив>",
      "cases": [
        { "match": "\\-l\\s+evidence\\.dat",
          "example": "-l evidence.dat",
          "output": "Archive:  evidence.dat\n…",
          "writes": ["-oN"] }          // необязательно: флаг, чей аргумент — имя файла,
                                       // в который движок запишет тот же вывод (для -oN/-o)
      ]
    }
  }
}
```

* `match` — регистронезависимый regexp против строки аргументов (после подстановки `{{var}}`);
  выигрывает первый совпавший `case`. Нет совпадения и нет `fallback` → честное
  «нет в этой лабе».
* `fs[].text` — utf-8, `fs[].b64` — точные байты (бинарники).

## Движок shell (клиент, `src/lab/`)

| Модуль | Роль |
|---|---|
| `vfs.js` | виртуальная ФС (`Uint8Array`), glob, нормализация путей |
| `shell.js` | токенайзер + парсер: кавычки, `\|`, `&&`, `\|\|`, `;`, `>`, `>>`, `<`, `2>` |
| `commands.js` | реализация coreutils и `file`-магии |
| `tools.js` | replay фикстур внешних инструментов |
| `complete.js` | tab-дополнение |
| `session.js` | оркестратор: пайпы, редиректы, `check`, `hint` |
| `LabShell.js` | единственный модуль, тянущий `@xterm` (ленивый чанк) |

**Поддерживаемые команды:** `ls cat echo pwd cd touch mkdir rm grep head tail wc sort uniq
cut find file xxd strings base64 dd env export history whoami id hostname uname which sleep`,
плюс лабораторные `help`, `hint [N]`, `check`, `clear`. У каждой команды есть `-h`/`--help`.

**Реальность, а не декорация:** `grep` ищет по настоящим байтам, `xxd` дампит настоящие
байты, `base64 -d` декодирует, `dd` реально режет файл, редиректы реально пишут файлы.
`file` повторяет поведение настоящего `file(1)`, включая полиглоты
(`Zip archive, with extra data prepended`, `file -k`).

**Честность.** Инструмент/флаг вне лабы → `command not found` или явное «нет в этой лабе».
Никакого выдуманного вывода.

## Проверка решения

`check` выполняет предикат из front-matter (`check:`) **и**, если в бандле задан
`expect`, сверяет точное значение скрытого ответа. Пока обе проверки не пройдут — «не
сходится». Это позволяет держать спойлер (сам флаг) в бандле, а не в тексте урока.
`hint` выдаёт подсказки по возрастанию силы и никогда не показывает полный ответ.

## Как автору записать фикстуры

```bash
# 1. скелет бандла
tools/lab-record.sh skeleton my-lab-id

# 2. захват вывода инструмента из РЕАЛЬНОГО окружения (не прод!)
tools/lab-record.sh case '-sV\s+{{target}}' 'nmap -sV 10.10.10.5' -- nmap -sV 10.10.10.5

# 3. сид-файл (точные байты, base64)
tools/lab-record.sh file /home/student/task/evidence.dat ./evidence.dat

# 4. вставить фрагменты в content/labs/my-lab-id.json и проверить
go run ./tools/labvalidate -content ./content
```

## Валидация

`tools/labvalidate` (Go, как `tools/quizvalidate`) проверяет для каждого урока с `lab:`:

* `kind` поддержан, `workdir` абсолютный, `check` непустой, есть подсказки;
* бандл существует, это валидный JSON, `id` совпадает;
* каждый файл из `lab.files` есть в сиде `fs`;
* `expect.file` лежит внутри `workdir`;
* у каждого `case` непустые `match` (компилируемый regexp) и `output`.

Запускается в `make test` и в `go test ./...` (`TestContentLabsValid`).

## Ограничения Phase 0

* Только клиент, никаких серверных контейнеров.
* Нет RE/WASM-песочницы (Capstone/Keystone/Unicorn) — это следующая фаза.
* Внешние инструменты — replay фикстур, а не живое сетевое взаимодействие.
* `kind` пока один — `shell`.
