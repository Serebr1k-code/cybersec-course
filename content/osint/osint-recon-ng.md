---
id: osint-recon-ng
title: "recon-ng: модульный фреймворк разведки в CLI"
category: osint
parent: osint-automation
difficulty: medium
order: 3
tags: [osint, recon-ng, cli, modules, automation]
prerequisites: [osint-automation]
useful_for:
  - "Recon для пентеста"
  - "Bug bounty"
  - "Автоматизация OSINT"
estimated_minutes: 34
summary: "recon-ng: workspaces, marketplace, модули recon/import/reporting, база SQLite, API-ключи, скрипты и типичные ошибки при recon."
lab:
  kind: shell
  title: "Практика: запросить базу recon-ng"
  toolset: [core, sqlite3]
  workdir: /home/student/task
  files: [task.md, recon.db]
  check: "grep -q 'nto{' answer.txt"
  hints:
    - "Убедись, что это база: `file recon.db`."
    - "Посмотри таблицы: `sqlite3 recon.db \".tables\"`."
    - "Выведи контакты: `sqlite3 recon.db \"SELECT * FROM contacts;\"`."
    - "Маркер `nto{...}` — в поле `notes` одного из контактов."
---

## Вопрос, с которого всё начинается

Разведку по домену удобно автоматизировать, но каждый инструмент хранит результат по-своему: один пишет в файл, другой просто печатает в консоль, третий требует свой формат. Хочется одну среду, где результаты копятся в одном месте, а источники подключаются модулями. Именно такую среду предоставляет recon-ng — консольный фреймворк разведки.

Читателю уже знакомы CT-логи, DNS и идея конвейера. Здесь мы разберём, как recon-ng организует данные и как те же шаги выполнить вручную, чтобы понять, что лежит внутри.

## Наш пример: workspace для домена

recon-ng построен вокруг **рабочей области (workspace)** — изолированного набора данных под одну цель. Внутри всё хранится в **SQLite** — встроенной базе данных (та же, что мы использовали для конвейера). Источники подключаются **модулями**: одни собирают данные, другие импортируют из файлов, третьи генерируют отчёты.

Проведём один типовой сценарий — от домена к списку хостов. Я покажу команды recon-ng и рядом — что происходит в базе, воспроизведя её через `sqlite3` (так видно устройство, а не только «магия» фреймворка).

## Шаг 1: создаём workspace и вставляем цель

В интерактивной оболочке recon-ng создание области и вставка домена выглядят так:

```
[recon-ng] > workspaces create acme
[recon-ng][acme] > db insert domains
[recon-ng][acme] > show domains
```

Первая команда создаёт базу `acme`, вторая вставляет домен (фреймворк спросит его значение), третья показывает таблицу `domains`. Под капотом это обычная SQLite-таблица. Воспроизведём её:

```
$ sqlite3 recon.db "CREATE TABLE domains(domain TEXT PRIMARY KEY);"
$ sqlite3 recon.db "INSERT OR IGNORE INTO domains VALUES('example.com');"
$ sqlite3 -header -column recon.db "SELECT domain FROM domains;"
  domain
-----------
example.com
```

Вот и вся «магия»: `workspaces` — это отдельный файл базы, `show domains` — это `SELECT` по таблице. Понимание этого снимает половину загадочности.

## Шаг 2: собираем хосты модулем

Теперь подключаем модуль сбора поддоменов. У recon-ng модули лежат в **marketplace** — каталоге, откуда их ставят:

```
[recon-ng][acme] > marketplace install recon/domains-hosts/hackertarget
[recon-ng][acme] > modules load recon/domains-hosts/hackertarget
[recon-ng][acme][hackertarget] > run
[recon-ng][acme] > show hosts
```

Модуль `hackertarget` читает таблицу `domains` и дописывает найденные хосты в таблицу `hosts`. Результат — та же таблица, что мы заполним руками:

```
$ sqlite3 -header -column recon.db "SELECT host,ip FROM hosts;"
      host            ip
----------------  -----------
www.example.com   198.18.0.17
api.example.com   198.18.0.18
mail.example.com  198.18.0.19
```

Три хоста с адресами. Ключевая идея recon-ng — **поток данных между таблицами**: модуль читает таблицу A, пишет в таблицу B, следующий модуль читает B. Никаких файлов вразнобой — всё в одной базе.

## Шаг 3: цепочка модулей

Один модуль редко даёт полную картину, поэтому их выстраивают в цепочку. Для домена типично:

- `recon/domains-hosts/hackertarget` — поддомены через внешний сервис;
- `recon/domains-hosts/bing_domain_web` — поддомены через поисковик;
- `recon/hosts-hosts/resolve` — резолв хостов в IP;
- `recon/hosts-hosts/reverse_resolve` — PTR по IP (соседи по хостингу);
- `recon/domains-contacts/whois_pocs` — контакты из WHOIS.

Для человека: `recon/profiles-profiles/namechk` (проверка username на площадках), `recon/contacts-credentials/hibp` (утечки email). Результаты накапливаются: hosts → IP → netblocks → contacts, образуя связную базу. Это тот же принцип «сбор → нормализация → хранение», что и в самодельном конвейере, только источники уже написаны за вас.

## Шаг 4: API-ключи

Многие модули ходят в сервисы, которым нужен ключ. recon-ng хранит их отдельно от модулей:

```
[recon-ng] > keys add shodan_api <KEY>
[recon-ng] > keys add virustotal_api <KEY>
[recon-ng] > keys list
```

Без ключей такие модули либо не запускаются, либо отдают урезанный результат. Как и в собственном конвейере, ключи не должны попадать в публичный репозиторий.

## Шаг 5: отчёт

Когда данные собраны, их выгружают. Категория модулей `reporting` формирует HTML/JSON-отчёт:

```
[recon-ng][acme] > modules load reporting/html
[recon-ng][acme][html] > options set FILENAME /tmp/report.html
[recon-ng][acme][html] > run
```

На выходе — файл с таблицами хостов и контактов. Данные в базе можно и просто выгрузить запросом, что удобно для внешней обработки:

```
$ sqlite3 recon.db "SELECT host,ip FROM hosts;"
www.example.com|198.18.0.17
api.example.com|198.18.0.18
mail.example.com|198.18.0.19
```

## Шаг 6: автоматизация через .rc-скрипты

Главное преимущество CLI — воспроизводимость. Сценарий можно записать в файл и повторять одной командой. Файл команд называется **.rc-скриптом**:

```
workspaces create acme
db insert domains
modules load recon/domains-hosts/hackertarget
run
modules load reporting/html
run
exit
```

Запуск:

```
$ ./recon-ng -w acme -r /tmp/recon.rc
```

Так строятся пайплайны: один файл описывает всю разведку, и его можно хранить в git, передавать коллеге и запускать по расписанию. Есть и Python API — `from recon.core import base` — для встраивания в собственные инструменты.

## Шаг 7: подводные камни

- **Устаревшие модули.** Источники меняют API, и часть модулей перестаёт работать — marketplace обновляется не всегда.
- **Отсутствие ключей.** Без них половина модулей молчит.
- **Смешивание workspace.** Данные разных целей в одной области перемешаются; для каждой цели — своя область.
- **Активные модули.** Некоторые шлют запросы прямо к цели — проверяйте авторизацию.
- **Нет верификации.** Данные из базы всё равно подтверждают вручную: источник мог ошибиться.

## Свои модули

Штатных модулей много, но иногда нужен нишевый источник — региональный реестр, внутренний форум, локальный API. Тогда пишут свой модуль: это обычный Python-класс с метаданными и методом `run`:

```python
from recon.core.module import BaseModule

class Module(BaseModule):
    meta = {
        "name": "My Custom Source",
        "author": "me",
        "description": "Adds hosts from a custom source",
        "query": "SELECT domain FROM domains",
    }
    def module_run(self, domains):
        for domain in domains:
            self.insert_hosts(host="sub." + domain)
```

Поле `meta["query"]` определяет, какую таблицу модуль читает; `module_run` получает строки и вызывает `insert_*` для записи. Модуль кладут в `~/.recon-ng/modules/`, после чего он появляется в marketplace наравне со штатными. Так нишевый источник встраивается в общий конвейер, а не живёт отдельным скриптом.

## recon-ng, SpiderFoot и Maltego

Три инструмента решают похожую задачу, но по-разному. **SpiderFoot** — автоматический широкий скан с веб-интерфейсом: запустил цель и получил набор находок, но гибкость ниже. **Maltego** — GUI и лучшая визуализация графа, сильна в анализе связей. **recon-ng** — CLI с SQLite и полным контролем над данными: выбирают, когда нужен скриптуемый пайплайн, воспроизводимость и возможность дописать свой модуль. На практике их комбинируют: recon-ng собирает и хранит, Maltego визуализирует, SpiderFoot даёт быстрый широкий охват.

## Что мы теперь знаем

- recon-ng хранит данные в SQLite, изолируя их по workspace.
- Модули читают одну таблицу и пишут в другую — так работает поток данных.
- Источники ставятся из marketplace; часть требует API-ключей.
- Отчёты генерируются модулями `reporting`, а данные выгружаются SQL-запросом.
- .rc-скрипты делают разведку воспроизводимой и автоматизируемой.

## Квиз

Проверь себя.

```quiz
- question: "Где recon-ng хранит результаты?"
  options:
    - "В облаке вендора"
    - "В локальной SQLite-базе по workspace"
    - "В JSON-файле на рабочем столе"
    - "В Redis"
  answer: 1
  explanation: "recon-ng использует SQLite и изолирует данные по workspace."
- question: "Какой командой установить модуль из marketplace?"
  options:
    - "modules install"
    - "marketplace install"
    - "pip install"
    - "load"
  answer: 1
  explanation: "marketplace install <path> ставит модуль."
- question: "Как модули обмениваются данными?"
  options:
    - "Через файлы вразнобой"
    - "Один читает таблицу A и пишет в таблицу B, следующий читает B"
    - "Через электронную почту"
    - "Никак"
  answer: 1
  explanation: "Поток данных идёт через таблицы базы."
- question: "Как запустить recon-ng неинтерактивно?"
  options:
    - "С флагом -r и rc-файлом"
    - "Только через GUI"
    - "Только через API"
    - "Никак"
  answer: 0
  explanation: "-r <file> подаёт команды из файла для автоматизации."
- question: "Какая категория модулей формирует отчёт?"
  options:
    - "recon"
    - "import"
    - "reporting"
    - "discovery"
  answer: 2
  explanation: "reporting-модули формируют HTML/JSON-отчёты."
```

## Куда дальше

В следующем уроке мы возьмём собранные находки и превратим их в отчёт, который сможет проверить сторонний человек. А пока главное запомни: recon-ng — это та же база данных и цепочка модулей, и понимание её устройства важнее заучивания команд.

## Где пригодится

- **Recon/пентест:** автоматический сбор поддоменов и контактов.
- **Bug bounty:** воспроизводимые recon-скрипты.
- **OSINT:** структурированное хранение находок.
- **CTF:** быстрый сбор данных о цели.
