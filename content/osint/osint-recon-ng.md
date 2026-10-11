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
---

recon-ng — это Metasploit-подобный фреймворк для веб-разведки, работающий в CLI и хранящий результаты в **SQLite**. Он построен вокруг **модулей**: одни собирают данные из источников, другие импортируют из файлов, третьи генерируют отчёты. Для OSINT это удобная альтернатива SpiderFoot, когда вы предпочитаете контроль в терминале и воспроизводимые скрипты.

## Что такое recon-ng

Фреймворк на Python: интерактивная оболочка (`recon-ng`), внутри — рабочая область (**workspace**), база данных, набор модулей из **marketplace** и команды для работы с ними. Каждый модуль имеет входные/выходные «таблицы» (например, `domains`, `hosts`, `contacts`, `credentials`). Данные накапливаются в БД, а модули читают их и дополняют.

## Установка

```bash
git clone https://github.com/lanmaster53/recon-ng
cd recon-ng && pip install -r REQUIREMENTS
./recon-ng
# внутри:
[recon-ng][default] > marketplace refresh
[recon-ng][default] > marketplace search
```

## Workspaces и marketplace

```bash
[recon-ng] > workspaces create target
[recon-ng] > db insert domains
# marketplace: список модулей
[recon-ng] > marketplace search
[recon-ng] > marketplace install recon/domains-hosts/hackertarget
[recon-ng] > modules load recon/domains-hosts/hackertarget
```

Workspace изолирует данные разных целей — не смешивайте их.

## Модули: recon / import / reporting

| Категория | Пример | Назначение |
|---|---|---|
| recon | `hackertarget`, `bing_domain_web` | Сбор поддоменов/hosts |
| recon | `whois_pocs`, `brute_hosts` | WHOIS-контакты, брут |
| recon | `profiler`, `namechk` | Профили и username |
| import | `csv`, `list` | Импорт из файлов |
| reporting | `report/html`, `report/json` | Отчёты |

```bash
[recon-ng] > modules load recon/domains-hosts/hackertarget
[recon-ng][target][hackertarget] > options set SOURCE target.com
[recon-ng][target][hackertarget] > run
[recon-ng] > show hosts
```

## Разобранный пример: от домена к отчёту

1. Создаём workspace и вставляем домен:
   ```bash
   [recon-ng] > workspaces create acme
   [recon-ng][acme] > db insert domains
   [recon-ng][acme] > show domains
   ```
2. Ставим модуль сбора поддоменов и запускаем:
   ```bash
   [recon-ng][acme] > marketplace install recon/domains-hosts/hackertarget
   [recon-ng][acme] > modules load recon/domains-hosts/hackertarget
   [recon-ng][acme][hackertarget] > run
   [recon-ng][acme] > show hosts
   ```
3. Добавляем `recon/domains-contacts/whois_pocs` — получаем контакты.
4. Для найденных email — модуль утечек (если есть ключ).
5. Экспортируем:
   ```bash
   [recon-ng][acme] > modules load reporting/html
   [recon-ng][acme][html] > options set FILENAME /tmp/report.html
   [recon-ng][acme][html] > run
   ```

## База данных и ключи

Данные живут в SQLite; их можно смотреть через `show <table>` и экспортировать (`db query`). Многие модули требуют **API-ключи**:

```bash
[recon-ng] > keys add shodan_api <KEY>
[recon-ng] > keys add virustotal_api <KEY>
[recon-ng] > keys list
```

Без ключей модули либо не работают, либо ограничены.

## Скрипты и автоматизация

recon-ng можно запускать неинтерактивно, подавая команды через файл:

```bash
cat > /tmp/recon.rc <<'EOF'
workspaces create acme
db insert domains
modules load recon/domains-hosts/hackertarget
run
exit
EOF
./recon-ng -w acme -r /tmp/recon.rc
```

Так строятся воспроизводимые пайплайны recon. Также поддерживаются `spool` (лог) и экспорт БД для внешней обработки.

## Подводные камни

- **Устаревшие модули.** Часть источников меняет API; marketplace не всегда обновляется.
- **Отсутствие ключей.** Как и в SpiderFoot, половина модулей не работает.
- **Смешивание workspace.** Данные разных целей перемешаются.
- **Шумные модули.** Brute-модули могут быть заметны и медленны.
- **Активные действия.** Некоторые модули шлют запросы к цели — проверяйте авторизацию.
- **Отсутствие верификации.** Данные из БД нужно подтверждать вручную.

## Что дальше / решение

recon-ng — CLI-альтернатива SpiderFoot; свяжите с `osint-spiderfoot`, `osint-maltego` и `osint-collection`. Дальше — верификация и отчёт. Для CTF/пентеста постройте `.rc`-скрипт под типовой сценарий домена.

## Справочная таблица

| Команда | Назначение |
|---|---|
| workspaces create | Новая область |
| db insert domains | Вставить цель |
| marketplace install | Установить модуль |
| modules load | Загрузить модуль |
| show hosts | Показать результаты |
| keys add | Добавить API-ключ |

| Категория | Пример |
|---|---|
| recon/domains-hosts | hackertarget |
| recon/domains-contacts | whois_pocs |
| reporting | html, json |

## Полезные сценарии и модули

recon-ng раскрывается в типовых цепочках. Для домена:

- `recon/domains-hosts/hackertarget` — поддомены через HackerTarget;
- `recon/domains-hosts/bing_domain_web` — поддомены через Bing;
- `recon/domains-hosts/brute_hosts` — перебор словарём;
- `recon/hosts-hosts/resolve` — резолв hosts в IP;
- `recon/hosts-hosts/reverse_resolve` — PTR по IP (соседи);
- `recon/domains-contacts/whois_pocs` — контакты WHOIS;
- `recon/domains-credentials/pwnedlist` — утечки (нужен ключ);
- `recon/profiles-profiles/profiler` — профили по username.

Для человека: `recon/profiles-profiles/namechk` (проверка username на площадках), `recon/contacts-credentials/hibp` (утечки). Результаты накапливаются: hosts → IP → netblocks → contacts, образуя связную базу. Важно понимать **поток данных**: модуль читает таблицу A, пишет в таблицу B; следующий модуль читает B.

## Сравнение с SpiderFoot и Maltego

| Критерий | recon-ng | SpiderFoot | Maltego |
|---|---|---|---|
| Интерфейс | CLI | Веб/CLI | GUI |
| Хранение | SQLite | SQLite/файлы | Граф |
| Автоматизация | rc-скрипты | Модули/API | Machines |
| Визуализация | Нет | Граф/отчёт | Лучшая |
| Гибкость | Высокая | Средняя | Средняя |

recon-ng выбирают, когда нужен скриптуемый CLI-пайплайн и полный контроль над данными.

## Лаборатория

1. Создайте workspace для тестового домена.
2. Прогоните цепочку: hackertarget → resolve → reverse_resolve.
3. Добавьте whois_pocs и посмотрите контакты.
4. Импортируйте свой список поддоменов модулем `import/list` и резолвните.
5. Сгенерируйте HTML-отчёт.
6. Напишите `.rc`-файл, повторяющий весь сценарий одной командой.

## Автоматизация через Python API

recon-ng можно использовать как библиотеку: модуль `recon.core` даёт доступ к базе, workspace и запуску модулей из Python. Это удобно для встраивания в собственный пайплайн и для генерации отчётов на лету.

```python
from recon.core import base
r = base.Recon()
r.init_workspace("acme")
r.add_domains("target.com")
# запуск модуля
r.run_module("recon/domains-hosts/hackertarget")
# чтение результатов
for row in r.query("SELECT host FROM hosts"):
    print(row)
r.close()
```

Помимо API, есть готовые «reporting»-модули и возможность писать свои: модуль — это Python-класс с метаданными, `repository` и `run()`. Свои модули позволяют добавить нишевый источник (региональный реестр, форум) в общий конвейер. Для командной работы храните `.rc`-скрипты и модули в git, чтобы recon был воспроизводимым.

## Расширение: свои модули

Свой модуль — это Python-класс с метаданными и методом `run()`. Скелет:

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
            # ... ваш сбор ...
            self.insert_hosts(host="sub." + domain)
```

`meta["query"]` определяет, какие данные модуль читает; `module_run` получает строки и вызывает `insert_*` для записи. Так можно подключить внутренний реестр, локальный форум или нишевый API. Модули кладутся в `~/.recon-ng/modules/`, после чего появляются в marketplace.

## Лаборатория

1. Создайте workspace, вставьте домен.
2. Прогоните цепочку hackertarget → resolve → reverse_resolve.
3. Добавьте whois_pocs, посмотрите контакты.
4. Импортируйте свой список поддоменов (`import/list`) и резолвните.
5. Сгенерируйте HTML-отчёт.
6. Напишите `.rc`-файл, повторяющий сценарий.
7. Напишите простой кастомный модуль и подключите его.

## Квиз

```quiz
- question: "Где recon-ng хранит результаты?"
  options:
    - "В облаке"
    - "В локальной SQLite-базе по workspace"
    - "В JSON-файле"
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
- question: "Зачем нужны API-ключи в recon-ng?"
  options:
    - "Для запуска оболочки"
    - "Многие модули без них не работают или ограничены"
    - "Для шифрования БД"
    - "Для отчётов"
  answer: 1
  explanation: "Модули Shodan/VirusTotal и др. требуют ключей."
- question: "Как запустить recon-ng неинтерактивно?"
  options:
    - "С флагом -r и rc-файлом"
    - "Только через GUI"
    - "Через API"
    - "Никак"
  answer: 0
  explanation: "-r <file> подаёт команды из файла для автоматизации."
- question: "Какая категория модулей генерирует отчёт?"
  options:
    - "recon"
    - "import"
    - "reporting"
    - "discovery"
  answer: 2
  explanation: "reporting-модули формируют HTML/JSON-отчёты."
```

## Где пригодится

- **Recon/пентест:** автоматический сбор поддоменов/контактов.
- **Bug bounty:** воспроизводимые recon-скрипты.
- **OSINT:** структурированное хранение находок.
- **CTF:** быстрый сбор данных о цели.
