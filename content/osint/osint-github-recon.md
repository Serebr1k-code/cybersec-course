---
id: osint-github-recon
title: "GitHub-разведка: утёкшие секреты и история коммитов"
category: osint
parent: osint-infra-artifacts
difficulty: medium
order: 2
tags: [github, secrets, gitleaks, trufflehog, git, osint]
prerequisites: [osint-infrastructure]
useful_for:
  - "Bug bounty: утёкшие ключи"
  - "Supply chain security"
  - "CTF категория OSINT"
estimated_minutes: 55
summary: "Поиск секретов в публичных репозиториях: операторы GitHub-поиска, gitleaks/trufflehog, история git, удалённые коммиты и форки."
---

Публичные репозитории — это **письма, которые никто не отправлял, но все читают**. Разработчики коммитят `.env`, ключи, пароли и внутренние хосты, а потом «удаляют» — но история git и форки всё помнят.

## Что искать

- API-ключи (AWS `AKIA`, Google `AIza`, Stripe `sk_live`, Slack `xox`).
- Пароли и строки подключения (`.env`, `config.yml`, `docker-compose`).
- Токены CI/CD, приватные ключи (`-----BEGIN ... PRIVATE KEY-----`).
- Внутренние хосты, домены, IP, имена сотрудников.
- Дампы БД, `*.sql`, `*.bak`.

## Операторы GitHub-поиска

| Оператор | Значение | Пример |
|---|---|---|
| `org:` / `user:` | организация/пользователь | `org:example` |
| `filename:` | имя файла | `filename:.env` |
| `path:` | путь | `path:config/` |
| `extension:` | расширение | `extension:pem` |
| `language:` | язык | `language:python` |
| `in:file` / `in:path` / `in:readme` | область | `in:file "api_key"` |
| `is:public` | только публичные | `is:public` |
| `created:` / `pushed:` | по датам | `pushed:>2024-01-01` |

Примеры запросов:

```
org:example filename:.env
"AKIA" org:example
filename:id_rsa org:example
path:.github/workflows "secrets"
```

> GitHub-поиск по умолчанию ищет только в **дефолтной ветке** и **не в истории**. Для истории — клонируйте репозиторий.

## gitleaks и trufflehog

Автоматический поиск секретов:

```bash
# Клонировать и просканировать всю историю
git clone https://github.com/example/repo.git
gitleaks detect --source repo --report report.json

# trufflehog — сканирует историю и проверяет валидность ключей
trufflehog git https://github.com/example/repo.git --json | tee truffle.json
```

**trufflehog** умеет **верифицировать** ключи (делает тестовый запрос) — это резко снижает ложные срабатывания. **gitleaks** — быстрый и удобный для CI.

## История git: где живут «удалённые» секреты

Даже если файл удалён в последнем коммите, он есть в истории:

```bash
cd repo

# Файлы, которые когда-либо существовали
git log --all --full-history -- '*.env'

# Содержимое конкретного файла в конкретном коммите
git show <commit>:path/to/.env

# Поиск строки по всей истории
git log -p --all | grep -iE 'password|secret|api_key' | head
```

`git log --all` включает **все ветки**, а не только текущую.

## Продвинутый поиск по истории и метаданным

```bash
# все файлы, содержавшие секреты, по всей истории и веткам
git log --all --full-history --diff-filter=D -- '*.env' '*.pem' '*.key'

# поиск по сообщениям коммитов
git log --all --grep='password' -i

# секреты в удалённых блобах (dangling)
git fsck --lost-found | grep commit
```

**gitleaks** сканирует всю историю; **trufflehog** ещё и верифицирует ключи.

## CI/CD и конфигурации

Отдельный класс утечек — конфиги пайплайнов:

```text
path:.github/workflows "secrets"
path:.gitlab-ci.yml "token"
filename:docker-compose.yml "PASSWORD"
```

Переменные CI (даже замаскированные в логах) иногда попадают в кэш/артефакты. Проверяйте `env`, `secrets.*`, шаги с `echo`.

## Форки и зеркала

Удалённый из основного репозитория коммит может остаться в **форках**. Ищите форки через:

- Вкладка **Forks** на GitHub.
- **GitHub Archive** / GH Archive — события платформы.
- **grep.app**, **Sourcegraph** — индекс по многим репозиториям.

## Проверка найденного ключа

Найденный ключ нужно **проверить на валидность** — но осторожно и легально (в рамках bug bounty — по правилам программы):

```bash
# AWS: безопасная проверка личности ключа (не тратит ресурсы)
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
```

Если ключ валиден — **немедленно сообщайте владельцу** через программу. Не используйте его для доступа к данным сверх PoC.

## Инструменты и интеграция

- **gitleaks** — быстрый, для CI и локально.
- **trufflehog** — верификация, много источников (GitHub/GitLab/S3).
- **GitHub code search API** — `org:`, `filename:`, `path:`.
- **grep.app / Sourcegraph** — поиск по многим репозиториям.
- **GH Archive** — события платформы (форки, пуши).

## Разобранный пример

1. GitHub-поиск: `org:example filename:.env` → репозиторий `example/backend`.
2. Клонируем, `gitleaks detect` → в истории найден коммит с `DB_PASSWORD=...`.
3. Файл удалён в `HEAD`, но доступен через `git show <commit>:app/.env`.
4. Проверяем: пароль невалиден (уже сменили) — но в том же файле AWS-ключ.
5. `aws sts get-caller-identity` подтверждает ключ → отчёт по программе.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| GitHub search | `org: filename: path:` | поиск по коду |
| gitleaks | `detect --source repo` | секреты в истории |
| trufflehog | `git <url> --json` | верификация ключей |
| git log | `--all --full-history -- '*.env'` | история файлов |
| grep.app/Sourcegraph | веб | поиск по многим репо |
| GH Archive | датасеты | события платформы |

## Частые ошибки

- **Искать только в текущей ветке** — пропустить историю.
- **Игнорировать форки и зеркала.**
- **Не верифицировать ключи** (много ложных).
- **Использовать найденный ключ во вред** — это уже атака.
- **Забывать про CI-конфиги** (`.github/workflows`) — там секреты в переменных.
- **Не проверять дату коммита** — секрет может быть уже отозван.

## Что делать дальше / решение

- **Нужны секреты** → GitHub-поиск → клон → `gitleaks`/`trufflehog`.
- **Нужна история** → `git log --all --full-history` → `git show`.
- **Нужны форки** → Forks + GH Archive + grep.app.
- **Нужна верификация** → безопасный вызов API ключа → репорт.

## Сканирование в масштабе (org-wide)

Для большой организации один репозиторий — капля в море. Подход:

```bash
# получить список репозиториев организации (публичный API)
curl -s "https://api.github.com/orgs/example/repos?per_page=100" | jq -r '.[].clone_url' > repos.txt

# клонировать и просканировать пачкой
while read u; do git clone --quiet "$u" repo_$(basename "$u" .git); done < repos.txt
gitleaks detect --source . --report org_report.json
```

Дополнительно: **GH Archive** отдаёт события (пуши, создание репо) за любой час — можно находить свежие утечки в реальном времени. **grep.app/Sourcegraph** ищут по индексу без клонирования — полезно, когда репозиториев тысячи.

## Ответ на находку (disclosure)

Найденный валидный секрет — это ответственность. Правильный процесс:

1. **Не использовать** ключ дальше минимального PoC (подтверждение валидности).
2. **Определить владельца**: `org`/домен/почта из коммитов.
3. **Сообщить** через security.txt, программу bug bounty или напрямую.
4. **Не публиковать** ключ до исправления.
5. **Задокументировать**: репозиторий, коммит, время, тип ключа, что подтверждено.

Для собственной организации настройте **secret scanning** (GitHub Advanced Security, gitleaks в CI) и ротацию ключей.

## Типичные секреты и их отпечатки

| Секрет | Отпечаток (regex-начало) |
|---|---|
| AWS Access Key | `AKIA` / `ASIA` |
| Google API | `AIza` |
| Slack token | `xox[baprs]-` |
| Stripe | `sk_live_` / `rk_live_` |
| GitHub PAT | `ghp_` / `github_pat_` |
| JWT | `eyJ` |
| Приватный ключ | `-----BEGIN` |

Зная отпечатки, вы быстро фильтруете шум в результатах поиска и в выводе `gitleaks`/`trufflehog`.

## Квиз

```quiz
- question: "Почему удалённый из репозитория секрет всё ещё доступен?"
  options:
    - "Он остаётся в истории git и в форках"
    - "GitHub хранит его вечно в открытом виде на видном месте"
    - "Его восстанавливает поисковик"
    - "Это невозможно"
  answer: 0
- question: "Какой инструмент умеет верифицировать найденные ключи?"
  options:
    - "trufflehog"
    - "nmap"
    - "sqlmap"
    - "exiftool"
  answer: 0
- question: "Что делает команда `git log --all --full-history -- '*.env'`?"
  options:
    - "Ищет все коммиты, где когда-либо менялись .env-файлы, по всем веткам"
    - "Удаляет .env из истории"
    - "Скачивает .env"
    - "Шифрует .env"
  answer: 0
- question: "Какой GitHub-оператор ограничивает поиск организацией?"
  options:
    - "`org:`"
    - "`site:`"
    - "`in:`"
    - "`host:`"
  answer: 0
- question: "Что правильно при обнаружении валидного ключа?"
  options:
    - "Сообщить владельцу и использовать только для минимального PoC"
    - "Слить все данные"
    - "Опубликовать ключ"
    - "Продать его"
  answer: 0
```

## Где пригодится

- **Bug bounty:** утёкшие ключи — высокооплачиваемый класс находок.
- **Supply chain:** аудит своих репозиториев и репозиториев зависимостей.
- **CTF (OSINT):** найти секрет в «случайном» репозитории.
- **Пентест:** получить первый доступ через утёкший токен.
