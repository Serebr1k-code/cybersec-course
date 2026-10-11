---
id: osint-secret-scanning
title: "Автоматический поиск секретов в репозиториях (trufflehog, gitleaks)"
category: osint
parent: osint-github-recon
difficulty: medium
order: 2
tags: [github, secrets, trufflehog, gitleaks, api-keys]
prerequisites: [osint-github-recon]
useful_for:
  - "Bug bounty: утёкшие ключи и токены"
  - "Пентест: доступ через секреты в коде"
estimated_minutes: 50
summary: "Как искать секреты в git-истории и live-коде: trufflehog, gitleaks, GitHub search и API, приоритизация находок, проверка валидности ключей."
---
Секреты (API-ключи, токены, пароли, приватные ключи) регулярно утекают в git-репозитории. Даже если файл удалили, он остаётся в **истории коммитов**. Автоматический поиск секретов — один из самых высокооплачиваемых приёмов bug bounty: валидный ключ AWS/Stripe/Slack часто даёт прямой доступ к инфраструктуре.

В этом уроке — где искать, какими инструментами, как безопасно верифицировать и как защищаться.

## Где искать

- **GitHub/GitLab** — публичные репозитории, история, gist.
- **gist**, **pastebin**, **Sourcegraph** — фрагменты кода.
- **npm/PyPI/Docker Hub** — секреты в опубликованных пакетах.
- **CI-логи** — переменные окружения в открытых сборках (Travis, GitHub Actions).
- **Форки и зеркала** — секрет мог остаться в форке после удаления в оригинале.
- **Wayback Machine** — старые версии страниц с ключами.

## gitleaks

Быстрый статический сканер (по файлам и истории). Работает офлайн, регулярно обновляемая база правил.

```bash
# скан текущего репозитория (дерево + история)
gitleaks detect --source . --report-format json --report-path leaks.json
# только текущее дерево (без истории)
gitleaks detect --source . --no-git
# скан удалённого репозитория
gitleaks detect --source https://github.com/org/repo
# вывод
gitleaks detect --source . -v
```

`gitleaks` находит по правилам-регуляркам (AWS, GCP, Slack, Stripe, приватные ключи) и помечает файл/строку/коммит.

## trufflehog

Отличие от gitleaks — **верификация**: trufflehog пытается подтвердить валидность ключа через API сервиса, что резко снижает число ложных срабатываний.

```bash
# скан репозитория
trufflehog git https://github.com/org/repo
# только верифицированные находки
trufflehog git file://./repo --only-verified
# файловая система
trufflehog filesystem ./path
# GitHub-организация (нужен токен)
trufflehog github --org=example --only-verified
```

## GitHub-поиск вручную

Встроенный поиск и дорки:

```text
org:example "AKIA"
org:example "-----BEGIN RSA PRIVATE KEY-----"
org:example filename:.env
"sk_live_" org:example
"xoxb-" org:example
"ghp_" org:example
```

Плюс `grep.app`, `Sourcegraph`, `searchcode` — поиск по коду в масштабе. Инструменты вроде `git-hound`/`shhgit` автоматизируют поиск по GitHub.

## Паттерны популярных секретов

| Сервис | Паттерн/префикс |
|---|---|
| AWS Access Key | `AKIA` / `ASIA` |
| GitHub token | `ghp_` / `gho_` / `github_pat_` |
| Slack | `xoxb-` / `xoxp-` |
| Stripe | `sk_live_` / `rk_live_` |
| Google API | `AIza` |
| Twilio | `SK` + 32 hex |
| SendGrid | `SG.` |
| Private key | `-----BEGIN ... PRIVATE KEY-----` |
| JWT | `eyJ` (три base64-секции) |

Эти префиксы — основа правил сканеров.

## Безопасная верификация

Найденный ключ нельзя просто «проверить на удачу». Безопасные read-only проверки:

```bash
# AWS — кто я (только чтение)
aws sts get-caller-identity
# GitHub token
curl -s -H "Authorization: token $TOKEN" https://api.github.com/user
# Slack
curl -s -H "Authorization: Bearer $TOKEN" https://slack.com/api/auth.test
# Stripe
curl -s https://api.stripe.com/v1/balance -u "$KEY:"
```

Правила: только read-only вызовы, не создавать ресурсы, не удалять данные, не запускать ничего ресурсоёмкого. Если ключ валиден — фиксируем как находку и немедленно сообщаем (bug bounty / владельцу).

## Разобранный пример: секрет в истории коммитов

1. Клонируем репозиторий и сканируем:

```bash
git clone https://github.com/example/app && cd app
gitleaks detect --source . -v
# Finding: AWS Access Key in config/settings.py (commit 3f2a1c)
```

2. Смотрим коммит:

```bash
git show 3f2a1c -- config/settings.py
# AWS_ACCESS_KEY_ID = "AKIA..."
# AWS_SECRET_ACCESS_KEY = "..."
```

3. Проверяем read-only:

```bash
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
# Account: 123456789012, Arn: arn:aws:iam::...:user/deploy
```

4. Если ключ валиден — фиксируем в отчёте (account, права) и сообщаем. Ключ активен, несмотря на то, что файл в текущем дереве уже без него — история хранит всё.

## Разобранный пример: секрет в форке

1. Оригинал почистил историю, но форк — нет.
2. Ищем форки популярного репо, сканируем их.
3. В форке находим ключ, которого уже нет в оригинале.
4. Вывод: чистка оригинала не гарантирует удаление — форки и кэши сохраняют секреты.

## Edge cases и подводные камни

- **Текущее дерево ≠ история**: всегда сканируйте `git log -p`.
- **Форки/зеркала**: секрет может жить вне оригинала.
- **Верификация может быть destructive**: только read-only.
- **Ложные срабатывания**: trufflehog `--only-verified` помогает.
- **Ротация vs удаление**: если ключ утёк, его надо отозвать — удаление файла бесполезно.
- **Этикет bug bounty**: не эксплуатировать дальше, чем нужно для доказательства.

## Защита

- **pre-commit hooks** с gitleaks/trufflehog — блокировать коммит с секретом.
- **Secret scanning** в CI/CD (GitHub secret scanning, GitLab).
- **Vault/секрет-менеджеры** вместо хардкода.
- **Ротация** всех ключей, попавших в историю.
- **История rewrite** (`git filter-repo`) — но помните про форки.

## Что дальше / решение

Практика: склонируйте публичный репозиторий и прогоните `gitleaks` + `trufflehog --only-verified`. Затем поищите по GitHub-доркам (`AKIA`, `sk_live_`). Всегда проверяйте ключ read-only и никогда не создавайте ресурсы. Для защиты — pre-commit хуки, secret scanning и Vault. Секреты в коде — самый частый и самый «дорогой» тип находки.

## Reference-таблица: инструменты поиска секретов

| Инструмент | Область | Верификация |
|---|---|---|
| gitleaks | git (дерево+история), FS | нет |
| trufflehog | git, FS, S3, GitHub | да (`--only-verified`) |
| git-hound | GitHub-организации | нет |
| shhgit | GitHub в реальном времени | нет |
| grep.app / Sourcegraph | поиск по коду | нет |
| gitleaks-action | CI/CD | нет |

## Чек-лист поиска секретов

1. Определить цель: репозиторий, организация, пакет, CI-лог.
2. Склонировать и просканировать историю (`gitleaks`, `trufflehog`).
3. Поискать в форках и зеркалах.
4. Проверить Wayback и pastebin.
5. Проверить CI-логи и переменные окружения.
6. Верифицировать только read-only (`sts get-caller-identity` и т.п.).
7. Зафиксировать: сервис, права, коммит/файл, статус.
8. Сообщить владельцу; не эксплуатировать дальше необходимого.

## Разобранный пример: массовый поиск по GitHub-организации

```bash
# дорки в веб-поиске GitHub
# org:example "AKIA"            → AWS-ключи
# org:example "-----BEGIN RSA PRIVATE KEY-----"
# org:example filename:.env
# org:example "sk_live_"

# автоматизация через trufflehog по организации
export GITHUB_TOKEN=ghp_...
trufflehog github --org=example --only-verified
```

Типичный результат: 3 верифицированных ключа (Slack, SendGrid, AWS read-only). Каждый — потенциальный доступ к сервису. Для каждого фиксируем сервис, права, где найден и статус валидности.

## Edge cases: где секреты переживают удаление

- **История коммитов** (`git log -p --all`) — файл удалён, коммит остался.
- **Форки** — не содержат чистку оригинала.
- **Кэш CI** — артефакты сборок хранят переменные окружения.
- **Docker-слои** — «удалённый» `.env` остаётся в слое.
- **Wayback Machine** — старая версия страницы с ключом.
- **gist и pastebin** — фрагменты кода, часто с ключами.

Вывод: удаление файла — не защита. Единственная надёжная мера — отзыв/ротация ключа и secret scanning на входе (pre-commit, CI). Практический чек-лист для защиты: включить gitleaks в pre-commit, secret scanning в GitHub/GitLab, Vault для секретов, обязательную ротацию при утечке.

## CI/CD-специфика: логи сборок и переменные

Открытые CI-системы (Travis, CircleCI, GitHub Actions) иногда выводят переменные окружения в логи, которые публичны. Точки поиска:

- **Логи сборок** публичных репозиториев: ищите `echo $SECRET`, `printenv`, `set -x`.
- **Артефакты сборок**: скомпилированные бинарники содержат вшитые ключи.
- **Кэш сборок**: `.cache` с конфигами.
- **Workflow-файлы**: `.github/workflows/*.yml` раскрывают, какие секреты используются и как.

```bash
# найти использование секретов в workflow (что вообще есть в проекте)
curl -s -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/search/code?q=secrets.+org:targetorg+filename:.yml" | jq -r '.items[].html_url'
```

Вывод:

```text
https://github.com/targetorg/app/blob/main/.github/workflows/deploy.yml
```

Так вы узнаёте **имена** секретов (`secrets.AWS_KEY`, `secrets.DEPLOY_TOKEN`) — полезно для понимания инфраструктуры даже без самих значений.

## Строки в бинарниках

Ключи попадают в скомпилированные файлы:

```bash
# извлечь строки и поискать паттерны
strings ./binary | grep -E 'AKIA|ghp_|sk_live_|xox|AIza|BEGIN .* PRIVATE KEY'
```

Для больших артефактов — специализированные сканеры:

```bash
# trufflehog по файловой системе/архиву
trufflehog filesystem ./release.tar.gz
# gitleaks по директории без git
gitleaks detect --source ./unpacked --no-git -v
```

Часто ключ «вшит» в мобильное приложение (APK/IPA) или во фронтенд-бандл — тогда он виден любому пользователю.

## Реагирование на валидный секрет

Порядок действий (минимальный, read-only, по правилам программы):

1. **Зафиксируйте** доказательство: где найден (коммит/файл/строка), тип, дата.
2. **Проверьте валидность** — только read-only (см. верификацию выше).
3. **Оцените blast radius** — что доступно: `aws iam list-*`, `aws s3 ls` (только чтение списков).
4. **Остановитесь** на доказательстве — не развивайте доступ.
5. **Сообщите** владельцу (security-контакт/программа) с PoC и рекомендацией ротации.
6. **Не сохраняйте** ключ в отчёте полностью — маскируйте (`AKIA…XXXX`).

Пример аккуратного использования AWS-ключа в отчёте:

```text
Ключ: AKIA…(маскирован)
Роль: deploy
Права: s3:GetObject (бакет backups-prod)
Impact: чтение бэкапов с PII
Рекомендация: немедленная ротация + ограничение политики
```

## Мониторинг и защита собственных репозиториев

Те же инструменты работают «в свою сторону»:

- **pre-commit hooks**: `gitleaks protect --staged` не даёт закоммитить секрет.
- **CI-скан**: запускайте gitleaks/trufflehog на каждом PR.
- **GitHub secret scanning**: встроенная защита + push protection.
- **Ротация**: любой секрет, попавший в историю, считается скомпрометированным — меняйте, а не просто удаляйте файл.
- **Проверка форков**: форки наследуют историю; удаление в апстриме не чистит форки.

```bash
# пример CI-шага (GitHub Actions)
# - name: secret scan
#   run: gitleaks detect --source . --redact -v
```

Флаг `--redact` маскирует значения секретов в выводе — важно для публичных логов CI.

## Чек-лист поиска секретов

- [ ] Просканированы и дерево, и **история** (`--no-git=false`, `git log -p`).
- [ ] Проверены форки, зеркала, gist, пасты.
- [ ] Находки отфильтрованы верификацией (`--only-verified`).
- [ ] Для каждой оценён blast radius.
- [ ] Значения маскированы в отчёте.
- [ ] Ключ не использован сверх read-only PoC.
- [ ] Владелец уведомлён; рекомендована ротация.
- [ ] Для своей организации — включены pre-commit/CI-сканы.

## Квиз

```quiz
- question: "Почему секрет может остаться доступным после удаления файла?"
  options:
    - "GitHub кэширует всё навсегда"
    - "Он остаётся в истории коммитов"
    - "Он дублируется в DNS"
    - "Он хранится в CT-логах"
  answer: 1
- question: "Чем trufflehog отличается от gitleaks?"
  options:
    - "Он не работает с git"
    - "Он умеет верифицировать валидность ключей через API"
    - "Он только для Python"
    - "Он бесплатный, а gitleaks платный"
  answer: 1
- question: "Как безопасно проверить валидность AWS-ключа?"
  options:
    - "Создать EC2-инстанс"
    - "`aws sts get-caller-identity` (read-only)"
    - "Удалить S3-бакет"
    - "Запустить miner"
  answer: 1
- question: "Какой паттерн ищут для токенов Slack?"
  options:
    - "`AKIA`"
    - "`xoxb-`"
    - "`sk_live_`"
    - "`ghp_`"
  answer: 1
- question: "Почему нужно сканировать историю, а не только текущее дерево?"
  options:
    - "Так быстрее"
    - "Удалённые секреты остаются в прошлых коммитах"
    - "Текущее дерево всегда чистое"
    - "GitHub требует этого"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с утёкшими ключами в приложенном репозитории.
- **Bug bounty:** утёкшие ключи — частый высокооплачиваемый отчёт.
- **Пентест:** доступ через секреты в коде организации.
- **Blue team:** аудит собственных репозиториев и pre-commit-хуки.
