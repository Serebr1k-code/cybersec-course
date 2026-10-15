---
id: cloud-iam-policy-eval
title: "Оценка IAM-политик: boundaries, conditions и confused deputy"
category: cloud
parent: cloud-iam-attack
difficulty: hard
order: 3
tags: [cloud, iam, policy, evaluation, permission-boundary, conditions, confused-deputy]
prerequisites: [cloud-iam-attack, cloud-privesc-iam]
useful_for:
  - "Точное понимание, что разрешено"
  - "Поиск обходов через conditions"
  - "Аудит политик и границ"
estimated_minutes: 50
summary: "Как облако оценивает права: explicit deny, SCP, permission boundaries, session policies, resource policies и conditions. Как читать логику и находить обходы через conditions и confused deputy."
lab:
  kind: shell
  title: "Практика: оценка IAM-политики и путь эскалации"
  toolset: [core]
  workdir: /home/student/iam
  files: [task.md, policy.json, trust.json, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Прочитай политику целиком: `cat policy.json` — какие действия (`Action`) она разрешает?"
    - "Опасная комбинация: `iam:PassRole` + создание/запуск вычислительного ресурса с этой ролью. Найди её."
    - "В политике есть поле-комментарий с внутренней заметкой и флагом. Поищи: `grep nto policy.json`."
    - "Выдели значение между кавычками: `grep nto policy.json | cut -d'\"' -f4 > found.txt`."
---

## Вопрос, с которого всё начинается

Ты видишь политику с `Action: "*"` и думаешь: «отлично, админ». Но вызов всё равно падает с `AccessDenied`. Почему? Потому что облако оценивает права **не по одной политике**, а по целому набору правил, и любое из них может запретить действие. Разберём, как это устроено.

## Наш пример: политика с «широкими» правами

Объект урока — политика `WildAdmin`, которая разрешает всё:

```
$ aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/WildAdmin --version-id v1 \
    --query "PolicyVersion.Document.Statement"
[
  { "Effect": "Allow", "Action": "*", "Resource": "*" }
]
```

Пользователь с такой политикой должен уметь всё. Но при вызове `aws s3 rm s3://protected/secret.txt` приходит отказ. Значит, где-то есть ограничение. Найдём его.

## Шаг 1: явный запрет (explicit deny)

Главное правило оценки: **любой явный `Deny` побеждает любой `Allow`**. Ищем запреты:

```
$ aws iam list-attached-user-policies --user-name test-user
{ "AttachedPolicies": [ { "PolicyName": "WildAdmin", ... }, { "PolicyName": "NoDelete", ... } ] }
$ aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/NoDelete --version-id v1 \
    --query "PolicyVersion.Document.Statement"
[
  { "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::protected/*" }
]
```

Вот причина: политика `NoDelete` явно запрещает удаление объектов в `protected`. Значит, `WildAdmin` бесполезен против этого запрета. Правило простое: **Deny > Allow**.

## Шаг 2: SCP — границы организации

Даже без явного Deny в политиках пользователя действие может блокировать **SCP** (Service Control Policy) — политика на уровне организации или OU. SCP не даёт прав, она только **ограничивает** максимум возможного:

```
$ aws organizations list-policies --filter SERVICE_CONTROL_POLICY
{ "Policies": [ { "Name": "DenyRegionsOutsideEU", ... } ] }
```

Если SCP запрещает работать в `us-east-1`, то никакие пользовательские Allow не помогут. Смысл: SCP — это «потолок» для всего, что ниже.

## Шаг 3: permission boundary — личный потолок

**Permission boundary** — это политика-граница на конкретного пользователя или роль. Она говорит: «что бы ни разрешали другие политики, выйти за эту рамку нельзя». В отличие от SCP, boundary применяется к отдельной сущности:

```
$ aws iam get-user --user-name test-user --query "User.PermissionsBoundary"
"arn:aws:iam::123456789012:policy/OnlyS3Boundary"
```

Права пользователя = **пересечение** всех Allow и границы. Если boundary разрешает только S3, то `Action: "*"` превращается в «только S3».

## Шаг 4: session policy — потолок для сессии

При входе в роль можно передать **session policy** — она дополнительно сужает права текущей сессии:

```
$ aws sts assume-role --role-arn arn:aws:iam::123456789012:role/DeployRole \
    --role-session-name test --policy file://narrow.json
```

Так выдаётся роль, но с урезанными на время сессии правами. Для атакующего это значит: даже заняв роль, ты можешь не получить весь её набор.

## Шаг 5: resource policy — правило на самом объекте

Есть и обратная сторона: **resource policy** прикреплена к ресурсу (например, к бакету) и разрешает доступ тем, у кого нет прав в IAM. Классический пример — публичный бакет: в его policy стоит `Principal: "*"`, и тогда читать может кто угодно:

```
$ aws s3api get-bucket-policy --bucket mycompany-public
{ "Statement": [ { "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mycompany-public/*" } ] }
```

Так «доступ» может появиться не из твоих прав, а из настройки ресурса.

## Шаг 6: conditions и confused deputy

Политики часто сужаются блоком `Condition`. Например, роль доверяет сервису, только если запрос пришёл от конкретного аккаунта:

```
"Condition": { "StringEquals": { "aws:SourceAccount": "123456789012" } }
```

Если такого условия нет, получается **confused deputy** («сбитый с толку посредник»): сервис-посредник может быть обманут и выполнить действие от чужого имени. Классика — сервис, которому доверяет роль, позволяет другому клиенту заставить его сделать запрос. Поэтому условия `ExternalId` и `SourceAccount` обязательны в доверии сервисам.

## Шаг 7: как проверить итоговые права

AWS умеет симулировать решение об авторизации:

```
$ aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:user/test-user \
    --action-names s3:DeleteObject --resource-arns arn:aws:s3:::protected/secret.txt
{
  "EvaluationResults": [ { "EvalDecision": "implicitDeny", "MatchedStatements": [] } ]
}
```

`implicitDeny` значит: явного разрешения нет — и это уже отказ. Так можно точно понять, почему действие не проходит, не перебирая вслепую.

## Шаг 8: порядок оценки целиком

Упрощённо: **explicit Deny** (в любой политике) → **SCP** → **resource policy** → **boundary** → **session policy** → **identity policy**. Если хотя бы на одном шаге стоит запрет или нет разрешения — доступ закрыт. Именно поэтому «политика с `*`» не гарантирует админа.

## Шаг 9: как это влияет на планирование атаки

Поскольку Deny и границы побеждают, **перед** действием полезно проверить, нет ли ограничений. Быстро узнать потолок для роли можно, посмотрев её boundary и SCP:

```
$ aws iam get-role --role-name test-role --query "Role.PermissionsBoundary"
"arn:aws:iam::123456789012:policy/OnlyS3Boundary"
$ aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/OnlyS3Boundary --version-id v1 \
    --query "PolicyVersion.Document.Statement[].Action"
[["s3:GetObject","s3:ListBucket"]]
```

Теперь ясно: какую бы широкую политику ни имела роль, реально доступен только S3. Такой анализ экономит время и объясняет «непонятные» отказы.

## Шаг 10: защита через границы

Правильная архитектура использует границы намеренно: boundary не даёт скомпрометированной роли выйти за очерченный круг даже при ошибке в политиках; SCP держит регионы и опасные сервисы; условия `ExternalId` и `SourceAccount` закрывают confused deputy. То есть всё, что мы изучали как «ограничители», — это и есть инструменты защиты.

## Шаг 11: практический порядок проверки

Когда непонятно, почему действие не проходит, иди по списку: (1) есть ли явный Deny в любой из политик; (2) не блокирует ли SCP; (3) нет ли ограничивающей resource policy; (4) какой у сущности permission boundary; (5) нет ли session policy; (6) есть ли вообще Allow в identity policy. Пройдя эти шесть пунктов, ты почти всегда находишь причину. И наоборот — при планировании атаки проверяй те же шесть мест, чтобы не тратить время на заведомо закрытые действия.

## Частые вопросы

**«Почему Allow не сработал?»** Скорее всего, где-то есть Deny, граница или SCP. Явный запрет всегда побеждает разрешение.

**«Чем boundary отличается от SCP?»** SCP ограничивает целые аккаунты/OU, boundary — конкретную сущность.

**«Может ли ресурс дать доступ, которого нет в IAM?»** Да: resource policy (например, публичный бакет) разрешает доступ независимо от твоих прав.

**«Как точно узнать причину отказа?»** `simulate-principal-policy` вернёт решение (`allowed`/`implicitDeny`) без слепого перебора.

## Что мы теперь знаем

По-простому:

1. Любой явный Deny побеждает любой Allow.
2. SCP ограничивает организацию, boundary — отдельную сущность.
3. Session policy сужает права на время сессии.
4. Resource policy даёт доступ к самому ресурсу.
5. Conditions и ExternalId защищают от confused deputy.

## На что смотреть дальше

- **Ищи Deny и границы.** `Action: "*"` может быть обрезан.
- **Проверяй SCP и boundary.** Они задают потолок.
- **Смотри resource policies.** Публичный ресурс = доступ без прав.
- **Симулируй.** `simulate-principal-policy` отвечает точнее догадок.

## Разбор: почему конкретный вызов даёт AccessDenied

Теория становится полезной, когда есть реальный отказ. Восстановим причину по журналу. Сначала — сам факт вызова и его результат:

```
$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
    --max-results 1 --query 'Events[0].CloudTrailEvent' --output text | jq '{userIdentity,errorCode,errorMessage}'
{
  "userIdentity": { "arn": "arn:aws:iam::123456789012:user/test-user" },
  "errorCode": "AccessDenied",
  "errorMessage": "User is not authorized ... with an explicit deny in an identity-based policy"
}
```

Формулировка `explicit deny in an identity-based policy` — прямая подсказка: где-то есть явный `Deny`. Дальше идём по цепочке: `list-attached-user-policies` → находим `NoDelete` → в её `Statement` видим `Deny` на `s3:DeleteObject`. Причина найдена, и никакой перебор не нужен.

Если бы сообщение было `implicit deny`, порядок другой: значит, **разрешения просто нет** — проверяем boundary, SCP и наличие `Allow` вообще. Разница между explicit и implicit deny — ключ к быстрой диагностике.

## Ловушки при чтении условий

Блок `Condition` — самое частое место ошибок, потому что внешне «запрет» может выглядеть как «разрешение» и наоборот:

- **`Null`** — `{"Null": {"aws:TagKeys": "true"}}` истинно, когда ключа **нет**. Легко перепутать.
- **`ForAllValues` vs `ForAnyValue`** — первый требует, чтобы **все** ключи из запроса удовлетворяли условию (и пустой набор даёт `true`!), второй — достаточно одного.
- **`StringEquals` vs `StringLike`** — второй уважает `*`/`?`, из-за чего проверка может «протечь».
- **`aws:SourceArn`/`aws:SourceAccount`** — без них доверие сервису превращается в confused deputy.
- **регион / `aws:RequestedRegion`** — SCP часто режет по нему; проверяйте, куда уходит вызов.
- **`sts:ExternalId`** — обязателен для доверия третьим лицам; отсутствие = дыра.

Практическое правило: перед атакой читайте условия **буквально** и проверяйте их `simulate-principal-policy` с теми же параметрами контекста, что у реального запроса. Симулятор не врёт — он прогоняет ту же логику оценки.

## Ограничения симулятора

`simulate-principal-policy` — мощный, но не всеведущий инструмент. Он не учитывает **resource policies** (доступ к бакету, к очереди), не моделирует `Principal` в политиках доверия и может не знать про SCP, если у вызывающего нет прав их читать. Поэтому его ответ `implicitDeny` ещё не значит «доступа нет вообще»: проверьте отдельно, не даёт ли доступ сам ресурс. И наоборот — `allowed` от симулятора не гарантирует, что ресурс существует и доступен по сети. Используйте его как **один** источник истины, а не единственный.

## Квиз

Проверь себя.

```quiz
- question: "Что побеждает при конфликте Allow и Deny?"
  options:
    - "Deny"
    - "Allow"
    - "Побеждает более новый"
    - "Зависит от региона"
  answer: 0
  explanation: "Явный запрет сильнее любого разрешения."
- question: "Что такое SCP?"
  options:
    - "Политика-ограничитель на уровне организации/OU"
    - "Пароль администратора"
    - "Тип ключа"
    - "Правило DNS"
  answer: 0
  explanation: "SCP задаёт максимум прав для аккаунтов."
- question: "Что делает permission boundary?"
  options:
    - "Задаёт потолок прав для конкретной сущности"
    - "Даёт админ-права"
    - "Отключает логи"
    - "Меняет регион"
  answer: 0
  explanation: "Права = пересечение Allow и границы."
- question: "Что такое confused deputy?"
  options:
    - "Обман сервиса-посредника, который выполняет действие от чужого имени"
    - "Ошибка в DNS"
    - "Сбой KMS"
    - "Утечка бакета"
  answer: 0
  explanation: "Защита — условия ExternalId и SourceAccount."
- question: "Какая команда покажет, почему действие отклонено?"
  options:
    - "aws iam simulate-principal-policy"
    - "aws s3 ls"
    - "dig"
    - "curl"
  answer: 0
  explanation: "Она симулирует решение об авторизации."
```

## Куда дальше

Мы разобрали логику оценки. Дальше — **AWS Organizations**: как устроены мульти-аккаунт среды, SCP и границы доверия между аккаунтами, и как между ними искать пути. А пока запомни главное: права — это не одна политика, а пересечение множества правил, и Deny всегда сильнее.

## Где пригодится

- **Пентест:** точно понимать, что реально разрешено.
- **Bug bounty:** находить обходы условий и границ.
- **Аудит:** выявлять слишком широкие boundary и SCP.
- **Blue team:** проектировать защиту через Deny и границы.
