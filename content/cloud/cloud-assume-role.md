---
id: cloud-assume-role
title: "Cross-account роли и confused deputy: цепочки доверия"
category: cloud
parent: cloud-aws-organizations
difficulty: expert
order: 1
tags: [cloud, aws, sts, assume-role, confused-deputy, cross-account, trust-policy]
prerequisites: [cloud-privesc-iam, cloud-aws-organizations]
useful_for:
  - "Эскалация между AWS-аккаунтами"
  - "Эксплуатация misconfigured trust policies"
  - "Понимание confused deputy и OIDC-доверия"
estimated_minutes: 40
summary: "Как работают cross-account роли, цепочки AssumeRole, ExternalId и confused deputy. Практические приёмы поиска и эксплуатации слабых trust policies."
lab:
  kind: shell
  title: "Практика: cross-account роль и confused deputy"
  toolset: [core, aws]
  workdir: /home/student/assume
  files: [task.md, notes.md, trust-policy.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "В `trust-policy.json` разбери `Condition`: нет `sts:ExternalId` — это confused deputy."
    - "Роль доверяет аккаунту; прими её: `aws sts assume-role --role-arn <arn> --role-session-name x`."
    - "Получив временные креды, читай секрет: `aws secretsmanager get-secret-value --secret-id prod/flag`, затем `grep nto out.json > found.txt`."

---

## Вопрос, с которого всё начинается

В чужом AWS-аккаунте есть роль, которая явно доверяет нашему аккаунту. Можно ли ей воспользоваться и получить доступ к чужому аккаунту? Ответ зависит от того, что написано в её **trust policy**. Разберём одну такую роль и заодно поймём, где здесь прячется ошибка «confused deputy».

## Наш пример: роль CrossAccountDeploy

Объект урока — роль `CrossAccountDeploy` в аккаунте `production` (`111111111111`). Мы сидим в аккаунте `development` (`222222222222`). Посмотрим, кому роль доверяет.

<!-- lab -->

## Шаг 1: что такое trust policy

**Trust policy** — это отдельный документ роли, который отвечает на вопрос «кто может её надеть». В отличие от обычной policy (что роль **может**), trust policy описывает, **кому разрешено** войти в роль через `sts:AssumeRole`. Посмотрим её:

```
$ aws iam get-role --role-name CrossAccountDeploy \
    --query "Role.AssumeRolePolicyDocument"
{
  "Statement": [
    { "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::222222222222:root" },
      "Action": "sts:AssumeRole" }
  ]
}
```

Читаем: роль доверяет аккаунту `222222222222` — это наш аккаунт. Причём доверие выдано **всему аккаунту** (`:root`), а не конкретному пользователю. Значит, любой пользователь в нашем аккаунте, у которого есть право `sts:AssumeRole`, может войти в эту роль.

## Шаг 2: пробуем войти

Входим в роль:

```
$ aws sts assume-role --role-arn arn:aws:iam::111111111111:role/CrossAccountDeploy \
    --role-session-name pentest
{
  "Credentials": {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "SessionToken": "...",
    "Expiration": "2024-05-01T18:00:00Z"
  }
}
```

Сработало. Теперь экспортируем креды и проверяем, кем стали:

```
$ export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
$ aws sts get-caller-identity
{"Arn": "arn:aws:sts::111111111111:assumed-role/CrossAccountDeploy/pentest",
 "Account": "111111111111"}
```

Мы в аккаунте `production`. Дальше смотрим, что роль может делать (её обычные политики) — возможно, она ведёт ещё дальше.

## Шаг 3: confused deputy и ExternalId

Почему доверие «всему аккаунту» опасно? Представь, что роль доверяет не только нам, но и **стороннему сервису**, которому клиент дал доступ. Тогда возникает **confused deputy** («сбитый с толку посредник»): посредник может быть обманут и выполнить действие от чужого имени. Защита — условие `ExternalId`:

```
"Condition": { "StringEquals": { "sts:ExternalId": "a1b2c3d4" } }
```

`ExternalId` — секретное значение, которое знает только владелец и его сервис. Без него чужой клиент не займёт роль. Если в trust policy условия нет — это находка.

## Шаг 4: цепочки AssumeRole

Роли часто образуют цепочки: одна роль даёт право занять другую. Это удобно для управления, но и для атакующего — путь вглубь:

```
development  --(assume CrossAccountDeploy)-->  production  --(assume AdminRole)-->  админ
```

На каждом шаге мы проверяем trust policy следующей роли и смотрим, разрешён ли вход нашим текущим аккаунтом. Если да — цепочка продолжается. На практике для автоматического перебора таких цепочек используют инструменты вроде `aws-escalate` или собственные скрипты по графу доверий.

## Шаг 5: как искать слабые доверия

Ищем trust policies, где `Principal` слишком широк:

- `"AWS": "*"` — роль может занять кто угодно (почти всегда ошибка);
- `:root` без условий — доверие целому аккаунту;
- отсутствие `ExternalId` для сторонних сервисов;
- доверие по `PrincipalOrgID`, которое не проверяет конкретную роль.

Для быстрого просмотра всех ролей с нестандартным доверием:

```
$ aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), '222222222222')].[RoleName]" --output text
CrossAccountDeploy
DeployPipelineRole
```

Так за один запрос видны все роли, доверяющие нашему аккаунту.

## Шаг 6: OIDC-доверие

Современный вариант — доверие к **OIDC-провайдеру** (например, GitHub Actions). Роль доверяет токену от GitHub, если он выдан нужному репозиторию:

```
"Principal": { "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com" },
"Condition": { "StringLike": { "token.actions.githubusercontent.com:sub": "repo:acme-corp/*:*" } }
```

Опасность — в слишком широком условии `sub`. Если оно допускает любой репозиторий или любую ветку, злоумышленник может создать подходящий репозиторий и получить доступ. Проверяй условие `sub` так же внимательно, как `ExternalId`.

## Шаг 7: как защищаться

- ограничивать `Principal` конкретной ролью, а не `:root`;
- всегда использовать `ExternalId` для сторонних доверий;
- сужать OIDC-условие до конкретного репозитория и ветки;
- логировать и алертить на `AssumeRole` из незнакомых аккаунтов.

## Шаг 8: пример из CTF

В учебной задаче сюжет часто такой: дан ключ пользователя в аккаунте-«песочнице». У ключа есть `sts:AssumeRole` на `*`. В том же аккаунте лежит роль с trust policy, доверяющей `*`. Ты занимаешь эту роль, а её политики разрешают `sts:AssumeRole` на роль в «продакшен»-аккаунте, которая уже имеет доступ к бакету с флагом. Цепочка из трёх AssumeRole — и ты добрался. Ключевой навык здесь не «взлом», а **чтение trust policies**: без анализа доверий ты просто не поймёшь, какая роль ведёт куда. Поэтому в CTF и в реальном пентесте первым делом выписывают все роли и их `Principal`, а потом строят маршрут.

## Шаг 9: доверие важнее ключей

Пользователь не «надевается» — у него есть ключ. Роль же существует, чтобы её занимали по доверию. Поэтому при пентесте ищи не ключи, а **доверия**: даже если все ключи отозваны, misconfigured trust policy позволит снова занять роль. И наоборот: без доверия никакой ключ в чужой аккаунт не пустит. Этот сдвиг мышления — ключевой для работы с облаками.

## Шаг 10: как проверить собственные доверия

Прежде чем искать чужие слабости, полезно оценить свой аккаунт теми же глазами: какие роли доверяют вашему аккаунту `:root`, где отсутствует `ExternalId`, какие OIDC-условия слишком широки. Это ровно те находки, которые искал бы противник, — и их лучше закрыть заранее. Такой «аудит доверий» стоит проводить регулярно, потому что роли и условия меняются вместе с инфраструктурой.

## Частые вопросы

**«Почему роль доверяет всему аккаунту?»** Так пишут по умолчанию (`:root`). Это значит, что любой пользователь аккаунта может занять роль.

**«Что защищает от confused deputy?»** Условие `sts:ExternalId` — секретное значение, которое знает только владелец и его сервис.

**«Как искать слабые доверия?»** Ищи `Principal: "*"`, `:root` без условий и слишком широкие OIDC-условия `sub`.

**«Зачем нужны цепочки?»** Они позволяют из слабого аккаунта дойти до сильного: одна роль даёт право занять следующую.

## Что мы теперь знаем

По-простому:

1. Trust policy решает, кто может войти в роль.
2. Доверие `:root` открывает роль всему аккаунту.
3. `ExternalId` защищает от confused deputy.
4. Роли образуют цепочки, по которым можно двигаться.
5. OIDC-доверие требует внимательного условия `sub`.

## На что смотреть дальше

- **Читай trust policy первой.** От неё зависит всё.
- **Ищи `*` и `:root`.** Самые слабые доверия.
- **Проверяй ExternalId.** Его отсутствие — находка.
- **Строй цепочку.** Одна роль часто ведёт к следующей.

## Confused deputy на практике: S3, Lambda и CloudFormation

Абстрактный «сбитый с толку посредник» становится конкретным, когда доверие выдано не человеку, а сервису. Классический пример — **S3 bucket policy**, где владелец разрешает запись сервису, а сервис передаёт эту возможность клиенту:

```
{ "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::audit-logs/*" }
```

Если условие не сужено по `aws:SourceArn`/`SourceAccount`, чужой аккаунт может настроить собственный трейл, указав вашу корзину как приёмник, и лить туда данные от своего имени — посредник «путается», чей это запрос. Защита всегда одна: **Condition с SourceArn** и `ExternalId` там, где участвует третья сторона.

Другой живой вектор — **`iam:PassRole` + Lambda**. Пользователь, которому разрешено создавать функции и передавать роль, фактически исполняет код **от имени этой роли**. Это не «assume», а передача роли как параметра; confused deputy тут в том, что сервис Lambda принимает роль на веру. Проверка:

```bash
$ aws iam list-attached-role-policies --role-name CrossAccountDeploy
$ aws lambda create-function --function-name probe --runtime python3.12 \
    --role arn:aws:iam::111111111111:role/CrossAccountDeploy \
    --handler index.handler --zip-file fileb://probe.zip
```

Если роль привилегированна, а `PassRole` не ограничен условием `iam:PassedToService`, ты получаешь её права, не входя в неё. Всегда проверяй, **куда** передаётся роль, а не только **кому**.

## Трассировка цепочки: CloudTrail и session name

Когда цепочка AssumeRole построена, её нужно подтвердить по логам. События `AssumeRole` пишутся в CloudTrail с полями `userIdentity`, `requestParameters.roleArn` и `responseElements.assumedRoleUser`, а `role-session-name` становится частью ARN:

```bash
# Все AssumeRole за сутки с разбивкой по ролям
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time 2026-01-01T00:00:00Z \
    --query "Events[].CloudTrailEvent" --output text \
  | jq -r 'fromjson | .requestParameters.roleArn' | sort | uniq -c | sort -rn
```

Практические правила: давай **осмысленный** `role-session-name` — по нему в логах видно, кто именно надел роль (по умолчанию там случайный идентификатор). Если в цепочке используется `--external-id`, он **не** попадает в CloudTrail — не рассчитывай восстановить его из логов. И помни про `sts:AssumeRoleWithSAML`/`WithWebIdentity`: у них свой набор полей, и confused deputy там выглядит иначе (широкое условие `sub`, отсутствие проверки аудитории токена).

## Квиз

Проверь себя.

```quiz
- question: "Что описывает trust policy роли?"
  options:
    - "Кому разрешено войти в роль через AssumeRole"
    - "Что роль может делать"
    - "Размер роли"
    - "Её теги"
  answer: 0
  explanation: "Trust policy — про вход, а не про права роли."
- question: "Чем опасно доверие к ':root' без условий?"
  options:
    - "Любой пользователь аккаунта может занять роль"
    - "Роль исчезает"
    - "Пропадают логи"
    - "Ключ шифруется"
  answer: 0
  explanation: "Доверие выдано всему аккаунту."
- question: "Что защищает от confused deputy?"
  options:
    - "Условие sts:ExternalId"
    - "Смена региона"
    - "Длинный пароль"
    - "MFA"
  answer: 0
  explanation: "ExternalId знает только владелец и его сервис."
- question: "Что такое цепочка AssumeRole?"
  options:
    - "Последовательность ролей, где одна даёт занять другую"
    - "Список бакетов"
    - "Набор ключей"
    - "Правило DNS"
  answer: 0
  explanation: "По цепочке можно двигаться вглубь."
- question: "На что смотреть в OIDC-доверии?"
  options:
    - "Условие sub — оно должно ограничивать репозиторий и ветку"
    - "Цвет иконки"
    - "Размер токена"
    - "Регион"
  answer: 0
  explanation: "Слишком широкий sub позволяет подделать контекст."
```

## Куда дальше

Мы разобрали доверия между AWS-аккаунтами. Дальше — **Azure**: Entra ID и Azure RBAC, где роли назначаются на scope, а приложения получают права через API permissions. А пока запомни главное: cross-account доступ существует ровно там, где есть явное доверие, и trust policy — его единственный источник.

## Где пригодится

- **Пентест:** движение между AWS-аккаунтами.
- **Red team:** построение цепочек доверия.
- **Аудит:** поиск слабых trust policies и отсутствующих ExternalId.
- **Blue team:** контроль cross-account-доверий и OIDC-условий.
