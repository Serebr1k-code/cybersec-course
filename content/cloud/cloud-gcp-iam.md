---
id: cloud-gcp-iam
title: "GCP IAM и имперсонация сервисных аккаунтов: пути эскалации"
category: cloud
parent: cloud-iam-identity
difficulty: hard
order: 3
tags: [cloud, gcp, iam, service-account, impersonation, privesc]
prerequisites: [cloud-gcp-basics, cloud-iam-basics]
useful_for:
  - "Эскалация привилегий в GCP"
  - "Анализ IAM-политик и поиск путей имперсонации"
  - "Автоматизация аудита GCP-проектов"
estimated_minutes: 40
summary: "Как читать IAM-политики GCP, находить пути имперсонации сервисных аккаунтов и эскалировать до owner. Практические команды gcloud, gcpwn и разбор типовых цепочек."
---

## Вопрос, с которого всё начинается

В GCP нет пользователей-«ключей» как в AWS. Вместо них — **сервисные аккаунты**, и главный вектор эскалации — право **имперсонации**: возможность «примерить» другой аккаунт. Как найти такой путь и дойти до владельца проекта? Разберём на ключе сервисного аккаунта.

## Наш пример: ключ сервисного аккаунта

Объект урока — JSON-ключ сервисного аккаунта `ci-runner@acme-project.iam.gserviceaccount.com`, найденный в репозитории. Активируем его и посмотрим, что он умеет.

## Шаг 1: что такое сервисный аккаунт

**Сервисный аккаунт** — это «робот» в GCP: у него есть email вида `name@project.iam.gserviceaccount.com` и права, выданные через IAM. Ключ к нему — это файл с приватным ключом, который подписывает запросы. Если ключ утёк, ты работаешь от имени этого аккаунта.

```
$ gcloud auth activate-service-account --key-file ci-runner.json
Activated service account credentials for: [ci-runner@acme-project.iam.gserviceaccount.com]
```

## Шаг 2: читаем IAM-политику проекта

Смотрим, кто и что может в проекте:

```
$ gcloud projects get-iam-policy acme-project --format=json
{
  "bindings": [
    { "role": "roles/editor", "members": ["serviceAccount:ci-runner@acme-project.iam.gserviceaccount.com"] },
    { "role": "roles/iam.serviceAccountTokenCreator",
      "members": ["serviceAccount:ci-runner@acme-project.iam.gserviceaccount.com"] }
  ]
}
```

Читаем: у `ci-runner` есть роль `editor` (широкие права на ресурсы) и, что важнее, `roles/iam.serviceAccountTokenCreator`. Последняя позволяет **выпускать токены** для других сервисных аккаунтов — то есть имперсонировать их.

## Шаг 3: что такое имперсонация

**Имперсонация** — это вход «от имени» другого аккаунта без его ключа. Право `iam.serviceAccounts.getAccessToken` (или `TokenCreator`) позволяет получить токен целевого аккаунта:

```
$ gcloud auth print-access-token --impersonate-service-account=admin-sa@acme-project.iam.gserviceaccount.com
ya29.c.b0AX...TokenForAdminSA
```

Если целевой аккаунт (`admin-sa`) имеет роль `roles/owner`, мы только что получили владельца проекта. Вот и весь путь: слабый аккаунт с правом имперсонации → сильный аккаунт.

## Шаг 4: строим цепочку имперсонаций

Как и в AWS, здесь бывают цепочки. Один аккаунт может имперсонировать второй, второй — третий, и так до owner. Путь ищется по IAM-политикам: ищем биндинги `iam.serviceAccountTokenCreator`, `iam.serviceAccountUser` и `iam.serviceAccounts.getAccessToken`. Каждый такой биндинг — ребро графа.

```
$ gcloud iam service-accounts list --format="value(email)"
admin-sa@acme-project.iam.gserviceaccount.com
ci-runner@acme-project.iam.gserviceaccount.com
backup-sa@acme-project.iam.gserviceaccount.com
```

Дальше для каждого аккаунта проверяют, кто может его имперсонировать, и строят путь до самого привилегированного.

## Шаг 5: другие типовые пути эскалации в GCP

| Право/роль | Что даёт |
|------------|----------|
| `iam.serviceAccountTokenCreator` | выпускать токены другого SA |
| `iam.serviceAccountUser` | запускать ресурсы под другим SA (например, Compute) |
| `iam.serviceAccountKeys.create` | создать постоянный ключ для SA |
| `iam.roles.update` | переписать роль на более широкую |
| `resourcemanager.projects.setIamPolicy` | выдать себе любую роль |
| `iam.serviceAccounts.setIamPolicy` | выдать себе доступ к SA |

Последние два — прямые аналоги `iam:CreatePolicyVersion` в AWS: право менять политику даёт эскалацию.

## Шаг 6: автоматизация

Вручную строить граф долго. Для GCP есть `gcpwn` и `gcloud` в связке: перебирают аккаунты, проверяют права, строят цепочки имперсонации и эскалации. Порядок работы тот же, что и везде: сначала ручная разведка, потом автоматизация.

## Шаг 7: почему это работает

GCP строит всё вокруг сервисных аккаунтов и явных permission. Право «имперсонировать» выглядит безобидно, но по сути это право **стать другим аккаунтом** — а значит, унаследовать все его права. Разработчики выдают его для CI/CD «чтобы работало», не понимая, что открывают путь к owner.

## Шаг 8: как защищаться

- не выдавать `TokenCreator` без крайней необходимости;
- запрещать создание ключей сервисных аккаунтов (`disableServiceAccountKeyCreation`);
- использовать Workload Identity вместо ключей;
- ограничивать `setIamPolicy` и регулярно ревьюить биндинги.

## Шаг 9: сквозной пример цепочки

Соберём всё в одну историю. Найден ключ `ci-runner` в публичном репозитории. Активируем его и видим роль `editor` — уже доступ к ресурсам. Но интереснее биндинг `iam.serviceAccountTokenCreator` на `admin-sa`. Имперсонируем `admin-sa` и получаем его токен:

```
$ gcloud auth print-access-token --impersonate-service-account=admin-sa@acme-project.iam.gserviceaccount.com
ya29.c.b0AX...AdminSA
```

Смотрим, что может `admin-sa`:

```
$ gcloud projects get-iam-policy acme-project --flatten="bindings[].members" \
    --filter="bindings.members:admin-sa@acme-project.iam.gserviceaccount.com" \
    --format="table(bindings.role)"
ROLE
roles/owner
```

`roles/owner` — полный контроль над проектом. Итог: утёкший ключ слабого аккаунта плюс один биндинг имперсонации равны владельцу проекта. Именно поэтому в GCP `TokenCreator` считают опасным правом наравне с `setIamPolicy`.

## Шаг 10: практический порядок действий

Порядок при пентесте GCP такой: (1) активировать найденный ключ; (2) узнать проект и аккаунт (`gcloud config list`); (3) прочитать IAM-политику проекта; (4) выписать все биндинги имперсонации; (5) построить цепочку до самого привилегированного сервисного аккаунта; (6) проверить его роли. Так из одного ключа получается карта путей к owner. И помни: у каждого проекта своя политика, а выше есть folder и organization policies, которые тоже могут ограничивать — их стоит проверять отдельно.

## Шаг 11: типичные ошибки конфигурации

В GCP чаще всего встречаются такие проблемы: ключи сервисных аккаунтов, лежащие в CI/CD; `TokenCreator` выдан широкому набору аккаунтов; отсутствуют org policies, запрещающие создание ключей; сервисным аккаунтам выдают `editor` или `owner` «чтобы работало». Каждая из них — ребро в графе эскалации. Полезно помнить, что в GCP **сам факт наличия ключа** уже является риском: ключ долгоживущий, и его утечка равносильна компрометации аккаунта. Поэтому зрелые организации переходят на Workload Identity и вовсе отключают создание ключей.

## Шаг 12: шпаргалка по эскалации в GCP

Запомни три права-множителя: `iam.serviceAccountTokenCreator` (стать другим сервисным аккаунтом), `iam.serviceAccounts.setIamPolicy` (выдать себе доступ к сервисному аккаунту) и `resourcemanager.projects.setIamPolicy` (выдать себе любую роль в проекте). Любое из них в руках даже слабого аккаунта ведёт к owner. Всё остальное — детали реализации.

## Практический совет

Начни с `gcloud projects get-iam-policy` — оттуда видны все пути имперсонации. Дальше строй цепочку до самого привилегированного сервисного аккаунта.

## Частые вопросы

**«Чем сервисный аккаунт отличается от пользователя?»** Это «робот»: у него email вида `name@project.iam.gserviceaccount.com` и права через IAM.

**«Почему имперсонация — это эскалация?»** Потому что она позволяет «стать» другим аккаунтом и унаследовать все его права.

**«Какие права искать в первую очередь?»** `iam.serviceAccountTokenCreator`, `iam.serviceAccounts.setIamPolicy` и `resourcemanager.projects.setIamPolicy`.

**«Как строится путь до owner?»** По графу имперсонаций: каждый `TokenCreator` — ребро, ведущее к более привилегированному аккаунту.

## Что мы теперь знаем

По-простому:

1. В GCP права даются сервисным аккаунтам через IAM.
2. Утёкший ключ = работа от имени этого аккаунта.
3. Имперсонация позволяет «стать» другим аккаунтом.
4. `TokenCreator` и `setIamPolicy` — прямые пути эскалации.
5. Цепочки имперсонаций ведут до owner.

## На что смотреть дальше

- **Ищи TokenCreator.** Это главный множитель прав в GCP.
- **Строй граф.** Имперсонации образуют цепочки.
- **Проверяй setIamPolicy.** Право менять политику = эскалация.
- **Смотри ключи SA.** Утёкший ключ — готовый вход.

## Квиз

Проверь себя.

```quiz
- question: "Что такое сервисный аккаунт в GCP?"
  options:
    - "Учётная запись-робот с правами через IAM"
    - "Пользователь ОС"
    - "Правило firewall"
    - "Тип бакета"
  answer: 0
  explanation: "Сервисные аккаунты используются сервисами и CI/CD."
- question: "Что позволяет право iam.serviceAccountTokenCreator?"
  options:
    - "Выпускать токен другого сервисного аккаунта (имперсонировать)"
    - "Создавать бакеты"
    - "Менять DNS"
    - "Запускать ВМ"
  answer: 0
  explanation: "Это право имперсонации."
- question: "Какое право напрямую даёт выдать себе любую роль в проекте?"
  options:
    - "resourcemanager.projects.setIamPolicy"
    - "compute.instances.list"
    - "storage.objects.get"
    - "logging.logs.list"
  answer: 0
  explanation: "Право менять IAM-политику проекта = эскалация."
- question: "Что даёт iam.serviceAccountKeys.create?"
  options:
    - "Создать постоянный ключ для аккаунта"
    - "Удалить проект"
    - "Отключить логи"
    - "Сменить регион"
  answer: 0
  explanation: "Постоянный ключ — долгоживущий доступ."
- question: "Как строится путь к owner?"
  options:
    - "По цепочке имперсонаций сервисных аккаунтов"
    - "Через смену пароля"
    - "Через DNS"
    - "Через один бакет"
  answer: 0
  explanation: "Каждый TokenCreator — ребро графа."
```

## Куда дальше

Мы разобрали GCP IAM. Дальше — **AKS**: как из пода в Kubernetes получить managed identity и выйти в подписку Azure. А пока запомни главное: в GCP право имперсонировать сервисный аккаунт — это право стать им, и цепочки таких прав ведут до владельца проекта.

## Где пригодится

- **CTF (Cloud):** GCP-задачи с утёкшими ключами SA.
- **Bug bounty:** over-permissive service accounts.
- **Пентест:** аудит имперсонации и `setIamPolicy`.
- **Blue team:** Workload Identity вместо ключей, минимизация TokenCreator.
