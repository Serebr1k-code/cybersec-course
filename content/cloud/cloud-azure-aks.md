---
id: cloud-azure-aks
title: "AKS: managed identity пода, kubelet identity и Azure RBAC"
category: cloud
parent: cloud-azure-platform-deep
difficulty: hard
order: 1
tags: [cloud, azure, aks, kubernetes, managed-identity, workload-identity, rbac]
prerequisites: [cloud-azure-platform-deep, cloud-kubernetes-rbac]
useful_for:
  - "Пентест Azure Kubernetes Service"
  - "Захват managed identity из пода"
  - "Lateral movement от AKS к подписке"
estimated_minutes: 50
summary: "AKS: managed identity кластера, kubelet identity, Azure AD Workload Identity и IMDS пода. Как из контейнера получить токен Entra ID и эскалировать в подписку."
---

## Вопрос, с которого всё начинается

Ты получил выполнение команды в поде внутри Azure Kubernetes Service (AKS). Вроде бы это «всего лишь» контейнер. Но у AKS есть managed identity, а у подов — доступ к metadata Azure. Значит, из контейнера можно получить токен и выйти в подписку. Разберём этот путь.

**AKS** — управляемый Kubernetes в Azure. Kubernetes — оркестратор контейнеров; «под» — минимальная единица запуска (один или несколько контейнеров).

## Наш пример: под app-frontend

Объект урока — под `app-frontend-7d9f8`, в который мы попали через уязвимость приложения. Сначала осмотримся.

## Шаг 1: попадаем в под и смотрим окружение

```
$ kubectl exec -it app-frontend-7d9f8 -- sh
/ # whoami
nobody
/ # env | grep -i -E 'azure|identity|tenant'
IDENTITY_ENDPOINT=http://169.254.169.254/metadata/identity/oauth2/token
IDENTITY_HEADER=eyJhbGciOi...
AZURE_CLIENT_ID=c3f1d2e4-...
```

Обрати внимание на переменные `IDENTITY_ENDPOINT` и `IDENTITY_HEADER`. Их наличие означает, что у пода включена managed identity (или workload identity). Это наш мостик в Azure.

## Шаг 2: что такое managed identity в AKS

У AKS есть несколько уровней identity:

- **Cluster identity** — используется самим кластером для управления ресурсами.
- **Kubelet identity** — от неё работает kubelet (агент на ноде); у неё часто есть доступ к реестру образов и сети.
- **Pod identity / Workload Identity** — identity, назначенная поду, чтобы он обращался к Azure-ресурсам.

Именно последняя нас интересует: если под имеет identity, он может получить токен Azure.

## Шаг 3: получаем токен

Пробуем metadata-эндпоинт пода:

```
/ # curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=$AZURE_CLIENT_ID"
{
  "access_token": "eyJ0eXAiOiJKV1Qi...",
  "expires_on": "1714580000",
  "resource": "https://management.azure.com/"
}
```

Мы получили токен на ARM (API управления Azure). Теперь им можно пользоваться.

## Шаг 4: используем токен

Подставим токен в запрос к ARM и перечислим ресурсы подписки:

```
/ # curl -s -H "Authorization: Bearer eyJ0eXAi..." \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"
{"value":[{"id":"/subscriptions/11111111-...","displayName":"Production"}]}
```

Мы видим подписку `Production`. Из контейнера мы дошли до управления облаком. Дальше — читаем секреты из Key Vault, если identity имеет на это права.

## Шаг 5: Workload Identity — современный вариант

Раньше в AKS использовали aad-pod-identity; теперь — **Azure AD Workload Identity**. Под получает федеративный токен, который обменивается на токен Entra ID. Для атакующего разница в деталях: endpoint тот же, но проверять нужно и переменные окружения, и смонтированный токен:

```
/ # ls /var/run/secrets/azure/tokens/
azure-identity-token
```

Наличие этого файла — признак workload identity. Его содержимое обменивается на токен Azure тем же запросом к metadata.

## Шаг 6: kubelet identity и движение по кластеру

Даже без pod identity у kubelet identity часто есть полезные права: `AcrPull` (читать образы из реестра), доступ к сети. А если у нас есть права в Kubernetes (например, через service account пода), можно прочитать **секреты кластера**:

```
$ kubectl get secrets -A
NAMESPACE   NAME              TYPE
default     registry-cred     kubernetes.io/dockerconfigjson
```

`registry-cred` может содержать креды к реестру образов, а другие секреты — к внешним сервисам. Это отдельный, не облачный, но не менее важный путь.

## Шаг 7: как эскалировать в подписку

Цепочка обычно такая: под → managed identity → ARM/Graph/Key Vault. Масштаб зависит от прав identity. Если identity имеет `Contributor` на подписке — ты управляешь ресурсами; если `User.ReadWrite.All` в Graph — управляешь пользователями. Поэтому после получения токена первым делом читают его `roles`/`scp` и проверяют ресурсы, до которых дотягивается identity.

## Шаг 8: как защищаться

- выдавать подам identity только с нужными правами;
- использовать Workload Identity и не давать широких ролей kubelet identity;
- ограничивать RBAC Kubernetes, чтобы секреты не читались свободно;
- включать аудит доступа к metadata и ARM.

## Шаг 9: практический чек-лист из пода

Попав в под AKS, проверь по порядку:

1. переменные окружения: `env | grep -i identity`;
2. смонтированные токены: `ls /var/run/secrets/azure/tokens/`;
3. доступ к metadata: запрос с заголовком `Metadata: true`;
4. секреты кластера: `kubectl get secrets -A`;
5. роли identity: перечисление ресурсов через ARM по полученному токену.

Пять шагов занимают минуты и дают полную картину: есть ли выход в Azure и насколько он широк.

## Шаг 10: почему из пода так легко попасть в облако

Pod identity существует именно для того, чтобы под обращался к Azure **без секретов** — через metadata. Значит, эндпоинт открыт по замыслу, и никакого «взлома» для получения токена не нужно: достаточно быть внутри пода. Граница безопасности проходит не по контейнеру, а по **правам identity**. Отсюда практический вывод: если под скомпрометирован, масштаб ущерба определяется исключительно ролью его identity. Поэтому в защите AKS главное — выдавать подам минимальные роли и не давать kubelet identity лишнего.

## Шаг 11: шпаргалка из пода

Запомни три факта: pod identity даёт токен в Azure через metadata; kubelet identity часто имеет доступ к реестру и сети; секреты кластера ведут к внешним сервисам. Проверяя эти три вещи, ты за минуты оценишь, насколько глубоко можно уйти из контейнера.

## Шаг 12: что делать с полученным токеном

Первым делом перечисли ресурсы подписки и проверь Key Vault — это самые ценные цели. Только потом двигайся дальше по кластеру: секреты и сервисные аккаунты могут вести ещё глубже.

## Практический совет

Первым делом проверь переменные окружения пода: если там есть `IDENTITY_ENDPOINT`, путь в Azure открыт. Дальше сразу пробуй получить токен на ARM — это самый прямой способ оценить масштаб.

## Частые вопросы

**«Почему под вообще может ходить в Azure?»** Из-за managed identity: она создана, чтобы под получал доступ без хранения секретов.

**«Что проверять в первую очередь?»** Переменные окружения (`IDENTITY_ENDPOINT`), смонтированный токен и запрос к metadata с заголовком `Metadata: true`.

**«Что такое kubelet identity?»** Identity ноды, от которой работает kubelet; у неё часто есть доступ к реестру образов.

**«Куда идти после получения токена?»** Перечислить ресурсы подписки и проверить Key Vault — там самые ценные данные.

## Что мы теперь знаем

По-простому:

1. AKS — управляемый Kubernetes в Azure.
2. Под может иметь managed identity и ходить в metadata Azure.
3. Токен выдаётся с заголовком `Metadata: true` на нужный resource.
4. Kubelet identity и секреты кластера — дополнительный путь.
5. Масштаб ущерба определяют права identity.

## На что смотреть дальше

- **Проверяй переменные окружения пода.** `IDENTITY_ENDPOINT` — мостик в Azure.
- **Ищи смонтированный токен.** Признак Workload Identity.
- **Читай роли identity.** От них зависит всё.
- **Смотри секреты кластера.** Они ведут к внешним сервисам.

## Квиз

Проверь себя.

```quiz
- question: "Что такое AKS?"
  options:
    - "Управляемый Kubernetes в Azure"
    - "База данных"
    - "Тип бакета"
    - "CDN"
  answer: 0
  explanation: "Azure Kubernetes Service — managed Kubernetes."
- question: "Что означает переменная IDENTITY_ENDPOINT в поде?"
  options:
    - "У пода есть managed identity, доступная через metadata"
    - "Под выключен"
    - "Есть SSH"
    - "Под в другой сети"
  answer: 0
  explanation: "Через неё получают токен Azure."
- question: "Какой заголовок нужен при запросе токена у metadata Azure?"
  options:
    - "Metadata: true"
    - "Metadata-Flavor: Google"
    - "X-aws-token"
    - "Authorization: Basic"
  answer: 0
  explanation: "Azure отклоняет запросы без него."
- question: "Что такое kubelet identity?"
  options:
    - "Identity, от которой работает kubelet ноды"
    - "Пользователь каталога"
    - "Тип пода"
    - "Правило сети"
  answer: 0
  explanation: "У неё часто есть доступ к реестру образов."
- question: "От чего зависит масштаб доступа из пода?"
  options:
    - "От прав назначенной identity"
    - "От размера пода"
    - "От имени кластера"
    - "От количества нод"
  answer: 0
  explanation: "Роль identity определяет доступные ресурсы."
```

## Куда дальше

Мы разобрали AKS. Дальше — **Logic Apps**: low-code сервис Azure, где workflow держит managed identity и подключения к сервисам, а инъекции в параметры дают доступ к данным. А пока запомни главное: под в AKS — это потенциальная точка входа в подписку Azure через managed identity.

## Где пригодится

- **Пентест:** путь от контейнера к облаку.
- **CTF (Cloud):** AKS-задачи с metadata пода.
- **Red team:** lateral movement из кластера в подписку.
- **Blue team:** минимизация прав pod identity и kubelet identity.
