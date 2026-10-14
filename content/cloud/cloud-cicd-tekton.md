---
id: cloud-cicd-tekton
title: 'Tekton / Argo Workflows / Rollouts: пайплайны в кластере'
category: cloud
parent: cloud-cicd-servers
difficulty: expert
order: 3
tags: [cloud, cicd, tekton, argo, kubernetes, serviceaccount, triggers]
prerequisites: [cloud-cicd-secrets]
useful_for:
  - 'Атаки на Kubernetes-native CI/CD'
  - 'Кража секретов из пайплайнов'
  - 'CTF cloud'
estimated_minutes: 50
summary: 'Tekton (и Argo Workflows/Rollouts): Pipeline и TaskRun как поды, ServiceAccounts и секреты, Triggers и webhooks, побег из TaskRun. Сквозной пример — TaskRun с широким ServiceAccount.'
lab:
  kind: shell
  title: 'Практика: SA пайплайна с cluster-admin'
  toolset: [core]
  workdir: /home/student/tekton
  files: [task.md, pipelinerun.yaml, rbac.yaml, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Посмотри PipelineRun и RBAC: `cat pipelinerun.yaml` и `cat rbac.yaml`.'
    - 'Флаг — в notes.md. Найди строку с nto: `grep nto notes.md` и запиши флаг в found.txt.'
---

## Вопрос, с которого всё начинается

Кластер использует Tekton: пайплайны описываются как CRD и выполняются как поды. Ты получил код в одном из TaskRun или доступ к созданию пайплайнов. Вопрос: какие права у ServiceAccount, под которым бежит пайплайн, можно ли прочитать секреты других задач и как выйти из TaskRun на узел? Tekton наследует всю модель безопасности Kubernetes.

## Tekton в Kubernetes

Tekton — Kubernetes-native CI/CD: вместо отдельного сервера всё описывается CRD (Pipeline, Task, PipelineRun, TaskRun). Каждый шаг выполняется как контейнер в поде. Это даёт гибкость и переносимость, но означает, что пайплайн наследует модель безопасности кластера: ServiceAccounts, RBAC, секреты, pod security. Для атакующего Tekton — это ещё один способ запустить код в кластере с чужими правами.

## Сквозной пример: Pipeline и TaskRun

Пайплайн выглядит так:
```
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: deploy-prod
spec:
  serviceAccountName: deployer
  pipelineRef:
    name: deploy
```
Пайплайн бежит под ServiceAccount `deployer`. Если у `deployer` широкие RBAC-права (например, доступ к секретам всего namespace или кластера), то любой, кто может создать PipelineRun с этим SA, получает эти права. Это ключ к эскалации в кластерных CI/CD.

## ServiceAccounts и секреты

Каждый TaskRun использует ServiceAccount. Секреты монтируются в под из этого SA или из привязанных secret-ресурсов. Атакующий ищет: ServiceAccount с широкими правами, секреты, смонтированные в пайплайны, доступ к чтению секретов через RBAC. Если он может создать TaskRun (или изменить существующий) с нужным SA, он выполняет код с правами этого SA — вплоть до cluster-admin.

## Triggers и webhooks

Tekton Triggers принимают события (webhook из Git) и создают PipelineRun. Если TriggerBinding/TriggerTemplate настроены слабо, атакующий через событие (например, push в репозиторий) запускает пайплайн с секретами. Это тот же «pwn request», что и в других CI: изменение репозитория приводит к исполнению кода в кластере. Проверяй, какие события могут запускать пайплайны и с какими SA.

## TaskRun и pod security

TaskRun — это под. Значит, к нему применимы pod security, capabilities, hostPath, hostNetwork. Если TaskRun запускается с привилегиями (privileged, hostPath, hostNetwork), он может выйти на узел. Даже без явных привилегий, широкий SA даёт доступ к API-серверу: можно создавать поды, читать секреты, менять RBAC. Поэтому безопасность Tekton — это безопасность подов и RBAC.

## Argo Workflows и Rollouts

Argo Workflows — ещё одна Kubernetes-native система пайплайнов; Argo Rollouts управляет деплоями (canary, blue-green). У них та же модель: CRD + ServiceAccounts. Компромисс контроллера Argo или прав на CRD даёт контроль над пайплайнами и деплоями. Argo Rollouts, в частности, может управлять трафиком и версиями приложений, поэтому его компромисс влияет на продакшн напрямую.

## Обход и эскалация

Пути эскалации. Первый: создать PipelineRun/TaskRun с привилегированным SA. Второй: изменить существующий пайплайн (если есть права). Третий: использовать Trigger для запуска с секретами. Четвёртый: выйти из TaskRun на узел через привилегии или hostPath. Пятый: прочитать секреты через API, если RBAC позволяет. Цель — получить доступ к секретам и/или к узлу.

## Типовые мисконфиги

| Мисконфиг | Последствие | Как искать |
|---|---|---|
| SA с широкими правами | эскалация в кластер | RBAC |
| Секреты всего namespace | кража через пайплайн | RBAC на secrets |
| Привилегированный TaskRun | побег на узел | pod security |
| Слабые Triggers | запуск с секретами | TriggerBinding |
| Права на CRD Tekton | подмена пайплайнов | RBAC |
| hostPath/hostNetwork | доступ к узлу | спецификация |

## Полный прогон: от доступа к секретам

Шаги. Первый: определить Tekton в кластере (`kubectl get pipelines,taskruns`). Второй: выгрузить PipelineRun и их ServiceAccounts. Третий: проверить RBAC этих SA. Четвёртый: если есть права — создать TaskRun с нужным SA и командой чтения секретов. Пятый: прочитать секреты или создать под с привилегиями. Шестой: закрепиться (создать SA/токен). Седьмой: учесть аудит API-сервера.

## Инструменты и команды

`tkn` — CLI Tekton: `tkn pipeline list`, `tkn pipelinerun describe`, `tkn taskrun logs`. `kubectl` для CRD: `kubectl get sa,secrets,pipelines -A`. `argo` CLI для Argo Workflows. Для эскалации — `kubectl auth can-i --as=system:serviceaccount:...`. Для побега — обычные техники Kubernetes (privileged, hostPath).

## OPSEC и детект

Все действия через API-сервер фиксируются в audit-логах: создание PipelineRun, чтение секретов, изменение RBAC. Привилегированные поды видны в pod security. Запуск пайплайна вне обычного графика — аномалия. Тихий сценарий — использовать существующий пайплайн или точные обращения к API. Помни: кластерные CI/CD обычно под пристальным наблюдением.

## Частые вопросы

Наследует ли Tekton RBAC Kubernetes? Да, через ServiceAccounts. Можно ли прочитать секреты через пайплайн? Да, если у SA есть доступ. Опасны ли Triggers? Да, если событие запускает пайплайн с секретами. Можно ли выйти на узел? Да, через привилегии или hostPath. Как защититься? Минимум прав SA, изоляция подов, строгие Triggers, аудит.

## Что не сработает

Если SA пайплайна имеет минимальные права, эскалация не сработает. Строгий pod security блокирует привилегированные TaskRun. Закрытые Triggers не дадут запустить пайплайн через событие. И если RBAC на секреты ограничен, прочитать чужие секреты не выйдет.

## Разбор кейса: побег из TaskRun

История из практики. Команда разрешила пайплайнам запускать поды с `hostPath` для кэша сборки. Атакующий, получив возможность создать TaskRun, указал `hostPath: /` и примонтировал корень узла. Из шага он записал SSH-ключ в `/root/.ssh/authorized_keys` узла. Никаких привилегированных флагов не понадобилось — только hostPath. Это классическая ошибка: удобство сборки (кэш, доступ к файлам) открывает побег. Правильная настройка — pod security restricted и запрет hostPath.

## Argo Rollouts и деплой

Argo Rollouts управляет постепенными деплоями: canary, blue-green, анализ метрик. Его компромисс влияет на продакшн напрямую: атакующий может продвинуть вредоносную версию, изменить трафик или откатить защиту. Контроллер Argo Rollouts имеет права на изменение ресурсов приложений, поэтому права на его CRD (Rollout) ценны. Как и Tekton, Argo наследует модель Kubernetes: ServiceAccount и RBAC определяют, что возможно.

## Tekton и облачные креды

Пайплайны Tekton часто деплоят в облако и хранят облачные креды в секретах Kubernetes или через Workload Identity. Атакующий ищет секреты, смонтированные в TaskRun, или SA с правами на облако (например, через Workload Identity Federation). Получив такой SA, он выполняет код с облачными правами: читает бакеты, меняет ресурсы, эскалирует в облаке. Tekton — это мост из кластера в облако.

## Практический чек-лист пентеста Tekton

Порядок действий. Один: определить Tekton/Argo в кластере. Два: выгрузить PipelineRun/TaskRun и их ServiceAccounts. Три: проверить RBAC этих SA (`kubectl auth can-i`). Четыре: проверить pod security (privileged, hostPath, hostNetwork). Пять: проверить Triggers на запуск с секретами. Шесть: если есть права — создать TaskRun с нужным SA. Семь: прочитать секреты или выйти на узел. Восемь: закрепиться и учесть аудит.

## Что дальше в дереве

Модуль CI/CD-серверов завершён. Дальше — секрет-менеджеры: Vault и CyberArk, где сосредоточены креды ко всей инфраструктуре. А пока главное: в Tekton права пайплайна определяет ServiceAccount, а hostPath и привилегии дают побег.

## Tekton против Jenkins и GitLab

Классические CI (Jenkins, GitLab) — это серверы с агентами, часто вне Kubernetes. Tekton и Argo живут внутри кластера и используют его примитивы. Отсюда разница в атаке: у Jenkins цель — сервер и его агенты; у Tekton — ServiceAccount, RBAC и pod security кластера. Зато Tekton не требует отдельной инфраструктуры, и его слабости — это слабости кластера. Если кластер уже скомпрометирован, Tekton не добавляет защиты, а иногда и упрощает эскалацию.

## Защита Tekton и Argo

Меры: минимальные права ServiceAccounts пайплайнов (без cluster-admin, без доступа ко всем секретам), строгий pod security (запрет privileged, hostPath, hostNetwork), ограничение Triggers (кто может запускать пайплайны и с какими SA), аудит API-сервера, разделение namespace для разных команд. Дополнительно — не давать пайплайнам доступ к секретам всего кластера и использовать Workload Identity вместо долгоживущих облачных ключей.

## Итоговая цепочка атаки на Tekton

Соберём сценарий. Атакующий с правом создавать PipelineRun замечает, что пайплайн деплоя бежит под ServiceAccount с широкими правами. Он создаёт свой TaskRun с тем же SA и командой, читающей секреты кластера. Секреты содержат облачные креды деплоя. Дальше он выходит в облако и читает бакеты. Вся цепочка держится на одном: SA пайплайна имеет больше прав, чем нужно, а создание PipelineRun доступно атакующему. Ограничение прав SA разрывает атаку.

## Что мы теперь знаем

1. Tekton — Kubernetes-native CI/CD: пайплайны как CRD, шаги как поды.
2. ServiceAccount пайплайна определяет его права — широкий SA даёт эскалацию.
3. Triggers — тот же «pwn request», запускающий пайплайн с секретами.
4. TaskRun подчиняется pod security: привилегии и hostPath дают побег.
5. Argo Workflows/Rollouts имеют ту же модель и те же риски.

## Квиз

Проверь себя.

```quiz
- question: "Чем определяется «право» пайплайна в Tekton?"
  options:
    - "ServiceAccount, под которым он выполняется"
    - "Именем Pipeline"
    - "Размером образа"
    - "Числом шагов"
  answer: 0
  explanation: "Пайплайн бежит под ServiceAccount и наследует его RBAC-права."
- question: "Почему Triggers похожи на pwn request?"
  options:
    - "Событие (например, push) может запустить пайплайн с секретами"
    - "Они ускоряют сборку"
    - "Они шифруют логи"
    - "Они хранят пароли"
  answer: 0
  explanation: "Через событие атакующий запускает пайплайн с доступом к секретам."
- question: "Как выйти из TaskRun на узел?"
  options:
    - "Через привилегии, hostPath или hostNetwork"
    - "Через DNS"
    - "Через длинное имя"
    - "Через тег образа"
  answer: 0
  explanation: "TaskRun — это под, и привилегии позволяют выйти на узел."
- question: "Что общего у Tekton и Argo Workflows?"
  options:
    - "Обе системы — Kubernetes-native: CRD и ServiceAccounts"
    - "Обе работают без кластера"
    - "Обе не используют секреты"
    - "Обе только для Windows"
  answer: 0
  explanation: "Обе описывают пайплайны как CRD и наследуют модель безопасности Kubernetes."
```

## Куда дальше

Этим уроком завершается модуль CI/CD-серверов. А пока главное: в Tekton права пайплайна определяет ServiceAccount, и широкий SA даёт эскалацию в кластер.

## Где пригодится

- Атаки на Kubernetes-native CI/CD.
- Кража секретов из пайплайнов.
- CTF cloud.
