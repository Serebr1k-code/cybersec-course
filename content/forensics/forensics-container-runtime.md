---
id: forensics-container-runtime
title: 'Контейнеры в облаке: runtime, слои и оркестратор'
category: forensics
parent: forensics-cloud-runtime
difficulty: hard
order: 2
tags: [cloud, container, kubernetes, runtime, layers, forensics]
prerequisites: [forensics-cloud-identity, forensics-containers]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Cloud Security'
estimated_minutes: 50
summary: 'Как расследовать облачные контейнеры (EKS/GKE/AKS/Fargate): слои образа, runtime-логи, аудит-логи Kubernetes и следы эфемерных подов.'
lab:
  kind: shell
  title: 'Практика: Контейнеры в облаке'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

В облаке подозрительная активность шла из **контейнера**, который уже пересоздан. Пода
нет, контейнера нет — остался только образ. Что можно восстановить?

## Наш пример: под, который исчез

В Kubernetes-кластере был под `worker-7f8d`. Сейчас его нет:

```
$ kubectl get pods -n default
NAME       READY   STATUS    RESTARTS   AGE
api-1      1/1     Running   0          5d
```

Но в аудит-логах и логах узла остались следы. Разбираемся, где их искать.

## Чем контейнер отличается от ВМ

**Контейнер** — это процесс (или группа), запущенный в изолированном окружении на общем
ядре. У него нет «диска» в привычном смысле: есть **образ** (набор слоёв только для
чтения) и **записываемый слой**, который при пересоздании контейнера исчезает.

В облаке (EKS/GKE/AKS) контейнеры запускает оркестратор на узлах. В «serverless»-варианте
(Fargate/Cloud Run) узла вообще не видно.

## Шаг 1: слои образа

Образ состоит из слоёв; каждый слой — это diff файловой системы. Слои можно скачать и
изучить:

```
$ docker pull registry.example.com/app:1.2.3
$ docker history --no-trunc registry.example.com/app:1.2.3
sha256:...  COPY malicious.sh /entrypoint.sh
```

Если атакующий внедрил код в образ, он останется в слое — даже если контейнер пересоздан.

## Шаг 2: runtime-логи узла

На узле работает **runtime** (containerd/dockerd). Его логи фиксируют запуск/остановку
контейнеров, а `kubelet` пишет свои журналы:

```
$ journalctl -u kubelet | grep worker-7f8d
Started container worker-7f8d
Killing container worker-7f8d (OOMKilled)
```

По ним видно, **когда** под жил и **как** завершился (например, был убит).

## Шаг 3: аудит-логи Kubernetes

**Kubernetes audit log** — главный источник: кто создал под, с каким образом, какие
команды выполнял через `exec`:

```
{"verb":"create","objectRef":{"resource":"pods","name":"worker-7f8d"},
 "user":{"username":"system:serviceaccount:default:ci"},"sourceIPs":["10.0.0.7"]}
{"verb":"exec","objectRef":{"resource":"pods","name":"worker-7f8d"},
 "user":{"username":"admin"},"requestURI":"/exec?command=sh"}
```

Видно: под создан сервисным аккаунтом `ci`, а затем кто-то делал `exec sh` — то есть
получил shell внутри контейнера.

## Шаг 4: runtime-security события

Инструменты вроде Falco фиксируют подозрительное поведение в runtime (запуск shell,
запись в /etc, обращения к metadata). Их события — отдельный источник улик.

## Ловушки

- **Эфемерность**: записываемый слой исчезает при пересоздании; снимать нужно **пока под
  жив** (или через `kubectl cp`/debug-контейнер).
- **Общие тома**: если данные писались в persistent volume, они переживут под.
- **Общий узел**: несколько подов делят ядро; следы могут смешиваться.

## Что мы теперь знаем

- Контейнер = образ (слои) + записываемый слой, который исчезает.
- Внедрённый в образ код остаётся в слое.
- Runtime-логи узла показывают жизненный цикл контейнера.
- Аудит-логи Kubernetes фиксируют создание подов и `exec`.
- Данные в persistent volume переживают контейнер.

## Квиз

Проверь себя.

```quiz
- question: Из чего состоит контейнер?
  options:
    - 'из образа (слоёв) и записываемого слоя'
    - 'из диска и памяти'
    - 'из BIOS'
    - 'из SMART'
  answer: 0
  explanation: 'Образ — слои только для чтения; записываемый слой исчезает при пересоздании.'
- question: Где искать следы `exec` внутрь пода?
  options:
    - 'в SMART'
    - 'в audit log Kubernetes'
    - 'в BIOS'
    - 'в файле /etc/passwd узла'
  answer: 1
  explanation: 'Аудит-лог Kubernetes фиксирует verb=exec и пользователя.'
- question: Что переживает пересоздание контейнера?
  options:
    - 'записываемый слой'
    - 'данные в persistent volume'
    - 'временные файлы'
    - 'ничего'
  answer: 1
  explanation: 'Persistent volume хранится отдельно и переживает под.'
- question: Где остаётся внедрённый в образ код?
  options:
    - 'в логах'
    - 'в слое образа'
    - 'в памяти узла'
    - 'в аудит-логе'
  answer: 1
  explanation: 'Слой образа хранит diff файловой системы и сохраняет изменения.'
```

## Куда дальше

Контейнеры — это уже вычисления. Дальше — **виртуальные машины**: у них есть диск, но и он
в облаке не совсем «диск». А пока запомни: образ и аудит-логи Kubernetes — главные улики.

## Где пригодится

- **Cloud Security** — расследование в Kubernetes.
- **DFIR / Incident Response** — восстановление действий в контейнерах.
- **CTF Forensics** — задачи с образами и аудит-логами.
