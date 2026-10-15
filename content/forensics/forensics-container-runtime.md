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

## Анатомия контейнера: слои, записываемый слой, runtime

Контейнер — это не «маленькая ВМ», а **процесс** в изоляции (namespaces + cgroups) на
общем ядре. Его файловая система — стек слоёв:

- **слои образа** — только для чтения, каждый слой diff предыдущего;
- **записываемый слой** (upperdir) — изменения во время работы; при пересоздании контейнера
  **исчезает**;
- **тома** (volumes) — постоянные данные вне слоя, переживают пересоздание.

В облаке оркестратор (Kubernetes/EKS/GKE/AKS) запускает контейнеры на узлах; в
serverless-варианте (Fargate/Cloud Run) узла не видно вообще — только логи и API.

Отсюда ключевое правило: **снимай улики, пока контейнер жив** — записываемый слой
эфемерен.

## Практика: анализ образа и слоёв

**1. Скачать образ и посмотреть слои:**

```
$ docker pull registry.example.com/app:1.2.3
$ docker history --no-trunc registry.example.com/app:1.2.3
IMAGE          CREATED        CREATED BY                          SIZE
sha256:aaa...  2 days ago     /bin/sh -c #(nop) COPY app /app     10MB
sha256:bbb...  2 days ago     /bin/sh -c COPY malicious.sh /...   1kB
```

Внедрённый код в слое **останется** в образе, даже если контейнер пересоздан. Слой можно
распаковать и изучить:

```
$ docker save registry.example.com/app:1.2.3 -o app.tar
$ tar xf app.tar && ls
blobs  index.json  manifest.json
```

**2. Живой контейнер (пока жив):**

```
$ docker cp <container>:/etc/passwd /evidence/passwd
$ docker exec <container> sh -c 'ps aux; cat /proc/1/environ' > /evidence/proc.txt
$ docker diff <container>          # что изменено относительно образа
```

`docker diff` показывает изменённые/добавленные файлы в записываемом слое — это и есть
«что делал процесс внутри».

## Kubernetes audit log: главный источник

Аудит-лог Kubernetes фиксирует каждый API-запрос: кто, что, откуда.

```
{"verb":"create","objectRef":{"resource":"pods","name":"worker-7f8d"},
 "user":{"username":"system:serviceaccount:default:ci"},"sourceIPs":["10.0.0.7"]}
{"verb":"exec","objectRef":{"resource":"pods","name":"worker-7f8d"},
 "user":{"username":"admin"},"requestURI":"/exec?command=sh&stdin=true"}
```

Из записи видно: под создан сервисным аккаунтом `ci`, а затем `admin` делал `exec sh` —
получил shell внутри контейнера. Аномалии: `exec`/`attach` в рутинное время, создание
привилегированных подов, монтирование `hostPath`, доступ к `kube-system`.

## Runtime-логи узла

На узле работает runtime (containerd/dockerd) и `kubelet`:

```
$ journalctl -u kubelet | grep worker-7f8d
Started container worker-7f8d
Killing container worker-7f8d (OOMKilled)
```

По ним видно **когда** под жил и **как** завершился. Плюс runtime-security (Falco) пишет
события: запуск shell, запись в `/etc`, обращения к metadata — отдельный поток улик.

## Ограничения

- **Эфемерность** — записываемый слой исчезает при пересоздании; нужен снимок «пока жив».
- **Общее ядро** — следы разных подов могут смешиваться; изоляция не абсолютна.
- **Serverless** — узла нет; доступны только логи и API-аудит.
- **Тома переживают под** — данные в PV остаются; их надо проверять отдельно.
- **Аудит может быть выключен** — тогда `exec` и создание подов не видны (само по себе
  подозрительно).
- **Образ мог быть перезаписан** — тег `latest` мог измениться; фиксируй **digest**.

## Практический чеклист

1. Снять улики **пока контейнер жив** (`docker cp`, `docker diff`, `exec`).
2. `docker history --no-trunc` — внедрённый код в слоях.
3. `docker save` — сохранить образ с фиксацией **digest**.
4. Kubernetes audit log — `create`/`exec`/`attach`/`hostPath`.
5. `journalctl -u kubelet` — жизненный цикл пода.
6. Runtime-security (Falco) — подозрительное поведение.
7. Проверить persistent volumes — данные переживают под.

## Сценарий: под исчез, но следы остались

**1. Констатация.** Пода `worker-7f8d` больше нет:

```
$ kubectl get pods -n default
NAME       READY   STATUS    RESTARTS   AGE
api-1      1/1     Running   0          5d
```

**2. Аудит-лог Kubernetes** показывает жизненный путь пода:

```
{"verb":"create","objectRef":{"resource":"pods","name":"worker-7f8d"},
 "user":{"username":"system:serviceaccount:default:ci"},"sourceIPs":["10.0.0.7"]}
{"verb":"exec","objectRef":{"resource":"pods","name":"worker-7f8d"},
 "user":{"username":"admin"},"requestURI":"/exec?command=sh&stdin=true"}
{"verb":"delete","objectRef":{"resource":"pods","name":"worker-7f8d"}}
```

Читается однозначно: сервисный аккаунт `ci` создал под, кто-то (с правами admin) вошёл
через `exec sh`, затем под удалили. Всё это — до того, как под исчез.

**3. Логи узла** подтверждают время и причину завершения:

```
$ journalctl -u kubelet | grep worker-7f8d
Started container worker-7f8d
Killing container worker-7f8d
```

**4. Образ** — если код внедрили в образ, он в слое:

```
$ docker history --no-trunc registry.example.com/worker:1.2.3 | grep -i copy
```

**5. Вывод.** Даже без живого пода восстановлены: кто создал, как вошёл, когда удалили,
что было в образе. Действия: отозвать сервисный аккаунт `ci`, проверить его права,
проверить узел (не скомпрометирован ли kubelet), проверить persistent volumes.

## Service accounts и RBAC как вектор

Сервисный аккаунт `ci` с широкими правами — частая причина компрометации: его токен лежит
в поде и легко извлекается. В аудите ищи:

- создание подов от сервисных аккаунтов, которым это «не положено»;
- `exec`/`attach` в поды другими пользователями;
- создание `ClusterRoleBinding` с `cluster-admin`;
- монтирование `hostPath` (доступ к узлу);
- чтение секретов (`get secrets`).

## Ограничения

- **Эфемерность** — записываемый слой исчез вместе с подом; снимать надо «пока жив».
- **Общее ядро** — следы подов смешиваются.
- **Serverless** — узла нет; только логи и API-аудит.
- **Аудит может быть выключен** — `exec`/`create` не видны.
- **Тег `latest`** — образ мог измениться; фиксируй **digest**.
- **Тома** — данные в PV переживают под; проверяй отдельно.

## Практический чеклист

1. Снять улики **пока контейнер жив** (`docker cp`, `diff`, `exec`).
2. `docker history --no-trunc` — внедрённый код в слоях.
3. `docker save` — образ с фиксацией **digest**.
4. Kubernetes audit log — `create`/`exec`/`attach`/`hostPath`.
5. `journalctl -u kubelet` — жизненный цикл.
6. Проверить RBAC и сервисные аккаунты.
7. Проверить persistent volumes и узел.

## Сводка: где живут улики контейнера

| Улика | Источник | Переживает под? |
|-------|----------|-----------------|
| Записываемый слой | `docker diff` | **нет** |
| Образ и слои | `docker history`/`save` | да |
| Аудит Kubernetes | audit log | да (если включён) |
| Жизненный цикл | `journalctl -u kubelet` | да (пока логи есть) |
| Runtime-события | Falco | да |
| Данные | persistent volume | да |

Главный вывод: **слой эфемерен** — снимай его первым, пока под жив; образ, аудит и тома
живут дольше и дают контекст.

## Один вывод

Контейнер эфемерен, но не бесследен: аудит Kubernetes, логи kubelet, слои образа и
persistent volumes вместе восстанавливают то, что происходило внутри пода. Ключ — начать
сохранение улик **до** пересоздания контейнера.

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
