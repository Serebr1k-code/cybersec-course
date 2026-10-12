---
id: cloud-k8s-falco-bypass
title: "Обход Falco: правила runtime-детекта и слепые зоны"
category: cloud
parent: cloud-k8s-security-deep
difficulty: expert
order: 4
tags: [cloud, kubernetes, falco, runtime, detection, evasion, syscall]
prerequisites: [cloud-k8s-security-deep, cloud-logging-detection]
useful_for:
  - "Обход runtime-детекта Kubernetes"
  - "Понимание Falco для OPSEC"
  - "Пентест кластеров с мониторингом"
estimated_minutes: 50
summary: "Falco: правила, драйверы (eBPF/kernel module), макросы и исключения. Какие техники побега детектируются, как снизить шум и где остаются слепые зоны runtime-мониторинга."
---

## Задача

Ты уже получил выполнение в поде Kubernetes и хочешь выйти за его пределы. Но в кластере работает **Falco** — система runtime-безопасности, которая следит за системными вызовами. Как понять, заметят ли твой побег, и выбрать путь, который оставит меньше следов? Задача урока — разобрать модель Falco, увидеть, какие техники детектируются, и найти слепые зоны.

## Что такое Falco

**Falco** — де-факто стандарт runtime-детекта в Kubernetes. Он перехватывает **системные вызовы** (syscall) через **eBPF** (программу в ядре) или kernel module и проверяет их по **правилам**. Правило — это условие (на языке Falco) плюс описание и приоритет. Пример: правило «Terminal shell in container» срабатывает, когда в контейнере запускается интерактивный shell.

Компоненты:

- **Драйвер** — eBPF probe или kernel module; перехватывает syscall.
- **Правила** — условие + output + priority.
- **Макросы/списки** — переиспользуемые условия (`spawned_process`, `sensitive_files`).
- **Exceptions** — исключения по полям (image, namespace, команда) — частая причина слепых зон.
- **Outputs** — stdout, syslog, gRPC → Falcosidekick → SIEM.

## Данные, с которыми работаем

Прежде чем что-то делать, разведай покрытие Falco:

```bash
$ kubectl get ds -A | grep falco
falco      falco      2         2     2    ...
$ kubectl get ds falco -n falco -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}'
2/2
```

Falco работает на обоих узлах. Смотрим список правил и исключений:

```bash
$ kubectl exec -n falco ds/falco -- falco --list 2>/dev/null | head -6
Terminal shell in container
Read sensitive file untrusted
Mount operation
Write below binary dir
Launch Privileged Container
```

## Шаг 1: смотрим, что триггерит Falco

Выполняем «громкие» техники и наблюдаем логи:

```bash
$ kubectl exec -it mypod -- /bin/sh
# Falco: Warning Terminal shell in container (user=root command=sh)

$ kubectl exec mypod -- cat /etc/shadow
# Falco: Warning Read sensitive file untrusted (file=/etc/shadow)

$ kubectl exec mypod -- mount -t tmpfs tmpfs /mnt
# Falco: Notice Mount operation

$ kubectl exec mypod -- nsenter --target 1 --mount --pid -- bash
# Falco: Warning Process ran with ptrace / shell in container
```

Вывод: почти все классические техники побега покрыты стандартными правилами. Значит, для OPSEC нужно либо избегать их, либо искать слепые зоны.

## Шаг 2: ищем исключения

Админы добавляют исключения, чтобы уменьшить шум. Это и есть слепые зоны:

```bash
$ kubectl get cm -n falco falco-rules -o yaml | grep -A5 -i exception
exceptions:
  - name: allowed_namespaces
    fields: [k8s.ns.name]
    comps: [in]
    values: [[monitoring, logging]]
```

Если твой под живёт в `monitoring` или `logging` — правила для него не сработают. Ищи namespace из исключений.

## Шаг 3: выбираем тихие пути

Самые «шумные» техники — интерактивный shell, чтение `/etc/shadow`, `mount`, `nsenter`. Менее заметные:

- **Действия через API Kubernetes.** Создание Job или изменение spec выглядит как нормальная деятельность, а не runtime-аномалия.
- **exec без shell.** `kubectl exec -- /bin/cat /etc/shadow` иногда не триггерит «shell in container», хотя чтение файла — триггерит.
- **Облачные API (IMDS).** Действия через облачную идентичность Falco не видит вообще — только cloud audit logs.
- **Существующие привилегированные процессы.** Заставить легитимный агент выполнить действие вместо запуска своего.
- **Узел без Falco.** Если `numberReady < desired`, запланируй под на узел без агента.

## Полный прогон от начала до конца

1. `kubectl get ds -A` → Falco на 2/2 узлах.
2. `falco --list` → какие правила активны.
3. Проверяем техники → shell, `/etc/shadow`, `mount` детектируются.
4. `cm falco-rules` → исключения по namespace `monitoring`.
5. Действуем через k8s API (Job) или облачный API — тише для Falco.

## Если не сработало

- **Falco на всех узлах.** Тогда слепых узлов нет — ищи исключения или работай через API.
- **Алерты в SIEM.** Если Falco пишет в SIEM через Falcosidekick, «тихие» события всё равно всплывут при корреляции.
- **Кастомные правила.** Админ мог добавить правила под твои техники — проверь ConfigMap полностью.
- **eBPF vs module.** Разное покрытие syscall; eBPF может пропускать часть событий.
- **Falco как цель.** Если у тебя есть доступ в namespace `falco`, можно править правила — но это очень шумно и, вероятно, уже заметно.

## Сравнение техник и детекта

Полезно держать таблицу «техника → детектируется ли Falco по умолчанию».

| Техника | Стандартное правило Falco | Шумность |
|---|---|---|
| Интерактивный shell в контейнере | Terminal shell in container | Высокая |
| Чтение /etc/shadow | Read sensitive file untrusted | Высокая |
| mount | Mount operation | Средняя |
| nsenter в PID 1 | Process ran with ptrace / shell | Высокая |
| Запись в бинарник | Write below binary dir | Высокая |
| Создание привилегированного пода через API | Launch Privileged Container | Средняя |
| Действия через облачный API (IMDS) | Нет (только cloud audit) | Низкая для Falco |
| Создание Job через k8s API | Может не триггерить runtime-правило | Средняя |

Вывод: самые «тихие» пути — через API и облачные API, а не через runtime-манипуляции. Но эти пути детектируются другими слоями (k8s audit, cloud audit). Настоящая OPSEC — понимать весь стек детекта и выбирать путь с минимумом согласованных следов.

## Что мы теперь знаем

- Falco перехватывает syscall и триггерит правила на «громкие» техники побега.
- Исключения (по namespace/image/команде) создают слепые зоны.
- Действия через k8s API и облачный API Falco не видит — но видят другие слои (k8s audit, cloud audit).
- Отсутствие Falco на узле — прямой путь обхода.
- OPSEC — это весь стек детекта, а не только Falco.

## На что смотреть дальше

- **cloud-k8s-pod-security**: уровни Pod Security и обход restricted.
- **cloud-runc-escape-deep**: техники побега через runc.
- **cloud-logging-detection**: слои детекта в облаке.

## Квиз

Проверь себя.

```quiz
- question: "Что перехватывает Falco?"
  options:
    - "Системные вызовы через eBPF/kernel module"
    - "Только сетевой трафик"
    - "Только логи kubelet"
    - "Только IAM"
  answer: 0
  explanation: "Falco наблюдает syscall для runtime-детекта."
- question: "Что часто создаёт слепые зоны в Falco?"
  options:
    - "Широкие исключения (exceptions) в правилах"
    - "Мало памяти"
    - "Много подов"
    - "Тип диска"
  answer: 0
  explanation: "Исключения по namespace/image/команде могут скрывать технику."
- question: "Какая техника побега наименее шумна для Falco?"
  options:
    - "Действия через облачный API (IMDS) вместо runtime-манипуляций"
    - "Интерактивный shell"
    - "Чтение /etc/shadow"
    - "mount"
  answer: 0
  explanation: "Cloud API не виден Falco, но виден cloud audit logs."
- question: "Куда Falco обычно отправляет алерты?"
  options:
    - "stdout/syslog/gRPC (Falcosidekick → SIEM)"
    - "В KMS"
    - "В Route 53"
    - "В NSG"
  answer: 0
  explanation: "Falco выводит события в stdout/syslog/gRPC."
- question: "Почему «тихие» для Falco пути не гарантируют невидимость?"
  options:
    - "Их детектируют другие слои — k8s audit и cloud audit logs"
    - "Falco видит всё"
    - "Они оставляют файлы"
    - "Они требуют root"
  answer: 0
  explanation: "OPSEC требует учитывать весь стек детекта, а не только Falco."
```

## Куда дальше

В следующем уроке мы разберём **побег из контейнера через runc** — конкретные CVE и `nsenter`. А пока главное запомни: **Falco детектирует «громкие» runtime-техники, поэтому тише всего — действовать через API, но помни, что у детекта несколько слоёв.**

## Где пригодится

- **Red team:** OPSEC против runtime-детекта.
- **Blue team:** настройка Falco.
- **Пентест k8s:** оценка мониторинга.
- **Сертификация:** CKS.
