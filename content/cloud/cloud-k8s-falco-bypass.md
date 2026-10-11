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

## Зачем этот урок

Falco — де-факто стандарт runtime-безопасности в Kubernetes. Он наблюдает системные вызовы (через eBPF или kernel module) и триггерит правила: запуск shell в контейнере, монтирование, чтение `/etc/shadow`, доступ к `/proc/*/root`, `nsenter`, изменение файлов бинарников. Для атакующего Falco — главный враг OPSEC при побеге: даже если Pod Security обойдён, Falco может заметить технику. Понимание его правил позволяет выбирать менее детектируемые пути и оценивать риск.

## Модель Falco

- **Драйвер**: eBPF probe или kernel module — перехватывает syscall.
- **Правила**: условие (на языке Falco) + output + priority. Примеры: `Terminal shell in container`, `Read sensitive file untrusted`, `Launch Privileged Container`.
- **Макросы/списки**: переиспользуемые условия (`spawned_process`, `container`, `sensitive_files`).
- **Exceptions**: исключения по полям (image, namespace, команда) — частая причина слепых зон.
- **Outputs**: stdout, syslog, gRPC → Falcosidekick → SIEM.
- **Слепые зоны**: правила по умолчанию, кастомизация, отключённые правила, отсутствие Falco на узле.

## Инструменты и команды

```bash
# Проверить, установлен ли Falco (DaemonSet)
kubectl get ds -A | grep falco
kubectl get pods -n falco

# Посмотреть правила и исключения
kubectl exec -n falco ds/falco -- falco --list 2>/dev/null | head -40
kubectl get cm -n falco falco-rules -o yaml 2>/dev/null | grep -A5 -i exception

# Логи Falco
kubectl logs -n falco ds/falco --tail=50 | grep -i warning

# Проверить, на каких узлах Falco есть
kubectl get ds falco -n falco -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}'
```

## Разобранный пример: что триггерит Falco

Сценарий: мы выполняем побег и хотим понять, что заметит Falco.

```bash
# Техника 1: shell в контейнере — правило "Terminal shell in container"
kubectl exec -it mypod -- /bin/sh
# Falco: Warning Terminal shell in container (user=root ... command=sh)

# Техника 2: чтение /etc/shadow — "Read sensitive file untrusted"
cat /etc/shadow
# Falco: Warning Read sensitive file untrusted (file=/etc/shadow)

# Техника 3: монтирование — "Mount operation"
mount -t tmpfs tmpfs /mnt
# Falco: Notice Mount operation

# Техника 4: nsenter в PID 1 — "Contact K8S API Server / PTRACE" (зависит от правил)
nsenter --target 1 --mount --pid -- bash
# Falco: возможно "PTRACE anti-debug" или "Process ran with ptrace"
```

Большинство «громких» техник побега покрыты стандартными правилами. Значит, для OPSEC нужно либо избегать их, либо использовать техники, которые Falco не детектирует по умолчанию.

## Менее детектируемые техники

- **Использование существующих привилегированных процессов.** Вместо запуска своего shell — заставить легитимный процесс (агент, оператор) выполнить действие.
- **Через API k8s.** Создание ресурса через API (например, Job) может выглядеть как нормальная деятельность, а не runtime-аномалия.
- **exec без shell.** Запуск бинарника напрямую (`kubectl exec -- /bin/cat /etc/shadow`) вместо интерактивного `sh` иногда не триггерит правило «shell in container», но чтение чувствительного файла всё равно может.
- **Файловые операции без mount.** Копирование через `/proc/<pid>/root` может не триггерить правило mount, но `ptrace`/`/proc/*/root` может иметь своё правило.
- **Облачные API вместо кластера.** Действия через cloud identity (IMDS) не видны Falco — только cloud audit logs.
- **Слепые узлы.** Если Falco не на всех узлах (например, `numberReady < desired`), запланируйте под на узел без Falco.

## Слепые зоны и исключения

- **Exceptions в правилах.** Админы добавляют исключения по namespace/image/команде, чтобы уменьшить шум. Проверяйте ConfigMap `falco-rules` на `exceptions`.
- **Отключённые правила.** Некоторые правила могут быть отключены (например, шумные). Список виден через `falco --list`.
- **Кастомные outputs.** Если Falco пишет только в stdout без Falcosidekick/SIEM, алерты могут не доходить.
- **Приоритеты.** Правила с низким priority могут не алертить.
- **eBPF vs module.** eBPF может пропускать некоторые события при определённых конфигурациях.
- **Falco сам как цель.** Если у вас есть доступ к namespace falco, можно изменить правила/исключения (шумно, но эффективно).

## Чек-лист OPSEC

1. Проверить наличие Falco на узлах (`get ds`).
2. Посмотреть список правил и исключений.
3. Определить, какие ваши техники детектируются.
4. Выбрать менее шумные пути (API вместо exec, cloud API вместо runtime).
5. Проверить, куда идут алерты (stdout/SIEM).
6. Проверить, есть ли узлы без Falco.
7. По возможности — не использовать интерактивный shell и чтение чувствительных файлов.

## Обход защит и edge cases

- **Namespace с исключением.** Если исключения покрывают определённый namespace, действуйте там.
- **Image в allowlist.** Исключения по image позволяют запускать определённые образы без алертов.
- **Rate limiting.** Массовые события могут «затопить» алерты (не рекомендуется, шумно).
- **Falco rules update.** Правила могут быть старыми; новые техники могут не детектироваться.
- **Kernel-модуль vs eBPF.** Разные покрытия syscall.

## Частые ошибки и подводные камни

- Считать, что Falco видит всё: смотрите исключения и отключённые правила.
- Игнорировать, куда идут алерты: без SIEM они могут быть незамеченными.
- Использовать интерактивный shell там, где можно обойтись API.
- Забыть проверить узлы без Falco.
- Не учитывать cloud audit logs как отдельный слой детекта.

## Защита и детект (для защитника)

- Держать Falco на всех узлах; актуальные правила.
- Минимизировать исключения; ревьюить их.
- Отправлять алерты в SIEM (Falcosidekick) с высоким priority.
- Добавлять кастомные правила под ваши техники угроз.
- Коррелировать runtime-алерты с cloud audit logs.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — Falco не на всех узлах. Второй — широкие исключения. Третий — алерты только в stdout. Четвёртый — отключённые шумные правила. Пятый — старые правила. Все они создают слепые зоны.

## Практическое задание

1. Установите Falco и проверьте срабатывание на shell в контейнере.
2. Посмотрите ConfigMap с правилами и найдите исключения.
3. Добавьте исключение для namespace и убедитесь, что алерт пропал.
4. Настройте Falcosidekick и проверьте доставку в SIEM.

## Что дальше / решение

Falco — ключевой слой runtime-детекта. Оцените его покрытие, выберите менее шумные техники, учитывайте cloud audit logs. Зафиксируйте слепые зоны в графе. Помните: побег через API или cloud identity детектируется другими средствами (audit), поэтому OPSEC — это про весь стек, а не только Falco.

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

Вывод: самые «тихие» пути — через API (создание ресурсов, изменение spec) и через облачные API, а не через runtime-манипуляции. Но эти пути детектируются другими слоями (k8s audit, cloud audit). Настоящая OPSEC — понимать весь стек детекта и выбирать путь, который оставляет минимум согласованных следов.

## Квиз

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
```

## Где пригодится

- **Red team:** OPSEC против runtime-детекта.
- **Blue team:** настройка Falco.
- **Пентест k8s:** оценка мониторинга.
- **Сертификация:** CKS.
