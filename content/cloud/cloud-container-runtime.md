---
id: cloud-container-runtime
title: "Рантаймы контейнеров: runc/containerd/CRI-O и CVEs побега"
category: cloud
parent: cloud-containers-docker
difficulty: hard
order: 4
tags: [cloud, runc, containerd, cri-o, cve, escape, container-runtime]
prerequisites: [cloud-containers-docker, cloud-kubernetes-escape]
useful_for:
  - "Эксплуатация уязвимостей рантаймов контейнеров"
  - "Понимание архитектуры containerd/CRI-O"
  - "Оценка патч-уровня кластеров"
estimated_minutes: 40
summary: "Архитектура контейнерных рантаймов (Docker/containerd/CRI-O/runc) и классы уязвимостей побега: runc CVEs, монтирования, cgroups. Как определить версии и на что ориентироваться."
---
## Зачем этот урок

Рантайм (runc, containerd, CRI-O) — то, что реально создаёт контейнер. Уязвимости в нём позволяют вырваться наружу даже без мисконфигураций. Разберём стек, определение версий, известные классы уязвимостей и знаменитый CVE-2024-21626.

## Стек рантаймов

Docker/containerd → containerd-shim → runc (OCI runtime) → процесс. Kubernetes общается с CRI (containerd/CRI-O). Уязвимость в runc затрагивает всех, кто его использует; в containerd — тех, кто через него.

## Определение версий

```bash
runc --version
containerd --version
crictl version
docker version --format '{{.Server.Version}}'
cat /proc/self/status | grep Seccomp
# изнутри контейнера
cat /etc/os-release
ls -la /proc/1/exe
```

Версия runc в образе может отличаться от версии на ноде — проверяйте оба.

## Известные классы уязвимостей

- **CVE-2019-5736** — runc overwrite, побег при `exec` в контейнер.
- **CVE-2022-0492** — cgroup v1 release_agent.
- **CVE-2024-21626** — runc file descriptor leak (`/proc/self/fd`).
- **CVE-2022-29162** — runc capabilities.
- **containerd CVE-2020-15257** — abstract socket namespace.

## Разобранный пример: CVE-2024-21626 (runc fd leak)

Уязвимость позволяла процессу с `runc init` получить доступ к хостовой ФС через leaked fd. Проверка уязвимости:

```bash
runc --version
# runc version 1.1.11 → уязвим (исправлено в 1.1.12)
ls -la /proc/self/fd | head
```

Если версия уязвима и вы контролируете образ (например, через `docker build` или CI), можно создать Dockerfile, который при запуске обращается к `/proc/self/fd/<n>` и монтирует хост. Точный эксплойт зависит от окружения — важно определить версию и наличие `WORKDIR`-трюка.

## containerd и CRI-O

containerd хранит образы и контейнеры; CRI-O — альтернатива для K8s. Проверяйте:
```bash
crictl info | jq '.config'
ctr version
crictl ps -a --no-trunc
```
Ошибки конфигурации: небезопасный `insecure_registry`, отсутствие seccomp по умолчанию.

## Образы и registry

- **Образ с setuid/привилегированным бинарём** — усиливает побег.
- **Небезопасные registry** (`insecure: true`) — MITM и подмена образа.
- **Теги вместо digest** — mutable, подмена.
- **Supply chain**: зависимость в образе с RCE.

```bash
docker pull myimage:latest
docker inspect myimage:latest | jq '.[].RepoDigests'
trivy image myimage:latest
```

## Защита

- Обновляйте runc/containerd (патчи против 21626 и др.).
- Используйте digest, а не теги.
- Seccomp-профиль по умолчанию, AppArmor/SELinux.
- User namespaces (rootless) для изоляции.
- Runtime-мониторинг (Falco) и сканирование образов (trivy).

## Частые ошибки

- Считать, что обновлён только нода — образ может нести свой runc.
- Игнорировать версию containerd.
- Использовать `:latest` в продакшене.
- Не проверять seccomp-профиль.
- Полагаться только на конфигурацию, забывая про CVE.

## Что дальше / решение

Определите точные версии runc/containerd и сопоставьте с известными CVE. Для подтверждения уязвимости — PoC в изолированном стенде. Для защиты — патчинг, rootless, runtime-мониторинг.

## Rootless и user namespaces

Rootless-режим запускает демон от непривилегированного пользователя, используя user namespaces. Это снижает риск побега, но не убирает его полностью: уязвимости в userns или setuid-бинарники всё ещё опасны. Проверка:

```bash
docker info | grep -i rootless
cat /proc/sys/user/max_user_namespaces
unshare --user --map-root-user id
```

## Разобранный пример: детект версии и CVE

```bash
runc --version
# runc version 1.1.11
# spec: 1.0.2-dev
# go: go1.21.4
# CVE-2024-21626 fixed in 1.1.12 → уязвимо
containerd --version
# containerd github.com/containerd/containerd v1.7.11
```

Сопоставляем с базой (GitHub advisories, `cve-bin-tool`). Для подтверждения — PoC в изолированном стенде.

## Инструменты сканирования

```bash
trivy image --severity CRITICAL,HIGH myimage:latest
grype myimage:latest
docker-bench-security
cve-bin-tool --offline mybinary
syft myimage:latest -o json > sbom.json
```

`trivy image` флаги: `--severity`, `--scanners vuln,misconfig,secret`, `-f json`. `syft` строит SBOM — база для поиска уязвимых зависимостей.

## Таблица ключевых CVE

| CVE | Компонент | Суть | Фикс |
|-----|-----------|------|------|
| 2019-5736 | runc | перезапись runc при exec | 1.0-rc6+ |
| 2022-0492 | ядро/cgroup | release_agent | патч ядра |
| 2024-21626 | runc | утечка fd | 1.1.12 |
| 2020-15257 | containerd | abstract socket | 1.4.3 |
| 2024-24789 | containerd | digest обход | 1.7.13 |

## Что проверять в первую очередь

1. Версия runc/containerd на ноде.
2. Наличие user namespaces и rootless.
3. Seccomp-профиль (по умолчанию или unconfined).
4. Registry: digest vs тег, insecure.
5. Образ: setuid-бинарники, старые зависимости.

## Практическое задание

На тестовой ноде соберите версии `runc`, `containerd`, `crictl`, сопоставьте с известными CVE (используйте `cve-bin-tool` и GitHub advisories). Для уязвимой версии найдите публичный PoC, ИЗУЧИТЕ его код (что он делает, куда стучится, не разрушителен ли), и проверьте на изолированном стенде. Оцените, какие ещё компоненты стека могут быть уязвимы, и составьте план патчинга. Это отрабатывает навык version-diff: фикс-релиз указывает прямо на уязвимость.

## Rootless и user namespaces: что это даёт атакующему

Rootless снижает последствия побега: процесс внутри userns не имеет прав на хосте напрямую. Но если в образе есть setuid-бинарник или уязвимость в ядре (например, в userns-обработке), побег всё равно возможен. Проверяйте `docker info | grep -i rootless`, `cat /proc/sys/user/max_user_namespaces` и наличие `newuidmap`/`newgidmap`. Если userns отключён (`max_user_namespaces=0`), rootless не работает вовсе.

## Составление плана патчинга

Определив уязвимые версии, сопоставьте их с доступными обновлениями. Для runc/containerd — обновление пакетов ноды; для образов — пересборка с новыми базовыми слоями; для ядра — патч и перезагрузка. Ведите таблицу: компонент, текущая версия, целевая версия, CVE, риск. Это тот же процесс, что и для любой инфраструктуры, но с учётом эфемерности контейнеров: образы нужно пересобирать и перезапускать, иначе фикс не применится.

## Где искать версии в реальном кластере

Версия runc на ноде не видна из пода. Чтобы её узнать, нужен доступ к ноде (через побег или node-debug). Из пода можно оценить стек косвенно: `/proc/1/cgroup`, наличие `/run/containerd/containerd.sock`, версия ядра (`uname -r`). Версия ядра важна: некоторые CVE (например, cgroup) зависят от неё. Составьте таблицу «нода → runc → containerd → ядро» и сопоставьте с CVE. Это стандартный шаг при оценке кластера на уязвимости рантайма.

## Версии и патч-уровень в кластере

Определение точных версий — первый шаг оценки рантайма. Помимо `runc --version` на ноде, проверьте версию, встроенную в образы (там может быть свой runc/containerd). Сопоставьте с advisory и определите приоритет патчинга. Помните, что обновление ноды не обновляет образы: их нужно пересобирать. Ведите таблицу «компонент → версия → CVE → фикс → статус», чтобы не потерять трек.

## Сводка по уязвимостям рантайма

| CVE | Компонент | Условие эксплуатации |
|-----|-----------|----------------------|
| 2019-5736 | runc | exec в контейнер |
| 2022-0492 | ядро/cgroup v1 | release_agent |
| 2024-21626 | runc | fd leak, свой образ |
| 2020-15257 | containerd | abstract socket |
| 2024-24789 | containerd | digest обход |

Определите версии, сопоставьте с таблицей и выберите достижимый вектор. Начинайте с самых простых в проверке.

## Квиз

```quiz
- question: "Какой компонент является низкоуровневым OCI-рантаймом, создающим namespace контейнера?"
  options:
    - "kubelet"
    - "runc"
    - "kubectl"
    - "etcd"
  answer: 1
  explanation: "runc реализует OCI runtime spec и создаёт namespace/cgroups."
- question: "Как определить версию контейнерного рантайма узла в кластере?"
  options:
    - "kubectl get nodes -o jsonpath containerRuntimeVersion"
    - "route -n"
    - "ps aux"
    - "cat /etc/hostname"
  answer: 0
  explanation: "nodeInfo.containerRuntimeVersion содержит версию рантайма."
- question: "К какому классу относится CVE-2021-30465 в runc?"
  options:
    - "SQL-инъекция"
    - "symlink-race при монтировании, ведущий к доступу к хосту"
    - "XSS"
    - "переполнение буфера в браузере"
  answer: 1
  explanation: "CVE-2021-30465 — symlink race в монтированиях runc."
- question: "Почему containerd/CRI-O unix-socket важны для атакующего?"
  options:
    - "Они шифруют трафик"
    - "Через них можно управлять контейнерами на хосте, как через docker.sock"
    - "Они только для чтения"
    - "Они не существуют"
  answer: 1
  explanation: "Это управляющие сокеты рантайма — доступ к ним равен контролю над контейнерами."
- question: "Что снижает риск побега через рантайм?"
  options:
    - "Больше capabilities"
    - "Обновление рантайма и изолированные рантаймы (gVisor/Kata)"
    - "Монтирование docker.sock"
    - "privileged: true"
  answer: 1
  explanation: "Патчи и sandbox-рантаймы уменьшают поверхность атаки рантайма."
```

## Где пригодится

- **Пентест Kubernetes** — оценка патч-уровня.
- **Red team** — побег через уязвимость движка.
- **IR/Blue team** — приоритизация обновлений.
- **DevSecOps** — управление версиями рантаймов.
- **CTF** — задачи на container escape.
