---
id: cloud-k8s-pod-security
title: "Pod Security Admission: уровни, labels и обход restricted"
category: cloud
parent: cloud-k8s-security-deep
difficulty: hard
order: 2
tags: [cloud, kubernetes, pod-security, psa, pss, admission, restricted, baseline]
prerequisites: [cloud-k8s-security-deep, cloud-kubernetes-rbac]
useful_for:
  - "Обход Pod Security Admission"
  - "Пентест кластеров с PSA"
  - "Понимание ограничений подов"
estimated_minutes: 45
summary: "Pod Security Admission: уровни privileged/baseline/restricted, режимы enforce/audit/warn, labels namespace и version-pinned. Как читать политику и находить обходы."
---

## Задача

В кластере Kubernetes включён **Pod Security Admission (PSA)** — встроенный контроллер, который запрещает опасные поды. Ты хочешь запустить привилегированный под, чтобы выйти на узел, но получаешь ошибку `violates PodSecurity`. Как это обойти? Задача урока — понять модель PSA и найти слабое место — чаще всего не в самой политике, а в конфигурации namespace.

## Что такое PSA

**PSA** пришёл на смену PodSecurityPolicy и применяет **Pod Security Standards (PSS)** к namespace по меткам. Это «стена», которая может запретить привилегированные поды, `hostPath`, `hostPID` и опасные capabilities.

Уровни:

- `privileged` — без ограничений.
- `baseline` — запрещает самые опасные поля, но разрешает, например, `hostNetwork`.
- `restricted` — `baseline` плюс жёсткие требования к `securityContext`.

Режимы:

- `enforce` — **отклоняет** нарушающие поды.
- `audit` — пишет в audit log.
- `warn` — предупреждение пользователю.

Уровень задаётся метками на namespace: `pod-security.kubernetes.io/enforce`, `.../audit`, `.../warn`, и версией `.../enforce-version`. Ключевое: **PSA действует на namespace, а не на отдельный под.** Если namespace без метки (или с `privileged`), ограничений нет.

## Данные, с которыми работаем

Инвентаризация меток:

```bash
$ kubectl get ns --show-labels | grep pod-security
prod   ...   pod-security.kubernetes.io/enforce=restricted
```

`prod` защищён уровнем `restricted`. Но важно проверить все namespace, а не только очевидные:

```bash
$ kubectl get ns -o json | jq -r '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'
kube-system
monitoring
legacy-apps
```

Три namespace **без метки** — значит, ограничений там нет.

## Шаг 1: проверяем права и запускаем привилегированный под

```bash
$ kubectl auth can-i create pods -n legacy-apps
yes
```

Есть право. Пробуем то, что запрещено в `prod`:

```bash
$ cat <<'EOF' | kubectl apply -n legacy-apps -f -
apiVersion: v1
kind: Pod
metadata: { name: escape }
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: c
    image: alpine
    securityContext: { privileged: true }
    command: ["sleep","infinity"]
EOF
pod/escape created
```

Под создан. Теперь из него видно процессы узла (`hostPID`) и его сеть (`hostNetwork`) — путь к побегу.

## Шаг 2: если namespace защищён — ищем другие рычаги

Проверяем, нет ли права менять саму метку:

```bash
$ kubectl auth can-i update ns/prod
yes
$ kubectl label ns prod pod-security.kubernetes.io/enforce=privileged --overwrite
namespace/prod labeled
```

Ослабили политику — теперь под проходит. Это недооценённое право: `update` на namespace сводит PSA на нет.

## Шаг 3: version pinning и baseline

Версия стандарта влияет на запреты: `enforce-version: v1.24` может разрешать то, что запрещено в `v1.29`.

```bash
$ kubectl get ns prod -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce-version}'
v1.24
```

А уровень `baseline` разрешает `hostNetwork`/`hostPort` — уже доступ к сети хоста и перехват трафика. Проверяй и уровень, и версию: часто хотя бы один namespace окажется на `baseline` или без метки.

## Полный прогон от начала до конца

1. `kubectl get ns --show-labels` → у `prod` `restricted`.
2. Ищем namespace без метки → `legacy-apps`.
3. `auth can-i create pods -n legacy-apps` → yes.
4. Применяем привилегированный под → создан.
5. Из пода — `hostPID`/`hostNetwork` → побег на узел.

## Если не сработало

- **Все namespace помечены.** Тогда проверь права `update` на namespace, версию стандарта и default-уровень кластера.
- **CRD/агрегированные API.** Некоторые CRD создают поды в обход PSA — проверь установленные операторы.
- **Ephemeral containers.** `kubectl debug` добавляет эфемерные контейнеры; старые версии PSA их не проверяют.
- **Привилегированный контроллер.** Если DaemonSet/оператор уже привилегированный — измени его spec и переиспользуй.
- **kube-system.** Часто `privileged`; при доступе — прямая лазейка.
- **Static pods.** Kubelet создаёт их в обход admission.

## Version pinning и baseline подробнее

Версия стандарта влияет на то, что разрешено: `enforce-version: v1.24` может разрешать поля, запрещённые в `v1.29`. Смотрим версию и проверяем, что разрешает текущий уровень:

```bash
$ kubectl get ns prod -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce-version}'
v1.24
$ kubectl label ns test pod-security.kubernetes.io/enforce=baseline --overwrite
namespace/test labeled
$ kubectl apply -n test -f hostnet-pod.yaml   # под с hostNetwork: true
pod/hostnet created
```

`baseline` допускает `hostNetwork`/`hostPort` — это уже доступ к сети хоста и потенциальный перехват трафика. Для атакующего вывод: проверяй и уровень, и версию, и default-уровень кластера; часто хотя бы один namespace окажется на `baseline` или без метки.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — namespace без метки. Второй — `privileged` в kube-system, куда есть доступ. Третий — право `update` на namespace у непривилегированной роли. Четвёртый — version pinning на старую версию. Пятый — CRD или оператор, создающий поды в обход PSA. Каждый из них позволяет получить привилегированный под, а оттуда — побег на узел. Для защитника вывод: помечай **все** namespace (включая kube-system) уровнем не ниже `baseline`, а `prod` — `restricted`, и запрети менять метки непривилегированным ролям. Дополнительно используй Kyverno/OPA для политик, которые PSA не покрывает (например, запрет конкретных образов или registry).

## Объекты, обходящие PSA

PSA применяется к Pod и контроллерам (Deployment, Job, StatefulSet), но не покрывает всё. **Статические поды** kubelet создаёт в обход admission. **Агрегированные API и CRD** некоторых операторов создают поды напрямую. **Ephemeral-контейнеры** (`kubectl debug`) добавляются к существующему поду, и старые версии PSA их не проверяют. **Init-контейнеры** проверяются, но их конфигурация может отличаться. Проверяя кластер, посмотри, какие операторы и CRD установлены, — среди них часто находится обход.

## Что мы теперь знаем

- PSA действует на namespace по меткам, а не на отдельный под.
- Режимы: `enforce` блокирует, `audit`/`warn` — нет.
- Namespace без метки = нет ограничений — самый простой обход.
- Право `update` на namespace позволяет снять/ослабить политику.
- Version pinning на старую версию оставляет известные послабления.
- CRD, статические поды и эфемерные контейнеры могут обходить PSA.

## На что смотреть дальше

- **cloud-runc-escape-deep**: что делать с привилегированным подом дальше.
- **cloud-k8s-falco-bypass**: runtime-детект, который сработает на побеге.
- **cloud-kubernetes-rbac**: как получить право `update` на namespace.

## Глазами защитника

Pod Security Admission (PSA) применяют на уровне namespace через метку `pod-security.kubernetes.io/enforce`. Уровни: privileged, baseline, restricted. Baseline запрещает privileged и hostPath; restricted добавляет требования к пользователю, capabilities и seccomp. Обход — namespace без метки, ресурсы, обходящие PSA (CronJob, старые API), и версии, где политика не enforced. Аудит: все namespace помечены, режим `enforce`, а не только `warn` или `audit`.

## Частые вопросы

**Что такое PSA?**

Встроенный admission-контроллер, применяющий Pod Security Standards по метке namespace. Заменяет устаревший PSP.

**Чем baseline отличается от restricted?**

Baseline запрещает опасные настройки (privileged, hostPath); restricted дополнительно требует non-root, отсутствие лишних capabilities и seccomp.

**Как обойти PSA?**

Через namespace без метки (по умолчанию privileged), через `ephemeralContainers`, через ресурсы, которые PSA не проверяет.

**Почему `warn` недостаточно?**

`warn` и `audit` не блокируют под, только логируют. Без `enforce` политика не мешает атаке.

**Что такое version pinning?**

Метка версии PSA (`v1.25`), определяющая набор правил. Устаревшая версия может пропускать новые проверки.

**Как проверить уровень namespace?**

`kubectl get ns --show-labels` — ищи `pod-security.kubernetes.io/enforce`.

**Как защититься?**

`enforce` на всех namespace, актуальная версия, покрытие всех ресурсов, отказ от исключений.

**Помогает ли PSA против побега?**

Да, restricted закрывает большинство векторов. Но непомеченный namespace — дыра.

## Разбор: namespace без метки

Кластер использует PSA, но новый namespace создан без метки, а по умолчанию действует уровень `privileged`. Атакующий создаёт там под с `hostPath: /` и захватывает узел. Политика была, но не применялась к этому namespace. Защита — запретить создание namespace без enforce-метки через admission и следить за новыми namespace.

## Что чаще всего упускают

Namespace без метки: по умолчанию действует `privileged`, поэтому новый namespace — открытая дверь. Проверяй `kubectl get ns --show-labels` и требуй `enforce` на всех. Второе — режимы `warn` и `audit`: они не блокируют под. Третье — ресурсы, которые PSA не проверяет. Вывод: PSA защищает только там, где включён `enforce`; наличие контроллера в кластере само по себе ничего не гарантирует.

**Что если namespace помечен `baseline`?**

Baseline не требует non-root и seccomp, поэтому остаются векторы вроде `hostNetwork` и опасных capabilities. Restricted заметно строже.

**Как проверить, что `enforce` реально работает?**

Попробуй создать привилегированный под в помеченном namespace — он должен быть отклонён. Если создался, метка не действует или уровень ниже ожидаемого.

**Помогает ли PSA против уязвимости рантайма?**

Нет, уязвимость рантайма обходит настройки пода. PSA закрывает конфигурационные векторы, но не баги runc и containerd.

## Квиз

Проверь себя.

```quiz
- question: "На каком уровне действует Pod Security Admission?"
  options:
    - "На namespace (по меткам)"
    - "На отдельный под"
    - "На узел"
    - "На контейнер"
  answer: 0
  explanation: "PSA применяет стандарты к namespace через labels."
- question: "Что означает режим enforce?"
  options:
    - "Отклоняет поды, нарушающие стандарт"
    - "Только предупреждает"
    - "Пишет в аудит"
    - "Ничего"
  answer: 0
  explanation: "enforce блокирует; audit/warn — нет."
- question: "Самый простой обход PSA?"
  options:
    - "Использовать namespace без метки PSA"
    - "Отключить KMS"
    - "Сменить образ"
    - "Использовать SSH"
  answer: 0
  explanation: "Без метки namespace ограничения не применяются."
- question: "Что запрещает уровень restricted?"
  options:
    - "privileged, hostPath, hostPID, требует runAsNonRoot и seccomp"
    - "Только привилегированные поды"
    - "Только сеть"
    - "Только образы"
  answer: 0
  explanation: "restricted — самый строгий уровень PSS."
- question: "Почему право update на namespace опасно?"
  options:
    - "Позволяет ослабить или снять метку PSA"
    - "Даёт root на узле"
    - "Читает секреты"
    - "Меняет биллинг"
  answer: 0
  explanation: "Изменив метку enforce, можно разрешить привилегированные поды."
```

## Куда дальше

В следующем уроке мы разберём **побег из контейнера через runc** — конкретные CVE и `nsenter`. А пока главное запомни: **PSA защищает namespace, поэтому ищи namespace без метки или право ослабить её — обход почти всегда в конфигурации, а не в политике.**

## Где пригодится

- **Пентест k8s:** обход admission.
- **Blue team:** настройка PSA.
- **Red team:** поиск namespace-лазейки.
- **Сертификация:** CKS.
