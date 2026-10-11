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
---

## Зачем этот урок

В Kubernetes данные приложений живут в **томах**: PersistentVolume (PV), привязанных к PersistentVolumeClaim (PVC) через StorageClass и CSI-драйвер. Атакующему storage интересен по трём причинам: (1) том может содержать секреты, БД и приватные ключи; (2) **снапшот** тома можно склонировать в свой namespace и прочитать чужие данные; (3) CSI **node-плагин** обычно привилегированный и имеет доступ к файловой системе узла, что даёт побег из пода. Этот урок — про storage-модель Kubernetes, поиск опасных конфигураций и практические пути к данным.

## Как устроена storage-модель Kubernetes

Основные объекты:

- **PersistentVolume (PV)** — том (облачный диск, NFS, локальный). Cluster-scoped.
- **PersistentVolumeClaim (PVC)** — запрос на том в namespace; привязывается к PV.
- **StorageClass (SC)** — «класс» хранилища с provisioner (CSI-драйвер) и параметрами (тип диска, шифрование, reclaimPolicy).
- **CSI Driver** — плагин, реализующий provision/attach/mount/snapshot. Состоит из controller-части (Deployment) и **node-части** (DaemonSet, привилегированный, монтирует тома на узле).
- **VolumeSnapshot / VolumeSnapshotClass** — снапшоты томов (CRD от snapshot-controller).
- **VolumeAttributesClass** (новое) — параметры для томов.

Ключевые свойства:

- `accessModes`: `ReadWriteOnce` (один узел), `ReadOnlyMany`, `ReadWriteMany` (много узлов, зависит от драйвера).
- `reclaimPolicy`: `Delete` (том удаляется с PVC), `Retain` (остаётся).
- `volumeBindingMode`: `Immediate` или `WaitForFirstConsumer`.
- Секреты драйвера (креды облачного storage) хранятся в Secret и передаются CSI-плагину.

Атакующие поверхности: клонирование/восстановление снапшота в свой namespace; доступ к PV, привязанному к другому поду (`ReadWriteMany`); node-плагин CSI с `hostPath`/privileged; секреты StorageClass/CSI.

## Инструменты и команды

Разведка:

```bash
kubectl get pv,pvc,sc -A
kubectl get storageclass -o json | jq '.items[] | {name:.metadata.name,provisioner:.provisioner,params:.parameters}'
kubectl get volumesnapshot,volumesnapshotclass -A
kubectl describe pvc -n target-ns
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.persistentVolumeClaim!=null) | "\(.metadata.namespace)/\(.metadata.name)"'
```

Проверка node-плагинов CSI:

```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.name|test("csi")) | "\(.metadata.namespace)/\(.metadata.name) privileged=\(.spec.containers[0].securityContext.privileged) hostPath=\(.spec.volumes[]?.hostPath.path)"'
```

Клонирование снапшота (если RBAC позволяет):

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
      storage: 10Gi
  dataSource:
    name: target-snapshot
    kind: VolumeSnapshot
    apiGroup: snapshot.storage.k8s.io
```

```bash
kubectl apply -f pvc.yaml
kubectl run reader --image=alpine -n attacker \
  --overrides='{"spec":{"containers":[{"name":"reader","image":"alpine","command":["sh","-c","ls -la /data; sleep 3600"],"volumeMounts":[{"name":"d","mountPath":"/data"}]}],"volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"stolen-data"}}]}}'
kubectl exec -n attacker reader -- ls -la /data
```

## Разобранный пример: от PVC к чужим данным

Сценарий: у вас есть право создавать PVC и VolumeSnapshot в своём namespace, а в `prod` есть снапшоты тома с БД.

Шаг 1 — находим снапшоты (они могут быть cluster-scoped или в namespace):

```bash
kubectl get volumesnapshot -A
# NAMESPACE   NAME             READYTOUSE   SOURCEPVC     ...
# prod        db-snap-2026     true         db-data       ...
```

Шаг 2 — создаём PVC из снапшота **в своём** namespace, используя тот же StorageClass:

```bash
kubectl get volumesnapshot -n prod db-snap-2026 -o json | jq '.spec.source'
# {"persistentVolumeClaimName":"db-data"}
```

PVC с `dataSource` (см. выше). Если снапшот в другом namespace, а вы не имеете прав читать его — создание PVC может быть отклонено; но часто снапшоты доступны, а PVC — нет.

Шаг 3 — монтируем PVC в свой под и читаем данные:

```bash
kubectl apply -f pvc.yaml
kubectl exec -n attacker reader -- ls -la /data
kubectl exec -n attacker reader -- cat /data/mysql/ibdata1 | head -c 200
```

Шаг 4 — если снапшот недоступен, ищем **Retain**-тома, оставшиеся после удаления PVC, и `ReadWriteMany`-тома, доступные нескольким подам. Если у вас есть право создать под в namespace с RWX-томом, вы можете смонтировать его и читать.

Шаг 5 — **node-плагин CSI**. Если CSI node-плагин привилегированный (обычно да), и вы можете exec в него или создать под, использующий его драйвер, вы получаете доступ к хостовой файловой системе (через `hostPath` в node-плагине). Это путь к побегу (`cloud-kubernetes-escape`).

Шаг 6 — секреты CSI. StorageClass может ссылаться на Secret с кредами облачного storage; если у вас есть доступ к нему, вы получаете креды к бакетам/дискам.

## Варианты атак и обходы

- **Клонирование снапшота.** Основной путь: `VolumeSnapshot` → PVC в своём namespace → чтение данных.
- **Перепривязка PV.** Если PV был освобождён (`Retain`), но не удалён, новый PVC может его подхватить (зависит от `claimRef`).
- **RWX-тома.** Том с `ReadWriteMany` монтируется несколькими подами; если вы в одном из них — читаете данные.
- **Node-плагин CSI.** Привилегированный DaemonSet с доступом к `/var/lib/kubelet`, `/dev`, хостовым путям → побег.
- **Секреты драйвера.** Креды облачного storage в Secret, привязанном к CSI/SC.
- **Локальные тома.** `local` PV привязан к узлу; доступ к нему — доступ к данным узла.
- **VolumeAttachment.** Если есть права на `VolumeAttachment`, можно прикрепить том к своему узлу.
- **Snapshot-контроллер.** Его SA может создавать снапшоты любых PVC; компромисс — массовая кража.
- **Reclaim policy.** `Delete` уничтожает том при удалении PVC — destructive-риск; `Retain` оставляет данные.

## Частые ошибки и подводные камни

- **Считать storage «неинтересным».** Тома — это БД, секреты и ключи.
- **Игнорировать namespace-ограничения.** Снапшот и PVC могут быть в разных namespace; проверяйте, что разрешено.
- **Забывать про StorageClass.** Один и тот же снапшот можно восстановить только в совместимый SC.
- **Путать PV и PVC.** PV cluster-scoped, PVC — в namespace.
- **Не проверять node-плагин.** Именно он даёт побег, а не controller-часть.
- **Destructive-операции.** Удаление PVC с `reclaimPolicy: Delete` уничтожает данные — согласуйте.

## Защита и детект

- **Ограничьте создание PVC/VolumeSnapshot.** RBAC на эти ресурсы — только нужным SA.
- **Namespace-изоляция снапшотов.** Не давайте создавать PVC из снапшотов других namespace.
- **Минимум привилегий CSI node-плагина.** Хотя он обычно privileged, ограничивайте доступ к нему.
- **Шифрование томов.** Шифрование облачных дисков + секреты в KMS.
- **reclaimPolicy: Retain** для критичных данных, чтобы случайное/вредоносное удаление не уничтожило данные.
- **Детект.** Audit logs API-сервера: создание PVC из снапшота, `VolumeAttachment`, exec в CSI-поды. Falco — подозрительные mount/доступ к hostPath. Алерты на создание PVC с `dataSource` из чужого namespace.
- **Pod Security Standards.** `restricted`/`baseline` ограничивают привилегированные поды и hostPath.

## CSI в облаке: диски, снапшоты и IAM

В managed-кластерах CSI-драйверы связаны с облачным storage: AWS EBS (`ebs.csi.aws.com`), GCP PD (`pd.csi.storage.gke.io`), Azure Disk (`disk.csi.azure.com`). Это создаёт дополнительные поверхности:

- **Креды драйвера.** Controller-часть использует права (через IRSA/Workload Identity/MI) для создания и прикрепления дисков. Если вы можете exec в controller-под или прочитать его SA-токен, вы получаете права на облачный storage — создавать/удалять/снапшотить диски аккаунта.
- **Облачные снапшоты.** `VolumeSnapshot` часто маппится на облачный снапшот (EBS snapshot, PD snapshot). Право на его создание = право читать содержимое диска, включая данные других PVC.
- **VolumeAttachment и attach.** Драйвер прикрепляет диск к узлу; если вы контролируете attachment, можно прикрепить чужой диск к своему узлу.
- **Шифрование.** Если диски шифруются ключом KMS, а у драйвера есть доступ к ключу, вы можете расшифровать снапшот; если нет — данные бесполезны.
- **Cross-AZ/cross-region.** Снапшот можно восстановить в другом регионе/зоне — иногда это обходит ограничения.

Практический пример: в EKS controller-под `ebs-csi-controller` имеет IRSA-роль с `ec2:CreateSnapshot`, `ec2:CreateVolume`, `ec2:AttachVolume`. Exec в него (или кража токена) даёт эти права в AWS — а значит, возможность скопировать EBS-том любого инстанса.

## Практический чек-лист storage-аудита

1. Инвентаризация: PV, PVC, StorageClass, VolumeSnapshot, VolumeSnapshotClass.
2. Для каждой StorageClass — provisioner, параметры, ссылки на секреты.
3. Какие PVC содержат чувствительные данные (БД, секреты, ключи)?
4. Могу ли я создавать PVC/VolumeSnapshot (`kubectl auth can-i`)?
5. Могу ли я создавать PVC с `dataSource` из снапшота/другого PVC?
6. Есть ли RWX-тома и освобождённые (Retain) PV?
7. CSI node-плагины: privileged? hostPath? доступ к ним?
8. CSI controller: какие облачные права у его SA (IRSA/WI/MI)?
9. Шифрование томов и доступ к KMS.
10. Pod Security Standards: разрешены ли privileged/hostPath?

Этот чек-лист ведёт от «какие данные есть» к «как до них добраться» и вскрывает как data-plane (снапшоты), так и control-plane (права драйвера) пути.

## Что дальше / решение

Storage в Kubernetes — это данные и путь к узлу. Начните с инвентаризации PV/PVC/SC/снапшотов и определения, какие из них содержат чувствительные данные. Если у вас есть право создавать PVC из снапшота — клонируйте в свой namespace и читайте. Если доступен RWX-том или освобождённый PV — перепривяжите. Для побега ищите привилегированный CSI node-плагин и `hostPath`. Записывайте найденные тома, снапшоты и полученные данные как находки; отмечайте, если смогли прочитать чужой namespace.

## Квиз

```quiz
- question: "Что позволяет сделать VolumeSnapshot атакующему с правом создавать PVC?"
  options:
    - "Склонировать том в свой namespace и прочитать данные"
    - "Удалить кластер"
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
```

## Где пригодится

- **Пентест:** кража данных и побег через storage.
- **Red team:** доступ к БД и секретам кластера.
- **Blue team:** аудит RBAC на PVC/снапшоты и pod security.
- **Сертификация:** CKS.
