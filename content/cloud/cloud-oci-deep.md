---
id: cloud-oci-deep
title: 'Модуль: Oracle Cloud (OCI) глубоко — IAM, сеть, хранилище, serverless'
category: cloud
parent: cloud-provider-breadth
difficulty: hard
order: 6
tags: [cloud, oci, oracle, iam, network, storage, serverless, module]
prerequisites: [cloud-provider-breadth]
useful_for:
  - 'Пентест сред на Oracle Cloud'
  - 'Разбор утёкших OCI-ключей и ссылок'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль об Oracle Cloud Infrastructure: от чтения конфига OCI CLI и IAM-политик до сети, Object Storage и serverless-функций. Один сквозной сюжет — утёкший CI-креденшел и путь к захвату ресурсов.'
---

Этот подмодуль углубляет Oracle Cloud Infrastructure. OCI часто встречается в корпоративном сегменте: банки, ERP, Oracle Database, интеграционные платформы. Модель прав здесь своя, и её часто настраивают «как получилось» — с широкими политиками и долгоживущими ключами. Здесь мы проходим всю цепочку: от конфига CLI до serverless-функции.

## Что покрывает подмодуль

1. **Tenancy, compartments, IAM и поверхность атаки** (`cloud-oci-basics`) — как читать конфиг OCI CLI и понимать, что даёт утёкший API-ключ.
2. **IAM-политики, dynamic groups и instance principals** (`cloud-oci-iam`) — глаголы inspect/read/use/manage, наследование по compartment и пути эскалации.
3. **VCN: security lists, NSG и шлюзы** (`cloud-oci-vcn`) — как читать сетевой конфиг и находить открытые наружу сервисы.
4. **Object Storage: pre-authenticated requests и публичные бакеты** (`cloud-oci-object-storage`) — почему ссылка может быть креденшелом.
5. **Functions и API Gateway: resource principal и захват прав** (`cloud-oci-functions`) — что даёт компромисс serverless-кода.

## Почему такой порядок

Сначала — идентичность (кто ты и что тебе можно), потом — сеть (куда дотянешься), затем — данные (что украдёшь) и, наконец, вычисления (где закрепишься). Эта последовательность повторяет реальный путь атакующего: ключ → права → сеть → данные → персистентность.

## Как проходить подмодуль

Идите по списку. После каждого урока фиксируйте три вещи: какой сущностью OCI оперировали, какой глагол политики её открывал и что именно утекло или захвачено. Держите в голове соответствие: tenancy≈аккаунт, compartment≈проект, policy≈правило IAM, instance principal≈роль для ресурса.

## Квиз

Проверь себя.

```quiz
- question: "Какой глагол OCI-политики даёт полный контроль над ресурсом?"
  options:
    - "manage"
    - "read"
    - "inspect"
    - "use"
  answer: 0
  explanation: "Иерархия inspect < read < use < manage; manage включает создание, изменение и удаление."
- question: "Что такое pre-authenticated request?"
  options:
    - "Ссылка со встроенным доступом к объекту или бакету"
    - "Тип IAM-политики"
    - "Сетевой шлюз"
    - "Формат OCID"
  answer: 0
  explanation: "PAR — самодостаточная ссылка; её утечка равна утечке доступа к данным."
- question: "Как OCI Functions получает права без ключей в коде?"
  options:
    - "Через resource principal и dynamic group"
    - "Через пароль в переменной окружения"
    - "Через SSH-ключ"
    - "Через IAM-пользователя с постоянным ключом"
  answer: 0
  explanation: "Платформа выдаёт короткоживущий токен resource principal, права определяет dynamic group."
```

## Куда дальше

После OCI логично перейти к Alibaba Cloud: там права живут в RAM, а метаданные ECS отдают роль почти как в AWS. А пока главное: в OCI всё решает политика, а ключ — лишь вход в неё.

## Где пригодится

- Пентест компаний на Oracle Cloud.
- Разбор утечек OCI-конфигов и PAR-ссылок.
- CTF-задачи категории cloud.
