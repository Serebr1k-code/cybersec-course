---
id: cloud-iac-platforms
title: 'Модуль: IaC за пределами Terraform — Pulumi, CDK, Crossplane'
category: cloud
parent: cloud-iac-deep
difficulty: hard
order: 2
tags: [cloud, iac, pulumi, cdk, crossplane, terragrunt, module]
prerequisites: [cloud-terraform]
useful_for:
  - 'Пентест Infrastructure as Code'
  - 'Кража секретов из пайплайнов деплоя'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль об инструментах «инфраструктура как код» вне классического Terraform: Pulumi (реальные языки), AWS CDK (синтез в CloudFormation), Crossplane (IaC внутри Kubernetes) и Terragrunt/Atlantis (автоматизация применения). У всех одна цель для атакующего: код, который исполняется с правами деплоя.'
---

Terraform ты уже разобрал: state, backend, `terraform state pull`. Но Terraform — не единственный способ описать инфраструктуру. Pulumi пишет её на TypeScript и Python, AWS CDK синтезирует CloudFormation из кода, Crossplane управляет ресурсами изнутри Kubernetes, а Terragrunt/Atlantis автоматизируют `apply`. Каждый инструмент добавляет новый слой — и новую точку, где можно исполнить свой код с правами деплоя.

## Что покрывает подмодуль

1. **Pulumi** (`cloud-pulumi`) — стеки, backend state, secrets-provider и злоупотребление динамическими провайдерами.
2. **AWS CDK** (`cloud-aws-cdk`) — синтез в CloudFormation, bootstrap-роли и эскалация через деплой.
3. **Crossplane** (`cloud-crossplane`) — Kubernetes-native IaC, ProviderConfig и эскалация через Managed Resources.
4. **Terragrunt / Atlantis** (`cloud-terragrunt-atlantis`) — DRY-обёртки, автоматизация PR и выполнение команд на сервере деплоя.

## Почему такой порядок

Идём от «код, который ты пишешь сам» к «сервер, который применяет код за тебя». Pulumi и CDK — это про то, как изменение кода в репозитории превращается в изменение облака. Crossplane — про то, как то же самое делается изнутри кластера. Atlantis — про то, как CI-сервер получает право запускать `apply` из pull request. Чем ближе инструмент к автоматическому применению, тем меньше шагов между твоим коммитом и правами в облаке.

## Как проходить подмодуль

Держи в голове один вопрос: «какой код здесь исполняется и с чьими правами?». Pulumi и CDK исполняют твой код на машине деплоя с облачными кредами. Crossplane исполняет код в поде контроллера с ролью кластера. Atlantis исполняет команды, пришедшие из PR. Ответ на этот вопрос и есть путь атаки.

## Квиз

Проверь себя.

```quiz
- question: "Что общего у инструментов этого подмодуля?"
  options:
    - "Все исполняют код деплоя с правами на облако"
    - "Они все бесплатны"
    - "Они не работают с облаком"
    - "Они заменяют Kubernetes"
  answer: 0
  explanation: "Pulumi, CDK, Crossplane и Atlantis в итоге применяют изменения от имени роли с широкими правами."
- question: "Почему state и secrets важны для Pulumi?"
  options:
    - "Он хранит значения ресурсов, включая секреты, в backend"
    - "Он хранит только имена"
    - "Он всегда публичен"
    - "Он не имеет секретов"
  answer: 0
  explanation: "Backend state содержит атрибуты ресурсов; секреты шифруются ключом secrets-provider."
- question: "Чем опасен bootstrap в AWS CDK?"
  options:
    - "Он создаёт роли деплоя, которые часто избыточно широки"
    - "Он удаляет аккаунт"
    - "Он отключает IAM"
    - "Он не создаёт ресурсов"
  answer: 0
  explanation: "CDKToolkit и cfn-exec-роли получают права, достаточные для создания почти любых ресурсов."
- question: "Где Crossplane берёт облачные креды?"
  options:
    - "В Kubernetes Secret, на который ссылается ProviderConfig"
    - "В DNS"
    - "В логах"
    - "В маршрутах"
  answer: 0
  explanation: "ProviderConfig ссылается на Secret с ключами; доступ к Secret равен доступу к облаку."
```

## Куда дальше

Дальше — Pulumi: тот же Terraform по смыслу, но код на реальном языке. А пока главное: любой IaC-инструмент в итоге исполняет код с правами деплоя.

## Где пригодится

- Пентест IaC и пайплайнов деплоя.
- Кража секретов из state и backend.
- CTF-задачи категории cloud.
