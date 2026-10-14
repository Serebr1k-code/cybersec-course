#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Insert '## Квиз' sections into the cloud-* gB lessons (before '## Куда дальше')."""
import os
C = "content/forensics"

QUIZ = {
"cloud-serverless": r'''## Квиз

Проверь себя.

```quiz
- question: Что расследуют у serverless-функции, если диска нет?
  options:
    - 'ничего'
    - 'логи, конфигурацию и события управления'
    - 'только память'
    - 'SMART диска'
  answer: 1
  explanation: 'Диска нет, поэтому опираются на логи, конфигурацию и события провайдера.'
- question: Какой сервис фиксирует, кто менял код функции?
  options:
    - 'S3'
    - 'CloudTrail'
    - 'VPC Flow Logs'
    - 'CloudWatch'
  answer: 1
  explanation: 'CloudTrail хранит события управления (UpdateFunctionCode и т.п.).'
- question: Что показывает роль исполнения (execution role)?
  options:
    - 'пароль функции'
    - 'права, которые функция может использовать'
    - 'версию ОС'
    - 'IP-адрес'
  answer: 1
  explanation: 'Роль определяет доступ функции к сервисам облака.'
- question: Что переживает «исчезновение» функции?
  options:
    - 'ничего'
    - 'логи выполнения, события, конфигурация, версии'
    - 'только память'
    - 'только диск'
  answer: 1
  explanation: 'Улики живут на «периферии»: логи, события, конфигурация, версии.'
```
''',
"cloud-container-runtime": r'''## Квиз

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
''',
"cloud-vm-hypervisor": r'''## Квиз

Проверь себя.

```quiz
- question: Как безопасно снять диск работающей облачной ВМ?
  options:
    - 'выключить ВМ'
    - 'создать снимок тома (snapshot)'
    - 'отформатировать том'
    - 'скопировать по RDP'
  answer: 1
  explanation: 'Снимок не изменяет работающую ВМ и фиксирует состояние тома.'
- question: Что даёт консольный вывод (serial console)?
  options:
    - 'пароли'
    - 'вывод системы, переживающий перезагрузки'
    - 'список файлов'
    - 'MAC-адрес'
  answer: 1
  explanation: 'Консольный лог полезен, когда систему не запустить.'
- question: К чему у тебя НЕТ доступа в облаке?
  options:
    - 'к своей ВМ'
    - 'к гипервизору'
    - 'к снимкам'
    - 'к логам'
  answer: 1
  explanation: 'Гипервизор управляется провайдером; доступны только ВМ и её тома.'
- question: Что именно фиксирует снимок тома?
  options:
    - 'текущее состояние в реальном времени'
    - 'состояние на момент снятия'
    - 'будущее состояние'
    - 'только метаданные'
  answer: 1
  explanation: 'ВМ продолжает меняться, а снимок — это «моментальный слепок».'
```
''',
"cloud-storage": r'''## Квиз

Проверь себя.

```quiz
- question: Что даёт версионирование объекта?
  options:
    - 'сжатие'
    - 'сохранение удалённых объектов и старых версий'
    - 'шифрование'
    - 'ускорение'
  answer: 1
  explanation: 'Удаление добавляет delete-marker, но версии остаются.'
- question: Как восстановить удалённый объект в S3?
  options:
    - 'перезагрузить бакет'
    - 'get-object с конкретным version-id'
    - 'удалить бакет'
    - 'включить SMART'
  answer: 1
  explanation: 'list-object-versions + get-object --version-id возвращают версию.'
- question: Что фиксирует доступ к объектам?
  options:
    - 'SMART'
    - 'server access logs и CloudTrail data events'
    - 'BIOS'
    - 'консоль'
  answer: 1
  explanation: 'Эти логи показывают, кто читал объекты.'
- question: Что такое presigned URL?
  options:
    - 'постоянный публичный доступ'
    - 'временная подписанная ссылка на объект'
    - 'ключ шифрования'
    - 'резервная копия'
  answer: 1
  explanation: 'Утечка presigned URL даёт доступ без ключей на время действия.'
```
''',
"cloud-iac-state": r'''## Квиз

Проверь себя.

```quiz
- question: Что содержит terraform.tfstate?
  options:
    - 'только код'
    - 'описание созданных ресурсов и их атрибутов (иногда секреты)'
    - 'только логи'
    - 'SMART'
  answer: 1
  explanation: 'State — снимок ресурсов, включая атрибуты вроде паролей БД.'
- question: Что такое drift в IaC?
  options:
    - 'ускорение'
    - 'расхождение между кодом/state и реальной инфраструктурой'
    - 'сжатие'
    - 'резервная копия'
  answer: 1
  explanation: 'Ручные изменения создают ресурсы, которых нет в state.'
- question: Чем полезен terraform.tfstate.backup?
  options:
    - 'ничем'
    - 'это предыдущее состояние, по нему видно изменения'
    - 'это пароль'
    - 'это лог'
  answer: 1
  explanation: 'Сравнение текущего и backup-состояний показывает, что менялось.'
- question: Что дают CloudFormation stack events?
  options:
    - 'пароли'
    - 'историю развёртывания ресурсов'
    - 'скорость диска'
    - 'MAC-адреса'
  answer: 1
  explanation: 'Stack events фиксируют, когда и что создавалось/менялось.'
```
''',
"cloud-secrets-manager": r'''## Квиз

Проверь себя.

```quiz
- question: Что фиксирует аудит-лог Vault?
  options:
    - 'только ошибки'
    - 'кто, когда и к какому секрету обращался'
    - 'скорость диска'
    - 'SMART'
  answer: 1
  explanation: 'На каждый запрос пишутся записи request/response с пользователем и путём.'
- question: Как называется событие чтения секрета в AWS?
  options:
    - 'GetObject'
    - 'GetSecretValue'
    - 'DecryptAll'
    - 'PutSecret'
  answer: 1
  explanation: 'GetSecretValue в CloudTrail фиксирует чтение секрета.'
- question: Что может быть анти-форензикой со стороны ключей KMS?
  options:
    - 'создание ключа'
    - 'ScheduleKeyDeletion — попытка уничтожить ключ'
    - 'шифрование'
    - 'ротация'
  answer: 1
  explanation: 'Планирование удаления ключа может скрывать следы.'
- question: Что делать с секретами, которые прочитал атакующий?
  options:
    - 'оставить'
    - 'немедленно ротировать (сменить)'
    - 'зашифровать повторно'
    - 'удалить из логов'
  answer: 1
  explanation: 'Прочитанные секреты считаются скомпрометированными и подлежат ротации.'
```
''',
"cloud-cicd": r'''## Квиз

Проверь себя.

```quiz
- question: Почему CI/CD — лакомая цель атакующего?
  options:
    - 'он медленный'
    - 'пайплайны обычно имеют широкие права в облаке'
    - 'в нём нет логов'
    - 'он публичный'
  answer: 1
  explanation: 'Через пайплайн атакующий получает права «легально».'
- question: Что показывает лог запусков пайплайна?
  options:
    - 'только ошибки'
    - 'кто запустил, из какой ветки и что выполнялось'
    - 'скорость диска'
    - 'SMART'
  answer: 1
  explanation: 'По логу видно источник запуска и шаги сборки.'
- question: Где может оказаться внедрённый атакующим код?
  options:
    - 'в SMART'
    - 'в артефакте сборки (образе)'
    - 'в BIOS'
    - 'в DNS'
  answer: 1
  explanation: 'Образ-артефакт может содержать добавленные файлы.'
- question: Что такое раннер?
  options:
    - 'пароль'
    - 'машина, где выполняется пайплайн'
    - 'тип шифрования'
    - 'логи'
  answer: 1
  explanation: 'Компрометация раннера позволяет влиять на все сборки.'
```
''',
}

for lid, quiz in QUIZ.items():
    p = os.path.join(C, lid + ".md")
    with open(p, encoding="utf-8") as f:
        txt = f.read()
    if "## Квиз" in txt:
        print("skip:", lid); continue
    if "## Куда дальше" not in txt:
        print("!! no kuda anchor:", lid); continue
    txt = txt.replace("## Куда дальше", quiz.rstrip() + "\n\n## Куда дальше", 1)
    with open(p, "w", encoding="utf-8") as f:
        f.write(txt)
    print("quiz inserted:", lid)
