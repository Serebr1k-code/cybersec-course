---
id: forensics-cloud-multi
title: "Модуль: мультиоблачная форензика"
category: forensics
parent: forensics-cloud
difficulty: hard
order: 2
tags: [cloud, azure, gcp, entra, forensics, roadmap]
prerequisites: [forensics-cloud]
useful_for:
  - "CTF Forensics категория"
  - "Cloud Incident Response"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Этап ветки «Облако»: форензика Azure/Entra ID и GCP — журналы активности, аудит-логи, признаки компрометации и сбор облачных доказательств."
---

Этот модуль расширяет облачную ветку за пределы AWS. Базовый урок и `forensics-cloud-trail` разобрали AWS CloudTrail; здесь мы добавляем **Azure/Entra ID** и **GCP**, потому что в мультиоблачных средах следы атаки разбросаны по нескольким control plane.

## Что покрывает этот модуль

- **Azure/Entra ID** — Azure Activity Log, Entra ID sign-in/audit logs, диагностические настройки, признаки компрометации приложения и managed identity.
- **GCP** — Cloud Audit Logs (Admin Activity, Data Access), IAM-изменения, признаки кражи service account и Workload Identity.

## Рекомендуемый порядок изучения

1. `forensics-azure-forensics` — Azure/Entra: где лежат логи и как их собирать.
2. `forensics-gcp-forensics` — GCP: audit logs и анализ IAM-событий.

## Что вы будете уметь

- Находить и выгружать Azure Activity/Entra audit logs.
- Читать GCP Cloud Audit Logs и отличать Admin Activity от Data Access.
- Строить таймлайн облачных событий и сопоставлять его с локальными артефактами.

## Источники логов

| Облако | Лог | Что видно |
|--------|-----|-----------|
| Azure | Activity Log | операции с ресурсами (ARM) |
| Entra ID | Sign-in / Audit | входы, изменения объектов, приложения |
| GCP | Admin Activity | изменения ресурсов и IAM |
| GCP | Data Access | доступ к данным (может быть выключен) |

## Квиз

```quiz
- question: "Какой лог Azure фиксирует операции с ресурсами на уровне control plane?"
  options:
    - "Sign-in log"
    - "Activity Log"
    - "Data Access log"
    - "NetFlow"
  answer: 1
  explanation: "Azure Activity Log — журнал операций с ресурсами (ARM control plane)."
- question: "Чем GCP Admin Activity отличается от Data Access?"
  options:
    - "Ничем"
    - "Admin Activity — изменения ресурсов, Data Access — чтение/запись данных (часто выключен)"
    - "Data Access — это биллинг"
    - "Admin Activity доступен только в AWS"
  answer: 1
  explanation: "Admin Activity всегда включён и логирует изменения; Data Access логирует доступ к данным и по умолчанию может быть выключен."
- question: "Почему мультиоблачная форензика сложнее однооблачной?"
  options:
    - "Логи в облаках всегда полные"
    - "Следы атаки разбросаны по нескольким control plane и разным форматам логов"
    - "В облаках нет логов"
    - "Облака не поддерживают время"
  answer: 1
  explanation: "Azure, GCP и AWS имеют разные форматы и разные точки логирования; их нужно коррелировать."
```

## Где пригодится

- **CTF:** задачи с облачными логами разных провайдеров.
- **Cloud IR:** расследование инцидентов в Azure/GCP.
- **Threat Hunting:** поиск аномальных IAM- и resource-операций.
- **Аудит:** проверка настроек логирования в мультиоблаке.
