---
id: forensics-mobile-ios-deep
title: "Модуль: iOS — бэкапы, keychain, локация и jailbreak"
category: forensics
parent: forensics-mobile
difficulty: hard
order: 5
tags: [forensics, mobile, ios, backup, keychain, jailbreak, roadmap]
prerequisites: [forensics-mobile]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Мобильная форензика"
estimated_minutes: 13
summary: "Этап ветки «мобильные»: глубокий iOS — структура бэкапов, keychain, геолокация, следы jailbreak и блокировка экрана."
---

iOS устроен иначе, чем Android: закрытая ФС, шифрование, бэкапы. Но и у него есть
источники данных. Этот модуль — про глубокий анализ iOS.

## Что покрывает этот модуль

- **Бэкапы** — структура и извлечение.
- **Keychain** — секреты и пароли.
- **Геолокация** — где был телефон.
- **Jailbreak** — следы взлома.
- **Блокировка** — пароль и попытки.
- **U-FED workflow** — процесс извлечения.

## Рекомендуемый порядок изучения

1. `forensics-ios-backup` — база: бэкап.
2. `mobile-ios-keychain-deep` — секреты.
3. `mobile-ios-location` — локация.
4. `mobile-jailbreak-artifacts` — jailbreak.
5. `mobile-screen-lock` — блокировка.
6. `mobile-ufed-workflow` — процесс.

## Что вы будете уметь

- Разбирать iOS-бэкапы.
- Извлекать keychain.
- Читать геолокацию.
- Находить следы jailbreak.

## Артефакт → вопрос | Путь

| Артефакт | Отвечает на вопрос |
|----------|--------------------|
| `Manifest.db` | структура бэкапа |
| `keychain-backup.plist` | пароли |
| `Cache.sqlite` | локация |
| `Cydia`/`/var/lib/dpkg` | jailbreak |

## Куда дальше

Открывай урок **«iOS-бэкапы»** — начнём с извлечения.
