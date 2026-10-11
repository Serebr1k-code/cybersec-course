---
id: hardware-uefi
title: "UEFI/BIOS: поверхность атаки прошивки и Secure Boot"
category: hardware
parent: hardware-bootloader
difficulty: hard
order: 3
tags: [uefi, bios, secure-boot, spi, me, firmware, uefi-shell, flash, bootkit]
prerequisites: [hardware-firmware-extract, hardware-secure-boot]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Аппаратная безопасность"
  - "Red team / защита конечных точек"
estimated_minutes: 55
summary: "Как анализировать и атаковать прошивку UEFI/BIOS: извлечение из SPI-флеш, разбор UEFI-модулей, обход Secure Boot, постоянные буткиты и защита."
---

UEFI — прошивка, запускающаяся до ОС и имеющая полный доступ к железу. Она хранится в SPI-флеш на материнской плате, а в современных системах — с Intel ME/AMD PSP. Буткит в UEFI переживает переустановку ОС. Урок про извлечение, разбор и атаку прошивки.

## Где живёт прошивка

| Компонент | Носитель | Роль |
|-----------|----------|------|
| UEFI/BIOS | SPI-флеш (8–32 МБ) | Инициализация, загрузчик |
| Intel ME / AMD PSP | Часть SPI | Управление, защита |
| NVRAM | SPI | Переменные (в т.ч. Secure Boot) |
| Опциональные ROM | PCIe | Прошивки устройств |

## Извлечение прошивки

```bash
# 1) Программно из ОС (Linux)
sudo apt install flashrom
sudo flashrom -p internal -r bios.bin

# 2) Через SPI-программатор (CH341A + clip) — офлайн
flashrom -p ch341a_spi -r bios.bin
# 3) Из дампа дампа (UEFITool) или с сайта вендора
```

## Разбор UEFI: UEFITool и модули

UEFI состоит из томов, файлов и секций. Инструменты:

```bash
# UEFITool (GUI/CLI) — навигация по структуре
uefitool bios.bin
# Извлечение модулей
uefiextract bios.bin
# binwalk как быстрый обзор
binwalk -e bios.bin
```

Что искать:

- **DXE-драйверы** — исполняемый код UEFI (PE32+), в т.ч. `Smm`-модули.
- **SMM (System Management Mode)** — Ring -2, максимальные привилегии; уязвимости там критичны.
- **NVRAM переменные** — `SecureBoot`, `db`, `dbx`, `PK`, `KEK`.
- **Модули вендора** — часто с уязвимостями (SMM callout, недостаточная валидация).

```bash
# Поиск интересных строк
strings -a bios.bin | grep -iE 'SecureBoot|Setup|password|Admin'
```

## Secure Boot: как работает и как обходят

Secure Boot проверяет подпись загрузчиков по базам `db`/`dbx`. Обходы:

- **Уязвимые подписанные загрузчики** (`db` содержит уязвимый бинарь) → BootHole-класс.
- **Отключение через NVRAM** — если есть физический/админ доступ, `SecureBoot=0`.
- **SBAT-обходы** — старые загрузчики с известными багами.
- **DBX-неполнота** — отсутствие отзыва.

```bash
# Проверить состояние (Linux)
mokutil --sb-state
efibootmgr -v
# Список ключей в прошивке (из ОС)
ls /sys/firmware/efi/efivars/
```

## Разобранный пример: буткит в SPI-флеш

**Дано:** физический доступ к ноутбуку, задача — понять, можно ли внедрить персистентный буткит.

1. Считываем SPI через CH341A: `flashrom -p ch341a_spi -r bios.bin`.
2. Открываем в UEFITool, ищем DXE-драйверы и SMM-модули.
3. Проверяем, включён ли **BIOS Write Protect** и **Boot Guard** — они мешают модификации.
4. Если защита слаба, модифицируем модуль (или подменяем загрузчик) и прошиваем обратно.
5. В ОС буткит остаётся незамеченным — переустановка ОС его не удаляет.

## Защита и проверка

- **Boot Guard / Verified Boot** — подпись ключевых модулей.
- **BIOS Write Protect** — запрет записи из ОС.
- **Измерения в TPM** (PCR) — детект изменений прошивки.
- **CHIPSEC** — проверка прошивки на уязвимости.

```bash
# CHIPSEC: проверка SPI и защит
sudo python3 chipsec_main.py -m common.bios_wp
sudo python3 chipsec_main.py -m common.secureboot.variables
```

## Частые ошибки

- **Считать, что переустановка ОС удаляет буткит.** UEFI-имплант переживает её.
- **Игнорировать SMM.** SMM-уязвимости дают Ring -2.
- **Не проверять Boot Guard.** Он блокирует модификацию прошивки.
- **Портить дамп.** Всегда делайте резервную копию перед прошивкой.
- **Забывать про ME/PSP.** Отдельная прошивка с собственными уязвимостями.
- **Правовые рамки.** Модификация чужого железа — только с разрешения.

## Что дальше / решение

- Есть SPI-доступ → `flashrom` + UEFITool + CHIPSEC.
- Нужен обход Secure Boot → ищите уязвимый подписанный загрузчик.
- Нужна защита → Boot Guard, Write Protect, TPM-измерения.
- Смежные уроки: `hardware-firmware-extract`, `hardware-secure-boot`, `hardware-flash-dumping`.

## UEFITool: команды и модули

```bash
# извлечь прошивку из образа
uefi-firmware-parser -e firmware.bin -O out/
# UEFITool (GUI/CLI)
UEFIExtract firmware.bin
UEFIFind firmware.bin list
# посмотреть модули
uefi-firmware-parser -e firmware.bin | grep -iE 'dxe|pe32|setup'
```

Ищите: `Setup` (настройки), `DXE`-драйверы (исполняются в рантайме), `PEI`-модули, переменные NVRAM. Модули — обычные PE-файлы, их можно анализировать в Ghidra.

## Обход Secure Boot

| Метод | Условие |
|-------|---------|
| Отключить в Setup | доступ к настройкам |
| Уязвимый подписанный загрузчик | старый grub/shim с CVE |
| `db`/`MOK` с слабым ключом | можно подписать свой |
| Evil Maid: замена DXE-драйвера | физический доступ |
| BootHole и подобные CVE | конкретные версии |
| SMM-эксплойт | уязвимость в SMI |

## Практическое задание

Возьмите образ UEFI (например, OVMF для QEMU), извлеките модули через `UEFITool`, найдите `Setup` и определите, какие опции доступны. Проверьте, включён ли Secure Boot в конфигурации. Это базовый навык анализа прошивок.

## Secure Boot: как работает

UEFI Secure Boot проверяет подпись загрузчика по базе `db` (разрешённые) с учётом `dbx` (отозванные). Ключи: PK (platform key), KEK (key exchange), db/dbx. Если загрузчик не подписан доверенным ключом — загрузка блокируется. Обходы: уязвимый подписанный загрузчик, отзыв через dbx, изменение NVRAM при физическом доступе, SMM-эксплойт. Проверка состояния:

```bash
mokutil --sb-state
efi-readvar -v db
efi-readvar -v dbx
```

`mokutil --sb-state` покажет `SecureBoot enabled/disabled`; `efi-readvar` — содержимое баз.

## Практическое задание

Возьмите образ OVMF (используется в QEMU), извлеките модули через `UEFIExtract`, найдите `SecureBootConfig`-модули и `Setup`. Определите, включён ли Secure Boot и какие ключи в `db`. Затем попробуйте загрузить неподписанный загрузчик — загрузка должна быть отклонена. Это демонстрирует механизм защиты на практике.

## Инструменты анализа UEFI

`UEFITool`/`UEFIExtract` разбирают структуру прошивки на модули, `uefi-firmware-parser` даёт программный доступ, Ghidra — дизассемблирование PE-модулей. Chipsec проверяет конфигурацию платформы:

```bash
chipsec_main -m common.secureboot.variables
chipsec_util uefi var-list
```

`chipsec` показывает состояние Secure Boot и переменные NVRAM. Используйте его для аудита платформы перед атакой.

## Практика: аудит платформы через chipsec

```bash
chipsec_main -m common.bios_wp
chipsec_main -m common.secureboot.variables
chipsec_util uefi var-list
chipsec_util spi dump firmware.bin
```

`chipsec_main -m common.bios_wp` покажет, защищён ли BIOS от записи; `uefi var-list` — переменные Secure Boot; `spi dump` — дамп SPI-флеш. Если BIOS не защищён от записи, атакующий с локальным доступом может внедрить буткит.

## Итог

Прошивка UEFI — постоянная точка присутствия: переживает переустановку ОС. Анализ через UEFITool, аудит через chipsec, обход Secure Boot через уязвимые загрузчики или физический доступ. Для защиты — обновления прошивки, включённый Secure Boot, защита BIOS от записи.

## Быстрая проверка прошивки

```bash
UEFIExtract firmware.bin
efi-readvar -v db
efi-readvar -v dbx
chipsec_main -m common.bios_wp
```

Найдите модули DXE, проверьте базы db/dbx и защиту BIOS от записи. Если BIOS не защищён, а Secure Boot отключён — установка буткита возможна при физическом/локальном доступе.

## Итог по UEFI

Прошивка — постоянная точка присутствия, переживающая переустановку ОС. Анализ: UEFIExtract/UEFITool для модулей, chipsec для состояния платформы, Ghidra для DXE-драйверов. Обход Secure Boot возможен через уязвимые загрузчики или физический доступ. Защита: обновления, Secure Boot, write-protect BIOS.

## Квиз

```quiz
- question: "Где хранится прошивка UEFI?"
  options:
    - "В SPI-флеш на материнской плате"
    - "На жёстком диске"
    - "В ОЗУ"
    - "На SIM-карте"
  answer: 0
  explanation: "UEFI живёт в SPI-флеш (с ME/PSP)."
- question: "Каким инструментом считывают и прошивают SPI?"
  options:
    - "flashrom"
    - "nmap"
    - "tcpdump"
    - "hydra"
  answer: 0
  explanation: "flashrom работает с SPI-программаторами."
- question: "Что такое SMM?"
  options:
    - "Режим максимальных привилегий (Ring -2) в x86"
    - "Протокол IoT"
    - "Формат прошивки"
    - "Тип антенны"
  answer: 0
  explanation: "System Management Mode — высокопривилегированный режим."
- question: "Что проверяет Secure Boot?"
  options:
    - "Подпись загрузчиков по базам db/dbx"
    - "Пароль пользователя"
    - "Скорость диска"
    - "IP-адрес"
  answer: 0
  explanation: "Secure Boot валидирует подписи загрузчиков."
- question: "Почему UEFI-буткит опасен?"
  options:
    - "Он переживает переустановку ОС и живёт до её загрузки"
    - "Он ускоряет загрузку"
    - "Он шифрует диск"
    - "Он безвреден"
  answer: 0
  explanation: "Прошивочный имплант персистентен."
```

## Где пригодится

- **CTF:** Hardware-задачи с прошивками и Secure Boot.
- **Red team:** персистентность уровня прошивки.
- **Аппаратная безопасность:** аудит защит платформы.
- **Работа/Blue team:** CHIPSEC, TPM-мониторинг, Boot Guard.
- **Дальше по дереву:** `hardware-firmware-extract`, `hardware-secure-boot`.
