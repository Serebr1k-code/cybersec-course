---
id: hardware-tpm
title: "TPM и доверенная платформа: PCR, sealed secrets, атаки"
category: hardware
parent: hardware-secure-boot
difficulty: hard
order: 2
tags: [tpm, trusted-platform, pcr, measured-boot, bitlocker, attestation, secure-boot]
prerequisites: [hardware-secure-boot, hardware-uefi]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест: обход BitLocker и защит загрузки"
  - "Аудит доверенной загрузки"
estimated_minutes: 50
summary: "Как работает TPM 1.2/2.0: PCR, измеряемая загрузка, sealed secrets, BitLocker, attestation и практические атаки на доверенную платформу."
---

**TPM (Trusted Platform Module)** — выделенный криптопроцессор на материнской плате (или встроенный в CPU как firmware-TPM), который хранит ключи и измерения целостности платформы. Он лежит в основе Secure Boot, BitLocker, измеряемой загрузки и удалённой аттестации. Для пентестера TPM интересен тем, что его защиты можно обойти: через дамп памяти, cold-boot, спуфинг шины LPC/SPI, подмену измерений или атаки на реализацию. Этот урок — про модель TPM, PCR, sealed secrets и практические атаки.

## Что такое TPM и зачем он нужен

TPM решает три задачи:

1. **Хранение ключей** — приватные ключи не покидают модуль; операции (подпись, расшифрование) выполняются внутри.
2. **Измерения целостности** — в регистры PCR записываются хэши загружаемых компонентов (firmware, bootloader, ядро, ОС).
3. **Привязка секретов** — секрет можно «запечатать» (seal) так, что он расшифруется только при определённом состоянии PCR.

Если злоумышленник меняет загрузчик, PCR изменятся, и секрет не расшифруется. Именно так BitLocker защищает ключ шифрования диска: он «привязан» к PCR, отражающим нормальную загрузку.

## Версии TPM

| Версия | Интерфейс | Особенности |
|--------|-----------|-------------|
| TPM 1.2 | LPC/SPI | SHA-1, ограниченные алгоритмы |
| TPM 2.0 | LPC/SPI, CRB | гибкие алгоритмы, больше иерархий, NV-индексы |
| fTPM | внутри CPU | реализация в firmware (AMD/Intel) |
| Discrete TPM | чип на плате | Infineon, STMicro, Nuvoton |

TPM 2.0 доминирует. Он поддерживает алгоритмы SHA-256, RSA, ECC, иерархии (owner, platform, endorsement, null), а также **NV storage** и **attestation**.

## PCR: регистры измерений

PCR — это регистры, в которые нельзя просто «записать» значение. Есть только операция **extend**: `PCR_new = HASH(PCR_old || measurement)`. Поэтому состояние PCR отражает всю историю загрузки, и подделать его без перезаписи всей цепочки невозможно.

Типовые PCR (UEFI):

| PCR | Что измеряется |
|-----|----------------|
| 0 | firmware (UEFI) |
| 1 | конфигурация платформы |
| 2 | опциональный ROM |
| 3 | опциональный ROM config |
| 4 | MBR / GPT + boot code |
| 7 | Secure Boot policy |
| 8–15 | ОС/загрузчик (Linux: kernel cmdline, initrd) |

Считать PCR можно так:

```bash
# Linux
cat /sys/class/tpm/tpm0/pcr-sha256/0
# Windows
tpmtool getdeviceinformation
# tpm2-tools
sudo tpm2_pcrread sha256:0,4,7
```

## Sealed secrets и BitLocker

BitLocker использует TPM так: **Volume Master Key (VMK)** запечатан к состоянию PCR (обычно 7, 11). При нормальной загрузке PCR совпадают, TPM отдаёт VMK, диск расшифровывается. Если загрузчик изменён (или включён PIN, или вставлен USB-загрузчик) — PCR не совпадают, и запрашивается recovery-ключ.

```bash
# Linux: запечатать/распечатать секрет через tpm2-tools
echo -n "secret" | tpm2_createprimary -C o -c primary.ctx
echo -n "secret" | tpm2_create -C primary.ctx -u key.pub -r key.priv -i-
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_unseal -c key.ctx -p pcr:sha256:7
```

Нарушение PCR (например, изменение Secure Boot policy) блокирует unseal — это и есть механизм защиты.

## Attestation: удалённое доказательство

**Remote attestation** позволяет серверу убедиться, что клиент загрузился в доверенном состоянии. TPM подписывает набор PCR своим ключом (AK, Attestation Key), а сервер проверяет подпись и значения. Это применяется в zero-trust, device identity, DRM. Атака на attestation — попытка подделать измерения или использовать чужой AK.

## Практические атаки на TPM

- **Cold-boot attack** — выключить/охладить память, вытащить TPM-ключи из RAM/шины. Работает против fTPM и дискретных решений, если ключи оказываются в памяти.
- **Спуфинг шины LPC/SPI** — перехват обмена между CPU и дискретным TPM (классика bit-flipping на LPC, атаки на Infineon).
- **Fault injection** — glitch/voltage-атаки на TPM для обхода проверок (см. `hardware-fault-injection`).
- **Обход PCR** — если загрузчик позволяет «склеить» измерения (TOCTOU), можно загрузиться изменённым, но с «правильными» PCR.
- **Утечки ключей** — атаки на конкретные реализации (Infineon ROCA и др.), downgrade TPM 2.0 → 1.2.

## Разобранный пример: проверка привязки BitLocker к PCR

```powershell
# Windows: посмотреть, к каким PCR привязан BitLocker
manage-bde -protectors -get C:
# Numeric Password / TPM:
#   PCR Validation Profile:
#   0, 2, 4, 11
```

Если защита только TPM+PIN и PCR 0,2,4,11 — можно попытаться изменить загрузчик так, чтобы PCR совпали (сложно) либо атаковать сам TPM (cold-boot/fault injection). Часто проще найти recovery-ключ в AD/Entra ID или в backup.

```bash
# Linux: считать PCR и сравнить с эталоном
sudo tpm2_pcrread sha256:0,2,4,7,11
# Любое расхождение с известным-хорошим состоянием -> измерение нарушено
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `tpm2-tools` | работа с TPM 2.0 (PCR, seal, attest) |
| `tpm-tools` | TPM 1.2 |
| `tpmtool` (Windows) | инфо и очистка TPM |
| `manage-bde` | BitLocker и привязка к PCR |
| `TPM2.0 Reference` | спецификация |
| ChipWhisperer | fault injection на TPM |
| Логический анализатор | перехват LPC/SPI |

## Частые ошибки и подводные камни

- **TPM.clear стирает owner-иерархию** — запечатанные секреты становятся недоступны навсегда.
- **fTPM уязвим к cold-boot**: ключи в памяти CPU/firmware.
- **PCR extend необратим**: после extend откатить состояние нельзя, только clear.
- **Неверная иерархия**: unseal под owner не сработает, если ключ создан под endorsement.
- **Secure Boot off меняет PCR 7** — запечатанные к нему секреты не расшифруются.

## fTPM vs дискретный TPM

**Дискретный TPM** — отдельный чип на плате, общающийся по LPC/SPI. Он изолирован от CPU, но его шину можно перехватить и спуфить. **Firmware TPM (fTPM)** — реализация в защищённой среде CPU (AMD PSP / Intel ME/PTT). Она быстрее и дешевле, но разделяет память с платформой, что делает её уязвимой к cold-boot и ошибкам firmware. **Виртуальный TPM (vTPM)** используется в ВМ и тоже имеет свои особенности (привязка к хосту, миграция). Для пентеста важно понимать: у fTPM ключи могут оказываться в обычной DRAM, а у дискретного — застревать на шине. Отсюда разные стратегии атак: против fTPM чаще идут cold-boot и баги прошивки, против дискретного — bus sniffing и fault injection.

## TPM и Linux: IMA/EVM

На Linux измеряемая загрузка продолжается в рантайме через **IMA (Integrity Measurement Architecture)** и **EVM (Extended Verification Module)**. IMA хэширует исполняемые файлы и библиотеки и extend'ит их в PCR 10; EVM проверяет расширенные атрибуты. Вместе они дают непрерывную проверку целостности после загрузки — то, чего не хватает «статической» цепочке доверия.

```bash
# Проверить IMA
cat /sys/kernel/security/ima/policy 2>/dev/null
# Посмотреть измерения IMA
head /sys/kernel/security/ima/ascii_runtime_measurements 2>/dev/null
dmesg | grep -i ima | head
```

Если IMA включена, подмена бинарника после загрузки отразится в PCR 10 и в журнале измерений. Для защитника это способ поймать руткит, для атакующего — дополнительное препятствие, которое надо обойти (например, отключить IMA или подделать измерения).

## Диагностика TPM-проблем на практике

Частые сценарии, с которыми сталкивается пентестер или админ:

- **TPM не виден в ОС** — проверьте, включён ли он в BIOS/UEFI (PTT/fTPM/Discrete), и есть ли `/dev/tpm0` в Linux.
- **BitLocker просит recovery при каждом старте** — обычно изменились PCR (обновление BIOS, отключение Secure Boot, изменение порядка загрузки). Сравните текущие PCR с эталонными из TCG log.
- **«TPM is owned» / нельзя создать ключи** — иерархия занята; возможно, требуется `clear` (но это уничтожит существующие ключи).
- **Attestation не проходит** — проверьте nonce (replay), срок действия сертификата AK, соответствие PCR эталону.
- **Ошибки после обновления прошивки** — firmware меняет PCR 0/1; запечатанные к ним секреты надо перепривязать.

Полезные команды для диагностики: `dmesg | grep -i tpm`, `tpm2_getcap properties-fixed`, `tpm2_pcrread`, на Windows — `tpmtool getdeviceinformation` и `Get-Tpm` в PowerShell.

## Что дальше / решение

- Нужна измеряемая загрузка детально → `hardware-measured-boot`.
- Нужен глубокий разбор TPM 2.0 → `hardware-tpm-deep`.
- Нужен обход Secure Boot → `hardware-secure-boot`, `hardware-uefi`.
- Нужны glitch-атаки → `hardware-fault-injection`.

## Квиз

```quiz
- question: "Как изменяется регистр PCR?"
  options:
    - "Прямой записью"
    - "Только через extend: PCR_new = HASH(PCR_old || measurement)"
    - "Сбросом питания"
    - "Через NVRAM"
  answer: 1
  explanation: "Extend делает состояние необратимым и зависящим от истории."
- question: "К чему BitLocker привязывает ключ шифрования?"
  options:
    - "К паролю BIOS"
    - "К состоянию PCR (например, 7 и 11)"
    - "К MAC-адресу"
    - "К серийному номеру диска"
  answer: 1
  explanation: "VMK запечатан к PCR, отражающим нормальную загрузку."
- question: "Какая атака извлекает ключи TPM через память при отключении питания?"
  options:
    - "Cold-boot"
    - "SQL injection"
    - "Phishing"
    - "Race condition"
  answer: 0
  explanation: "Cold-boot читает остаточные данные в RAM."
- question: "Что подписывает AK при remote attestation?"
  options:
    - "Пароль"
    - "Набор PCR (измерения платформы)"
    - "MAC-адрес"
    - "Прошивку диска"
  answer: 1
  explanation: "Attestation Key подписывает измерения для проверяющего."
- question: "Что произойдёт после TPM.clear с запечатанными секретами?"
  options:
    - "Они сохранятся"
    - "Они станут недоступны навсегда"
    - "Они расшифруются"
    - "Их можно восстановить из PCR"
  answer: 1
  explanation: "clear удаляет owner-иерархию и ключи."
```

## Где пригодится

- **CTF:** Hardware-задачи на обход измеряемой загрузки.
- **Пентест:** анализ BitLocker, обход защит загрузки.
- **Аудит:** проверка конфигурации TPM и Secure Boot.
- **Работа:** проектирование доверенной загрузки, hardening.
- **Дальше по дереву:** `hardware-tpm-deep`, `hardware-measured-boot`, `hardware-secure-boot`.
