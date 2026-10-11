---
id: forensics-disk-encryption
title: "Шифрование дисков: LUKS, BitLocker, VeraCrypt, FileVault"
category: forensics
parent: forensics-img-encryption
difficulty: hard
order: 1
tags: [luks, bitlocker, veracrypt, filevault, cryptsetup, encryption, recovery]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery (шифрованные диски)"
  - "Incident Response"
estimated_minutes: 60
summary: "Форензика шифрованных дисков: определение типа шифрования, заголовки LUKS/BitLocker/VeraCrypt/FileVault, извлечение ключей из памяти и TPM, монтирование и восстановление."
---

Полнодисковое шифрование (FDE) — стандарт для ноутбуков и серверов, и в задачах forensics всё чаще попадаются шифрованные образы. «Просто смонтировать» их нельзя: нужен **ключ** или **пароль**. Этот урок — про определение типа шифрования, понимание заголовков, поиск ключей в памяти/TPM и корректное монтирование.

## Определение типа шифрования

Первым делом — понять, чем зашифрован том.

```bash
file disk.img
# -> LUKS encrypted file, ver 1 [aes, xts-plain64, sha256]
# -> BitLocker ... / VeraCrypt ...
# -> "PC encrypted volume" (FileVault / APFS encrypted)

blkid disk.img
# TYPE="crypto_LUKS" | "BitLocker" | "crypto_TCRYPT"(VeraCrypt)

# LUKS
cryptsetup luksDump disk.img | head -30
# BitLocker (Linux: cryptsetup умеет bitlk)
cryptsetup bitlkDump disk.img | head -30
# VeraCrypt
cryptsetup tcryptDump disk.img 2>/dev/null | head -30
```

Признаки:
- **LUKS**: magic `LUKS\xba\xbe` (0x4C554B53BABE) в начале; заголовок с keyslot-ами.
- **BitLocker**: signature `-FVE-FS-` (0x2D4656452D46532D) в boot-секторе.
- **VeraCrypt/TrueCrypt**: нет сигнатуры (стелс), определяется по энтропии/`cryptsetup tcryptDump` с паролем.
- **FileVault (APFS)**: контейнер APFS с зашифрованными томами; ключи в keychain.

## LUKS

LUKS-заголовок хранит:
- **magic**, версию (LUKS1/LUKS2);
- **cipher/mode/hash** (обычно `aes-xts-plain64`, sha256);
- **master key** (зашифрован) — он и расшифровывает данные;
- **keyslots** (обычно 8) — каждый содержит зашифрованный master key; для открытия нужен пароль/ключевой файл keyslot-а;
- **PBKDF** (Argon2/PBKDF2) — медленный вывод ключа.

```bash
cryptsetup luksDump disk.img
#  Version: 2
#  Cipher: aes-xts-plain64
#  PBKDF: argon2id
#  Keyslots: 0,1  (по паролям)

# Открыть с паролем
sudo cryptsetup open disk.img dec
sudo mount -o ro /dev/mapper/dec /mnt/dec

# С ключевым файлом
sudo cryptsetup open --key-file key.bin disk.img dec

# LUKS2: добавить/убрать keyslot, узнать, какие есть
cryptsetup luksDump --dump-master-key disk.img   # если пароль keyslot известен
```

Восстановление заголовка (если повреждён): `cryptsetup luksHeaderBackup`/`luksHeaderRestore`, либо поиск **резервной копии заголовка** — LUKS2 хранит её отдельно (`--header-backup-file`). Если заголовок уничтожен, а данных много — master key иногда можно найти в памяти.

```bash
# Дамп заголовка (до повреждения — для резерва)
sudo cryptsetup luksHeaderBackup disk.img --header-backup-file luks.header
# Восстановление
sudo cryptsetup luksHeaderRestore disk.img --header-backup-file luks.header
```

## BitLocker

BitLocker использует AES (CBC/128 или XTS/256) и **VMK** (Volume Master Key), защищённый:
- паролем (recovery password, 48 цифр);
- TPM (авторазблокировка без ввода);
- ключевым файлом на USB (`.BEK`);
- recovery key.

`cryptsetup` (≥2.0) умеет открывать BitLocker через `bitlk`:

```bash
cryptsetup bitlkDump disk.img
#  Version: 2
#  Cipher: aes-xts
#  Key: ... 
#  Created: ...
#  Protection: Password / Recovery / TPM

# Открыть recovery-паролем (48 цифр)
sudo cryptsetup bitlkOpen disk.img bl
sudo mount -o ro /dev/mapper/bl /mnt/bl

# Открыть .BEK-файлом (нужен для того же тома)
sudo cryptsetup bitlkOpen --key-file startup.bek disk.img bl
```

Recovery-ключ часто находится в:
- `$MFT`/реестре как `BitLocker` metadata;
- файле `.BEK` на USB;
- **AD DS** (если том в домене) — `msFVE-RecoveryInformation`;
- памяти (`windows.bitlocker` в Volatility — если том был разблокирован).

```bash
# Volatility 3: поиск ключей BitLocker в дампе памяти
vol -f mem.raw windows.bitlocker 2>/dev/null || vol -f mem.raw windows.registry.printkey --key "BitLocker"
```

## VeraCrypt / TrueCrypt

VeraCrypt (форк TrueCrypt) использует **отрицаемые** тома и **скрытые** тома. Заголовок не имеет сигнатуры, поэтому `file`/`blkid` могут показать «data». Определяется по энтропии и через `cryptsetup tcryptDump`.

```bash
# VeraCrypt-том (обычный)
cryptsetup tcryptDump --veracrypt disk.img
sudo cryptsetup open --type tcrypt --veracrypt disk.img vc
# Параметры (алгоритм/режим/хеш) должны совпадать с созданными
sudo cryptsetup open --type tcrypt --veracrypt \
  --hash=sha512 --cipher=aes-xts-plain64 disk.img vc

# Скрытый том: сначала открыть внешний, потом внутренний с offset
# (скрытый том лежит внутри внешнего в конце)
```

Ключевой момент: для открытия нужно знать **алгоритм, режим, хеш и длину ключа** — они не всегда стандартные. В CTF подсказка обычно есть в тексте задачи.

## FileVault (macOS)

FileVault 2 использует CoreStorage/APFS + ключи в **keychain** и Secure Enclave. Заголовок — APFS-контейнер с зашифрованными томами.

```bash
# Определить APFS
apfsutil list disk.img          # или через apfs-fuse
# Ключ часто в keychain из бэкапа/образа пользователя
# Инструменты: apfs-fuse, libfvde (fvdeinfo/fvdemount)
sudo apt install -y libfvde-utils
fvdeinfo disk.img | head
sudo fvdemount disk.img /mnt/fv -p <password>
```

`libfvde` (Digital Forensics Framework) — основной инструмент для FileVault.

## Поиск ключей и паролей

Ключи часто «лежат рядом» с шифрованным томом:
- **Память**: если система была разблокирована, master key в RAM. Volatility: `windows.bitlocker`, `linux.luks` (Volatility 3 `linux` плагины), `strings` по дампу.
- **Дамп hibernation** (`hiberfil.sys`) — содержит содержимое RAM на момент сна.
- **Файлы**: `.BEK`, keyfile, заметки, скрипты, `crypttab`.
- **TPM**: если включён автозапуск — ключ «отдаётся» без пароля; эмулируйте TPM или ищите plaintext-ключ в памяти.

```bash
# LUKS master key из памяти (если том разблокирован)
# AES-ключевые расписания выглядят как высокоэнтропийные блоки
strings -n 16 mem.raw | grep -iE 'luks|master'    # грубо, для подсказки

# hiberfil.sys -> RAM
vol -f hiberfil.sys windows.info
```

## Разобранный пример: CTF «LUKS с ключом в памяти»

```bash
# Даны: disk.img (LUKS2) и mem.raw (дамп памяти разблокированной системы)

# 1. Тип шифрования
file disk.img
cryptsetup luksDump disk.img | head

# 2. Пароль в задаче/файле подсказки?
strings disk.img | grep -iE 'pass|key' | head

# 3. Если нет — ключ в памяти
vol -f mem.raw linux.luks 2>/dev/null
# или strings по дампу в поисках пароля
strings -n 6 mem.raw | grep -iE 'luks|password|crypt' | head

# 4. Открыть
sudo cryptsetup open --key-file recovered.key disk.img dec
sudo mount -o ro /dev/mapper/dec /mnt/dec
cat /mnt/dec/flag.txt

# --- BitLocker-вариант ---
cryptsetup bitlkDump disk.img | head
sudo cryptsetup bitlkOpen disk.img bl     # ввести 48-цифр recovery
sudo mount -o ro /dev/mapper/bl /mnt/bl
```

## Частые ошибки

- **Путать LUKS1 и LUKS2** — разный формат заголовка и PBKDF (Argon2 vs PBKDF2).
- **Забывать про keyslot** — пароль от одного keyslot не открывает другой.
- **Открывать VeraCrypt без указания алгоритма/хеша** — параметры должны совпадать.
- **Считать стелс-VeraCrypt «пустым диском»** — энтропия и `tcryptDump` выдают.
- **Не искать recovery key в AD/`$MFT`** — для BitLocker это самый частый путь.
- **Монтировать расшифрованный том read-write** — испортит улики.
- **Игнорировать hiberfil.sys** — там часто ключи.

## Квиз

```quiz
- question: "Какой magic у заголовка LUKS?"
  options:
    - "`-FVE-FS-`"
    - "`LUKS\\xba\\xbe`"
    - "`0xEF53`"
    - "`_BHRfS_M`"
  answer: 1
- question: "Чем `cryptsetup bitlkOpen` открывает BitLocker-том?"
  options:
    - "только TPM"
    - "recovery-паролем или .BEK-файлом"
    - "только мастер-ключом"
    - "ключом LUKS"
  answer: 1
- question: "Почему VeraCrypt-том сложнее определить автоматически?"
  options:
    - "он всегда сжат"
    - "заголовок не имеет сигнатуры (стелс/отрицаемость)"
    - "он использует FAT"
    - "он только для macOS"
  answer: 1
- question: "Где чаще всего найти master key разблокированного LUKS-тома при форензике?"
  options:
    - "в суперблоке ext4"
    - "в дампе оперативной памяти"
    - "в $MFT"
    - "в PCAP"
  answer: 1
- question: "Какой инструмент используют для FileVault?"
  options:
    - "`mdadm`"
    - "`libfvde` (fvdeinfo/fvdemount)"
    - "`cryptsetup tcrypt`"
    - "`ewfmount`"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с шифрованными образами и ключами в памяти.
- **Data recovery:** восстановление доступа к шифрованным дискам.
- **Incident Response:** разбор «залоченных» хостов, поиск recovery-ключей.
- **Судебная экспертиза:** работа с FDE в рамках закона и полномочий.
- **Enterprise:** аудит и восстановление BitLocker/FileVault в организациях.
