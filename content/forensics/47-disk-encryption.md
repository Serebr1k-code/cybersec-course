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

## Вопрос, с которого всё начинается

У тебя образ `disk.img`, но при монтировании система говорит «unknown filesystem».
Ты заглядываешь в начало файла и видишь не таблицу разделов, а случайные байты.
Это не повреждение — это **полнодисковое шифрование (FDE)**. Данные целы, но
закрыты ключом.

Чтобы их прочитать, нужен **ключ** или **пароль**. В этом уроке мы определим тип
шифрования и найдём ключ там, где его чаще всего теряют, — в дампе памяти.

## Шаг 1: определяем тип шифрования

Первым делом — понять, чем зашифрован том. Инструмент `file` смотрит на сигнатуру:

```bash
$ file disk.img
disk.img: LUKS encrypted file, ver 2 [aes, xts-plain64, sha256]
```

Строка `LUKS` сразу называет систему. `blkid` уточняет метку:

```bash
$ blkid disk.img
disk.img: TYPE="crypto_LUKS"
```

У разных систем свои сигнатуры:

- **LUKS** — magic `LUKS\xba\xbe` в начале файла;
- **BitLocker** — подпись `-FVE-FS-` в загрузочном секторе;
- **VeraCrypt/TrueCrypt** — сигнатуры **нет** (это часть замысла: том выглядит как
  случайные данные);
- **FileVault (macOS)** — контейнер APFS с зашифрованными томами.

## Шаг 2: разбираем заголовок LUKS

Заголовок LUKS — служебная область в начале тома. Он хранит алгоритм, режим и, самое
важное, **master key** (главный ключ) — тот, которым реально зашифрованы данные.
Master key не хранится открыто: он зашифрован в одном из **keyslot**-ов, и чтобы его
достать, нужен пароль (или ключевой файл) от этого keyslot.

```bash
$ cryptsetup luksDump disk.img
Version:        2
Cipher:         aes-xts-plain64
PBKDF:          argon2id
Keyslots:       0, 1
```

Читаем: версия 2, алгоритм AES в режиме XTS, для вывода ключа из пароля используется
**Argon2id** (специально медленная функция — чтобы перебор был дорогим), и открыть
том можно двумя паролями (keyslot 0 и 1).

## Шаг 3: открываем том паролем

Если пароль известен (или найден), открываем:

```bash
$ sudo cryptsetup open disk.img dec
Enter passphrase for disk.img:
$ sudo mount -o ro /dev/mapper/dec /mnt/dec
$ cat /mnt/dec/flag.txt
CTF{luks_header_holds_the_key}
```

`cryptsetup open` расшифровывает master key паролем и создаёт виртуальное устройство
`/dev/mapper/dec`, которое монтируется как обычный диск. Можно передать и ключевой
файл:

```bash
$ sudo cryptsetup open --key-file key.bin disk.img dec
```

## Шаг 4: где искать ключ, если пароля нет

Ключи часто лежат **рядом** с шифрованным томом. Основные места:

- **Дамп памяти**: если система была разблокирована, master key остаётся в
  оперативной памяти. Это самый частый путь в CTF.
- **Дамп гибернации** (`hiberfil.sys`) — по сути, содержимое памяти на момент сна.
- **Файлы**: ключевые файлы, `.BEK` (BitLocker), заметки, `crypttab`.
- **TPM**: если включена авторазблокировка, ключ «отдаётся» без пароля — эмулируйте
  TPM или ищите ключ в памяти.

```bash
$ vol -f mem.raw linux.luks 2>/dev/null
$ strings -n 6 mem.raw | grep -iE 'luks|password|crypt' | head
```

Volatility-плагин `linux.luks` умеет находить master key разблокированного LUKS прямо
в дампе. Если пароль подбирается, восстановленный ключ сохраняют и открывают им том.

## Шаг 5: BitLocker

BitLocker использует AES и **VMK** (Volume Master Key), который защищён одним из
способов: паролем (recovery password из 48 цифр), TPM (авторазблокировка), ключевым
файлом на USB (`.BEK`) или recovery key.

```bash
$ cryptsetup bitlkDump disk.img
Version:      2
Cipher:       aes-xts
Protection:   Password / Recovery / TPM
$ sudo cryptsetup bitlkOpen disk.img bl
$ sudo mount -o ro /dev/mapper/bl /mnt/bl
```

Где искать recovery-ключ:

- в реестре/`$MFT` как метаданные BitLocker;
- в файле `.BEK` на флешке;
- в **Active Directory** (если том в домене) — атрибут `msFVE-RecoveryInformation`;
- в памяти — если том был разблокирован:

```bash
$ vol -f mem.raw windows.bitlocker
```

## Шаг 6: VeraCrypt и FileVault

**VeraCrypt** (форк TrueCrypt) умеет **скрытые** тома и не имеет сигнатуры — том
выглядит как случайные данные. Определяется по высокой энтропии и через
`cryptsetup tcryptDump`. Для открытия нужно знать **алгоритм, режим и хеш** — они
должны совпадать с созданными:

```bash
$ cryptsetup tcryptDump --veracrypt disk.img
$ sudo cryptsetup open --type tcrypt --veracrypt \
    --hash=sha512 --cipher=aes-xts-plain64 disk.img vc
```

**FileVault** (macOS) использует APFS и ключи в keychain. Основной инструмент —
`libfvde`:

```bash
$ fvdeinfo disk.img | head
$ sudo fvdemount disk.img /mnt/fv -p <password>
```

## Шаг 7: резервная копия заголовка

Заголовок LUKS — самое уязвимое место: если его повредить, том открыть нельзя, даже
зная пароль. Поэтому заголовок заранее копируют, а при потере восстанавливают:

```bash
$ sudo cryptsetup luksHeaderBackup disk.img --header-backup-file luks.header
$ sudo cryptsetup luksHeaderRestore disk.img --header-backup-file luks.header
```

В CTF часто поступают наоборот: **сохраняют найденный заголовок**, чтобы можно было
экспериментировать с паролями, не портя оригинал. А если заголовок уничтожен, но
данных много — master key иногда удаётся найти в памяти (см. Шаг 4), потому что
именно он, а не пароль, расшифровывает данные.

## Шаг 8: сводка по системам

| Система | Сигнатура | Ключ ищут | Инструмент |
|---------|-----------|-----------|-----------|
| LUKS | `LUKS\xba\xbe` | пароль/keyslot, память | `cryptsetup` |
| BitLocker | `-FVE-FS-` | recovery, `.BEK`, AD, TPM | `cryptsetup bitlk*` |
| VeraCrypt | нет (стелс) | пароль + точные параметры | `cryptsetup tcrypt` |
| FileVault | APFS-контейнер | keychain | `libfvde` |

## Шаг 9: если ключа нет совсем

Бывает, что ни пароля, ни ключа в памяти, ни recovery-записи нет. Тогда остаётся
несколько путей, и все они ограничены:

- **Перебор пароля** — `cryptsetup open` в цикле с небольшим словарём; медленно из-за
  Argon2, поэтому большие словари бессмысленны. В CTF пароль почти всегда подсказан
  в тексте задачи.
- **Поиск ключа в других дампах** — гибернация, swap-файл, дампы виртуальной машины.
- **Аппаратные атаки** (Cold Boot, DMA) — за рамками офлайн-форензики и часто
  невозможны из-за TPM.

Главный вывод: без ключа FDE не «взламывают» — ключ **ищут**. Поэтому при снятии
данных с включённой системы память сохраняют в первую очередь.

## Что мы теперь знаем

- Тип шифрования определяется по сигнатуре (`file`, `blkid`).
- LUKS хранит master key зашифрованным в keyslot; пароль его разблокирует.
- `cryptsetup open` создаёт устройство `/dev/mapper/...` для монтирования.
- Ключи часто в памяти, гибернации, файлах `.BEK` или в AD.
- BitLocker открывается recovery-паролем или `.BEK`; VeraCrypt требует точных
  параметров; FileVault — через `libfvde`.

## На что смотреть дальше

- **Путать LUKS1 и LUKS2** — разный формат заголовка и разная функция вывода ключа.
- **Забывать про keyslot** — пароль от одного не открывает другой.
- **Открывать VeraCrypt без алгоритма/хеша** — параметры должны совпадать.
- **Считать стелс-VeraCrypt «пустым диском»** — выдаёт высокая энтропия.
- **Монтировать расшифрованный том read-write** — испортите улики.
- **Не искать recovery key в AD** — для BitLocker это самый частый путь.

## Квиз

Проверь себя.

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

## Куда дальше

Мы разобрали, как открыть зашифрованный диск. Дальше займёмся памятью всерьёз:
научимся находить в дампах инъекции кода и руткиты — то, чего нет ни на одном диске.
А пока запомни: **шифрованный том бесполезен без ключа, а ключ чаще всего живёт в
памяти**.

## Где пригодится

- **CTF:** задачи с шифрованными образами и ключами в памяти.
- **Data recovery:** восстановление доступа к шифрованным дискам.
- **Incident Response:** разбор «залоченных» хостов, поиск recovery-ключей.
- **Судебная экспертиза:** работа с FDE в рамках закона и полномочий.
- **Enterprise:** аудит и восстановление BitLocker/FileVault в организациях.
