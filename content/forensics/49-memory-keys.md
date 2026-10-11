---
id: forensics-memory-keys
title: "Извлечение ключей и паролей из памяти"
category: forensics
parent: forensics-volatility-deep
difficulty: hard
order: 1
tags: [memory, credentials, keys, hashes, lsass, volatility, mimikatz]
prerequisites: [forensics-volatility-deep]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (credential access)"
  - "Penetration testing (post-exploit)"
estimated_minutes: 55
summary: "Поиск учётных данных в дампах памяти: хеши и пароли из LSASS, SAM/registry из памяти, LSA secrets, кэш браузеров, ключи шифрования и токены; инструменты Volatility 3, pypykatz, mimikatz."
---
Дамп памяти — золотая жила для извлечения учётных данных: хеши, пароли, ключи шифрования и токены остаются в памяти в открытом виде. Извлекая их, аналитик понимает, какими учётными записями владел атакующий, и восстанавливает цепочку латерального движения. Этот урок — про LSASS, SAM/реестр из памяти, LSA secrets, кэш браузеров и ключи, с инструментами Volatility, pypykatz и mimikatz.

## Откуда берутся секреты

| Источник | Что содержит |
|----------|-------------|
| `lsass.exe` | хеши NTLM, Kerberos-тикеты, WDigest/SSP-пароли |
| Реестр в памяти | SAM (локальные хеши), SECURITY (LSA secrets) |
| DPAPI | master keys для расшифровки сохранённых паролей |
| Браузеры | пароли/куки в памяти |
| Крипто-ключи | BitLocker, EFS, VPN |
| Токены | access/refresh, сессионные |

## LSASS и хеши

LSASS хранит материал аутентификации. Извлечение — ключевая задача.

```bash
# Volatility: хеши и LSA
$ vol -f mem.raw windows.hashdump
$ vol -f mem.raw windows.lsadump
$ vol -f mem.raw windows.cachedump
# pypykatz по дампу LSASS
$ vol -f mem.raw windows.memmap --pid <lsass_pid> --dump
$ pypykatz lsa minidump lsass.dmp
```

```bash
# дамп LSASS (офлайн-анализ) — инструменты: procdump, comsvcs.dll
$ procdump -ma lsass.exe lsass.dmp
$ pypykatz lsa minidump lsass.dmp
USERNAME: bob
NT: 8846f7eaee8fb117ad06bdd830b7586c
SHA1: ...
WDigest: ...
```

`mimikatz` — классика (на живой системе), `pypykatz` — Python-реализация для офлайн-дампов.

```bash
$ mimikatz # sekurlsa::logonpasswords
$ mimikatz # lsadump::sam
$ mimikatz # lsadump::secrets
```

## SAM и SECURITY из памяти

Volatility умеет достать кусты реестра прямо из памяти:

```bash
$ vol -f mem.raw windows.registry.hivelist
$ vol -f mem.raw windows.registry.printkey --key 'SAM\Domains\Account\Users'
$ vol -f mem.raw windows.hashdump        # локальные хеши из памяти
$ vol -f mem.raw windows.lsadump         # LSA secrets (пароли служб, авто-логин)
```

Хеши NTLM ломаются `hashcat -m 1000`, кэш домена (DCC2) — `-m 2100`.

## DPAPI

DPAPI шифрует сохранённые пароли (браузеры, RDP, WiFi) master key, привязанным к SID/паролю пользователя. Найдя master key и хеш пользователя, можно расшифровать всё.

```bash
$ vol -f mem.raw windows.registry.printkey --key 'Protect\S-1-5-21-...\...'
$ mimikatz # dpapi::masterkey /in:... /sid:... /password:...
$ mimikatz # dpapi::cred /in:... /masterkey:...
```

## Браузеры и приложения

Пароли/куки браузеров хранятся зашифрованными (DPAPI/AES), но ключи бывают в памяти.

```bash
# Chrome: ключ в Local State + база Login Data
$ grep -a 'DPAPI' mem.raw | head          # грубый поиск
$ pypykatz dpapi ...
# инструменты: chrome_decrypt, pypykatz
$ python3 chrome_decrypt.py --local_state LocalState --login_data 'Login Data'
```

## Ключи шифрования

- **BitLocker**: recovery key / VMK могут быть в памяти.
- **EFS**: приватные ключи в памяти.
- **VPN/IPsec**: PSK, сертификаты.

```bash
# BitLocker key из памяти (Volatility 2: bitlocker)
$ vol -f mem.raw windows.bitlocker
$ grep -a 'BitLocker' mem.raw | head
```

## Разобранный пример

Дан `mem.raw`. Нужно извлечь учётные данные.

```bash
# 1. Хеши из памяти
$ vol -f mem.raw windows.hashdump
Administrator:500:...:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1001:...:8846f7eaee8fb117ad06bdd830b7586c:::
# 2. LSA secrets
$ vol -f mem.raw windows.lsadump
[*] DefaultPassword = P@ssw0rd123
# 3. LSASS дамп -> pypykatz
$ vol -f mem.raw windows.memmap --pid 636 --dump
$ pypykatz lsa minidump pid.636.dmp | grep -iE 'username|nt|wdigest'
USERNAME: bob
NT: 8846...
WDigest: Summer2024!
# 4. Ломаем хеши
$ hashcat -m 1000 '8846...' rockyou.txt
8846...:Summer2024!
```

Итог: хеш и WDigest-пароль из LSASS, пароль службы из LSA secrets.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Хеши из памяти | `vol ... windows.hashdump` |
| LSA secrets | `vol ... windows.lsadump` |
| Кэш домена | `vol ... windows.cachedump` |
| LSASS-дамп | `procdump`, `comsvcs.dll`, `vol memmap` |
| Парсинг LSASS | `pypykatz`, `mimikatz` |
| DPAPI | `mimikatz dpapi::` |
| Ломать NTLM | `hashcat -m 1000` |

## Частые ошибки

- **Дамп LSASS на живой системе без прав** — нужен SYSTEM/admin.
- **Забывать про WDigest** — на старых ОС пароль в открытом виде.
- **Не ломать хеши офлайн** — онлайн-брут недопустим.
- **Игнорировать DPAPI** — без master key браузерные пароли не читаются.
- **Считать, что память «устарела»** — секреты живут часами.
- **Не фиксировать источник** каждого секрета.

## Что дальше / решение

Конвейер: `hashdump`/`lsadump` (реестр) → `memmap` LSASS → `pypykatz` → `hashcat` (офлайн) → DPAPI (браузеры). Связка: `forensics-memory` (основы), `forensics-volatility-deep` (плагины), `forensics-registry-hives` (кусты), `forensics-tls-decrypt` (ключи TLS).

## Kerberos-тикеты и Pass-the-Hash

Из памяти извлекаются не только хеши, но и **Kerberos-тикеты** (TGT/TGS), которые позволяют аутентифицироваться без пароля.

```bash
$ mimikatz # sekurlsa::tickets /export
$ mimikatz # sekurlsa::ekeys
# pypykatz: тикеты
$ pypykatz lsa minidump lsass.dmp | grep -i -A5 'Kerberos'
```

Тикеты можно конвертировать в `.kirbi`/`.ccache` и использовать с `Rubeus`/`impacket`. **Pass-the-Hash**: с NTLM-хешем можно аутентифицироваться без пароля (`pth` в mimikatz, `-H` в impacket/netexec). Это делает хеши из памяти критичными.

```bash
# pth (теоретически, на целевой системе)
$ impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c admin@target
```

## Инструменты и их назначение

| Инструмент | Роль |
|-----------|------|
| `vol ... windows.hashdump` | NTLM-хеши из памяти |
| `vol ... windows.lsadump` | LSA secrets |
| `vol ... windows.cachedump` | DCC2-кэш домена |
| `pypykatz` | парсинг LSASS-дампа (офлайн) |
| `mimikatz` | живой дамп и расшифровка |
| `hashcat` | офлайн-подбор |
| `impacket` | использование тикетов/хешей |

```bash
# комбинированный офлайн-разбор
$ vol -f mem.raw windows.memmap --pid <lsass> --dump
$ pypykatz lsa minidump lsass.dmp > secrets.txt
$ grep -iE 'username|NT:|SHA1:|WDigest' secrets.txt
```

## Чек-лист извлечения секретов

1. Определить PID `lsass.exe` (`windows.pslist`).
2. Дамп LSASS (`windows.memmap --dump` или `procdump`).
3. `pypykatz lsa minidump` — хеши, тикеты, WDigest.
4. `windows.hashdump`/`windows.lsadump` — локальные хеши и LSA secrets.
5. Собрать DPAPI master keys и расшифровать браузерные пароли.
6. Проверить наличие BitLocker/EFS/VPN-ключей.
7. Ломать хеши офлайн (`hashcat -m 1000`/`-m 2100`).
8. Зафиксировать IOC и источник каждого секрета.

## Ограничения и нюансы

- **Windows 10/11 + Credential Guard** — LSASS защищён (LSAISO), хеши могут быть недоступны.
- **WDigest** отключён по умолчанию в новых ОС — пароль в открытом виде есть только на старых/настроенных.
- **Дамп памяти со временем деградирует** — чем позже снят, тем меньше секретов.
- **Хеши ≠ пароли** — NTLM можно использовать для PTH, но не всегда восстановить пароль.
- **Юридические ограничения** — секреты пользователей чувствительны; фиксируйте цепочку.

## Краткое резюме

Дамп памяти — богатейший источник учётных данных: NTLM-хеши и Kerberos-тикеты (LSASS), LSA secrets (пароли служб/авто-логин), кэш домена (DCC2), DPAPI master keys (браузерные пароли), ключи шифрования. Инструменты: `vol ... hashdump`/`lsadump`/`cachedump` (реестр из памяти), `pypykatz`/`mimikatz` (LSASS), `hashcat` (офлайн-подбор). Хеши и тикеты позволяют аутентифицироваться (PTH/PTT) без пароля. Учитывайте Credential Guard и то, что секреты со временем исчезают — снимайте память как можно раньше.

## Квиз

```quiz
- question: "Какой процесс Windows хранит NTLM-хеши и Kerberos-билеты в памяти?"
  options:
    - "`explorer.exe`"
    - "`lsass.exe`"
    - "`svchost.exe`"
    - "`winlogon.exe`"
  answer: 1
- question: "Какая утилита разбирает дамп LSASS кроссплатформенно?"
  options:
    - "`mmls`"
    - "`pypykatz`"
    - "`hashcat`"
    - "`ewfmount`"
  answer: 1
- question: "Какой хайв нужен вместе с SAM для расшифровки хешей?"
  options:
    - "`NTUSER.DAT`"
    - "`SYSTEM`"
    - "`SOFTWARE`"
    - "`USRCLASS.DAT`"
  answer: 1
- question: "Какой плагин Volatility даёт локальные хеши из памяти?"
  options:
    - "`windows.netscan`"
    - "`windows.hashdump`"
    - "`windows.malfind`"
    - "`windows.vadinfo`"
  answer: 1
- question: "Почему WDigest делает пароли особенно уязвимыми?"
  options:
    - "шифрует их слабо"
    - "хранит их в LSASS открытым текстом"
    - "пишет их на диск"
    - "удаляет их"
  answer: 1
```

## Где пригодится

- **CTF:** дампы памяти с паролями/хешами/токенами.
- **Incident Response:** оценка утечки учётных данных после компрометации.
- **Пентест:** извлечение кредов для lateral movement (в рамках правил).
- **Threat Hunting:** поиск техник credential access (T1003).
- **Форензика:** восстановление ключей шифрования из памяти.
