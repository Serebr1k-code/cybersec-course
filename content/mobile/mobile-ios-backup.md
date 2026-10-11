---
id: mobile-ios-backup
title: "iOS-бэкапы: извлечение и анализ данных без jailbreak"
category: mobile
parent: mobile-ios-advanced
difficulty: medium
order: 1
tags: [ios, backup, itunes, idevicebackup2, manifest, keychain, forensics, no-jailbreak]
prerequisites: [mobile-ios-basics]
useful_for:
  - "Пентест мобильных приложений (iOS)"
  - "Форензика iOS"
  - "Bug bounty iOS"
estimated_minutes: 50
summary: "Как устроен iTunes/Finder-бэкап iOS, как его извлечь (idevicebackup2, iMazing), расшифровать ManifestKeyBag и анализировать содержимое без jailbreak."
---
## Введение

iTunes/Finder-бэкап — легальный способ получить данные iOS-устройства **без jailbreak**. Бэкап содержит песочницы приложений (документы, базы, preferences, Keychain при шифровании), метаданные и манифест с путями. Для пентестера это ценный источник: если приложение хранит токены/пароли в файлах, они окажутся в бэкапе, даже если «приложение защищено». Для форензики — стандартный артефакт.

Важно: современные бэкапы **шифрованные по умолчанию** (пароль задаёт пользователь) — тогда в них попадает и Keychain. Без шифрования Keychain недоступен, но файлы песочницы — да. Мы разберём оба случая.

## Структура бэкапа

Бэкап — это каталог с файлами, названными по SHA1 от домена+пути:

```
Manifest.db        # SQLite: таблица Files(fileID, domain, relativePath, flags)
Manifest.plist     # метаданные: IsEncrypted, Lockdown, Applications
Status.plist       # состояние бэкапа
Info.plist         # версия, устройство
<aa>/<fileID>      # сами файлы (имя = SHA1)
```

`Manifest.db` — ключ к навигации: `fileID` = SHA1(`domain-relativePath`), и по нему находится файл на диске.

```sql
-- извлечь пути приложения
SELECT fileID, domain, relativePath FROM Files
WHERE domain='AppDomain-com.target.app';
```

## Извлечение бэкапа

```bash
# список устройств
idevice_id -l
# сделать бэкап (без шифрования)
idevicebackup2 backup --full ./backup_dir
# шифрованный бэкап (нужен пароль)
idevicebackup2 -i backup --full ./backup_dir   # введёт пароль

# альтернативы: libimobiledevice, iMazing, iTunes/Finder
```

Проверка шифрования:

```bash
plutil -p ./backup_dir/Manifest.plist | grep -i encrypted
# IsEncrypted => true/false
```

## Расшифровка и распаковка

Если бэкап зашифрован, его нужно расшифровать. Инструменты: `iphone-dataprotection`, `iOSbackup`, или скрипты, восстанавливающие ключи из `ManifestKeyBag` (пароль → PBKDF2 → AES-ключи). После расшифровки удобно разложить дерево:

```bash
# iphone_backup_decrypt (Python)
python3 backup_tool.py --backup ./backup_dir --password 'pass' --output ./decrypted
# или iOSbackup
python3 -m iOSbackup -b ./backup_dir -p 'pass' -o ./out
```

Итог — человекочитаемое дерево `AppDomain-com.target.app/Documents/...`.

## Полный сквозной пример: поиск токена в бэкапе

```bash
# 1. Находим файлы приложения
sqlite3 ./backup_dir/Manifest.db \
  "SELECT fileID,relativePath FROM Files WHERE domain='AppDomain-com.target.app';"

# 2. Вычисляем fileID для конкретного пути
echo -n "AppDomain-com.target.app-Library/Preferences/com.target.app.plist" | sha1sum

# 3. Копируем и читаем plist
cp ./backup_dir/ab/abcdef...  ./prefs.plist
plutil -p ./prefs.plist | grep -iE 'token|password|secret'

# 4. Ищем по всем файлам
grep -rIl "eyJ" ./decrypted/ | head        # JWT-подобные
sqlite3 ./decrypted/AppDomain-com.target.app/Library/Application\ Support/db.sqlite ".tables"
```

Так обнаруживаются зашитые/закэшированные токены, cookie, кэш ответов API.

## Keychain в бэкапе

Keychain попадает в бэкап **только если он шифрован**. Артефакт — `KeychainDomain/keychain-2.db`:

```bash
sqlite3 ./decrypted/KeychainDomain/keychain-2.db \
  "SELECT svce,acct,data FROM genp;" | head
```

Значения `data` зашифрованы системным ключом, но при расшифрованном бэкапе доступны через утилиты (`iphone-dataprotection.keychainviewer`). Это ценно для форензики.

## Анализ бэкапа инструментами форензики

`iLEAPP`/`ALEAPP` парсят бэкап/дамп и выдают отчёт (геолокации, сообщения, установленные приложения, cookies). Для iOS:

```bash
python3 ileapp.py -t itunes -i ./backup_dir -o ./ileapp_out
```

Отчёт покажет `AppDomain`-артефакты, `Library/Cookies`, `Library/Caches`, базы приложений.

## Частые ошибки

- **Бэкап «пустой» по приложению**: приложение исключило данные из бэкапа (`NSURLIsExcludedFromBackupKey`) — это правильная защита, находки нет.
- **`Manifest.db` зашифрован**: ожидаемо при encrypted backup — сначала расшифровать.
- **Неверный fileID**: домен/путь в SHA1 должны совпадать символ-в-символ.
- **Игнор `IsEncrypted`**: без пароля часть данных недоступна — не делайте вывод «данных нет».
- **Платные/старые утилиты**: используйте libimobiledevice (свободный набор).
- **Обновление iOS**: структура бэкапа меняется, старые парсеры могут ломаться.

## Что дальше / решение

Бэкап — быстрый способ найти утечки данных без jailbreak. Если нашли секреты в файлах/plist — это находка (небезопасное хранение). Дальше: `mobile-ios-data-protection` (классы защиты), `mobile-ios-keychain` (секреты), `mobile-forensics-ios` (полный дамп). Если нужен полный дамп — jailbreak + checkm8.

## Справочная таблица

| Артефакт | Путь в бэкапе | Что искать |
|----------|---------------|-----------|
| Файлы приложения | `AppDomain-<bundle>` | токены, БД, кэш |
| Preferences | `.../Library/Preferences` | plist с секретами |
| Cookies | `.../Library/Cookies` | сессии |
| Keychain | `KeychainDomain/keychain-2.db` | пароли (если шифрован) |
| Манифест | `Manifest.db` | карта путей |

| Инструмент | Назначение |
|-----------|-----------|
| `idevicebackup2` | создание/восстановление бэкапа |
| `plutil` | чтение plist |
| `sqlite3` | работа с Manifest.db |
| `iLEAPP` | форензик-отчёт |
| `iOSbackup` | расшифровка |

## Расшифровка бэкапа вручную (PBKDF2/AES)

Зашифрованный бэкап защищён паролем, из которого через PBKDF2 выводятся ключи. Схема (упрощённо): `Manifest.plist` содержит `ManifestKey` (зашифрованный AES-ключ манифеста), а пароль → PBKDF2-HMAC-SHA256 (или SHA1) → ключ для расшифровки `ManifestKey`. Понимание схемы нужно, чтобы писать/отлаживать кастомные расшифровщики, когда готовые утилиты не справляются с новой версией iOS.

```python
import hashlib, plistlib
from Crypto.Cipher import AES

# 1. пароль -> ключ (параметры берутся из BackupKeyBag)
def derive(password, salt, iterations, keylen):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, keylen)

# 2. расшифровать ManifestKey (AES-CBC с IV)
# 3. полученным ключом расшифровать каждый файл (AES-CBC)
```

Готовые реализации: `iphone-dataprotection` (`keybag.py`, `backup_tool.py`), `iOSbackup` (Python). Они автоматизируют этот путь и раскладывают дерево.

## Разбор Manifest.db и восстановление дерева

`Manifest.db` — карта бэкапа. Полезные запросы:

```sql
-- домены и количество файлов
SELECT domain, COUNT(*) c FROM Files GROUP BY domain ORDER BY c DESC LIMIT 20;

-- все файлы конкретного приложения
SELECT fileID, relativePath, flags FROM Files
WHERE domain='AppDomain-com.target.app' ORDER BY relativePath;

-- файлы с расширением .db
SELECT relativePath FROM Files WHERE relativePath LIKE '%.db';

-- файлы, помеченные как удалённые (flags)
SELECT relativePath, flags FROM Files WHERE flags & 1 = 1;
```

`fileID` = SHA1(`domain-relativePath`), и путь к файлу в бэкапе — `<первые 2 символа>/<fileID>`. Восстановление дерева:

```bash
sqlite3 Manifest.db "SELECT fileID,domain,relativePath FROM Files" | while IFS='|' read -r id dom path; do
  mkdir -p "restored/$dom/$(dirname "$path")"
  cp "ab/${id:0:2}/$id" "restored/$dom/$path" 2>/dev/null
done
```

## Keychain-артефакты и их расшифровка

При шифрованном бэкапе Keychain лежит в `KeychainDomain/keychain-2.db`. Таблица `genp` (generic passwords) содержит `svce` (сервис), `acct` (аккаунт) и `data` (зашифрованное значение). Для расшифровки нужен ключ класса, извлекаемый из `Keybag` бэкапа:

```bash
sqlite3 KeychainDomain/keychain-2.db "SELECT svce,acct FROM genp;" | head
# расшифровка значения (iphone-dataprotection)
python3 keychain_tool.py -k BackupKeyBag -d KeychainDomain/keychain-2.db
```

Это даёт пароли, токены и ключи, сохранённые приложением в Keychain — самые ценные артефакты пентеста iOS.

## Форензик-инструменты для бэкапа

| Инструмент | Назначение |
|-----------|-----------|
| `idevicebackup2` | создание/восстановление |
| `iOSbackup` | расшифровка бэкапа |
| `iphone-dataprotection` | Keychain + расшифровка |
| `iLEAPP` | форензик-отчёт |
| `iMazing` | GUI-извлечение |

Сквозной конвейер: `idevicebackup2` → расшифровка → разбор `Manifest.db` → `iLEAPP` → выписка артефактов (cookies, preferences, базы, Keychain).

## Юридические и практические заметки

Бэкап устройства может содержать данные третьих лиц (переписка, фото, контакты). В рамках пентеста приложения работайте только с данными целевого приложения (`AppDomain-com.target.app`), не анализируя лишнее. Фиксируйте, что извлечено, и удаляйте копии по завершении. Это часть профессиональной гигиены и требований приватности.

## Типичные находки в бэкапе

- Токены сессии в `Library/Preferences/*.plist` (не в Keychain) — небезопасное хранение.
- SQLite-базы с открытым текстом (`databases/*.db`).
- Cookies сессий (`Library/Cookies/Cookies.binarycookies`).
- Кэш ответов API (`Library/Caches/`) с чувствительными данными.
- Пароли/ключи в Keychain со слабым классом доступности.

Каждая из этих находок маппится на OWASP MASVS-STORAGE и легко демонстрируется в отчёте.

## Глубокий разбор бэкапа: восстановление дерева и поиск секретов

Разберём детально восстановление структуры бэкапа и поиск секретов. `Manifest.db` связывает `fileID` (SHA1 от `domain-relativePath`) с путями. Чтобы найти файлы приложения, запрашиваем по домену:

```sql
SELECT fileID, relativePath, flags FROM Files
WHERE domain='AppDomain-com.target.app' ORDER BY relativePath;
```

`flags` кодирует тип записи (файл/каталог/симлинк) и признак удаления. Удалённые записи (`flags & 1`) иногда содержат данные, помеченные как удалённые, но не стёртые — ценная находка.

Физически файлы лежат в подкаталогах `<aa>/<fileID>`, где `<aa>` — первые два символа fileID. Восстанавливаем дерево скриптом (см. основной урок) и получаем человекочитаемую структуру `AppDomain-com.target.app/Library/...`.

Поиск секретов: рекурсивный grep по JWT (`eyJ`), по ключевым словам (`token`, `secret`, `password`, `api_key`), разбор plist (`plutil -p`), запросы к SQLite (`sqlite3 ... .tables`). Часто токены лежат в `Library/Preferences/*.plist` (не в Keychain) — это небезопасное хранение.

## Keychain при шифрованном бэкапе

Если бэкап шифрован, Keychain доступен. Таблица `genp` в `keychain-2.db` содержит `svce`/`acct`/`data`. Расшифровка значения требует ключа класса из keybag бэкапа; утилиты `iphone-dataprotection` автоматизируют это. Полученные пароли и токены — самые ценные артефакты пентеста iOS.

## Что фиксировать в отчёте

Для каждой находки: путь в бэкапе, тип данных, факт небезопасного хранения, рекомендацию. Отдельно отметьте, попадают ли секреты в бэкап (то есть выгружаются ли они с устройства) — это усиливает находку.

## Квиз

```quiz
- question: "По чему именуются файлы внутри iOS-бэкапа?"
  options:
    - "По имени приложения"
    - "По SHA1 от domain+relativePath"
    - "По дате"
    - "По bundle id"
  answer: 1
- question: "Когда Keychain попадает в бэкап?"
  options:
    - "Всегда"
    - "Только если бэкап шифрован паролем"
    - "Никогда"
    - "Только на jailbreak"
  answer: 1
- question: "Где хранится карта путей бэкапа?"
  options:
    - "Info.plist"
    - "Manifest.db"
    - "Status.plist"
    - "keychain-2.db"
  answer: 1
- question: "Почему данные приложения могут отсутствовать в бэкапе?"
  options:
    - "Приложение исключило их из бэкапа"
    - "iOS их удаляет"
    - "Их нельзя прочитать"
    - "Они всегда в Keychain"
  answer: 0
- question: "Какой инструмент даёт форензик-отчёт по бэкапу iOS?"
  options:
    - "nmap"
    - "iLEAPP"
    - "Burp"
    - "apktool"
  answer: 1
```

## Где пригодится

- **Пентест iOS:** извлечение данных без jailbreak, поиск утечек.
- **Bug bounty:** небезопасное хранение, утечка токенов через бэкап.
- **Форензика:** стандартный артефакт расследования.
- **CTF:** Mobile-задачи с бэкапом.
