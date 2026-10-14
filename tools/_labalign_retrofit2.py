#!/usr/bin/env python3
"""Second retrofit batch: chain a prerequisite sub-step into 50 more labs
(rule: lab = lesson + reminder of the path, docs/LABS.md).

Categories (highest value first): web, forensics, crypto, reversing, osint, misc.
For each lesson it (1) appends a `## Повторение (`<prereq-id>`)` block to the
bundle's task.md text and (2) prepends a matching hint to the lesson
front-matter. Only additive edits; the bundle JSON formatting is preserved by
string-replacing the escaped task.md value. Added commands use only *basic*
tools (grep/cat/xxd/file/strings/head/cut/base64/md5sum/curl/python3/unzip) or
tools already present in the lesson, so no new lab-tool-untaught flag appears.
"""
import json
import os
import re
import sys

# id -> (prereq-id referenced, appended task.md block, new hint line)
EDITS = [
    # ------------------------------------------------------------------ web
    ("db-postgresql", "web-sqli",
     "\n## Повторение (`web-sqli`)\n\n"
     "Прежде чем дампить `secrets`, повтори из `web-sqli` самый первый шаг — "
     "**фингерпринт диалекта**. Подставь одиночную кавычку и прочитай текст ошибки:\n\n"
     "    curl -s \"http://shop.example/item?id=1'\" | grep -o 'ERROR:[^<]*'\n\n"
     "`unterminated quoted string` выдаёт именно PostgreSQL — от диалекта зависит "
     "весь дальнейший синтаксис (`||`, `string_agg`, комментарий `-- -`).\n",
     "Повторение (`web-sqli`): сначала фингерпринт диалекта — "
     "`curl -s \"http://shop.example/item?id=1'\"`; `unterminated quoted string` = PostgreSQL."),
    ("db-mssql", "web-sqli",
     "\n## Повторение (`web-sqli`)\n\n"
     "Прежде чем звать `xp_cmdshell`, вспомни из `web-sqli` первый шаг — "
     "**определение СУБД по ошибке**. Подставь кавычку в параметр:\n\n"
     "    curl -s \"http://portal.example/user?id=1'\"\n\n"
     "`Unclosed quotation mark` и `@@version` — признаки MSSQL; только после этого "
     "переходи к `-- -`, `CAST` и системным процедурам.\n",
     "Повторение (`web-sqli`): сначала фингерпринт — "
     "`curl -s \"http://portal.example/user?id=1'\"`; `Unclosed quotation mark` = MSSQL."),
    ("db-oracle", "web-sqli",
     "\n## Повторение (`web-sqli`)\n\n"
     "Прежде чем строить OOB-канал, вернись к первому шагу из `web-sqli` — "
     "**узнать диалект по ошибке**. Подставь кавычку:\n\n"
     "    curl -s \"http://erp.example/report?id=1'\"\n\n"
     "`ORA-01756` — это Oracle; помни, что тут `FROM dual`, а строку склеивает "
     "`||`/`LISTAGG`, а не `CONCAT`.\n",
     "Повторение (`web-sqli`): сначала фингерпринт — "
     "`curl -s \"http://erp.example/report?id=1'\"`; `ORA-01756` = Oracle."),
    ("db-sqlite", "web-sqli",
     "\n## Повторение (`web-sqli`)\n\n"
     "Первый шаг из `web-sqli` — **фингерпринт по ошибке** — здесь так же обязателен. "
     "Подставь кавычку:\n\n"
     "    curl -s \"http://shop.example/product?id=1'\"\n\n"
     "`unrecognized token` — характерная ошибка SQLite; метаданные тут лежат не в "
     "`information_schema`, а в `sqlite_master`.\n",
     "Повторение (`web-sqli`): сначала фингерпринт — "
     "`curl -s \"http://shop.example/product?id=1'\"`; `unrecognized token` = SQLite."),
    ("db-elasticsearch", "web-nosql-injection",
     "\n## Повторение (`web-nosql-injection`)\n\n"
     "Elasticsearch — не SQL, а HTTP-API; как и в `web-nosql-injection`, сначала "
     "**опроси корень сервиса** и проверь, что авторизации нет:\n\n"
     "    curl -s http://shop.local:9200/\n\n"
     "Если в ответе нет `security_exception` — кластер открыт, и дальше можно просто "
     "перечислять индексы.\n",
     "Повторение (`web-nosql-injection`): сначала `curl -s http://shop.local:9200/` — "
     "нет `security_exception` = открытый кластер."),
    ("db-other", "web-nosql-injection",
     "\n## Повторение (`web-nosql-injection`)\n\n"
     "Хранилища из длинного хвоста тоже отдают HTTP-API; в `web-nosql-injection` ты "
     "начинал с **проверки доступа к корню**. Здесь — CouchDB:\n\n"
     "    curl -s http://10.10.10.42:5984/\n\n"
     "Ответ с `\"couchdb\"` и без запроса пароля — это «admin party», с которого "
     "начинается дамп.\n",
     "Повторение (`web-nosql-injection`): сначала `curl -s http://10.10.10.42:5984/` — "
     "ответ без auth = admin party."),
    ("web-cookies-sessions", "web-http-basics",
     "\n## Повторение (`web-http-basics`)\n\n"
     "Cookie — это заголовок `Set-Cookie` в ответе и `Cookie` в следующем запросе "
     "(анатомия запроса — из `web-http-basics`). Сначала посмотри, какой идентификатор "
     "сессии выдаёт сервер ещё до входа:\n\n"
     "    curl -s -i https://shop.local/ -c jar.txt | grep -i 'set-cookie'\n\n"
     "Если этот же `session` остаётся валидным после логина жертвы — перед тобой "
     "фиксация сессии.\n",
     "Повторение (`web-http-basics`): cookie — это заголовок; сначала "
     "`curl -s -i https://shop.local/ -c jar.txt | grep -i set-cookie`."),
    ("web-host-header", "web-waf-bypass",
     "\n## Повторение (`web-waf-bypass`)\n\n"
     "В `web-waf-bypass` ключевая мысль — фильтр проверяет один слой, а бэкенд "
     "доверяет другому. Сначала зафиксируй базовый ответ, чтобы видеть разницу:\n\n"
     "    curl -s -i 'http://shop.local/admin' | head -n 1\n\n"
     "Теперь подставь внутренний хост в `X-Forwarded-Host` — доверие к заголовку "
     "и есть обход.\n",
     "Повторение (`web-waf-bypass`): сначала зафиксируй `curl -s -i 'http://shop.local/admin'` "
     "(403), потом подменяй `X-Forwarded-Host`."),
    ("web-http-parameter-pollution", "web-waf-bypass",
     "\n## Повторение (`web-waf-bypass`)\n\n"
     "HPP — это расхождение парсеров из `web-waf-bypass`: WAF и приложение читают один "
     "ввод по-разному. Сначала зафиксируй «нормальный» запрос в пределах лимита:\n\n"
     "    curl -s 'http://shop.local/transfer?amount=100'\n\n"
     "Затем продублируй параметр: WAF проверит первое значение, а приложение возьмёт "
     "последнее.\n",
     "Повторение (`web-waf-bypass`): WAF и приложение парсят ввод по-разному; сначала "
     "`curl -s 'http://shop.local/transfer?amount=100'`."),
    ("web-idor-uuid", "web-auth-jwt-idor",
     "\n## Повторение (`web-auth-jwt-idor`)\n\n"
     "Горизонтальный IDOR — отсутствие проверки владельца, как в `web-auth-jwt-idor`. "
     "Сначала попроси **свой** объект, чтобы зафиксировать формат ответа:\n\n"
     "    curl -s http://vuln.lab.local/api/user/1\n\n"
     "Дальше меняется только идентификатор — если сервер отдаёт чужой профиль, "
     "контроля доступа нет.\n",
     "Повторение (`web-auth-jwt-idor`): сначала свой объект "
     "`curl -s http://vuln.lab.local/api/user/1`, затем соседний id."),
    ("web-jwt-advanced", "web-auth-jwt-idor",
     "\n## Повторение (`web-auth-jwt-idor`)\n\n"
     "Структуру JWT (`header.payload.signature`) ты разбирал в `web-auth-jwt-idor`. "
     "Сначала декодируй свой токен из `token.txt` и выпиши `alg` и `role`:\n\n"
     "    cut -d. -f2 token.txt | base64 -d\n\n"
     "Если сервер не проверяет подпись, а только читает `alg`, токен можно "
     "подделать — это и есть `alg: none`.\n",
     "Повторение (`web-auth-jwt-idor`): сначала декодируй payload — "
     "`cut -d. -f2 token.txt | base64 -d`; выпиши `alg` и `role`."),
    ("web-ldap-injection", "web-nosql-ldap-xpath",
     "\n## Повторение (`web-nosql-ldap-xpath`)\n\n"
     "LDAP-фильтр — скобочное выражение `(&(uid=...)(userPassword=...))`, как в "
     "`web-nosql-ldap-xpath`. Сначала подай заведомо неверный пароль и зафиксируй "
     "ответ:\n\n"
     "    curl -s -X POST http://portal.corp.local/login --data 'username=alice&password=wrong'\n\n"
     "Дальше wildcard `*` в поле логина покажет, существует ли пользователь, — "
     "оттуда строится обход аутентификации.\n",
     "Повторение (`web-nosql-ldap-xpath`): фильтр = скобочное выражение; сначала "
     "`curl -s -X POST http://portal.corp.local/login --data 'username=alice&password=wrong'`."),
    ("web-file-upload-advanced", "web-file-upload",
     "\n## Повторение (`web-file-upload`)\n\n"
     "В `web-file-upload` ты обходил фильтр по расширению; здесь фильтр смотрит "
     "**magic bytes**. Сначала убедись, что полиглот начинается с сигнатуры GIF, "
     "иначе загрузку отобьют:\n\n"
     "    xxd -l 8 shell.gif\n\n"
     "`GIF89a` в первых байтах — и проверка по сигнатуре пройдена, хотя внутри файла "
     "PHP-код.\n",
     "Повторение (`web-file-upload`): сначала `xxd -l 8 shell.gif` — `GIF89a` в начале "
     "обходит проверку magic bytes."),
    ("web-graphql-deep", "web-api-rest-graphql-soap",
     "\n## Повторение (`web-api-rest-graphql-soap`)\n\n"
     "GraphQL — один `POST /graphql` с телом-запросом, как в "
     "`web-api-rest-graphql-soap`. Сначала спроси саму схему (introspection), "
     "чтобы увидеть поля:\n\n"
     "    curl -s -G http://vuln.lab.local/graphql --data-urlencode 'query={__schema{queryType{name}}}'\n\n"
     "Типы из ответа подскажут, где искать скрытое поле с флагом.\n",
     "Повторение (`web-api-rest-graphql-soap`): GraphQL — один эндпоинт; сначала "
     "introspection `query={__schema{queryType{name}}}`."),

    # ------------------------------------------------------------ forensics
    ("af-metadata-scrubbing", "forensics-metadata",
     "\n## Повторение (`forensics-metadata`)\n\n"
     "Прежде чем «стирать паспорт» файла, вспомни из `forensics-metadata`, где этот "
     "паспорт лежит: расширение врёт, а тип и метки видны по содержимому. Начни с "
     "осмотра:\n\n"
     "    file photo.jpg && strings photo.jpg | head\n\n"
     "Так ты увидишь, какие поля вообще есть (EXIF и прочее), — именно их потом и "
     "предстоит вычистить.\n",
     "Повторение (`forensics-metadata`): сначала `file photo.jpg && strings photo.jpg | head` — "
     "осмотри, какие поля есть до стирания."),
    ("af-secure-delete", "forensics-deleted-recovery",
     "\n## Повторение (`forensics-deleted-recovery`)\n\n"
     "Смысл `forensics-deleted-recovery` — обычное удаление не затирает данные: байты "
     "остаются в невыделенном месте. Прежде чем рассуждать о стирании, убедись, что "
     "следы ещё на месте:\n\n"
     "    strings disk.img | head\n\n"
     "Если строки видны — «удалённый» файл никуда не делся; secure delete нужен именно "
     "против этого.\n",
     "Повторение (`forensics-deleted-recovery`): удаление не затирает — сначала "
     "`strings disk.img | head`, следы на месте."),
    ("af-artifact-destruction", "forensics-windows-artifacts",
     "\n## Повторение (`forensics-windows-artifacts`)\n\n"
     "Журнал EVTX ты разбирал в `forensics-windows-artifacts`: записи идут с "
     "последовательными `record ID`. Здесь проверяется, что заметание следов "
     "оставляет **разрыв** в нумерации. Сначала посмотри данные:\n\n"
     "    cat evtx-gap.txt\n\n"
     "Пропущенный record ID и есть след уничтожения артефакта.\n",
     "Повторение (`forensics-windows-artifacts`): EVTX-записи нумеруются подряд; сначала "
     "`cat evtx-gap.txt`, ищи разрыв record ID."),
    ("forensics-file-magic", "forensics-intro",
     "\n## Повторение (`forensics-intro`)\n\n"
     "Главный принцип из `forensics-intro`: **расширение врёт, верь байтам**. Прежде "
     "чем что-то распаковывать, определи реальный тип файла по сигнатуре:\n\n"
     "    xxd -l 16 evidence.dat\n\n"
     "Первые байты и есть настоящий «паспорт» формата — от них зависит, чем открывать "
     "образец.\n",
     "Повторение (`forensics-intro`): расширение врёт — сначала "
     "`xxd -l 16 evidence.dat`, определи формат по сигнатуре."),
    ("forensics-disk-images", "forensics-filesystems",
     "\n## Повторение (`forensics-filesystems`)\n\n"
     "Таблицу разделов и разметку ФС ты разбирал в `forensics-filesystems`. Прежде чем "
     "монтировать раздел, найди его запись в MBR — тип `0x83` и LBA:\n\n"
     "    xxd -s 446 -l 16 disk.img\n\n"
     "Четыре байта LBA по смещению 454 дают начало раздела — это вход в дальнейший "
     "разбор.\n",
     "Повторение (`forensics-filesystems`): сначала найди запись раздела — "
     "`xxd -s 446 -l 16 disk.img`, LBA по смещению 454."),
    ("forensics-ext4-journal", "forensics-filesystems",
     "\n## Повторение (`forensics-filesystems`)\n\n"
     "Разметку ext4 (суперблок, дескрипторы групп, inode-таблица) ты разбирал в "
     "`forensics-filesystems`. Прежде чем идти в журнал, найди суперблок — он всегда "
     "лежит по смещению 1024:\n\n"
     "    xxd -s 1024 -l 64 disk.img\n\n"
     "Дальше путь тот же, что в уроке-предшественнике: суперблок → дескриптор группы "
     "→ inode → extent-дерево.\n",
     "Повторение (`forensics-filesystems`): суперблок ext4 — по смещению 1024; сначала "
     "`xxd -s 1024 -l 64 disk.img`."),
    ("forensics-fat", "forensics-filesystems",
     "\n## Повторение (`forensics-filesystems`)\n\n"
     "FAT — одна из ФС, разобранных в `forensics-filesystems`: загрузочный сектор, "
     "таблицы FAT, корневой каталог. Прежде чем собирать LFN, посмотри загрузочный "
     "сектор:\n\n"
     "    xxd -l 64 fat16.img\n\n"
     "По нему видны параметры BPB (размер сектора, кластера, число FAT) — без них "
     "разбор корневого каталога не сойдётся.\n",
     "Повторение (`forensics-filesystems`): сначала `xxd -l 64 fat16.img` — параметры "
     "BPB из загрузочного сектора."),
    ("forensics-exfat", "forensics-fat",
     "\n## Повторение (`forensics-fat`)\n\n"
     "exFAT — родственник FAT, разобранного в `forensics-fat`, но с другой сигнатурой "
     "загрузочного сектора. Сначала определи ФС именно по загрузочному сектору, а не "
     "по расширению:\n\n"
     "    xxd -l 64 sdcard.img\n\n"
     "Ищи сигнатуру `EXFAT` в начале — это отличает её от FAT12/16/32 из предыдущего "
     "урока.\n",
     "Повторение (`forensics-fat`): сначала `xxd -l 64 sdcard.img` — сигнатура `EXFAT` "
     "в загрузочном секторе."),
    ("forensics-evtx-deep", "forensics-windows-artifacts",
     "\n## Повторение (`forensics-windows-artifacts`)\n\n"
     "EVTX как формат разбирался в `forensics-windows-artifacts`: файл-заголовок, "
     "чанки, записи с BinXML. Прежде чем писать парсер, посмотри заголовок файла и "
     "убедись в сигнатуре:\n\n"
     "    xxd -l 16 Security.evtx\n\n"
     "`ElfFile\\0` — сигнатура EVTX; от неё строится разбор чанков и записей.\n",
     "Повторение (`forensics-windows-artifacts`): сначала `xxd -l 16 Security.evtx` — "
     "сигнатура EVTX `ElfFile\\0`."),
    ("forensics-browser", "forensics-windows-artifacts",
     "\n## Повторение (`forensics-windows-artifacts`)\n\n"
     "Артефакты Windows (реестр, EVTX, MFT) ты разбирал в `forensics-windows-artifacts`; "
     "браузерная история — из той же семьи «данные приложения». Сначала определи, что "
     "за файл перед тобой, — SQLite-база:\n\n"
     "    file History\n\n"
     "Дальше — тем же принципом, что и в предшественнике: сначала понять формат, потом "
     "читать записи.\n",
     "Повторение (`forensics-windows-artifacts`): сначала `file History` — определи, что "
     "это SQLite-база, прежде чем читать."),
    ("forensics-hibernation", "forensics-win-volatile",
     "\n## Повторение (`forensics-win-volatile`)\n\n"
     "Волатильные артефакты Windows ты разбирал в `forensics-win-volatile`: память и её "
     "следы на диске. `hiberfil.sys` — ровно такой след. Сначала проверь сигнатуру, "
     "чтобы убедиться, что это образ памяти:\n\n"
     "    xxd -l 32 hiberfil.sys\n\n"
     "Дальше — тот же порядок: заголовок, затем разбор содержимого.\n",
     "Повторение (`forensics-win-volatile`): `hiberfil.sys` — след памяти на диске; "
     "сначала `xxd -l 32 hiberfil.sys`."),
    ("forensics-ads", "forensics-win-deep",
     "\n## Повторение (`forensics-win-deep`)\n\n"
     "Глубокие артефакты NTFS разбирались в `forensics-win-deep`; Alternate Data "
     "Streams — один из способов спрятать данные в том же файле. Сначала посмотри "
     "листинг с потоками:\n\n"
     "    cat dir_r.txt\n\n"
     "Строка с `:secret` в конце имени файла — это и есть дополнительный поток, "
     "которого не видно в обычном `ls`.\n",
     "Повторение (`forensics-win-deep`): сначала `cat dir_r.txt` — ищи имя с `:secret` "
     "(ADS), невидимый в обычном листинге."),

    # --------------------------------------------------------------- crypto
    ("crypto-aes-structure", "crypto-aes-modes",
     "\n## Повторение (`crypto-aes-modes`)\n\n"
     "S-box — сердце AES, режимы которого (ECB/CBC/CTR) ты разбирал в "
     "`crypto-aes-modes`. Прежде чем реализовывать инверсию в GF(2^8), перечитай "
     "параметры поля:\n\n"
     "    cat notes.txt\n\n"
     "Полином `0x11b`, инверсия как `a^254`, affine с константой `0x63` — всё это уже "
     "фигурировало в разборе режимов, теперь нужно изнутри.\n",
     "Повторение (`crypto-aes-modes`): сначала `cat notes.txt` — полином GF(2^8) "
     "`0x11b`, инверсия `a^254`, affine `0x63`."),
    ("crypto-cbc-bitflip", "crypto-aes-modes",
     "\n## Повторение (`crypto-aes-modes`)\n\n"
     "Идею CBC (цепочка блоков, XOR с предыдущим шифртекстом) ты разбирал в "
     "`crypto-aes-modes`. Сначала посмотри параметры задачи и вспомни, почему правка "
     "байта в блоке N меняет блок N+1:\n\n"
     "    cat notes.txt\n\n"
     "Затем правь байты первого блока, чтобы контролируемо исказить открытый текст "
     "второго.\n",
     "Повторение (`crypto-aes-modes`): CBC = XOR с предыдущим блоком; сначала "
     "`cat notes.txt`, затем правь байты первого блока."),
    ("crypto-ecb-oracle", "crypto-aes-modes",
     "\n## Повторение (`crypto-aes-modes`)\n\n"
     "ECB — «режим-телефонная книга» из `crypto-aes-modes`: одинаковые блоки открытого "
     "текста дают одинаковый шифртекст. Сначала прочитай контракт оракула и убедись, "
     "что он именно ECB:\n\n"
     "    cat oracle.py\n\n"
     "Дальше эксплуатируй ровно это свойство — повторяющиеся блоки выдают структуру.\n",
     "Повторение (`crypto-aes-modes`): ECB даёт одинаковые блоки для одинакового текста; "
     "сначала `cat oracle.py` — проверь режим."),
    ("crypto-gcm", "crypto-aes-modes",
     "\n## Повторение (`crypto-aes-modes`)\n\n"
     "GCM — режим счётчика, который ты видел в `crypto-aes-modes`: keystream зависит от "
     "ключа и nonce. Сначала посмотри на шифртекст и вспомни, что даёт повтор nonce:\n\n"
     "    cat ct1.hex\n\n"
     "При одном и том же nonce keystream совпадает — XOR двух шифртекстов снимает его "
     "и обнажает XOR открытых текстов.\n",
     "Повторение (`crypto-aes-modes`): GCM = CTR; повтор nonce даёт одинаковый keystream — "
     "сначала `cat ct1.hex`."),
    ("crypto-hmac", "crypto-hashing",
     "\n## Повторение (`crypto-hashing`)\n\n"
     "HMAC строится на хэше; хэши (MD5/SHA, length-extension) ты разбирал в "
     "`crypto-hashing`. Сначала посмотри сообщение и MAC, чтобы понять формат проверки:\n\n"
     "    cat message.txt && cat mac.txt\n\n"
     "Затем перебирай ключи из `wordlist.txt`, сравнивая `HMAC-SHA256(key, msg)` с "
     "`mac.txt`.\n",
     "Повторение (`crypto-hashing`): HMAC = хэш с ключом; сначала "
     "`cat message.txt && cat mac.txt`, затем словарь `wordlist.txt`."),
    ("crypto-encoding-deep", "crypto-encodings",
     "\n## Повторение (`crypto-encodings`)\n\n"
     "Кодировки base16/32/64/85 ты разбирал в `crypto-encodings`; здесь их **склеили в "
     "цепочку**. Сначала определи внешний слой по алфавиту:\n\n"
     "    cat encoded.txt\n\n"
     "`A-Z2-7` (без цифр 0/1) — это base32; значит снимать слои надо снаружи внутрь.\n",
     "Повторение (`crypto-encodings`): сначала `cat encoded.txt` — алфавит `A-Z2-7` = "
     "base32, снимай слои снаружи внутрь."),
    ("crypto-classical", "crypto-intro",
     "\n## Повторение (`crypto-intro`)\n\n"
     "Основы крипто-CTF (кодирование ≠ шифрование, перебор малых пространств) ты прошёл "
     "в `crypto-intro`. Сначала осмотри шифртекст и оцени пространство ключей:\n\n"
     "    cat cipher.txt\n\n"
     "Для Цезаря ключей всего ~95 (печатный ASCII) — его не «ломают» анализом, а "
     "перебирают.\n",
     "Повторение (`crypto-intro`): сначала `cat cipher.txt`; у Цезаря ~95 ключей — "
     "перебор, а не анализ."),
    ("crypto-diffie-hellman", "crypto-number-theory",
     "\n## Повторение (`crypto-number-theory`)\n\n"
     "Модульную арифметику и дискретный логарифм ты разбирал в `crypto-number-theory`. "
     "Сначала выпиши параметры и оцени размер `p`:\n\n"
     "    cat p.txt && cat g.txt && cat h.txt\n\n"
     "Если `p` помещается в 20 бит — дискретный логарифм берётся перебором, и весь DH "
     "рушится.\n",
     "Повторение (`crypto-number-theory`): сначала `cat p.txt && cat g.txt && cat h.txt`; "
     "малый `p` = перебор дискретного логарифма."),

    # ------------------------------------------------------------- reversing
    ("reversing-android-apk", "reversing-managed-dotnet-java",
     "\n## Повторение (`reversing-managed-dotnet-java`)\n\n"
     "Managed-код (.NET/Java) ты разбирал в `reversing-managed-dotnet-java`: он "
     "компилируется в байт-код с богатой метаинформацией. APK — тот же managed-мир "
     "(DEX). Сначала посмотри, что это ZIP-контейнер:\n\n"
     "    unzip -l small.apk\n\n"
     "Дальше — как в предшественнике: найти байт-код (`classes.dex`) и вытащить из "
     "него строки.\n",
     "Повторение (`reversing-managed-dotnet-java`): APK — managed-контейнер; сначала "
     "`unzip -l small.apk`."),
    ("reversing-apk-structure", "reversing-android-apk",
     "\n## Повторение (`reversing-android-apk`)\n\n"
     "Каркас APK ты вскрывал в `reversing-android-apk` (`unzip -l` и строки из "
     "`classes.dex`). Прежде чем разбирать манифест и ресурсы, вспомни, что APK — ZIP:\n\n"
     "    unzip -l app.apk\n\n"
     "Дальше ищи `AndroidManifest.xml` и `resources.arsc` — от них зависит вся "
     "анатомия.\n",
     "Повторение (`reversing-android-apk`): APK = ZIP; сначала `unzip -l app.apk`, затем "
     "манифест и ресурсы."),
    ("reversing-6502-8bit", "reversing-asm",
     "\n## Повторение (`reversing-asm`)\n\n"
     "Читать машинный код как инструкции ты учился в `reversing-asm`; 6502 — та же "
     "логика, другой набор команд. Сначала определи формат контейнера по сигнатуре:\n\n"
     "    file game.nes\n\n"
     "`NES<EOF>` в начале — заголовок iNES; только потом смотри код в `xxd`.\n",
     "Повторение (`reversing-asm`): сначала `file game.nes` — сигнатура iNES, затем "
     "разбор кода."),
    ("reversing-architectures", "reversing-asm",
     "\n## Повторение (`reversing-asm`)\n\n"
     "Чтение ассемблера x86-64 ты осваивал в `reversing-asm`; здесь та же задача, но "
     "для другой ISA. Сначала посмотри сырые байты и убедись, что ELF-магии нет:\n\n"
     "    xxd blob.bin | head\n\n"
     "Отсутствие `7f 45 4c 46` (ELF) означает «сырой» машинный код — дальше определяй "
     "архитектуру по опкодам.\n",
     "Повторение (`reversing-asm`): сначала `xxd blob.bin | head` — нет ELF-магии, "
     "значит сырой код; определяй ISA."),
    ("reversing-anti-disassembly", "reversing-obfuscation",
     "\n## Повторение (`reversing-obfuscation`)\n\n"
     "Обфускацию и искажение потока управления ты разбирал в `reversing-obfuscation`; "
     "anti-disassembly — её близкий родственник. Сначала посмотри байты и найди "
     "подозрительные переходы:\n\n"
     "    xxd -l 32 blob.bin\n\n"
     "Байты `e9`/`e8` (jmp/call) рядом с мусором — типичный приём наложения, из-за "
     "которого линейный дизассемблер сбивается.\n",
     "Повторение (`reversing-obfuscation`): сначала `xxd -l 32 blob.bin` — ищи `e9`/`e8` "
     "и мусор (наложение байтов)."),
    ("reversing-decompiler", "reversing-static-analysis",
     "\n## Повторение (`reversing-static-analysis`)\n\n"
     "Статический анализ (Ghidra/IDA/radare2) ты начинал в `reversing-static-analysis`. "
     "Декомпилированный псевдо-C — его прямой результат. Сначала прочитай код и найди "
     "сравнение с секретом:\n\n"
     "    cat decompiled.c\n\n"
     "`strcmp`/массив байтов рядом с проверкой — то, что в предшественнике ты искал в "
     "дизассемблере, теперь уже декомпилировано.\n",
     "Повторение (`reversing-static-analysis`): сначала `cat decompiled.c` — ищи "
     "`strcmp` с массивом байтов."),

    # ----------------------------------------------------------------- osint
    ("osint-attack-surface", "osint-collection",
     "\n## Повторение (`osint-collection`)\n\n"
     "Сбор активов (домены, поддомены, IP, люди) ты вёл в `osint-collection`. Здесь эти "
     "находки уже сведены в таблицу — начни с её просмотра:\n\n"
     "    cat assets.csv\n\n"
     "Колонки `id`/`parent` позволяют построить карту связей — то, что в предшественнике "
     "собиралось по кусочкам.\n",
     "Повторение (`osint-collection`): сначала `cat assets.csv` — сводка собранных "
     "активов, стройте карту по `id`/`parent`."),
    ("osint-email-enum", "osint-people-search",
     "\n## Повторение (`osint-people-search`)\n\n"
     "Поиск людей по email и утечкам ты разбирал в `osint-people-search`. Здесь тот же "
     "pivot — от адреса к профилю. Сначала возьми адрес:\n\n"
     "    cat email.txt\n\n"
     "Дальше — приём предшественника: по этому email ищут публичные аккаунты (Gravatar "
     "и др.).\n",
     "Повторение (`osint-people-search`): сначала `cat email.txt`, затем pivot email → "
     "профиль, как в предшественнике."),
    ("osint-favicon", "osint-infrastructure",
     "\n## Повторение (`osint-infrastructure`)\n\n"
     "Инфраструктурный фингерпринт (Shodan/Censys/CT) ты изучал в "
     "`osint-infrastructure`; favicon-хэш — один из его приёмов. Сначала посчитай "
     "отпечатки всех трёх иконок и сравни:\n\n"
     "    md5sum shop.ico origin.ico cdn.ico\n\n"
     "Совпадение хэша `origin.ico` с `shop.ico` выдаёт настоящий сервер за CDN — та же "
     "логика «одна организация — одна сигнатура».\n",
     "Повторение (`osint-infrastructure`): сначала "
     "`md5sum shop.ico origin.ico cdn.ico` — совпавший хэш = один сервер."),
    ("osint-metadata", "osint-infrastructure",
     "\n## Повторение (`osint-infrastructure`)\n\n"
     "Цифровые следы инфраструктуры и артефактов ты собирал в `osint-infrastructure`. "
     "Метаданные файла — тот же класс следов. Сначала извлеки их инструментом из "
     "предшественника:\n\n"
     "    exiftool photo.jpg\n\n"
     "Поле `Software`/`GPS` — то, что выдаёт автора и место, как и в разборе "
     "инфраструктурных артефактов.\n",
     "Повторение (`osint-infrastructure`): сначала `exiftool photo.jpg` — метаданные как "
     "цифровой след."),
    ("osint-cert-transparency", "osint-dns-recon",
     "\n## Повторение (`osint-dns-recon`)\n\n"
     "Пассивный поиск поддоменов по DNS ты вёл в `osint-dns-recon`; Certificate "
     "Transparency — параллельный источник тех же имён. Сначала посмотри выгрузку "
     "CT-лога:\n\n"
     "    cat crt.json\n\n"
     "Поле `name_value` содержит имена хостов — их и извлекают тем же приёмом, что "
     "поддомены из DNS.\n",
     "Повторение (`osint-dns-recon`): сначала `cat crt.json` — имена из `name_value`, "
     "тот же класс находок, что поддомены."),
    ("osint-rdap", "osint-whois-asn",
     "\n## Повторение (`osint-whois-asn`)\n\n"
     "WHOIS/ASN-разведку ты разбирал в `osint-whois-asn`; RDAP — её структурированная "
     "(JSON) замена. Сначала сделай запрос записи домена:\n\n"
     "    curl -s https://rdap.verisign.com/com/v1/domain/github.com\n\n"
     "Те же регистрационные поля (ID, даты, регистратор), что в WHOIS, только в "
     "JSON.\n",
     "Повторение (`osint-whois-asn`): RDAP = WHOIS в JSON; сначала "
     "`curl -s https://rdap.verisign.com/com/v1/domain/github.com`."),

    # ------------------------------------------------------------------ misc
    ("misc-archive-tricks", "misc-fileformats",
     "\n## Повторение (`misc-fileformats`)\n\n"
     "В `misc-fileformats` ты учился определять формат по сигнатуре, а не по имени. "
     "Сначала проверь настоящий тип контейнера:\n\n"
     "    xxd -l 8 protected.7z\n\n"
     "`37 7a bc af 27 1c` — сигнатура 7z; только потом смотри пароль в `notes.txt`.\n",
     "Повторение (`misc-fileformats`): сначала `xxd -l 8 protected.7z` — сигнатура 7z "
     "`37 7a bc af 27 1c`."),
    ("misc-encoding-chains", "misc-encoding",
     "\n## Повторение (`misc-encoding`)\n\n"
     "Распознавать кодировку по алфавиту и снимать слои ты учился в `misc-encoding`. "
     "Сначала посмотри внешний слой:\n\n"
     "    cat flag.enc\n\n"
     "Определи его по алфавиту, сними — и переходи к следующему; пайпы (`|`) сцепляют "
     "декодеры в одну строку.\n",
     "Повторение (`misc-encoding`): сначала `cat flag.enc`, определи внешнюю кодировку "
     "по алфавиту, снимай слои пайпами."),
    ("misc-exif-deep", "misc-forensics-deep",
     "\n## Повторение (`misc-forensics-deep`)\n\n"
     "Файловую форензику ты вёл в `misc-forensics-deep`; EXIF/XMP — та же работа с "
     "внутренностями формата. Сначала открой дамп тегов и найди служебную метку:\n\n"
     "    grep -i nto meta_dump.txt\n\n"
     "Дамп `meta_dump.txt` — это уже извлечённые поля `photo.jpg`, среди них и спрятана "
     "метка.\n",
     "Повторение (`misc-forensics-deep`): сначала `grep -i nto meta_dump.txt` — метка "
     "среди тегов `photo.jpg`."),
    ("misc-esolang", "misc-intro",
     "\n## Повторение (`misc-intro`)\n\n"
     "Основы Misc-CTF (распознать артефакт и выбрать инструмент) ты проходил в "
     "`misc-intro`. Сначала определи язык программы по виду кода:\n\n"
     "    cat program.txt\n\n"
     "Набор символов `+-<>[].,` — это Brainfuck; дальше запусти интерпретатор `bf`, как "
     "инструмент этой лабы.\n",
     "Повторение (`misc-intro`): сначала `cat program.txt` — опознай язык (набор "
     "`+-<>[].,` = Brainfuck)."),
]


def patch_bundle(lid, block):
    path = f"content/labs/{lid}.json"
    raw = open(path, encoding="utf-8").read()
    b = json.loads(raw)
    entry = None
    for e in b.get("fs", []):
        if str(e.get("path", "")).endswith("task.md"):
            entry = e
            break
    if entry is None:
        print(f"  !! {lid}: no task.md in bundle")
        return False
    old = entry.get("text", "")
    if "## Повторение" in old:
        print(f"  -- {lid}: task.md already has Повторение, skipping")
        return False
    new = old + block
    old_esc = json.dumps(old, ensure_ascii=False)[1:-1]
    new_esc = json.dumps(new, ensure_ascii=False)[1:-1]
    if old_esc not in raw:
        print(f"  !! {lid}: escaped task.md text not found verbatim")
        return False
    raw = raw.replace(old_esc, new_esc, 1)
    json.loads(raw)  # validate
    open(path, "w", encoding="utf-8").write(raw)
    return True


def patch_hint(lid, hint):
    path = None
    for cat in ("web", "forensics", "crypto", "reversing", "osint", "misc"):
        p = f"content/{cat}/{lid}.md"
        if os.path.exists(p):
            path = p
            break
    if path is None:
        print(f"  !! {lid}: lesson md not found")
        return False
    raw = open(path, encoding="utf-8").read()
    if "Повторение (`" in raw:
        print(f"  -- {lid}: lesson already has a Повторение hint")
        return False
    m = re.search(r"^(\s*)hints:\s*$", raw, re.M)
    if not m:
        print(f"  !! {lid}: no hints: block in front-matter")
        return False
    indent = m.group(1) + "  "
    ins = f"{indent}- {json.dumps(hint, ensure_ascii=False)}\n"
    pos = m.end() + 1
    raw = raw[:pos] + ins + raw[pos:]
    open(path, "w", encoding="utf-8").write(raw)
    return True


def main():
    ok = 0
    for lid, prereq, block, hint in EDITS:
        if not os.path.exists(f"content/labs/{lid}.json"):
            print(f"  !! {lid}: bundle missing")
            continue
        a = patch_bundle(lid, block)
        b = patch_hint(lid, hint)
        if a and b:
            ok += 1
            print(f"  ok {lid} <- {prereq}")
    print(f"patched {ok}/{len(EDITS)}")


if __name__ == "__main__":
    main()
