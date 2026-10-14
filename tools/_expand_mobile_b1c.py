#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Third expansion: push batch-1 mobile lessons over 1200 real content words."""
import re, os

ROOT = '/home/Serebr1k/learning_tree'


def append(lesson_id, add):
    p = os.path.join(ROOT, 'content/mobile', lesson_id + '.md')
    txt = open(p, encoding='utf-8').read()
    m = re.search(r'^## Квиз\s*$', txt, re.MULTILINE)
    assert m, lesson_id
    txt = txt[:m.start()] + add.strip() + '\n\n' + txt[m.start():]
    open(p, 'w', encoding='utf-8').write(txt)
    print('expanded', lesson_id)


append('mobile-android-pendingintent', '''
## Шаг 15: чек-лист анализа за минуту

Когда видите PendingIntent в коде, пройдите по короткому списку. Какой метод создания —
`getActivity`, `getService`, `getBroadcast`? Какой флаг мутабельности? Есть ли рядом
`setPackage`, `setComponent`, `setClass`? Куда ведёт базовый Intent — в свой компонент или
наружу? Что лежит в extra и чувствительно ли это? Ответив на пять вопросов, вы почти всегда
сразу понимаете, баг перед вами или безопасный код. Этот же список удобно вставлять в
bug-bounty-репорт как обоснование.
''')

append('mobile-android-accessibility', '''
## Шаг 15: мини-чек-лист

Объявлен ли accessibility-сервис? Какая у него маска событий — узкая или `typeAllMask`?
Читает ли он `TYPE_VIEW_TEXT_CHANGED`? Делает ли сетевые запросы с собранным текстом? Есть
ли автоклик по кнопкам подтверждения? Если на большинство вопросов «да» — перед вами либо
кейлоггер, либо очень плохо спроектированный «помощник». В обоих случаях это находка.
''')

append('mobile-android-fileprovider', '''
## Шаг 16: мини-чек-лист

Найдите провайдер в манифесте: какой authority, включён ли `grantUriPermissions`. Откройте
`file_paths.xml`: есть ли `root-path`, есть ли `path="."`. Затем поищите, кто вызывает
`getUriForFile` и кто принимает внешний URI. Если широкий конфиг сочетается с приёмом
внешнего URI и grant-флагом — это рабочая уязвимость, а не теоретическая.
''')

append('mobile-android-contentprovider-sql', '''
## Шаг 17: мини-чек-лист

Провайдер экспортирован? Как строит SQL — `rawQuery` или `SQLiteQueryBuilder`? Передаются ли
`selectionArgs`? Есть ли `setStrict(true)` и `setProjectionMap`? Проверяется ли `sortOrder`?
Попробуйте `--where "1=1"` и посмотрите, вернутся ли лишние строки. Если да — инъекция
подтверждена, и можно переходить к `UNION` и `sqlite_master`. Этот порядок действий
воспроизводим в любом аудите Android-провайдера.
''')

print('done')
