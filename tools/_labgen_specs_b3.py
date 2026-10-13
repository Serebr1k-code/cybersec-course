# Batch 3: mobile static-analysis labs. Each seeds a decoded APK/IPA tree (real
# manifest + smali/java/res) and a real task; solutions use coreutils.
WD = '/home/student/task'


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _lab(id, title, files, hints, flag, fs, tools=None, toolset=None, task=None):
    spec = {
        'id': id, 'category': 'mobile', 'title': title,
        'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }
    if task:
        spec['fs'] = [x for x in spec['fs'] if not x['path'].endswith('/task.md')]
        spec['fs'] = [_f(f'{WD}/task.md', task)] + spec['fs']
    if tools:
        spec['tools'] = tools
    return spec


_ANDROID_HEAD = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '    package="com.vanta.app">\n'
    '  <application android:label="@string/app_name" android:debuggable="false">\n'
)

SPECS = [
    # 1. exported components -> secret in the exported activity's meta-data
    _lab(
        'mobile-android-components',
        'Практика: поиск экспортированного компонента',
        ['task.md', 'decoded'],
        [
            'В `decoded/AndroidManifest.xml` перечислены компоненты приложения.',
            'Ищи компоненты, доступные снаружи: атрибут `android:exported="true"`.',
            "У экспортированного компонента есть `meta-data` с секретом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{3xp0rt3d_4ct1v1ty_l34ks}',
        [
            _dir(WD), _dir(f'{WD}/decoded'),
            _f(f'{WD}/decoded/AndroidManifest.xml', _ANDROID_HEAD +
               '    <activity android:name=".ui.MainActivity" android:exported="true">\n'
               '      <intent-filter>\n        <action android:name="android.intent.action.MAIN"/>\n'
               '        <category android:name="android.intent.category.LAUNCHER"/>\n      </intent-filter>\n'
               '    </activity>\n'
               '    <activity android:name=".ui.SettingsActivity" android:exported="false"/>\n'
               '    <activity android:name=".ui.DebugActivity" android:exported="true">\n'
               '      <meta-data android:name="debug.token" android:value="nto{3xp0rt3d_4ct1v1ty_l34ks}"/>\n'
               '    </activity>\n'
               '  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/res/values/strings.xml',
               '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
               '  <string name="app_name">Vanta</string>\n'
               '  <string name="api_key">AIzaSyDECOY0000000000000000000000000000</string>\n'
               '</resources>\n'),
        ],
        task='# Задача: экспортированный компонент\n\nВ `decoded/` лежит распакованный APK. Найди компонент, доступный\n'
             'снаружи (`android:exported="true"`), в котором разработчики оставили секрет.\n'
             'Запиши флаг в `found.txt`.\n',
    ),
    # 2. broadcast receiver
    _lab(
        'mobile-broadcast-receivers',
        'Практика: незащищённый BroadcastReceiver',
        ['task.md', 'decoded'],
        [
            '`decoded/` — распакованный APK. Ищи экспортированные receiver-ы.',
            'Один receiver принимает действие и возвращает секрет через `putExtra`.',
            "Секрет зашит в smali/java этого receiver-а — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{br0adc4st_r3c31v3r_l34k}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app'),
            _f(f'{WD}/decoded/AndroidManifest.xml', _ANDROID_HEAD +
               '    <receiver android:name=".receivers.DebugReceiver" android:exported="true">\n'
               '      <intent-filter>\n        <action android:name="com.vanta.app.DEBUG"/>\n      </intent-filter>\n'
               '    </receiver>\n  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/receivers/DebugReceiver.smali',
               '.class public Lcom/vanta/app/receivers/DebugReceiver;\n'
               '.super Landroid/content/BroadcastReceiver;\n\n'
               '.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V\n'
               '    const-string v0, "token"\n'
               '    const-string v1, "nto{br0adc4st_r3c31v3r_l34k}"\n'
               '    invoke-virtual {p2, v0, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: BroadcastReceiver\n\nВ приложении есть экспортированный `BroadcastReceiver`. Через него утекает\n'
             'секрет. Найди receiver и значение, которое он отдаёт. Запиши флаг в `found.txt`.\n',
    ),
    # 3. deep links / intent filters
    _lab(
        'mobile-intents-deeplinks',
        'Практика: разбор deep-link схемы',
        ['task.md', 'decoded'],
        [
            'Deep-link схема описана в `AndroidManifest.xml` в `<data android:scheme=...>`.',
            'Найди intent-filter, который принимает кастомную схему (не http).',
            "Секрет отдаётся на определённом хосте/пути — найди `nto{` в коде обработчика и запиши в `found.txt`.",
        ],
        'nto{d33pl1nk_h1j4ck_4cc0unt}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/ui'),
            _f(f'{WD}/decoded/AndroidManifest.xml', _ANDROID_HEAD +
               '    <activity android:name=".ui.RouterActivity" android:exported="true">\n'
               '      <intent-filter>\n        <action android:name="android.intent.action.VIEW"/>\n'
               '        <category android:name="android.intent.category.DEFAULT"/>\n'
               '        <category android:name="android.intent.category.BROWSABLE"/>\n'
               '        <data android:scheme="vanta" android:host="auth"/>\n      </intent-filter>\n'
               '    </activity>\n  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/RouterActivity.smali',
               '.class public Lcom/vanta/app/ui/RouterActivity;\n'
               '.method public handle(Landroid/net/Uri;)V\n'
               '    const-string v0, "vanta://auth/callback?token=nto{d33pl1nk_h1j4ck_4cc0unt}"\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: deep-link\n\nПриложение принимает кастомную схему `vanta://`. Разбери манифест, найди\n'
             'обработчик deep-link и секрет, который он передаёт. Запиши флаг в `found.txt`.\n',
    ),
    # 4. intent redirection
    _lab(
        'mobile-intent-redirection',
        'Практика: intent redirection',
        ['task.md', 'decoded'],
        [
            'Компонент получает `Intent` и достаёт из него **вложенный** Intent (`getParcelableExtra`).',
            'Если он запускает вложенный Intent без проверки — это intent redirection.',
            "Секрет лежит в целевом приватном компоненте — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{1nt3nt_r3d1r3ct10n_pr1v4t3}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/ui'),
            _f(f'{WD}/decoded/AndroidManifest.xml', _ANDROID_HEAD +
               '    <activity android:name=".ui.ProxyActivity" android:exported="true"/>\n'
               '    <activity android:name=".ui.SecretActivity" android:exported="false">\n'
               '      <meta-data android:name="secret" android:value="nto{1nt3nt_r3d1r3ct10n_pr1v4t3}"/>\n'
               '    </activity>\n  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/ProxyActivity.smali',
               '.class public Lcom/vanta/app/ui/ProxyActivity;\n'
               '.method public onCreate(Landroid/os/Bundle;)V\n'
               '    const-string v0, "next_intent"\n'
               '    invoke-virtual {p1, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n'
               '    move-result-object v1\n'
               '    invoke-virtual {p0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: intent redirection\n\nЭкспортированный `ProxyActivity` запускает вложенный Intent без проверки. Найди\n'
             'приватный компонент, до которого так можно добраться, и его секрет. Запиши флаг в `found.txt`.\n',
    ),
    # 5. service hijacking
    _lab(
        'mobile-service-hijacking',
        'Практика: экспортированный Service',
        ['task.md', 'decoded'],
        [
            'Ищи экспортированные сервисы в манифесте: `<service ... android:exported="true">`.',
            'Сервис возвращает данные через binder/onBind — в коде есть секрет.',
            "Найди `nto{` в smali сервиса и запиши в `found.txt`.",
        ],
        'nto{s3rv1c3_h1j4ck_b1nd3r}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/svc'),
            _f(f'{WD}/decoded/AndroidManifest.xml', _ANDROID_HEAD +
               '    <service android:name=".svc.SyncService" android:exported="true"/>\n'
               '    <service android:name=".svc.InternalService" android:exported="false"/>\n'
               '  </application>\n</manifest>\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/svc/SyncService.smali',
               '.class public Lcom/vanta/app/svc/SyncService;\n'
               '.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;\n'
               '    const-string v0, "nto{s3rv1c3_h1j4ck_b1nd3r}"\n'
               '    return-object v0\n.end method\n'),
        ],
        task='# Задача: Service hijacking\n\nВ приложении экспортирован сервис. Найди его и секрет, который он отдаёт\n'
             'через binder. Запиши флаг в `found.txt`.\n',
    ),
    # 6. WebView JS bridge
    _lab(
        'mobile-webview-jsbridge',
        'Практика: JS-bridge в WebView',
        ['task.md', 'decoded'],
        [
            'Ищи в коде `addJavascriptInterface` — он открывает нативные методы в JS.',
            'Опасность — если метод отдаёт чувствительные данные.',
            "Найди метод с секретом (`nto{`) и запиши в `found.txt`.",
        ],
        'nto{js_br1dg3_3xp0s3s_n4t1v3}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/web'),
            _f(f'{WD}/decoded/smali/com/vanta/app/web/Bridge.smali',
               '.class public Lcom/vanta/app/web/Bridge;\n'
               '.method public getToken()Ljava/lang/String;\n'
               '    const-string v0, "nto{js_br1dg3_3xp0s3s_n4t1v3}"\n'
               '    return-object v0\n.end method\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/web/WebViewActivity.smali',
               '.class public Lcom/vanta/app/web/WebViewActivity;\n'
               '.method public setup()V\n'
               '    const-string v0, "bridge"\n'
               '    new-instance v1, Lcom/vanta/app/web/Bridge;\n'
               '    invoke-virtual {p0, v1, v0}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: WebView JS-bridge\n\nПриложение открывает веб-страницу во встроенном WebView и прокидывает нативный\n'
             'интерфейс в JS (`addJavascriptInterface`). Найди метод, который отдаёт секрет,\n'
             'и запиши флаг в `found.txt`.\n',
    ),
    # 7. WebView file access
    _lab(
        'mobile-webview',
        'Практика: WebView и доступ к файлам',
        ['task.md', 'decoded'],
        [
            'Опасные настройки WebView: `setAllowFileAccess`, `setJavaScriptEnabled`.',
            'При включённом file-доступе страница может прочитать локальные файлы.',
            "Секрет лежит в `assets/` — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{w3bv13w_f1l3_4cc3ss}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/assets'),
            _f(f'{WD}/decoded/assets/secret.txt', 'internal token: nto{w3bv13w_f1l3_4cc3ss}\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/web/WebViewActivity.smali',
               '.class public Lcom/vanta/app/web/WebViewActivity;\n'
               '.method public setup()V\n'
               '    const/4 v0, 0x1\n'
               '    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V\n'
               '    invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: WebView\n\nWebView приложения включил доступ к файлам и JavaScript. Через него можно\n'
             'прочитать локальные файлы. Найди секрет в `decoded/assets/` и запиши в `found.txt`.\n',
    ),
    # 8. clipboard leak
    _lab(
        'mobile-clipboard',
        'Практика: утечка через буфер обмена',
        ['task.md', 'decoded'],
        [
            'Ищи в коде `ClipboardManager.setPrimaryClip` — данные копируются в общий буфер.',
            'Любое приложение может прочитать буфер обмена.',
            "Найди строку с секретом и запиши `nto{` в `found.txt`.",
        ],
        'nto{cl1pb04rd_1s_w0rld_r34d4bl3}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/util'),
            _f(f'{WD}/decoded/smali/com/vanta/app/util/Clip.smali',
               '.class public Lcom/vanta/app/util/Clip;\n'
               '.method public copy(Landroid/content/Context;)V\n'
               '    const-string v0, "otp"\n'
               '    const-string v1, "nto{cl1pb04rd_1s_w0rld_r34d4bl3}"\n'
               '    invoke-static {v0, v1}, Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: буфер обмена\n\nПриложение копирует OTP в системный буфер обмена. Найди, что именно оно\n'
             'копирует, и запиши флаг в `found.txt`.\n',
    ),
    # 9. screenshot protection
    _lab(
        'mobile-screenshot-protection',
        'Практика: защита от скриншотов (FLAG_SECURE)',
        ['task.md', 'decoded'],
        [
            'От скриншотов защищает флаг окна `WindowManager.LayoutParams.FLAG_SECURE`.',
            'Ищи его в коде: `addFlags(...FLAG_SECURE)` или отсутствие такового.',
            "Экран с секретом **не** выставил FLAG_SECURE — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{scr33nsh0t_fl4g_s3cur3_m1ss1ng}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/ui'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/SecureActivity.smali',
               '.class public Lcom/vanta/app/ui/SecureActivity;\n'
               '.method public onCreate(Landroid/os/Bundle;)V\n'
               '    const/16 v0, 0x2000\n'
               '    invoke-virtual {p0, v0}, Landroid/view/Window;->addFlags(I)V\n'
               '    const-string v1, "balance"\n'
               '    return-void\n.end method\n'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/CardActivity.smali',
               '.class public Lcom/vanta/app/ui/CardActivity;\n'
               '.method public onCreate(Landroid/os/Bundle;)V\n'
               '    const-string v0, "nto{scr33nsh0t_fl4g_s3cur3_m1ss1ng}"\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: FLAG_SECURE\n\nВ приложении есть защищённый экран (`FLAG_SECURE`), а есть экран, где защиту\n'
             'забыли. Найди секрет на незащищённом экране и запиши в `found.txt`.\n',
    ),
    # 10. biometric bypass
    _lab(
        'mobile-biometric',
        'Практика: обход биометрии',
        ['task.md', 'decoded'],
        [
            '`BiometricPrompt.authenticate` принимает `AuthenticationCallback`.',
            'Если `onAuthenticationFailed` не блокирует, а `onAuthenticationSucceeded` логирует секрет — утечка.',
            "Найди `nto{` в обработчике биометрии и запиши в `found.txt`.",
        ],
        'nto{b10m3tr1c_c4llb4ck_byp4ss}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/auth'),
            _f(f'{WD}/decoded/smali/com/vanta/app/auth/BioCallback.smali',
               '.class public Lcom/vanta/app/auth/BioCallback;\n'
               '.method public onAuthenticationSucceeded(Landroidx/biometric/BiometricPrompt$AuthenticationResult;)V\n'
               '    const-string v0, "unlocked token"\n'
               '    const-string v1, "nto{b10m3tr1c_c4llb4ck_byp4ss}"\n'
               '    return-void\n.end method\n'
               '.method public onAuthenticationFailed()V\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: биометрия\n\nРазбери обработчик биометрической аутентификации. Найди секрет, который\n'
             'отдаётся после успеха, и запиши флаг в `found.txt`.\n',
    ),
    # 11. emulator detection
    _lab(
        'mobile-emulator-detection',
        'Практика: детект эмулятора',
        ['task.md', 'decoded'],
        [
            'Детект эмулятора проверяет `Build.FINGERPRINT`, `Build.MODEL`, файлы `qemu`/`goldfish`.',
            'Найди функцию детекта и путь, который она не проверяет.',
            "В коде есть отладочная ветка с секретом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{3mul4t0r_d3t3ct_byp4ss}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/anti'),
            _f(f'{WD}/decoded/smali/com/vanta/app/anti/EmuCheck.smali',
               '.class public Lcom/vanta/app/anti/EmuCheck;\n'
               '.method public isEmulator()Z\n'
               '    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;\n'
               '    const-string v1, "generic"\n'
               '    const-string v2, "nto{3mul4t0r_d3t3ct_byp4ss}"\n'
               '    return v0\n.end method\n'),
        ],
        task='# Задача: детект эмулятора\n\nПриложение проверяет, запущено ли оно на эмуляторе. Найди функцию детекта и\n'
             'секрет в отладочной ветке. Запиши флаг в `found.txt`.\n',
    ),
    # 12. root detection
    _lab(
        'mobile-root-detection',
        'Практика: обход root-детекта',
        ['task.md', 'decoded'],
        [
            'Root-детект ищет `su`, `magisk`, тестовые ключи (`test-keys`).',
            'Обход — переименовать бинарь, скрыть пакет Magisk, спрятать путь.',
            "Секрет зашит рядом с проверкой — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{r00t_d3t3ct_1s_n0t_s3cur1ty}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/anti'),
            _f(f'{WD}/decoded/smali/com/vanta/app/anti/RootCheck.smali',
               '.class public Lcom/vanta/app/anti/RootCheck;\n'
               '.method public isRooted()Z\n'
               '    const-string v0, "/system/xbin/su"\n'
               '    const-string v1, "nto{r00t_d3t3ct_1s_n0t_s3cur1ty}"\n'
               '    return v0\n.end method\n'),
        ],
        task='# Задача: root-детект\n\nНайди функцию проверки root и строку, которую разработчики оставили рядом.\n'
             'Запиши флаг в `found.txt`.\n',
    ),
    # 13. frida detection
    _lab(
        'mobile-frida-detection',
        'Практика: детект Frida',
        ['task.md', 'decoded'],
        [
            'Frida-детект ищет порт 27042, строки `frida`, `gum-js-loop`, `linjector`.',
            'Найди проверку и обойди её (переименование, хукинг).',
            "Секрет лежит в коде рядом с детектом — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{fr1d4_d3t3ct10n_byp4ss}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/anti'),
            _f(f'{WD}/decoded/smali/com/vanta/app/anti/FridaCheck.smali',
               '.class public Lcom/vanta/app/anti/FridaCheck;\n'
               '.method public detect()Z\n'
               '    const-string v0, "frida"\n'
               '    const-string v1, "27042"\n'
               '    const-string v2, "nto{fr1d4_d3t3ct10n_byp4ss}"\n'
               '    return v0\n.end method\n'),
        ],
        task='# Задача: детект Frida\n\nПриложение пытается обнаружить Frida. Найди проверку и секрет, оставленный\n'
             'рядом. Запиши флаг в `found.txt`.\n',
    ),
    # 14. tapjacking
    _lab(
        'mobile-tapjacking',
        'Практика: tapjacking / overlay',
        ['task.md', 'decoded'],
        [
            'Tapjacking возможен, если экран не блокирует наложение окон.',
            'Защита — `setFilterTouchesWhenObscured(true)` или проверка `MotionEvent.FLAG_WINDOW_IS_OBSCURED`.',
            "Экран без защиты содержит секрет — найди `nto{` и запиши в `found.txt`.",
        ],
        'nto{t4pj4ck1ng_0v3rl4y_4tt4ck}',
        [
            _dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/ui'),
            _f(f'{WD}/decoded/smali/com/vanta/app/ui/PayActivity.smali',
               '.class public Lcom/vanta/app/ui/PayActivity;\n'
               '.method public onCreate(Landroid/os/Bundle;)V\n'
               '    const/4 v0, 0x0\n'
               '    invoke-virtual {p0, v0}, Landroid/view/View;->setFilterTouchesWhenObscured(Z)V\n'
               '    const-string v1, "nto{t4pj4ck1ng_0v3rl4y_4tt4ck}"\n'
               '    return-void\n.end method\n'),
        ],
        task='# Задача: tapjacking\n\nЭкран оплаты не блокирует наложение чужих окон. Найди экран, у которого\n'
             'отключена защита, и секрет. Запиши флаг в `found.txt`.\n',
    ),
    # 15. API BOLA
    _lab(
        'mobile-api-bola',
        'Практика: BOLA/IDOR в мобильном API',
        ['task.md', 'api_log.txt', 'notes.txt'],
        [
            '`api_log.txt` — перехваченные запросы мобильного API.',
            'BOLA: объект запрашивается по своему id, а авторизация на сервере не проверяется.',
            "Подмени id чужого объекта в URL и найди ответ с секретом — запиши `nto{` в `found.txt`.",
        ],
        'nto{b0la_1d0r_m0b1l3_4p1}',
        [
            _dir(WD),
            _f(f'{WD}/api_log.txt',
               'GET /api/v1/users/1001/profile  -> 200 {"id":1001,"name":"alice"}\n'
               'GET /api/v1/users/1002/profile  -> 200 {"id":1002,"name":"bob"}\n'
               'GET /api/v1/users/1000/profile  -> 200 {"id":1000,"name":"admin","note":"nto{b0la_1d0r_m0b1l3_4p1}"}\n'
               'GET /api/v1/orders/1001         -> 200 {"order":1001}\n'),
            _f(f'{WD}/notes.txt', 'Запросы делаются от пользователя 1001. Соседние id — чужие объекты.\n'),
        ],
        task='# Задача: BOLA в мобильном API\n\nДан лог перехваченных запросов (`api_log.txt`). Найди объект, доступный\n'
             'пользователю 1001 по чужому id, и секрет в нём. Запиши флаг в `found.txt`.\n',
    ),
    # 16. mass assignment
    _lab(
        'mobile-mass-assignment',
        'Практика: mass assignment в API',
        ['task.md', 'profile.json', 'notes.txt'],
        [
            '`profile.json` — тело запроса на обновление профиля.',
            'Mass assignment: сервер принимает лишние поля (например `role`, `is_admin`).',
            "Добавь поле `role` и найди ответ с флагом — запиши `nto{` в `found.txt`.",
        ],
        'nto{m4ss_4ss1gnm3nt_3sc4l4t10n}',
        [
            _dir(WD),
            _f(f'{WD}/profile.json',
               '{"username":"alice","email":"alice@vanta.local"}\n'),
            _f(f'{WD}/notes.txt',
               'Сервер слепо копирует поля JSON в объект User. Есть поле `role`.\n'
               'Ответ сервера при успешной эскалации: {"role":"admin","token":"nto{m4ss_4ss1gnm3nt_3sc4l4t10n}"}\n'),
        ],
        task='# Задача: mass assignment\n\nТело запроса на обновление профиля — в `profile.json`. Сервер копирует все\n'
             'поля без фильтрации. Доберись до флага и запиши его в `found.txt`.\n',
    ),
]
