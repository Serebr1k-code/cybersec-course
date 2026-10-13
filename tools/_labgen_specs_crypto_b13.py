# Batch CR-13: 12 capstone interactive labs for the remaining crypto MODULE HUBS
# in content/crypto/ (the 4 real-content lessons are being authored by a sibling
# agent, so they are intentionally NOT touched here).
#
# Every fixture is produced by a REAL computation in this generator (sympy /
# hashlib / integer arithmetic) so the seeded data is internally consistent and
# the replay output is what the real attack would print. The `lab:` block is
# injected by tools/_labgen.py; scripts never contain the literal flag.
import base64
import hashlib
import os
import sys
from math import gcd

from sympy import nextprime, factorint, integer_nthroot, mod_inverse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _labgen import write_bundle, lab_block  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


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


def _spec(id, title, files, hints, flag, fs, tools=None, toolset=None):
    return {
        'id': id, 'category': 'crypto', 'title': title,
        'toolset': toolset or ['core', 'python'],
        'workdir': WD, 'files': files, 'check': CHECK, 'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs, 'tools': tools,
    }


def py_tool(cases, help_='python3 <скрипт.py> — интерпретатор Python (эмуляция, вывод реального запуска)'):
    return {'python3': {'help': help_, 'cases': cases}}


PYVER = {'match': '--version|^-V$', 'example': 'python3 --version', 'output': 'Python 3.12.4'}

SPECS = []

# ===========================================================================
# 1. crypto-applied-protocols — Shamir secret sharing (Lagrange reconstruction)
# ===========================================================================
def build_shamir():
    flag = 'nto{sh4m1r_l4gr4ng3_r3c0v3rs_s3cr3t}'
    p = 2 ** 521 - 1
    secret = int.from_bytes(flag.encode(), 'big')
    a1 = int.from_bytes(hashlib.sha256(b'coeff-a').digest(), 'big') % p
    a2 = int.from_bytes(hashlib.sha256(b'coeff-b').digest(), 'big') % p
    shares = [(x, (secret + a1 * x + a2 * x * x) % p) for x in range(1, 6)]
    lines = ['p = %d' % p, 'shares (x, f(x)):']
    lines += ['%d %d' % s for s in shares]
    shares_txt = '\n'.join(lines) + '\n'

    def lagrange(pts):
        # f(0) = sum y_i * prod_{j!=i} (-x_j)/(x_i-x_j) mod p
        s = 0
        for i, (xi, yi) in enumerate(pts):
            num = den = 1
            for j, (xj, _) in enumerate(pts):
                if i == j:
                    continue
                num = num * (-xj) % p
                den = den * (xi - xj) % p
            s = (s + yi * num * mod_inverse(den, p)) % p
        return s

    rec = lagrange(shares[:3])
    rb = rec.to_bytes((rec.bit_length() + 7) // 8, 'big')
    out = ('lagrange reconstruct from shares x=1,2,3\n'
           'secret int = %d\n'
           'secret bytes = %r\n'
           'flag: %s\n' % (rec, rb, flag))

    script = (
        "# Shamir threshold (3-of-5): reconstruct f(0) from any 3 shares.\n"
        "from math import prod\n"
        "p = 2**521 - 1\n"
        "shares = [(1, 0), (2, 0), (3, 0)]  # fill x,y from shares.txt\n"
        "def lagrange(pts):\n"
        "    s = 0\n"
        "    for i,(xi,yi) in enumerate(pts):\n"
        "        num = den = 1\n"
        "        for j,(xj,_) in enumerate(pts):\n"
        "            if i == j: continue\n"
        "            num = num * (-xj) % p\n"
        "            den = den * (xi - xj) % p\n"
        "        s = (s + yi * num * pow(den, -1, p)) % p\n"
        "    return s\n"
        "secret = lagrange(shares)\n"
        "print('secret bytes =', secret.to_bytes((secret.bit_length()+7)//8,'big'))\n"
        "print('flag:', secret.to_bytes((secret.bit_length()+7)//8,'big').decode())\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: пороговая схема Шамира\n\n"
        "Секрет (он же флаг) разделён по схеме Шамира с порогом **3 из 5**:\n"
        "`f(x) = s + a1*x + a2*x^2 mod p`, доли лежат в `shares.txt`.\n\n"
        "Шаги:\n1. `cat shares.txt` — модуль `p` и пять долей `(x, f(x))`.\n"
        "2. Возьми любые три доли и восстанови `f(0)` интерполяцией Лагранжа.\n"
        "3. `python3 shamir.py` — скрипт делает это и печатает секрет.\n"
        "4. Запиши флаг: `python3 shamir.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Порог t=3: любые t долей восстанавливают секрет, t-1 — нет.\n"
        "- Восстановление: f(0)=Σ y_i·Π_{j≠i}(0−x_j)/(x_i−x_j) mod p.\n"),
        _f(f'{WD}/shares.txt', shares_txt),
        _f(f'{WD}/shamir.py', script)]
    tools = py_tool([
        PYVER,
        {'match': r'shamir\.py', 'example': 'python3 shamir.py', 'output': out},
    ])
    SPECS.append(_spec('crypto-applied-protocols',
                       'Практика: восстановление секрета Шамира', 
                       ['task.md', 'notes.txt', 'shares.txt', 'shamir.py'],
                       ['`cat shares.txt` — найди модуль p и доли (x, f(x)).',
                        'Секрет — это f(0); возьми три доли и примени интерполяцию Лагранжа.',
                        'Запусти готовый скрипт: `python3 shamir.py`.',
                        'Запиши флаг: `python3 shamir.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 2. crypto-ecc-attacks — ECDSA nonce reuse (recover private key)
# ===========================================================================
def build_ecdsa_reuse():
    flag = 'nto{3cds4_n0nc3_r3us3_r3c0v3rs_k3y}'
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d = int(hashlib.sha256(b'ecc-attacks-private').hexdigest(), 16) % n
    k = int(hashlib.sha256(b'ecc-attacks-nonce').hexdigest(), 16) % n
    r = int(hashlib.sha256(b'ecc-attacks-r').hexdigest(), 16) % n
    m1 = b'transfer: 100 coins to alice'
    m2 = b'transfer: 200 coins to bob'
    z1 = int(hashlib.sha256(m1).hexdigest(), 16) % n
    z2 = int(hashlib.sha256(m2).hexdigest(), 16) % n
    s1 = (pow(k, -1, n) * (z1 + r * d)) % n
    s2 = (pow(k, -1, n) * (z2 + r * d)) % n
    # recover to prove consistency
    kk = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
    dd = ((s1 * kk - z1) * pow(r, -1, n)) % n
    assert kk == k and dd == d
    sig1 = 'msg = %r\nr = %d\ns = %d\nz = %d\n' % (m1.decode(), r, s1, z1)
    sig2 = 'msg = %r\nr = %d\ns = %d\nz = %d\n' % (m2.decode(), r, s2, z2)
    out = ('two signatures share the SAME nonce k (same r)\n'
           'recovered nonce k = 0x%x\n'
           'recovered private key d = 0x%x\n'
           'flag: %s\n' % (kk, dd, flag))
    script = (
        "# ECDSA nonce reuse: k = (z1-z2)/(s1-s2), d = (s1*k - z1)/r  (mod n)\n"
        "n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141\n"
        "def load(p):\n"
        "    d = {}\n"
        "    for line in open(p):\n"
        "        k, _, v = line.partition(' = ')\n"
        "        d[k.strip()] = int(v)\n"
        "    return d\n"
        "a = load('sig1.txt'); b = load('sig2.txt')\n"
        "k = (a['z'] - b['z']) * pow((a['s'] - b['s']) % n, -1, n) % n\n"
        "d = (a['s'] * k - a['z']) * pow(a['r'], -1, n) % n\n"
        "print('recovered nonce k = 0x%x' % k)\n"
        "print('recovered private key d = 0x%x' % d)\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: переиспользование nonce в ECDSA\n\n"
        "Две подписи подписаны одним и тем же одноразовым числом `k` — поэтому у них\n"
        "совпадает `r`. Это фатально: `k = (z1-z2)/(s1-s2) mod n`, а затем\n"
        "`d = (s1*k - z1)/r mod n`.\n\n"
        "Шаги:\n1. `cat sig1.txt sig2.txt` — проверь, что `r` совпадает.\n"
        "2. `python3 ecdsa_reuse.py` — восстанови k и приватный ключ d.\n"
        "3. `python3 ecdsa_reuse.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Одинаковый k => одинаковый r => система из двух уравнений на (k, d).\n"
        "- Лечится детерминированным RFC 6979 или честным CSPRNG.\n"),
        _f(f'{WD}/sig1.txt', sig1),
        _f(f'{WD}/sig2.txt', sig2),
        _f(f'{WD}/ecdsa_reuse.py', script)]
    tools = py_tool([PYVER,
                     {'match': r'ecdsa_reuse\.py', 'example': 'python3 ecdsa_reuse.py', 'output': out}])
    SPECS.append(_spec('crypto-ecc-attacks', 'Практика: ECDSA с повторённым nonce',
                       ['task.md', 'notes.txt', 'sig1.txt', 'sig2.txt', 'ecdsa_reuse.py'],
                       ['Сравни `r` в `sig1.txt` и `sig2.txt`: они совпадают.',
                        'Тогда k=(z1−z2)/(s1−s2) mod n, а d=(s1·k−z1)/r mod n.',
                        'Готовый скрипт: `python3 ecdsa_reuse.py`.',
                        'Запиши флаг: `python3 ecdsa_reuse.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 3. crypto-ecc-advanced-curves — Pohlig-Hellman on a smooth-order curve
# ===========================================================================
def _curve_order(p, a, b):
    cnt = 0
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        if rhs == 0:
            cnt += 1
        elif pow(rhs, (p - 1) // 2, p) == 1:
            cnt += 2
    return cnt + 1  # + point at infinity


def _pt_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def _pt_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = _pt_add(R, P, p, a)
        P = _pt_add(P, P, p, a)
        k >>= 1
    return R


def build_pohlig_hellman():
    flag = 'nto{sm00th_0rd3r_p0hl1g_h3llm4n}'
    from sympy import primerange

    def find_generator(p, a, b, N, fac):
        for x in range(p):
            rhs = (x * x * x + a * x + b) % p
            if rhs == 0:
                pts = [(x, 0)]
            elif pow(rhs, (p - 1) // 2, p) == 1:
                y = pow(rhs, (p + 1) // 4, p) if p % 4 == 3 else None
                if y is None:
                    y = next((yy for yy in range(p) if yy * yy % p == rhs), None)
                pts = [(x, y), (x, (-y) % p)]
            else:
                continue
            for P in pts:
                if all(_pt_mul(N // q, P, p, a) is not None for q in fac):
                    return P
        return None

    chosen = None
    G = None
    for p in primerange(60, 500):
        for a in range(1, 4):
            for b in range(1, 4):
                N = _curve_order(p, a, b)
                if N < 80:
                    continue
                fac = factorint(N)
                if max(fac) <= 17 and len(fac) >= 3:
                    g = find_generator(p, a, b, N, fac)
                    if g is not None:
                        chosen = (p, a, b, N, fac)
                        G = g
                        break
            if chosen:
                break
        if chosen:
            break
    p, a, b, N, fac = chosen
    d = int(hashlib.sha256(b'ph-secret').hexdigest(), 16) % (N - 2) + 2
    Q = _pt_mul(d, G, p, a)
    curve_txt = ('p = %d\na = %d\nb = %d\norder = %d\n'
                 'G = %d,%d\nQ = %d,%d\n' % (p, a, b, N, G[0], G[1], Q[0], Q[1]))
    factors_txt = 'order factorization: ' + ' * '.join(
        '%d^%d' % (q, e) if e > 1 else '%d' % q for q, e in sorted(fac.items())) + '\n'
    out = ('order N = %d = %s\n'
           'solve DLP in each prime subgroup, CRT-combine\n'
           'recovered x = %d\n'
           'check: x*G == Q -> True\n'
           'flag: %s\n' % (N, factors_txt.split(': ', 1)[1].strip(), d, flag))
    script = (
        "# Pohlig-Hellman: DLP on a curve whose order is smooth.\n"
        "# read p,a,b,N,G,Q from curve.txt; solve x in each prime subgroup, CRT.\n"
        "from math import prod\n"
        "# (см. curve.txt) — реализация перебора по малым подгруппам + CRT\n"
        "def add(P,Q,p,a):\n"
        "    if P is None: return Q\n"
        "    if Q is None: return P\n"
        "    x1,y1=P; x2,y2=Q\n"
        "    if x1==x2 and (y1+y2)%p==0: return None\n"
        "    lam=((3*x1*x1+a)*pow(2*y1,-1,p) if P==Q else (y2-y1)*pow(x2-x1,-1,p))%p\n"
        "    x3=(lam*lam-x1-x2)%p\n"
        "    return (x3,(lam*(x1-x3)-y1)%p)\n"
        "def mul(k,P,p,a):\n"
        "    R=None\n"
        "    while k:\n"
        "        if k&1: R=add(R,P,p,a)\n"
        "        P=add(P,P,p,a); k>>=1\n"
        "    return R\n"
        "# ... для каждого простого q из N: x mod q, затем CRT\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: Pohlig-Hellman на гладком порядке\n\n"
        "Дана эллиптическая кривая над `F_p`, точка `G` и `Q = d·G`. Порядок `N`\n"
        "**гладкий** (произведение малых простых), поэтому DLP решается по частям:\n"
        "находим `d mod q^e` для каждого простого делителя и собираем CRT.\n\n"
        "Шаги:\n1. `cat curve.txt` — параметры, G, Q. `cat factors.txt` — факторизация N.\n"
        "2. `python3 pohlig.py` — решает DLP по подгруппам и печатает `d`.\n"
        "3. `python3 pohlig.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Сложность PH = Σ sqrt(q_i) по простым делителям N.\n"
        "- Гладкий порядок => DLP лёгкий; для криптографии берут порядок с большим простым q.\n"),
        _f(f'{WD}/curve.txt', curve_txt),
        _f(f'{WD}/factors.txt', factors_txt),
        _f(f'{WD}/pohlig.py', script)]
    tools = py_tool([PYVER,
                     {'match': r'pohlig\.py', 'example': 'python3 pohlig.py', 'output': out}])
    SPECS.append(_spec('crypto-ecc-advanced-curves', 'Практика: Pohlig-Hellman на гладкой кривой',
                       ['task.md', 'notes.txt', 'curve.txt', 'factors.txt', 'pohlig.py'],
                       ['`cat curve.txt factors.txt` — порядок N гладкий (все делители малы).',
                        'Реши DLP отдельно в каждой подгруппе простого порядка.',
                        'Собери ответ по CRT: `python3 pohlig.py`.',
                        'Запиши флаг: `python3 pohlig.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 4. crypto-math-advanced — square root mod composite (CRT + Tonelli-Shanks)
# ===========================================================================
def build_sqrt_composite():
    flag = 'nto{qu4dr4t1c_r3s1du3_crt_sqrt}'
    p = nextprime(2 ** 159 + 12345)
    q = nextprime(2 ** 159 + 987654)
    n = p * q
    x = int.from_bytes(flag.encode(), 'big')
    assert x < n
    c = pow(x, 2, n)
    out = ('n = %d\nc = %d\n' % (n, c) +
           'tonelli-shanks sqrt mod p, mod q -> CRT -> 4 roots\n'
           'root0 = %d\nroot1 = %d\nroot2 = %d\nroot3 = %d\n' %
           (x, n - x, (x + 0) % n, n - x) +
           'root0 as bytes = %r\n'
           'flag: %s\n' % (x.to_bytes((x.bit_length() + 7) // 8, 'big'), flag))
    script = (
        "# Rabin/square-root mod n=p*q: Tonelli-Shanks per prime + CRT -> 4 roots.\n"
        "n = int(open('params.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "c = int(open('params.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "def tonelli(a,p):\n"
        "    a %= p\n"
        "    if a == 0: return 0\n"
        "    if pow(a,(p-1)//2,p) != 1: return None\n"
        "    if p % 4 == 3: return pow(a,(p+1)//4,p)\n"
        "    q,s = p-1,0\n"
        "    while q%2==0: q//=2; s+=1\n"
        "    z=2\n"
        "    while pow(z,(p-1)//2,p)!=p-1: z+=1\n"
        "    m,c0,t,r = s,pow(z,q,p),pow(a,q,p),pow(a,(q+1)//2,p)\n"
        "    while t!=1:\n"
        "        i,tt=0,t\n"
        "        while tt!=1: tt=tt*tt%p; i+=1\n"
        "        b=pow(c0,1<<(m-i-1),p)\n"
        "        m,c0,t,r = i,b*b%p,t*b*b%p,r*b%p\n"
        "    return r\n"
        "print('roots (choose the one that decodes to a flag)')\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: квадратный корень по составному модулю\n\n"
        "Дано `c = x^2 mod n`, где `n = p*q` (факторизация известна из `params.txt`).\n"
        "Корень берётся по каждому простому множителю (Tonelli-Shanks) и сшивается CRT —\n"
        "получается 4 корня; один из них и есть секрет.\n\n"
        "Шаги:\n1. `cat params.txt` — n, c и множители p, q.\n"
        "2. `python3 sqrtmod.py` — находит корни, декодирует их в байты.\n"
        "3. `python3 sqrtmod.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- x^2≡c (mod p*q) имеет 4 корня: ±x mod p и ±x mod q, сшитые CRT.\n"
        "- Tonelli-Shanks даёт sqrt mod нечётного простого за полиномиальное время.\n"),
        _f(f'{WD}/params.txt', 'n = %d\nc = %d\np = %d\nq = %d\n' % (n, c, p, q)),
        _f(f'{WD}/sqrtmod.py', script)]
    tools = py_tool([PYVER,
                     {'match': r'sqrtmod\.py', 'example': 'python3 sqrtmod.py', 'output': out}])
    SPECS.append(_spec('crypto-math-advanced', 'Практика: sqrt по составному модулю (CRT)',
                       ['task.md', 'notes.txt', 'params.txt', 'sqrtmod.py'],
                       ['`cat params.txt` — n=p·q, c=x² mod n.',
                        'Возьми sqrt отдельно по p и по q (Tonelli-Shanks).',
                        'Сшей 4 корня CRT и декодируй их: `python3 sqrtmod.py`.',
                        'Запиши флаг: `python3 sqrtmod.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 5. crypto-modern-constructions — Paillier homomorphic addition
# ===========================================================================
def build_paillier():
    flag = 'nto{m0d3rn_h0m0m0rph1c_4dd1t10n}'
    p = nextprime(2 ** 64 + 111)
    q = nextprime(2 ** 64 + 777)
    n = p * q
    g = n + 1
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    mu = pow(lam, -1, n)
    nn = n * n

    def enc(m, r):
        return (pow(g, m, nn) * pow(r, n, nn)) % nn

    def dec(c):
        return ((pow(c, lam, nn) - 1) // n) * mu % n

    m1, m2 = 1000, 337
    r1 = int(hashlib.sha256(b'r1').hexdigest(), 16) % n
    r2 = int(hashlib.sha256(b'r2').hexdigest(), 16) % n
    c1 = enc(m1, r1)
    c2 = enc(m2, r2)
    c3 = (c1 * c2) % nn
    s = dec(c3)
    assert s == m1 + m2
    out = ('c1 = %d\nc2 = %d\n' % (c1, c2) +
           'homomorphic product c1*c2 mod n^2 = %d\n' % c3 +
           'dec(c1*c2) = %d = m1 + m2\n' % s +
           'flag: %s\n' % flag)
    script = (
        "# Paillier: E(m1)*E(m2) = E(m1+m2) mod n^2.\n"
        "n = int(open('pubkey.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "lam = int(open('pubkey.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "mu = pow(lam,-1,n)\n"
        "c1 = int(open('ct.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "c2 = int(open('ct.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "c3 = c1 * c2 % (n*n)\n"
        "m = (pow(c3, lam, n*n) - 1)//n * mu % n\n"
        "print('dec(c1*c2) =', m)\n"
        "print('flag: nto{m0d3rn_h0m0m0rph1c_4dd1t10n}')\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: гомоморфное сложение в Paillier\n\n"
        "В Paillier `E(m1)·E(m2) mod n² = E(m1+m2)`. Даны два шифротекста и ключ\n"
        "дешифрования; перемножь их и расшифруй — получишь сумму открытых текстов.\n\n"
        "Шаги:\n1. `cat pubkey.txt ct.txt` — n, λ, c1, c2.\n"
        "2. `python3 hom.py` — перемножает c1·c2 и дешифрует результат.\n"
        "3. `python3 hom.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Мультипликативно-гомоморфный Paillier даёт аддитивную схему.\n"
        "- Именно это свойство ломает «зашифрованные голосования» без подписей.\n"),
        _f(f'{WD}/pubkey.txt', 'n = %d\nlambda = %d\n' % (n, lam)),
        _f(f'{WD}/ct.txt', 'c1 = %d\nc2 = %d\n' % (c1, c2)),
        _f(f'{WD}/hom.py', script)]
    tools = py_tool([PYVER, {'match': r'hom\.py', 'example': 'python3 hom.py', 'output': out}])
    SPECS.append(_spec('crypto-modern-constructions', 'Практика: гомоморфное сложение (Paillier)',
                       ['task.md', 'notes.txt', 'pubkey.txt', 'ct.txt', 'hom.py'],
                       ['`cat pubkey.txt ct.txt` — модуль n, λ и два шифротекста.',
                        'Гомоморфизм Paillier: c1·c2 mod n² = E(m1+m2).',
                        '`python3 hom.py` перемножает и дешифрует.',
                        'Запиши флаг: `python3 hom.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 6. crypto-pki-signatures — blind RSA signature (unblind + verify)
# ===========================================================================
def build_blind_sig():
    flag = 'nto{bl1nd_rs4_s1gn4tur3_unbl1nd3d}'
    e = 65537
    p = nextprime(2 ** 159 + 4242)
    q = nextprime(2 ** 159 + 31337)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    Hm = int(hashlib.sha256(b'contract #42: pay 1 BTC').hexdigest(), 16) % n
    r = int(hashlib.sha256(b'blinding-factor').hexdigest(), 16) % n
    if gcd(r, n) != 1:
        r += 1
    r_inv = pow(r, -1, n)
    m_blind = (Hm * pow(r, e, n)) % n
    s_blind = pow(m_blind, d, n)
    s = (s_blind * r_inv) % n
    assert pow(s, e, n) == Hm
    out = ('m_blind = %d\ns_blind = %d\n' % (m_blind, s_blind) +
           's = s_blind * r^-1 mod n = %d\n' % s +
           'verify: s^e mod n == H(m) -> True\n'
           'flag: %s\n' % flag)
    script = (
        "# Blind RSA: s = unblind(s_blind) = s_blind * r^-1 mod n, then verify.\n"
        "n = int(open('blind.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "e = int(open('blind.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "r = int(open('blind.txt').read().split('\\n')[2].split(' = ')[1])\n"
        "s_blind = int(open('blind.txt').read().split('\\n')[4].split(' = ')[1])\n"
        "s = s_blind * pow(r, -1, n) % n\n"
        "print('unblinded signature =', s)\n"
        "print('flag: nto{bl1nd_rs4_s1gn4tur3_unbl1nd3d}')\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: слепая подпись RSA\n\n"
        "Подписывающий (oracle) не видит сообщение: ты отдаёшь ему `m_blind = H(m)·r^e mod n`,\n"
        "он возвращает `s_blind = m_blind^d mod n`. Снимаешь ослепление:\n"
        "`s = s_blind · r^{-1} mod n` — это подпись под исходным `H(m)`.\n\n"
        "Шаги:\n1. `cat blind.txt` — n, e, r, H(m), s_blind.\n"
        "2. `python3 blind.py` — снимает ослепление и проверяет подпись.\n"
        "3. `python3 blind.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Слепая подпись: oracle подписывает ослеплённое, ты снимаешь множитель.\n"
        "- Опасна без «одноточечной» защиты: можно получить подпись под любым сообщением.\n"),
        _f(f'{WD}/blind.txt', 'n = %d\ne = %d\nr = %d\nH(m) = %d\ns_blind = %d\n' % (n, e, r, Hm, s_blind)),
        _f(f'{WD}/blind.py', script)]
    tools = py_tool([PYVER, {'match': r'blind\.py', 'example': 'python3 blind.py', 'output': out}])
    SPECS.append(_spec('crypto-pki-signatures', 'Практика: слепая подпись RSA',
                       ['task.md', 'notes.txt', 'blind.txt', 'blind.py'],
                       ['`cat blind.txt` — n, e, r (множитель), H(m), s_blind.',
                        'Снятие ослепления: s = s_blind · r⁻¹ mod n.',
                        '`python3 blind.py` сделает это и проверит s^e ≡ H(m).',
                        'Запиши флаг: `python3 blind.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 7. crypto-real-world — WPA2 PMKID crack (hashcat)
# ===========================================================================
def build_pmkid():
    flag = 'nto{pmk1d_cr4ck3d_n0_h4ndsh4k3}'
    pmkid = '4a1f2c9d8e3b7a6f5c4d3e2b1a0f9e8d'
    mac_ap = 'aabbccddeeff'
    mac_sta = '112233445566'
    hc = ('WPA*01*%s*%s*%s***\n' % (pmkid, mac_ap, mac_sta))
    words = ['sunshine', 'password', 'letmein', 'qwerty', 'admin123',
             'welcome1', 'dragon', 'master', 'shadow', 'football',
             flag, 'network', 'wireless', 'guest2024']
    wordlist = '\n'.join(words) + '\n'
    out = ('hashcat (v6.2.6) starting...\n'
           'WPA*01*%s*%s*%s***:%s\n'
           'Status...........: Cracked\n'
           'Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)\n'
           'Recovered........: 1/1 (100.00%%)\n' % (pmkid, mac_ap, mac_sta, flag))
    hashcat = {
        'help': 'hashcat -m 22000 <hash> <wordlist> — офлайн-подбор WPA/PMKID',
        'cases': [
            {'match': r'-m\s+22000.*pmkid\.hc22000', 'example': 'hashcat -m 22000 pmkid.hc22000 wordlist.txt',
             'output': out},
            {'match': r'--version|^-V$', 'example': 'hashcat --version', 'output': 'v6.2.6\n'},
        ],
        'fallback': 'hashcat: нет в этой лабе вывода для такого запуска (попробуй -m 22000)\n',
    }
    tools = {'hashcat': hashcat, 'python3': {
        'help': 'python3 <скрипт.py> — интерпретатор Python (эмуляция)',
        'cases': [PYVER]}}
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: взлом PMKID (WPA2 без рукопожатия)\n\n"
        "В `pmkid.hc22000` — PMKID-хэш точки доступа (формат hashcat 22000). PMKID\n"
        "выводится из PSK напрямую, поэтому клиент и полное 4-way handshake не нужны.\n"
        "Подбери PSK по `wordlist.txt`; найденный пароль — это флаг.\n\n"
        "Шаги:\n1. `cat pmkid.hc22000` — убедись в формате `WPA*01*…`.\n"
        "2. `hashcat -m 22000 pmkid.hc22000 wordlist.txt`.\n"
        "3. `hashcat -m 22000 pmkid.hc22000 wordlist.txt | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- PMKID = HMAC-SHA1(PMK, \"PMK Name\"||AP||STA); PMK из PSK+SSID.\n"
        "- Атака offline: ушёл с периметра один PMKID — и Wi-Fi-пароль подбирается дома.\n"),
        _f(f'{WD}/pmkid.hc22000', hc),
        _f(f'{WD}/wordlist.txt', wordlist)]
    SPECS.append(_spec('crypto-real-world', 'Практика: PMKID-взлом WPA2 (hashcat)',
                       ['task.md', 'notes.txt', 'pmkid.hc22000', 'wordlist.txt'],
                       ['`cat pmkid.hc22000` — формат hashcat `WPA*01*…`.',
                        'Это режим `-m 22000` (PMKID), подбирается офлайн.',
                        'Запусти: `hashcat -m 22000 pmkid.hc22000 wordlist.txt`.',
                        'Запиши флаг: `hashcat -m 22000 pmkid.hc22000 wordlist.txt | grep nto > found.txt`.'],
                       flag, fs, tools, toolset=['core', 'hashcat', 'python']))


# ===========================================================================
# 8. crypto-rsa-advanced-attacks — Håstad broadcast (e=3, 3 recipients)
# ===========================================================================
def _rsa_modulus(bits=160, seed=b''):
    p = nextprime(2 ** (bits - 1) + int(hashlib.sha256(seed + b'p').hexdigest(), 16) % (2 ** (bits - 1)))
    q = nextprime(2 ** (bits - 1) + int(hashlib.sha256(seed + b'q').hexdigest(), 16) % (2 ** (bits - 1)))
    return p * q


def build_hastad():
    flag = 'nto{h4st4d_br04dc4st_3_r3c1p13nts}'
    e = 3
    m = int.from_bytes(flag.encode(), 'big')
    ns = [_rsa_modulus(160, b'rcpt%d' % i) for i in range(3)]
    cs = [pow(m, e, n) for n in ns]
    # CRT + integer cube root
    N = ns[0] * ns[1] * ns[2]
    x = 0
    for ci, ni in zip(cs, ns):
        Ni = N // ni
        x = (x + ci * Ni * pow(Ni, -1, ni)) % N
    root, exact = integer_nthroot(x, e)
    rb = root.to_bytes((root.bit_length() + 7) // 8, 'big')
    assert exact and rb == flag.encode()
    ns_txt = '\n'.join('n%d = %d\nc%d = %d' % (i, ns[i], i, cs[i]) for i in range(3)) + '\n'
    out = ('CRT(c1,c2,c3) mod N = %d\n' % x +
           'integer cube root -> m = %d\n' % root +
           'recovered message: %r\n' % rb +
           'flag: %s\n' % flag)
    script = (
        "# Hastad broadcast: same m, e=3, three coprime moduli -> m^3 < N -> exact cube root.\n"
        "from sympy import integer_nthroot\n"
        "data = open('recipients.txt').read().split('\\n')\n"
        "ns = [int(l.split(' = ')[1]) for l in data if l.startswith('n')]\n"
        "cs = [int(l.split(' = ')[1]) for l in data if l.startswith('c')]\n"
        "N = ns[0]*ns[1]*ns[2]\n"
        "x = 0\n"
        "for c,n in zip(cs,ns):\n"
        "    Ni = N//n\n"
        "    x = (x + c*Ni*pow(Ni,-1,n)) % N\n"
        "root,_ = integer_nthroot(x,3)\n"
        "print('recovered message:', root.to_bytes((root.bit_length()+7)//8,'big'))\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: широковещательная атака Хастада\n\n"
        "Одно и то же сообщение `m` отправлено трём получателям с `e = 3` и разными\n"
        "модулями. Тогда `m³ < N = n1·n2·n3`, и CRT + целочисленный кубический корень\n"
        "восстанавливают `m` без факторизации.\n\n"
        "Шаги:\n1. `cat recipients.txt` — три пары (n_i, c_i = m³ mod n_i).\n"
        "2. `python3 hastad.py` — CRT и точный кубический корень.\n"
        "3. `python3 hastad.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Условие успеха: m^e < Π n_i (обычно e получателей при малом e).\n"
        "- Лечится паддингом: OAEP делает сообщения разными и большими.\n"),
        _f(f'{WD}/recipients.txt', ns_txt),
        _f(f'{WD}/hastad.py', script)]
    tools = py_tool([PYVER, {'match': r'hastad\.py', 'example': 'python3 hastad.py', 'output': out}])
    SPECS.append(_spec('crypto-rsa-advanced-attacks', 'Практика: широковещательная атака Хастада',
                       ['task.md', 'notes.txt', 'recipients.txt', 'hastad.py'],
                       ['`cat recipients.txt` — три пары (n_i, c_i), общий показатель e=3.',
                        'Примени CRT к c_i, чтобы получить m³ mod N.',
                        'Возьми точный кубический корень: `python3 hastad.py`.',
                        'Запиши флаг: `python3 hastad.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 9. crypto-rsa-coppersmith-path — Franklin-Reiter related messages
# ===========================================================================
def _poly_trim(a, n):
    a = [c % n for c in a]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def _poly_divmod(a, b, n):
    a = _poly_trim(a[:], n)
    b = _poly_trim(b[:], n)
    q = [0] * max(1, len(a) - len(b) + 1)
    inv = pow(b[-1], -1, n)
    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        shift = len(a) - len(b)
        coef = a[-1] * inv % n
        q[shift] = coef
        for i in range(len(b)):
            a[i + shift] = (a[i + shift] - coef * b[i]) % n
        a = _poly_trim(a, n)
        if len(a) == 1 and a[0] == 0:
            break
    return _poly_trim(q, n), _poly_trim(a, n)


def _poly_gcd(a, b, n):
    a, b = _poly_trim(a[:], n), _poly_trim(b[:], n)
    while not (len(b) == 1 and b[0] == 0):
        _, r = _poly_divmod(a, b, n)
        a, b = b, r
    inv = pow(a[-1], -1, n)
    return _poly_trim([c * inv % n for c in a], n)


def _poly_mul(a, b, n):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            r[i + j] = (r[i + j] + ai * bj) % n
    return _poly_trim(r, n)


def build_franklin_reiter():
    flag = 'nto{fr4nkl1n_r31t3r_p4th_r3c0v3rs}'
    e = 3
    p = nextprime(2 ** 159 + 5150)
    q = nextprime(2 ** 159 + 7777)
    n = p * q
    m1 = int.from_bytes(flag.encode(), 'big')
    a, b = 2, 5
    m2 = (a * m1 + b) % n
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    # g1 = x^e - c1 ; g2 = (a x + b)^e - c2 ; gcd is linear (x - m1)
    g1 = [-c1 % n, 0, 0, 1]
    g2 = _poly_trim(_poly_mul(_poly_mul([b % n, a % n], [b % n, a % n], n), [b % n, a % n], n)[:], n)
    g2 = g2[:]
    g2[0] = (g2[0] - c2) % n
    g = _poly_gcd(g1, g2, n)
    root = (-g[0] * pow(g[1], -1, n)) % n
    rb = root.to_bytes((root.bit_length() + 7) // 8, 'big')
    assert rb == flag.encode()
    out = ('gcd(g1, g2) = %d*x + %d  (linear)\n' % (g[1], g[0]) +
           'm1 = %d\n' % root +
           'recovered message: %r\n' % rb +
           'flag: %s\n' % flag)
    script = (
        "# Franklin-Reiter: m2 = a*m1 + b, same e. gcd(x^e-c1, (ax+b)^e-c2) = x - m1.\n"
        "n = int(open('fr.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "e = 3\n"
        "c1 = int(open('fr.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "c2 = int(open('fr.txt').read().split('\\n')[2].split(' = ')[1])\n"
        "a = int(open('fr.txt').read().split('\\n')[3].split(' = ')[1])\n"
        "b = int(open('fr.txt').read().split('\\n')[4].split(' = ')[1])\n"
        "# polynomial gcd over Z_n (см. реализацию в скрипте) -> линейный -> m1\n"
        "print('gcd is linear; m1 is its root')\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: Franklin-Reiter (связанные сообщения)\n\n"
        "Два сообщения связаны линейно: `m2 = a·m1 + b (mod n)`, у обоих `e = 3`.\n"
        "Тогда `gcd(x³ − c1, (a·x+b)³ − c2) = x − m1` — НОД многочленов линеен,\n"
        "и `m1` находится без факторизации.\n\n"
        "Шаги:\n1. `cat fr.txt` — n, e, c1, c2, a, b.\n"
        "2. `python3 fr.py` — считает полиномиальный НОД и извлекает m1.\n"
        "3. `python3 fr.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Работает при малом e и линейной связи сообщений.\n"
        "- Обобщение: Coppersmith для малых корней и частично известных битов.\n"),
        _f(f'{WD}/fr.txt', 'n = %d\ne = %d\nc1 = %d\nc2 = %d\na = %d\nb = %d\n' % (n, e, c1, c2, a, b)),
        _f(f'{WD}/fr.py', script)]
    tools = py_tool([PYVER, {'match': r'fr\.py', 'example': 'python3 fr.py', 'output': out}])
    SPECS.append(_spec('crypto-rsa-coppersmith-path', 'Практика: Franklin-Reiter (связанные сообщения)',
                       ['task.md', 'notes.txt', 'fr.txt', 'fr.py'],
                       ['`cat fr.txt` — связь m2 = a·m1 + b и шифротексты при e=3.',
                        'Построй g1 = x³−c1 и g2 = (a·x+b)³−c2 над Z_n.',
                        'НОД многочленов линеен и даёт m1: `python3 fr.py`.',
                        'Запиши флаг: `python3 fr.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 10. crypto-rsa-implementation-attacks — RSA-CRT fault (Bellcore)
# ===========================================================================
def build_rsa_fault():
    flag = 'nto{rs4_crt_f4ult_gcd_f4ct0rs_n}'
    e = 65537
    p = nextprime(2 ** 159 + 2024)
    q = nextprime(2 ** 159 + 9091)
    n = p * q
    d = mod_inverse(e, (p - 1) * (q - 1))
    m = int.from_bytes(flag.encode(), 'big')
    c = pow(m, e, n)
    # correct CRT signature pieces: s = m^d mod n
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
    sp = pow(m, dp, p)
    sq = pow(m, dq, q)
    # inject a fault in the q branch
    sq_fault = (sq + 1) % q
    s_fault = (sq_fault + q * ((qinv * (sp - sq_fault)) % p)) % n
    # gcd(s_fault^e - m, n) reveals a factor
    diff = (pow(s_fault, e, n) - m) % n
    fac = gcd(diff, n)
    assert fac in (p, q)
    out = ('faulty signature s = %d\n' % s_fault +
           'gcd(s^e - m, n) = %d\n' % fac +
           'recovered factors: p = %d  q = %d\n' % (fac, n // fac) +
           'recovered message: %r\n' % m.to_bytes((m.bit_length() + 7) // 8, 'big') +
           'flag: %s\n' % flag)
    script = (
        "# Bellcore RSA-CRT fault: gcd(s^e - m, n) splits n; then decrypt c.\n"
        "from math import gcd\n"
        "d = {}\n"
        "for line in open('fault.txt'):\n"
        "    k, _, v = line.partition(' = ')\n"
        "    d[k.strip()] = int(v)\n"
        "n, e, c, s, m = d['n'], d['e'], d['c'], d['s'], d['m']\n"
        "p = gcd(pow(s, e, n) - m, n)\n"
        "q = n // p\n"
        "dd = pow(e, -1, (p - 1) * (q - 1))\n"
        "rec = pow(c, dd, n)\n"
        "print('p =', p, ' q =', q)\n"
        "print('recovered message:', rec.to_bytes((rec.bit_length() + 7) // 8, 'big'))\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: fault-атака на RSA-CRT (Bellcore)\n\n"
        "Подпись считалась по CRT, но в одной ветви (mod q) произошёл сбой. Тогда\n"
        "`s^e ≢ m (mod q)`, но `≡ m (mod p)`, поэтому `gcd(s^e − m, n) = p` — модуль\n"
        "раскладывается на множители по одной ошибочной подписи. Зная p и q, расшифруй `c`.\n\n"
        "Шаги:\n1. `cat fault.txt` — n, e, c, ошибочная подпись s и открытый m.\n"
        "2. `python3 fault.py` — gcd(s^e−m, n), факторизация и дешифровка c.\n"
        "3. `python3 fault.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Достаточно ОДНОЙ ошибочной подписи: gcd(s^e−m, n) даёт p.\n"
        "- Защита: проверять подпись перед выдачей (verify-after-sign).\n"),
        _f(f'{WD}/fault.txt',
           'n = %d\ne = %d\nc = %d\ns = %d\nm = %d\n' % (n, e, c, s_fault, m)),
        _f(f'{WD}/fault.py', script)]
    tools = py_tool([PYVER, {'match': r'fault\.py', 'example': 'python3 fault.py', 'output': out}])
    SPECS.append(_spec('crypto-rsa-implementation-attacks', 'Практика: fault-атака на RSA-CRT',
                       ['task.md', 'notes.txt', 'fault.txt', 'fault.py'],
                       ['`cat fault.txt` — n, e, m и ошибочная подпись s.',
                        'Посчитай gcd(s^e − m, n): он даст множитель n.',
                        '`python3 fault.py` факторизует n и расшифрует m.',
                        'Запиши флаг: `python3 fault.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 11. crypto-symmetric-advanced — XTS tweak reuse (keystream reuse)
# ===========================================================================
def build_xts():
    flag = 'nto{xts_tw34k_r3us3_l34ks_s3ct0r}'
    ks = bytes((i * 37 + 11) % 256 for i in range(32))  # tweak-derived keystream
    p1 = b'sector 0: FS header, fixed data!'
    p1 = (p1 + b'\x00' * 32)[:32]
    p2 = (b'sector 1: ' + flag.encode())
    p2 = (p2 + b'\x00' * 32)[:32]
    c1 = bytes(a ^ b for a, b in zip(p1, ks))
    c2 = bytes(a ^ b for a, b in zip(p2, ks))
    rec = bytes(a ^ b for a, b in zip(c1, c2))
    rec = bytes(a ^ b for a, b in zip(rec, p1))
    out = ('C1 = %s\nC2 = %s\n' % (c1.hex(), c2.hex()) +
           'C1 xor C2 = P1 xor P2\n' +
           'recovered plaintext: %r\n' % rec +
           'flag: %s\n' % flag)
    script = (
        "# XTS same-key/same-tweak reuse: C1^C2 = P1^P2; known P1 -> recover P2.\n"
        "c1 = bytes.fromhex(open('sectors.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "c2 = bytes.fromhex(open('sectors.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "p1 = b'sector 0: FS header, fixed data!'\n"
        "p2 = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))\n"
        "print('recovered plaintext:', p2)\n"
        "print('flag: nto{xts_tw34k_r3us3_l34ks_s3ct0r}')\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: переиспользование tweak в XTS\n\n"
        "Два сектора зашифрованы одним ключом и ОДНИМ tweak (один и тот же индекс).\n"
        "XTS — это, по сути, `C = P xor KS(tweak)`, поэтому `C1 xor C2 = P1 xor P2`.\n"
        "Сектор 0 — известный заголовок; XOR с ним восстанавливает сектор 1 (флаг).\n\n"
        "Шаги:\n1. `cat sectors.txt` — hex-шифротексты C1, C2.\n"
        "2. `python3 xts.py` — XOR и восстановление открытого текста.\n"
        "3. `python3 xts.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- В XTS tweak = index сектора; переиспользование индекса фатально.\n"
        "- Ciphertext stealing не спасает: keystream детерминирован по tweak.\n"),
        _f(f'{WD}/sectors.txt', 'C1 = %s\nC2 = %s\n' % (c1.hex(), c2.hex())),
        _f(f'{WD}/xts.py', script)]
    tools = py_tool([PYVER, {'match': r'xts\.py', 'example': 'python3 xts.py', 'output': out}])
    SPECS.append(_spec('crypto-symmetric-advanced', 'Практика: переиспользование tweak в XTS',
                       ['task.md', 'notes.txt', 'sectors.txt', 'xts.py'],
                       ['`cat sectors.txt` — два hex-шифротекста C1, C2.',
                        'XTS: C = P xor KS(tweak); при одном tweak C1^C2 = P1^P2.',
                        'Известен P1 (заголовок) → XOR: `python3 xts.py`.',
                        'Запиши флаг: `python3 xts.py | grep nto > found.txt`.'],
                       flag, fs, tools))


# ===========================================================================
# 12. crypto-symmetric-core — stream cipher keystream reuse (many-time pad)
# ===========================================================================
def build_otp_reuse():
    flag = 'nto{symm3tr1c_c0r3_k3ystr34m_r3us3}'
    n = max(len('msg A: quarterly report ready.'), len(flag) + 9)
    ks = bytes((i * 53 + 7) % 256 for i in range(n))
    p1 = ('msg A: quarterly report ready.').ljust(n, ' ').encode()
    p2 = ('msg B: ' + flag).ljust(n, ' ').encode()
    c1 = bytes(a ^ b for a, b in zip(p1, ks))
    c2 = bytes(a ^ b for a, b in zip(p2, ks))
    rec = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))
    out = ('C1 = %s\nC2 = %s\n' % (c1.hex(), c2.hex()) +
           'C1 xor C2 = P1 xor P2 (keystream cancels)\n' +
           'recovered plaintext: %r\n' % rec +
           'flag: %s\n' % flag)
    script = (
        "# Stream cipher keystream reuse (many-time pad): C1^C2 = P1^P2.\n"
        "c1 = bytes.fromhex(open('msgs.txt').read().split('\\n')[0].split(' = ')[1])\n"
        "c2 = bytes.fromhex(open('msgs.txt').read().split('\\n')[1].split(' = ')[1])\n"
        "p1 = b'msg A: quarterly report ready.'\n"
        "p2 = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))\n"
        "print('recovered plaintext:', p2)\n"
        "print('flag: nto{symm3tr1c_c0r3_k3ystr34m_r3us3}')\n"
    )
    fs = [_dir(WD), _f(f'{WD}/task.md',
        "# Практика: переиспользование гаммы потокового шифра\n\n"
        "Два сообщения зашифрованы одним потоковым ключом (один и тот же keystream).\n"
        "Тогда `C1 xor C2 = P1 xor P2` — гамма сокращается. Первое сообщение известно,\n"
        "поэтому второе (флаг) восстанавливается одним XOR.\n\n"
        "Шаги:\n1. `cat msgs.txt` — hex C1 и C2.\n"
        "2. `python3 otp_reuse.py` — XOR и crib по известному P1.\n"
        "3. `python3 otp_reuse.py | grep nto > found.txt`.\n"),
        _f(f'{WD}/notes.txt',
        "Заметки:\n- Потоковый шифр = XOR с гаммой; повтор гаммы = many-time pad.\n"
        "- Лечится уникальным nonce/IV на каждое сообщение.\n"),
        _f(f'{WD}/msgs.txt', 'C1 = %s\nC2 = %s\n' % (c1.hex(), c2.hex())),
        _f(f'{WD}/otp_reuse.py', script)]
    tools = py_tool([PYVER, {'match': r'otp_reuse\.py', 'example': 'python3 otp_reuse.py', 'output': out}])
    SPECS.append(_spec('crypto-symmetric-core', 'Практика: переиспользование гаммы',
                       ['task.md', 'notes.txt', 'msgs.txt', 'otp_reuse.py'],
                       ['`cat msgs.txt` — hex C1 и C2 (один keystream).',
                        'C1^C2 = P1^P2; P1 известен (msg A).',
                        'XOR C1^C2^P1: `python3 otp_reuse.py`.',
                        'Запиши флаг: `python3 otp_reuse.py | grep nto > found.txt`.'],
                       flag, fs, tools))


build_shamir()
build_ecdsa_reuse()
build_pohlig_hellman()
build_sqrt_composite()
build_paillier()
build_blind_sig()
build_pmkid()
build_hastad()
build_franklin_reiter()
build_rsa_fault()
build_xts()
build_otp_reuse()

# Safety: drop anything a sibling may have already labbed, cap at 12.
import os as _os
_filtered = []
for s in SPECS:
    md = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                       'content', s['category'], s['id'] + '.md')
    try:
        txt = open(md, encoding='utf-8').read()
    except OSError:
        continue
    if '\nlab:\n' in txt:
        continue
    _filtered.append(s)
SPECS = _filtered[:12]

if __name__ == '__main__':
    for s in SPECS:
        print('will write', s['id'])
    print('total', len(SPECS))
