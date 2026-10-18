from typing import List, Tuple
from .gf import GF2m

Poly = List[int]

def trim(p: Poly) -> Poly:
    res = p[:]
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res

def p_deg(p: Poly) -> int:
    p = trim(p)
    return -1 if p == [0] else len(p) - 1

def p_add(a: Poly, b: Poly) -> Poly:
    r = [0] * max(len(a), len(b))
    for i, c in enumerate(a):
        r[i] ^= c
    for i, c in enumerate(b):
        r[i] ^= c
    return trim(r)

def p_esc(c: int, p: Poly, gf: GF2m) -> Poly:
    if not c:
        return [0]
    lc = gf.log[c]
    exp = gf.exp
    log = gf.log
    return trim([0 if not x else exp[lc + log[x]] for x in p])

def p_mul(a: Poly, b: Poly, gf: GF2m) -> Poly:
    r = [0] * (len(a) + len(b) - 1)
    exp = gf.exp
    log = gf.log
    for i, x in enumerate(a):
        if x:
            lx = log[x]
            for j, y in enumerate(b):
                if y:
                    r[i + j] ^= exp[lx + log[y]]
    return trim(r)

def p_divmod(a: Poly, b: Poly, gf: GF2m) -> Tuple[Poly, Poly]:
    a = trim(a)
    b = trim(b)
    if b == [0]:
        raise ZeroDivisionError("División polinómica por cero")
    if a == [0] or len(a) < len(b):
        return [0], a
    q = [0] * (len(a) - len(b) + 1)
    inv_lead = gf.inv(b[-1])
    lb = len(b)
    exp = gf.exp
    log = gf.log
    while a != [0] and len(a) >= lb:
        c = gf.mul(a[-1], inv_lead)
        shift = len(a) - lb
        q[shift] ^= c
        lc = log[c]
        for i, y in enumerate(b):
            if y:
                a[i + shift] ^= exp[lc + log[y]]
        a = trim(a)
    return trim(q), a

def p_mod(a: Poly, m_poly: Poly, gf: GF2m) -> Poly:
    return p_divmod(a, m_poly, gf)[1]

def p_eval(p: Poly, x: int, gf: GF2m) -> int:
    if not x:
        return p[0]
    r = 0
    exp = gf.exp
    log = gf.log
    lx = log[x]
    for c in reversed(p):
        r = (0 if not r else exp[log[r] + lx]) ^ c
    return r

def p_inv_mod(a: Poly, g: Poly, gf: GF2m) -> Poly:
    """Calcula a(x)^(-1) mod g(x) mediante el algoritmo de Euclides extendido."""
    r0, r1 = trim(g), p_mod(a, g, gf)
    u0, u1 = [0], [1]
    while len(r1) > 1:
        if r1 == [0]:
            raise ValueError("El polinomio no es invertible módulo g(x)")
        q, r2 = p_divmod(r0, r1, gf)
        r0, r1 = r1, r2
        u0, u1 = u1, p_add(u0, p_mul(q, u1, gf))
    if r1 == [0]:
        raise ValueError("El polinomio no es invertible módulo g(x)")
    return p_mod(p_esc(gf.inv(r1[0]), u1, gf), g, gf)

def p_sqrt_mod(u: Poly, g: Poly, gf: GF2m) -> Poly:
    """Calcula sqrt(u(x)) mod g(x) en característica 2.
    Escribe g(x) = g_even(x)^2 + x * g_odd(x)^2 => sqrt(x) = g_even * g_odd^(-1) mod g,
    y luego sqrt(u) = u_even + sqrt(x) * u_odd mod g."""
    g_even = trim([gf.sqrt(g[i]) for i in range(0, len(g), 2)])
    g_odd = trim([gf.sqrt(g[i]) for i in range(1, len(g), 2)])
    sqrt_x = p_mod(p_mul(g_even, p_inv_mod(g_odd, g, gf), gf), g, gf)
    u = p_mod(u, g, gf)
    u_even = trim([gf.sqrt(u[i]) for i in range(0, len(u), 2)])
    u_odd = trim([gf.sqrt(u[i]) for i in range(1, len(u), 2)])
    return p_mod(p_add(u_even, p_mul(sqrt_x, u_odd, gf)), g, gf)
