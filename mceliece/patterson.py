from typing import List, Optional, Dict, Any
from .gf import GF2m
from .poly import (
    Poly, trim, p_add, p_esc, p_mul, p_divmod, p_eval, p_inv_mod, p_sqrt_mod
)

def compute_goppa_syndrome(v_bits: List[int], alpha: List[int], g: Poly, gf: GF2m) -> Poly:
    """Calcula el síndrome racional S(x) = sum_{j: v_j=1} 1/(x + alpha_j) mod g(x).
    Usa la identidad exacta: S_d = sum_{l=0}^{t-1-d} g_{d+1+l} * s_l,
    donde s_l = sum_{j: v_j=1} alpha_j^l / g(alpha_j)."""
    t = len(g) - 1
    s = [0] * t
    for j, bit in enumerate(v_bits):
        if bit:
            aj = alpha[j]
            cur = gf.inv(p_eval(g, aj, gf))
            for l in range(t):
                s[l] ^= cur
                cur = gf.mul(cur, aj)
    S = [0] * t
    for d in range(t):
        acc = 0
        for l in range(t - d):
            acc ^= gf.mul(g[d + 1 + l], s[l])
        S[d] = acc
    return trim(S)


def patterson_locator(S: Poly, g: Poly, gf: GF2m, trace: Optional[Dict[str, Any]] = None) -> Poly:
    """Resuelve la ecuación clave sigma * S = sigma' (mod g) mediante Patterson.
    Si trace no es None y deg(g)==2 (modo toy), guarda los certificados R, W, tau, A, B."""
    S = trim(S)
    if S == [0]:
        return [1]
    t = len(g) - 1
    R = p_inv_mod(S, g, gf)
    T_poly = p_add(R, [0, 1])  # R(x) + x
    if T_poly == [0]:
        return [0, 1]          # sigma(x) = x
    W = p_sqrt_mod(T_poly, g, gf)

    if t == 2 and trace is not None:
        tau = p_inv_mod(W, g, gf)
        A, B = p_divmod(g, tau, gf)
        sigma = p_add(p_mul(A, A, gf), p_mul([0, 1], p_mul(B, B, gf), gf))
        trace.update(R=R, W=W, tau=tau, A=A, B=B)
        return sigma

    # Caso general: Euclides extendido a (g, W) con parada en deg(r1) <= t // 2
    r0, r1 = trim(g), W
    v0, v1 = [0], [1]
    half = t // 2
    while len(r1) - 1 > half:
        q_p, r2 = p_divmod(r0, r1, gf)
        r0, r1 = r1, r2
        v0, v1 = v1, p_add(v0, p_mul(q_p, v1, gf))
    A, B = r1, v1

    # sigma(x) = A(x)^2 + x * B(x)^2
    A2 = [0] * (2 * len(A) - 1)
    for i, c in enumerate(A):
        A2[2 * i] = gf.sq(c)
    xB2 = [0] * (2 * len(B))
    for i, c in enumerate(B):
        xB2[2 * i + 1] = gf.sq(c)
    sigma = p_add(A2, xB2)
    if sigma != [0] and sigma[-1] != 0:
        sigma = p_esc(gf.inv(sigma[-1]), sigma, gf)
    return sigma


def decode_patterson(C_bits: List[int], alpha: List[int], g: Poly, n: int, t: int, gf: GF2m) -> Optional[List[int]]:
    """Algoritmo Decode de Classic McEliece (Capítulo 10):
    1. Extiende C con k ceros: v = (C, 0, ..., 0) in F_2^n.
    2. Calcula síndrome S(v) y localizador sigma(x) con Patterson.
    3. Halla las raíces de sigma en alpha_0..alpha_{n-1}.
    4. Verifica peso wt(e) == t y que el síndrome de e coincida con S(v)."""
    mt = len(C_bits)
    v_bits = C_bits + [0] * (n - mt)
    S_v = compute_goppa_syndrome(v_bits, alpha[:n], g, gf)
    if S_v == [0]:
        return None
    try:
        sigma = patterson_locator(S_v, g, gf)
    except (ZeroDivisionError, ValueError):
        return None

    if len(sigma) - 1 != t:
        return None

    roots = [j for j in range(n) if p_eval(sigma, alpha[j], gf) == 0]
    if len(roots) != t:
        return None

    e_bits = [0] * n
    for pos in roots:
        e_bits[pos] = 1

    # Verificación de síndrome (rigidez: H * e == C <=> síndrome de Goppa de e == S_v)
    S_e = compute_goppa_syndrome(e_bits, alpha[:n], g, gf)
    if S_e != S_v:
        return None

    return e_bits
