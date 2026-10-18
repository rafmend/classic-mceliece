import os
from hashlib import shake_256
from typing import Tuple, List, Optional, Callable
from .params import ParameterSet, TOY_PARAMS
from .gf import (
    GF2m, get_gf, bits_to_bytes_le, bytes_to_bits_le, int_to_bytes_le
)
from .poly import Poly, p_eval
from .benes import encode_benes, decode_benes
from .patterson import decode_patterson
from .gpu import encode_cpu, encode_gpu

TOY_T_HEX_COLS = [0xa3, 0x53, 0x36, 0x39, 0x5d, 0xae, 0xd6, 0xe9]
TOY_PK_BYTES = bytes(
    sum(((TOY_T_HEX_COLS[j] >> r) & 1) << j for j in range(8))
    for r in range(8)
)


def _bitrev(val: int, m: int) -> int:
    r = 0
    for b in range(m):
        if (val >> b) & 1:
            r |= 1 << (m - 1 - b)
    return r


def field_ordering(alpha_bytes: bytes, params: ParameterSet) -> Optional[List[int]]:
    """Algoritmo FieldOrdering (Sección 9.2):
    Lee q enteros de 32 bits LE, verifica que sean distintos, ordena (a_i, i)
    y define alpha_i invirtiendo los m bits de pi(i)."""
    q = params.q
    m = params.m
    a_list = [int.from_bytes(alpha_bytes[4 * i : 4 * (i + 1)], "little") for i in range(q)]
    if len(set(a_list)) < q:
        return None
    pairs = sorted((a_list[i], i) for i in range(q))
    return [_bitrev(idx, m) for _, idx in pairs]


def irreducible_poly(g_bytes: bytes, params: ParameterSet, gf: GF2m) -> Optional[Poly]:
    """Algoritmo Irreducible (Sección 9.3):
    Extrae t elementos beta_j in GF(q), forma beta(y) en GF(q)[y]/F(y) y
    calcula su polinomio minimal mónico de grado t mediante eliminación gaussiana."""
    t = params.t
    q = params.q
    beta = [int.from_bytes(g_bytes[2 * j : 2 * (j + 1)], "little") & (q - 1) for j in range(t)]
    low_terms = params.F_poly_low_terms
    exp = gf.exp
    log = gf.log

    def poly_F_mul(A: List[int], B: List[int]) -> List[int]:
        res = [0] * (2 * t - 1)
        for i, a in enumerate(A):
            if a:
                la = log[a]
                for j, b in enumerate(B):
                    if b:
                        res[i + j] ^= exp[la + log[b]]
        for d in range(2 * t - 2, t - 1, -1):
            c = res[d]
            if c:
                for deg_low, coeff in low_terms:
                    res[d - t + deg_low] ^= gf.mul(c, coeff)
        return res[:t]

    powers = [[1] + [0] * (t - 1)]
    curr = beta[:]
    for _ in range(t):
        powers.append(curr)
        if len(powers) <= t:
            curr = poly_F_mul(curr, beta)

    # Sistema lineal t x t sobre GF(q): sum_{j=0}^{t-1} g_j * powers[j] = powers[t]
    mat = [[powers[col][row] for col in range(t)] + [powers[t][row]] for row in range(t)]
    for col in range(t):
        piv = next((r for r in range(col, t) if mat[r][col]), None)
        if piv is None:
            return None
        mat[col], mat[piv] = mat[piv], mat[col]
        inv_p = gf.inv(mat[col][col])
        mat[col] = [gf.mul(x, inv_p) for x in mat[col]]
        for r in range(t):
            if r != col and mat[r][col]:
                factor = mat[r][col]
                mat[r] = [mat[r][c] ^ gf.mul(factor, mat[col][c]) for c in range(t + 1)]

    return [mat[i][t] for i in range(t)] + [1]


def mat_gen(g: Poly, alpha: List[int], params: ParameterSet, gf: GF2m) -> Optional[bytes]:
    """Algoritmo MatGen sistemático (Sección 9.4):
    Construye H_hat (mt x n) sobre F_2 usando enteros Python como bitsets de fila,
    aplica eliminación gaussiana a (I_mt | T) y serializa T fila a fila."""
    m, n, t, mt, k, row_bytes = params.m, params.n, params.t, params.mt, params.k, params.row_bytes
    evals = [p_eval(g, alpha[j], gf) for j in range(n)]
    if any(v == 0 for v in evals):
        return None
    inv_g = [gf.inv(v) for v in evals]

    rows = [0] * mt
    col_val = inv_g[:]
    for i in range(t):
        base_row = i * m
        for j in range(n):
            val = col_val[j]
            if val:
                bit = 1 << j
                for b in range(m):
                    if (val >> b) & 1:
                        rows[base_row + b] |= bit
        if i + 1 < t:
            col_val = [gf.mul(col_val[j], alpha[j]) for j in range(n)]

    # Eliminación gaussiana por filas sobre las primeras mt columnas
    for c in range(mt):
        mask = 1 << c
        piv = next((r for r in range(c, mt) if rows[r] & mask), None)
        if piv is None:
            return None
        rows[c], rows[piv] = rows[piv], rows[c]
        rc = rows[c]
        for r in range(mt):
            if r != c and (rows[r] & mask):
                rows[r] ^= rc

    # Extraer submatriz derecha T (mt filas de k bits) y empaquetar cada fila en row_bytes LE
    out = bytearray(mt * row_bytes)
    for r in range(mt):
        t_row_int = rows[r] >> mt
        out[r * row_bytes : (r + 1) * row_bytes] = int_to_bytes_le(t_row_int, row_bytes)
    return bytes(out)


def pack_g_poly(g: Poly, params: ParameterSet) -> bytes:
    """Empaqueta los t coeficientes g_0..g_{t-1} de g(x)."""
    if params.m <= 8:
        return bytes(g[:params.t])
    out = bytearray(2 * params.t)
    for i in range(params.t):
        out[2 * i : 2 * (i + 1)] = g[i].to_bytes(2, "little")
    return bytes(out)


def unpack_g_poly(g_bytes: bytes, params: ParameterSet) -> Poly:
    """Desempaqueta g_0..g_{t-1} y añade el coeficiente mónico g_t = 1."""
    if params.m <= 8:
        return list(g_bytes[:params.t]) + [1]
    return [
        int.from_bytes(g_bytes[2 * i : 2 * (i + 1)], "little")
        for i in range(params.t)
    ] + [1]


def seeded_keygen(delta: bytes, params: ParameterSet) -> Tuple[bytes, bytes]:
    """Algoritmo SeededKeyGen determinista a partir de la semilla delta de 32 bytes."""
    gf = get_gf(params)
    if params.name == "toy":
        # Juguete exacto del Capítulo 11 / Apéndice A
        flujo = shake_256(b"\x40" + delta).digest(8)
        s_bytes = flujo[:2]
        pk_bytes = TOY_PK_BYTES
        c_bytes = b"\xff"
        g_poly = [0x8, 0x1, 0x1]
        g_packed = pack_g_poly(g_poly, params)
        alpha_packed = bytes(range(4))  # relleno fijo para formato toy
        sk_bytes = delta + c_bytes + g_packed + alpha_packed + s_bytes
        return pk_bytes, sk_bytes

    n, q, t = params.n, params.q, params.t
    e_len_bytes = (n + 32 * q + 16 * t + 256) // 8  # 16980 bytes para mceliece348864

    curr_delta = delta
    while True:
        E = shake_256(b"\x40" + curr_delta).digest(e_len_bytes)
        s_bytes = E[: params.s_bytes]
        off1 = params.s_bytes
        off2 = off1 + 4 * q
        off3 = off2 + 2 * t
        alpha_raw = E[off1:off2]
        g_raw = E[off2:off3]
        delta_next = E[off3 : off3 + 32]

        alpha = field_ordering(alpha_raw, params)
        if alpha is None:
            curr_delta = delta_next
            continue

        g_poly = irreducible_poly(g_raw, params, gf)
        if g_poly is None:
            curr_delta = delta_next
            continue

        pk_bytes = mat_gen(g_poly, alpha, params, gf)
        if pk_bytes is None:
            curr_delta = delta_next
            continue

        c_bytes = (0xFFFFFFFF).to_bytes(8, "little")
        g_packed = pack_g_poly(g_poly, params)
        alpha_packed = encode_benes(alpha, params.m)
        sk_bytes = curr_delta + c_bytes + g_packed + alpha_packed + s_bytes
        assert len(pk_bytes) == params.pk_bytes
        assert len(sk_bytes) == params.sk_bytes
        return pk_bytes, sk_bytes


def keygen(params: ParameterSet, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    delta = seed if seed is not None else os.urandom(32)
    return seeded_keygen(delta, params)


def fixed_weight(params: ParameterSet, rand_bytes_fn: Callable[[int], bytes] = os.urandom) -> List[int]:
    """Algoritmo FixedWeight (Sección 10.1): genera e in F_2^n uniforme de peso exacto t."""
    n, t, m, q, tau = params.n, params.t, params.m, params.q, params.tau
    mask = q - 1
    while True:
        buf = rand_bytes_fn(2 * tau)
        d = [int.from_bytes(buf[2 * j : 2 * (j + 1)], "little") & mask for j in range(tau)]
        in_range = [v for v in d if v < n]
        if len(in_range) < t:
            continue
        chosen = in_range[:t]
        if len(set(chosen)) < t:
            continue
        e_bits = [0] * n
        for pos in chosen:
            e_bits[pos] = 1
        return e_bits


def encap(
    pk_bytes: bytes,
    params: ParameterSet,
    use_gpu: bool = False,
    fixed_e_bits: Optional[List[int]] = None,
) -> Tuple[bytes, bytes, str]:
    """Algoritmo Encap(pk) -> (C, K, device_used) (Sección 10.4):
    1. e <- FixedWeight()
    2. C <- (I_mt | T) * e
    3. K <- SHAKE256(0x01 || bytes(e) || bytes(C), 32)"""
    e_bits = fixed_e_bits if fixed_e_bits is not None else fixed_weight(params)
    if use_gpu:
        C_bytes, device_used = encode_gpu(e_bits, pk_bytes, params)
    else:
        C_bytes = encode_cpu(e_bits, pk_bytes, params)
        device_used = "CPU"
    e_bytes = bits_to_bytes_le(e_bits)
    K = shake_256(b"\x01" + e_bytes + C_bytes).digest(32)
    return C_bytes, K, device_used


def unpack_sk(sk_bytes: bytes, params: ParameterSet) -> Tuple[bytes, bytes, Poly, List[int], bytes]:
    """Extrae (delta, c, g_poly, alpha, s_bytes) de la clave secreta."""
    if len(sk_bytes) != params.sk_bytes:
        raise ValueError(f"Tamaño de clave secreta inválido: {len(sk_bytes)} != {params.sk_bytes}")
    off = 0
    delta = sk_bytes[off : off + 32]; off += 32
    c_bytes = sk_bytes[off : off + params.c_bytes]; off += params.c_bytes
    g_raw = sk_bytes[off : off + params.g_bytes]; off += params.g_bytes
    alpha_raw = sk_bytes[off : off + params.alpha_bytes]; off += params.alpha_bytes
    s_bytes = sk_bytes[off : off + params.s_bytes]

    g_poly = unpack_g_poly(g_raw, params)
    if params.name == "toy":
        alpha = list(range(16))
    else:
        alpha = decode_benes(alpha_raw, params.m)
    return delta, c_bytes, g_poly, alpha, s_bytes


def decap(sk_bytes: bytes, C_bytes: bytes, params: ParameterSet) -> Tuple[bytes, bool]:
    """Algoritmo Decap(sk, C) -> (K, valid) (Sección 10.4):
    Si Patterson devuelve e' válido de peso t con H*e' == C:
        K = SHAKE256(0x01 || bytes(e') || bytes(C), 32), valid = True
    Si falla (rechazo implícito):
        K = SHAKE256(0x00 || s_bytes || bytes(C), 32), valid = False"""
    if len(C_bytes) != params.ct_bytes:
        raise ValueError(f"Tamaño de criptograma inválido: {len(C_bytes)} != {params.ct_bytes}")
    gf = get_gf(params)
    _, _, g_poly, alpha, s_bytes = unpack_sk(sk_bytes, params)
    C_bits = bytes_to_bits_le(C_bytes, params.mt)

    e_bits = decode_patterson(C_bits, alpha, g_poly, params.n, params.t, gf)
    if e_bits is not None:
        e_bytes = bits_to_bytes_le(e_bits)
        K = shake_256(b"\x01" + e_bytes + C_bytes).digest(32)
        return K, True
    else:
        K = shake_256(b"\x00" + s_bytes + C_bytes).digest(32)
        return K, False
