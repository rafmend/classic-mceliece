from typing import List
from .gf import bits_to_bytes_le, bytes_to_bits_le

def _benes_stages(pi: List[int], m: int) -> List[List[int]]:
    """Calcula las (2m-1) etapas de bits de control para que apply_benes(range(2^m)) == inv_pi."""
    n = 1 << m
    if m == 1:
        return [[pi[0]]]
    half = n >> 1
    inv_pi = [0] * n
    for i, p in enumerate(pi):
        inv_pi[p] = i
    c_in = [-1] * half
    c_out = [-1] * half
    for start in range(half):
        if c_in[start] != -1:
            continue
        u = start
        while c_in[u & (half - 1)] == -1:
            u_low = u & (half - 1)
            u_high = u >> (m - 1)
            c_in[u_low] = u_high
            y0 = pi[u]
            c_out[y0 & (half - 1)] = y0 >> (m - 1)
            u_partner = u ^ half
            y1 = pi[u_partner]
            c_out[y1 & (half - 1)] = (y1 >> (m - 1)) ^ 1
            u = inv_pi[y1 ^ half]
    pi_top = [0] * half
    pi_bot = [0] * half
    for j in range(half):
        in_top = j if c_in[j] == 0 else (j + half)
        in_bot = (j + half) if c_in[j] == 0 else j
        pi_top[j] = pi[in_top] & (half - 1)
        pi_bot[j] = pi[in_bot] & (half - 1)
    mid_top = _benes_stages(pi_top, m - 1)
    mid_bot = _benes_stages(pi_bot, m - 1)
    mid_stages = [t + b for t, b in zip(mid_top, mid_bot)]
    return [c_in] + mid_stages + [c_out]


def encode_benes(alpha: List[int], m: int) -> bytes:
    """Dada la lista de elementos alpha_0, ..., alpha_{q-1} en GF(2^m),
    calcula los bits de control de la red de Beneš que transforma [0..q-1] en alpha."""
    q = 1 << m
    inv_alpha = [0] * q
    for i, a in enumerate(alpha):
        inv_alpha[a] = i
    stages = _benes_stages(inv_alpha, m)
    flat_bits = [b for stage in stages for b in stage]
    return bits_to_bytes_le(flat_bits)


def decode_benes(control_bytes: bytes, m: int) -> List[int]:
    """Reconstruye la lista alpha_0, ..., alpha_{q-1} aplicando la red de Beneš."""
    n = 1 << m
    half = n >> 1
    num_stages = 2 * m - 1
    flat_bits = bytes_to_bits_le(control_bytes, num_stages * half)
    arr = list(range(n))
    for s in range(num_stages):
        bits = flat_bits[s * half : (s + 1) * half]
        k = (m - 1 - s) if s < m else (s - m + 1)
        stride = 1 << k
        block = stride << 1
        bit_idx = 0
        for base in range(0, n, block):
            for j in range(stride):
                if bits[bit_idx]:
                    i0 = base + j
                    i1 = i0 + stride
                    arr[i0], arr[i1] = arr[i1], arr[i0]
                bit_idx += 1
    return arr
