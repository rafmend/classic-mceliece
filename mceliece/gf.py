from typing import List
from .params import ParameterSet, TOY_PARAMS, MCELIECE348864_PARAMS

class GF2m:
    def __init__(self, params: ParameterSet):
        self.m = params.m
        self.q = params.q
        self.order = self.q - 1
        self.f_poly = params.f_poly
        self.exp = [0] * (2 * self.order)
        self.log = [0] * self.q

        v = 1
        gen = params.primitive_gen
        for e in range(self.order):
            self.exp[e] = v
            self.exp[e + self.order] = v
            self.log[v] = e
            v = self._clmul_mod(v, gen)

    def _clmul_mod(self, a: int, b: int) -> int:
        res = 0
        q = self.q
        mod = self.f_poly
        while b:
            if b & 1:
                res ^= a
            a <<= 1
            if a & q:
                a ^= mod
            b >>= 1
        return res

    def mul(self, a: int, b: int) -> int:
        return 0 if (not a or not b) else self.exp[self.log[a] + self.log[b]]

    def sq(self, a: int) -> int:
        return 0 if not a else self.exp[self.log[a] << 1]

    def sqrt(self, a: int) -> int:
        # En GF(2^m), sqrt(a) = a^(2^(m-1))
        if not a:
            return 0
        return self.exp[(self.log[a] << (self.m - 1)) % self.order]

    def inv(self, a: int) -> int:
        if not a:
            raise ZeroDivisionError("Inverso de 0 en GF(2^m)")
        return self.exp[self.order - self.log[a]]

    def pow(self, a: int, k: int) -> int:
        if k == 0:
            return 1
        if not a:
            return 0
        return self.exp[(self.log[a] * k) % self.order]


_GF_CACHE = {}

def get_gf(params: ParameterSet) -> GF2m:
    if params.name not in _GF_CACHE:
        _GF_CACHE[params.name] = GF2m(params)
    return _GF_CACHE[params.name]


def bits_to_bytes_le(bits: List[int]) -> bytes:
    """Empaqueta una lista de bits en bytes con orden little-endian por byte:
    el bit i va al bit (i % 8) del byte (i // 8)."""
    n_bytes = (len(bits) + 7) // 8
    out = bytearray(n_bytes)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def bytes_to_bits_le(data: bytes, n_bits: int) -> List[int]:
    """Desempaqueta los primeros n_bits de data siguiendo little-endian por byte."""
    return [(data[i >> 3] >> (i & 7)) & 1 for i in range(n_bits)]


def int_to_bytes_le(bitmask: int, n_bytes: int) -> bytes:
    """Convierte un entero Python (cuyo bit j representa la posición j) a n_bytes little-endian."""
    return bitmask.to_bytes(n_bytes, "little")


def bytes_to_int_le(data: bytes) -> int:
    """Convierte bytes little-endian a un entero Python (bit j = posición j)."""
    return int.from_bytes(data, "little")
