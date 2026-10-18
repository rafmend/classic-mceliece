from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass(frozen=True)
class ParameterSet:
    name: str
    param_id: int              # 0x00 = toy, 0x01 = mceliece348864
    m: int                     # grado de extensión del cuerpo GF(2^m)
    n: int                     # longitud del código
    t: int                     # capacidad correctora (peso del error)
    f_poly: int                # máscara binaria del polinomio irreducible f(z) de GF(2^m)
    primitive_gen: int         # generador multiplicativo primitivo de GF(2^m)*
    # Polinomio F(y) = y^t + sum_{deg, coeff} coeff * y^deg para Irreducible
    F_poly_low_terms: Tuple[Tuple[int, int], ...]
    pk_bytes: int              # mt * ceil(k / 8)
    sk_bytes: int              # 32 (delta) + c_bytes + g_bytes + alpha_bytes + s_bytes
    ct_bytes: int              # ceil(mt / 8)
    c_bytes: int               # 8 para estándar, 1 para toy
    g_bytes: int               # t * ceil(m / 8)
    alpha_bytes: int           # ceil((2m - 1) * 2^(m - 4))
    s_bytes: int               # ceil(n / 8)
    seed_bytes: int = 32
    key_bytes: int = 32
    nist_category: int | None = None  # NIST Category (1, 3, 5) or None for toy/didactic
    security_bits: int = 0            # Classical security level in bits
    security_description: str = ""    # Human-readable security summary

    @property
    def q(self) -> int:
        return 1 << self.m

    @property
    def mt(self) -> int:
        return self.m * self.t

    @property
    def k(self) -> int:
        return self.n - self.mt

    @property
    def row_bytes(self) -> int:
        return (self.k + 7) // 8

    @property
    def tau(self) -> int:
        return self.t if self.n == self.q else 2 * self.t


TOY_PARAMS = ParameterSet(
    name="toy",
    param_id=0x00,
    m=4,
    n=16,
    t=2,
    f_poly=0x13,               # z^4 + z + 1
    primitive_gen=0x02,        # z
    F_poly_low_terms=((0, 0x8), (1, 0x1)),  # y^2 + y + z^3
    pk_bytes=8,                # 8 filas * 1 byte
    sk_bytes=32 + 1 + 2 + 4 + 2,  # 41 bytes
    ct_bytes=1,                # 8 bits = 1 byte
    c_bytes=1,
    g_bytes=2,                 # 2 coefs * 1 byte
    alpha_bytes=4,             # 4 bytes en toy
    s_bytes=2,                 # 16 bits = 2 bytes
    nist_category=None,
    security_bits=0,
    security_description="Didáctico / Demostración (0 bits de seguridad, ¡NO USAR EN PRODUCCIÓN!)",
)

MCELIECE348864_PARAMS = ParameterSet(
    name="mceliece348864",
    param_id=0x01,
    m=12,
    n=3488,
    t=64,
    f_poly=0x1009,             # z^12 + z^3 + 1
    primitive_gen=0x03,        # z + 1 (orden 4095 en GF(2^12))
    F_poly_low_terms=((0, 0x2), (1, 0x1), (3, 0x1)),  # y^64 + y^3 + y + z
    pk_bytes=261120,           # 768 * 340 bytes
    sk_bytes=6492,             # 32 + 8 + 128 + 5888 + 436 bytes
    ct_bytes=96,               # 768 / 8 bytes
    c_bytes=8,
    g_bytes=128,               # 64 * 2 bytes
    alpha_bytes=5888,          # 23 * 2048 bits = 47104 bits = 5888 bytes
    s_bytes=436,               # 3488 / 8 bytes
    nist_category=1,
    security_bits=141,
    security_description="NIST Categoría 1 (~141 bits clásicos, ~128 bits cuánticos)",
)

PARAMS_BY_NAME: Dict[str, ParameterSet] = {
    "toy": TOY_PARAMS,
    "mceliece348864": MCELIECE348864_PARAMS,
}

PARAMS_BY_ID: Dict[int, ParameterSet] = {
    0x00: TOY_PARAMS,
    0x01: MCELIECE348864_PARAMS,
}
