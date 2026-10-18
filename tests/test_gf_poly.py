import pytest
from mceliece.params import TOY_PARAMS, MCELIECE348864_PARAMS
from mceliece.gf import get_gf, bits_to_bytes_le, bytes_to_bits_le
from mceliece.poly import (
    p_add, p_mul, p_divmod, p_inv_mod, p_sqrt_mod, p_eval, trim
)

def test_gf_inverses():
    for p in (TOY_PARAMS, MCELIECE348864_PARAMS):
        gf = get_gf(p)
        # Test 20 elements
        for val in range(1, min(gf.q, 50)):
            inv_val = gf.inv(val)
            prod = gf.mul(val, inv_val)
            assert prod == 1, f"Fallo inverso en {p.name}: {val} * {inv_val} = {prod}"

def test_gf_sqrt_sq():
    gf = get_gf(MCELIECE348864_PARAMS)
    for val in range(100):
        sq_val = gf.sq(val)
        sqrt_val = gf.sqrt(sq_val)
        assert sqrt_val == val, f"Fallo sqrt(sq({val})) = {sqrt_val}"

def test_bit_packing_le():
    bits = [1, 0, 1, 1, 0, 0, 0, 1, 1, 1]  # 10 bits
    # Byte 0: bits 0..7 -> 1 + 4 + 8 + 128 = 141 (0x8d)
    # Byte 1: bits 8..9 -> 1 + 2 = 3 (0x03)
    b = bits_to_bytes_le(bits)
    assert b == bytes([141, 3])
    recovered = bytes_to_bits_le(b, 10)
    assert recovered == bits

def test_poly_arithmetic():
    gf = get_gf(TOY_PARAMS)
    # g(x) = x^2 + x + z^3 = [8, 1, 1]
    g = [0x8, 0x1, 0x1]
    a = [0x4, 0x9]  # 4 + 9x
    inv_a = p_inv_mod(a, g, gf)
    prod = p_mul(a, inv_a, gf)
    rem = p_divmod(prod, g, gf)[1]
    assert rem == [1], f"a * a^(-1) mod g != 1: {rem}"
