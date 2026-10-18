from mceliece.params import TOY_PARAMS, MCELIECE348864_PARAMS
from mceliece.kem import keygen, seeded_keygen, encap, decap

def test_toy_kem_roundtrip():
    pk, sk = keygen(TOY_PARAMS, seed=b"\x5a" * 32)
    # fixed error at positions 10 and 13
    e_bits = [0] * 16
    e_bits[10] = e_bits[13] = 1
    C, K_enc, _ = encap(pk, TOY_PARAMS, fixed_e_bits=e_bits)
    assert C == bytes([0x98])
    assert K_enc.hex() == "597f46fbba325c68f0b0b45c6ea984961461eb220d1f24024ed888912b336278"

    K_dec, valid = decap(sk, C, TOY_PARAMS)
    assert valid is True
    assert K_dec == K_enc

    # Corrupted ciphertext
    C_bad = bytes([0x99])
    K_rej, valid_rej = decap(sk, C_bad, TOY_PARAMS)
    assert valid_rej is False
    assert K_rej.hex() == "ba1a72ac26b0fcf20c55c108bb681e27aa9c270c60802a821601130b7f1e1494"

def test_mceliece348864_kem_roundtrip():
    # Use deterministic seed
    seed = b"\x42" * 32
    pk, sk = seeded_keygen(seed, MCELIECE348864_PARAMS)
    assert len(pk) == 261120
    assert len(sk) == 6492

    C, K_enc, _ = encap(pk, MCELIECE348864_PARAMS)
    assert len(C) == 96
    assert len(K_enc) == 32

    K_dec, valid = decap(sk, C, MCELIECE348864_PARAMS)
    assert valid is True
    assert K_dec == K_enc

    # Test tampering 1 bit
    C_bad = bytearray(C)
    C_bad[0] ^= 0x01
    K_rej, valid_rej = decap(sk, bytes(C_bad), MCELIECE348864_PARAMS)
    assert valid_rej is False
    assert K_rej != K_enc
