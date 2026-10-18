import random
from mceliece.benes import encode_benes, decode_benes

def test_benes_m4():
    m = 4
    q = 1 << m
    pi = list(range(q))
    random.seed(42)
    random.shuffle(pi)
    control_bytes = encode_benes(pi, m)
    recovered = decode_benes(control_bytes, m)
    assert recovered == pi

def test_benes_m12_size():
    m = 12
    q = 1 << m
    pi = list(range(q))
    random.seed(1234)
    random.shuffle(pi)
    control_bytes = encode_benes(pi, m)
    assert len(control_bytes) == 5888, f"Tamaño incorrecto: {len(control_bytes)} != 5888"
    recovered = decode_benes(control_bytes, m)
    assert recovered == pi
