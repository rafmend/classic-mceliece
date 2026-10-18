from mceliece.params import TOY_PARAMS, MCELIECE348864_PARAMS
from mceliece.kem import keygen, encap, fixed_weight
from mceliece.gpu import get_gpu_info, encode_cpu, encode_gpu

def test_gpu_availability():
    info = get_gpu_info()
    assert "device_name" in info
    assert "available" in info

def test_gpu_cpu_consistency_toy():
    pk, _ = keygen(TOY_PARAMS, seed=b"\x5a" * 32)
    e_bits = [0] * 16
    e_bits[10] = e_bits[13] = 1
    c_cpu = encode_cpu(e_bits, pk, TOY_PARAMS)
    c_gpu, dev = encode_gpu(e_bits, pk, TOY_PARAMS)
    assert c_cpu == c_gpu == bytes([0x98])

def test_gpu_cpu_consistency_348864():
    pk, _ = keygen(MCELIECE348864_PARAMS, seed=b"\x42" * 32)
    e_bits = fixed_weight(MCELIECE348864_PARAMS)
    c_cpu = encode_cpu(e_bits, pk, MCELIECE348864_PARAMS)
    c_gpu, dev = encode_gpu(e_bits, pk, MCELIECE348864_PARAMS)
    assert c_cpu == c_gpu
    assert len(c_gpu) == 96
