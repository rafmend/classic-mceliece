import os
import subprocess
from pathlib import Path
import pytest
from mceliece.params import TOY_PARAMS, MCELIECE348864_PARAMS
from mceliece.kem import keygen
from mceliece.hybrid import encrypt_data, decrypt_data

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_hybrid_file_encryption_toy():
    pk, sk = keygen(TOY_PARAMS, seed=b"\x5a" * 32)
    message = b"Mensaje secreto de prueba para Classic McEliece Toy!"
    container, meta = encrypt_data(message, pk, TOY_PARAMS)
    assert meta["kem_ct_bytes"] == 1
    assert len(container) > len(message)

    recovered = decrypt_data(container, sk, TOY_PARAMS)
    assert recovered == message

def test_hybrid_file_encryption_mceliece348864(tmp_path):
    pk, sk = keygen(MCELIECE348864_PARAMS, seed=b"\x42" * 32)
    message = b"Prueba con clave NIST mceliece348864 y cifrado autenticado AES-256-GCM." * 10
    container, meta = encrypt_data(message, pk, MCELIECE348864_PARAMS, use_gpu=True)
    assert meta["kem_ct_bytes"] == 96

    recovered = decrypt_data(container, sk, MCELIECE348864_PARAMS)
    assert recovered == message

    # Probar que modificar 1 byte del archivo cifrado falla la autenticación
    bad_container = bytearray(container)
    bad_container[-1] ^= 0x55
    with pytest.raises(ValueError, match="Fallo de autenticación"):
        decrypt_data(bytes(bad_container), sk, MCELIECE348864_PARAMS)

def test_cli_subcommands(tmp_path):
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
    cli = str(REPO_ROOT / "mceliece_cli.py")
    wrapper = str(REPO_ROOT / "bin" / "mceliece")

    # 1. keygen
    key_prefix = str(tmp_path / "testkey")
    cmd = ["python3", cli, "keygen", "-p", "toy", "-o", key_prefix, "--armor"]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert os.path.exists(f"{key_prefix}.pk")
    assert os.path.exists(f"{key_prefix}.sk")

    # 2. info
    cmd = ["python3", cli, "info", f"{key_prefix}.pk"]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert "CLAVE PÚBLICA" in res.stdout

    # 3. enc
    in_file = tmp_path / "doc.txt"
    enc_file = tmp_path / "doc.txt.enc"
    dec_file = tmp_path / "doc.txt.dec"
    in_file.write_text("Contenido confidencial verificado por CLI.")

    cmd = ["python3", cli, "enc", "-k", f"{key_prefix}.pk", "-i", str(in_file), "-o", str(enc_file)]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert enc_file.exists()

    # 4. dec
    cmd = ["python3", cli, "dec", "-k", f"{key_prefix}.sk", "-i", str(enc_file), "-o", str(dec_file)]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert dec_file.read_text() == "Contenido confidencial verificado por CLI."

    # 5. verify --toy
    cmd = ["python3", cli, "verify", "--toy"]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert "100% de los números, certificados y matrices coinciden con el libro" in res.stdout

    # 6. bin/mceliece wrapper
    res = subprocess.run([wrapper, "--help"], env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert "Classic McEliece Post-Quantum Cryptosystem" in res.stdout
