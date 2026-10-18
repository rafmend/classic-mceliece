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


def test_cli_info_security_display(tmp_path):
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
    cli = str(REPO_ROOT / "mceliece_cli.py")

    # Clave toy
    toy_prefix = str(tmp_path / "toy_info")
    subprocess.run(["python3", cli, "keygen", "-p", "toy", "-o", toy_prefix], env=env, check=True)
    res_toy = subprocess.run(["python3", cli, "info", f"{toy_prefix}.pk"], env=env, capture_output=True, text=True)
    assert res_toy.returncode == 0
    assert "Categoría NIST: Ninguna" in res_toy.stdout
    assert "ALERTA DE SEGURIDAD" in res_toy.stdout
    assert "Categoría NIST: 1" not in res_toy.stdout

    # Clave estándar mceliece348864
    std_prefix = str(tmp_path / "std_info")
    subprocess.run(["python3", cli, "keygen", "-p", "mceliece348864", "-o", std_prefix, "--seed", "aa"*32], env=env, check=True)
    res_std = subprocess.run(["python3", cli, "info", f"{std_prefix}.pk"], env=env, capture_output=True, text=True)
    assert res_std.returncode == 0
    assert "Categoría NIST: 1" in res_std.stdout


def test_passphrase_cli_lifecycle(tmp_path):
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
    cli = str(REPO_ROOT / "mceliece_cli.py")

    prefix = str(tmp_path / "protected_key")
    passphrase = "CorrectHorseBatteryStaple!"

    # 1. keygen con --passphrase
    cmd = ["python3", cli, "keygen", "-p", "toy", "-o", prefix, "--armor", "--passphrase", passphrase]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert "cifrada con PBKDF2" in res.stdout

    # 2. info en clave privada cifrada
    res_info = subprocess.run(["python3", cli, "info", f"{prefix}.sk"], env=env, capture_output=True, text=True)
    assert res_info.returncode == 0
    assert "CLAVE PRIVADA CIFRADA" in res_info.stdout
    assert "PBKDF2-HMAC-SHA256" in res_info.stdout

    # 3. Cifrar archivo
    in_file = tmp_path / "plain.txt"
    enc_file = tmp_path / "plain.txt.enc"
    dec_file = tmp_path / "plain.txt.dec"
    in_file.write_text("Mensaje secreto cifrado con clave protegida")

    cmd = ["python3", cli, "enc", "-k", f"{prefix}.pk", "-i", str(in_file), "-o", str(enc_file)]
    subprocess.run(cmd, env=env, check=True)

    # 4. Descifrar con contraseña incorrecta (debe fallar)
    cmd_bad = ["python3", cli, "dec", "-k", f"{prefix}.sk", "-i", str(enc_file), "-o", str(dec_file), "--passphrase", "WrongPass"]
    res_bad = subprocess.run(cmd_bad, env=env, capture_output=True, text=True)
    assert res_bad.returncode != 0
    assert "Contraseña incorrecta" in res_bad.stderr

    # 5. Descifrar con contraseña correcta
    cmd_good = ["python3", cli, "dec", "-k", f"{prefix}.sk", "-i", str(enc_file), "-o", str(dec_file), "--passphrase", passphrase]
    res_good = subprocess.run(cmd_good, env=env, capture_output=True, text=True)
    assert res_good.returncode == 0
    assert dec_file.read_text() == "Mensaje secreto cifrado con clave protegida"


def test_lazy_torch_loading():
    cmd = [
        "python3",
        "-c",
        "import sys; from mceliece.gpu import get_gpu_info; info = get_gpu_info(load_torch=False); assert 'torch' not in sys.modules, 'torch was eagerly imported!'"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0

