import os
import base64
import textwrap
from typing import Tuple, Optional, Union
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .params import ParameterSet, PARAMS_BY_ID

PK_MAGIC = b"MCELPK\x01"
SK_MAGIC = b"MCELSK\x01"
SK_ENC_MAGIC = b"MCELSE\x01"

PEM_PK_BEGIN = "-----BEGIN CLASSIC MCELIECE PUBLIC KEY-----"
PEM_PK_END = "-----END CLASSIC MCELIECE PUBLIC KEY-----"
PEM_SK_BEGIN = "-----BEGIN CLASSIC MCELIECE SECRET KEY-----"
PEM_SK_END = "-----END CLASSIC MCELIECE SECRET KEY-----"
PEM_SK_ENC_BEGIN = "-----BEGIN ENCRYPTED CLASSIC MCELIECE SECRET KEY-----"
PEM_SK_ENC_END = "-----END ENCRYPTED CLASSIC MCELIECE SECRET KEY-----"

PBKDF2_ITERATIONS = 100_000
SALT_LEN = 16
NONCE_LEN = 12


def is_key_encrypted(file_bytes: bytes) -> bool:
    """Comprueba si un blob de clave corresponde a una clave privada cifrada."""
    stripped = file_bytes.lstrip()
    if stripped.startswith(b"-----BEGIN ENCRYPTED "):
        return True
    if stripped.startswith(SK_ENC_MAGIC):
        return True
    return False


def serialize_key(
    raw_key: bytes,
    params: ParameterSet,
    is_secret: bool,
    armor: bool = False,
    passphrase: Optional[Union[str, bytes]] = None,
) -> bytes:
    """Serializa una clave pública o privada. Si is_secret=True y se indica passphrase, cifra con PBKDF2 + AES-GCM."""
    if is_secret and passphrase:
        salt = os.urandom(SALT_LEN)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        pw_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        derived_key = kdf.derive(pw_bytes)
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(NONCE_LEN)
        aad = SK_ENC_MAGIC + bytes([params.param_id])
        ciphertext = aesgcm.encrypt(nonce, raw_key, aad)

        blob = aad + salt + nonce + ciphertext
        if not armor:
            return blob
        b64 = base64.b64encode(blob).decode("ascii")
        lines = "\n".join(textwrap.wrap(b64, 64))
        header = PEM_SK_ENC_BEGIN
        footer = PEM_SK_ENC_END
        return (
            f"{header}\nParameter-Set: {params.name}\n"
            f"KDF: PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS} iter)\n"
            f"Cipher: AES-256-GCM\n\n{lines}\n{footer}\n"
        ).encode("ascii")

    magic = SK_MAGIC if is_secret else PK_MAGIC
    blob = magic + bytes([params.param_id]) + raw_key
    if not armor:
        return blob
    b64 = base64.b64encode(blob).decode("ascii")
    lines = "\n".join(textwrap.wrap(b64, 64))
    header = PEM_SK_BEGIN if is_secret else PEM_PK_BEGIN
    footer = PEM_SK_END if is_secret else PEM_PK_END
    return f"{header}\nParameter-Set: {params.name}\n\n{lines}\n{footer}\n".encode("ascii")


def deserialize_key(
    file_bytes: bytes,
    expect_secret: bool,
    passphrase: Optional[Union[str, bytes]] = None,
) -> Tuple[bytes, ParameterSet, bool]:
    """Devuelve (raw_key, params, was_armored). Detecta automáticamente PEM o binario, y descifra si se requiere."""
    was_armored = False
    stripped = file_bytes.lstrip()
    if stripped.startswith(b"-----BEGIN "):
        was_armored = True
        text = file_bytes.decode("ascii")
        b64_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip()
            and not line.startswith("-----")
            and ":" not in line
        ]
        blob = base64.b64decode("".join(b64_lines))
    else:
        blob = file_bytes

    if expect_secret:
        if len(blob) >= 8 and blob[:7] == SK_ENC_MAGIC:
            param_id = blob[7]
            if param_id not in PARAMS_BY_ID:
                raise ValueError(f"Conjunto de parámetros desconocido: 0x{param_id:02x}")
            params = PARAMS_BY_ID[param_id]

            if not passphrase:
                raise ValueError("La clave privada está protegida con contraseña pero no se especificó ninguna.")

            off = 8
            salt = blob[off : off + SALT_LEN]; off += SALT_LEN
            nonce = blob[off : off + NONCE_LEN]; off += NONCE_LEN
            ciphertext = blob[off:]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
            )
            pw_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
            derived_key = kdf.derive(pw_bytes)
            aesgcm = AESGCM(derived_key)
            aad = SK_ENC_MAGIC + bytes([params.param_id])
            try:
                raw_key = aesgcm.decrypt(nonce, ciphertext, aad)
            except Exception:
                raise ValueError("Contraseña incorrecta o clave privada corrupta.")

            expected_len = params.sk_bytes
            if len(raw_key) != expected_len:
                raise ValueError(f"Longitud de clave incorrecta tras descifrar: {len(raw_key)} != {expected_len}")
            return raw_key, params, was_armored

        elif len(blob) >= 8 and blob[:7] == SK_MAGIC:
            param_id = blob[7]
            if param_id not in PARAMS_BY_ID:
                raise ValueError(f"Conjunto de parámetros desconocido: 0x{param_id:02x}")
            params = PARAMS_BY_ID[param_id]
            raw_key = blob[8:]
            expected_len = params.sk_bytes
            if len(raw_key) != expected_len:
                raise ValueError(f"Longitud de clave incorrecta: {len(raw_key)} != {expected_len}")
            return raw_key, params, was_armored
        else:
            raise ValueError("Formato de clave secreta (.sk) no válido o cabecera corrupta.")
    else:
        if len(blob) < 8 or blob[:7] != PK_MAGIC:
            raise ValueError("Formato de clave pública (.pk) no válido o cabecera corrupta.")
        param_id = blob[7]
        if param_id not in PARAMS_BY_ID:
            raise ValueError(f"Conjunto de parámetros desconocido: 0x{param_id:02x}")
        params = PARAMS_BY_ID[param_id]
        raw_key = blob[8:]
        expected_len = params.pk_bytes
        if len(raw_key) != expected_len:
            raise ValueError(f"Longitud de clave incorrecta: {len(raw_key)} != {expected_len}")
        return raw_key, params, was_armored
