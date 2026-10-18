import base64
import textwrap
from typing import Tuple
from .params import ParameterSet, PARAMS_BY_ID

PK_MAGIC = b"MCELPK\x01"
SK_MAGIC = b"MCELSK\x01"

PEM_PK_BEGIN = "-----BEGIN CLASSIC MCELIECE PUBLIC KEY-----"
PEM_PK_END = "-----END CLASSIC MCELIECE PUBLIC KEY-----"
PEM_SK_BEGIN = "-----BEGIN CLASSIC MCELIECE SECRET KEY-----"
PEM_SK_END = "-----END CLASSIC MCELIECE SECRET KEY-----"


def serialize_key(raw_key: bytes, params: ParameterSet, is_secret: bool, armor: bool = False) -> bytes:
    magic = SK_MAGIC if is_secret else PK_MAGIC
    blob = magic + bytes([params.param_id]) + raw_key
    if not armor:
        return blob
    b64 = base64.b64encode(blob).decode("ascii")
    lines = "\n".join(textwrap.wrap(b64, 64))
    header = PEM_SK_BEGIN if is_secret else PEM_PK_BEGIN
    footer = PEM_SK_END if is_secret else PEM_PK_END
    return f"{header}\nParameter-Set: {params.name}\n\n{lines}\n{footer}\n".encode("ascii")


def deserialize_key(file_bytes: bytes, expect_secret: bool) -> Tuple[bytes, ParameterSet, bool]:
    """Devuelve (raw_key, params, was_armored). Detecta automáticamente PEM o binario."""
    was_armored = False
    if file_bytes.lstrip().startswith(b"-----BEGIN "):
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

    expected_magic = SK_MAGIC if expect_secret else PK_MAGIC
    if len(blob) < 8 or blob[:7] != expected_magic:
        tipo = "secreta (.sk)" if expect_secret else "pública (.pk)"
        raise ValueError(f"Formato de clave {tipo} no válido o cabecera corrupta.")

    param_id = blob[7]
    if param_id not in PARAMS_BY_ID:
        raise ValueError(f"Conjunto de parámetros desconocido: 0x{param_id:02x}")
    params = PARAMS_BY_ID[param_id]
    raw_key = blob[8:]
    expected_len = params.sk_bytes if expect_secret else params.pk_bytes
    if len(raw_key) != expected_len:
        raise ValueError(f"Longitud de clave incorrecta: {len(raw_key)} != {expected_len}")
    return raw_key, params, was_armored
