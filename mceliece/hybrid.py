import os
from hashlib import shake_256
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .params import ParameterSet, PARAMS_BY_ID
from .kem import encap, decap

ENC_MAGIC = b"MCEL\x01"  # 5 bytes


def _derive_dem_key(shared_secret_k: bytes) -> bytes:
    """Deriva una clave AES-256 desde la clave de sesión K de 32 bytes con separación de dominio."""
    return shake_256(b"CLASSIC-MCELIECE-DEM-AES256GCM-V1" + shared_secret_k).digest(32)


def encrypt_data(
    plaintext: bytes,
    pk_bytes: bytes,
    params: ParameterSet,
    use_gpu: bool = False,
) -> Tuple[bytes, Dict[str, Any]]:
    """Cifra bytes arbitrarios usando KEM Classic McEliece + DEM AES-256-GCM.
    Estructura del contenedor:
    [MCEL\\x01 (5B)] [param_id (1B)] [ct_len (2B LE)] [C (ct_bytes)] [nonce (12B)] [ciphertext + tag (N + 16B)]"""
    C_bytes, K, device_used = encap(pk_bytes, params, use_gpu=use_gpu)
    dem_key = _derive_dem_key(K)
    nonce = os.urandom(12)

    header = ENC_MAGIC + bytes([params.param_id]) + len(C_bytes).to_bytes(2, "little") + C_bytes
    aesgcm = AESGCM(dem_key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, header)

    container = header + nonce + ct_and_tag
    meta = {
        "params": params.name,
        "device": device_used,
        "kem_ct_bytes": len(C_bytes),
        "plaintext_bytes": len(plaintext),
        "container_bytes": len(container),
    }
    return container, meta


def decrypt_data(container: bytes, sk_bytes: bytes, sk_params: ParameterSet) -> bytes:
    """Descifra y autentica un contenedor .enc usando la clave secreta."""
    if len(container) < 8 or container[:5] != ENC_MAGIC:
        raise ValueError("El archivo no es un contenedor cifrado Classic McEliece válido (MCEL\\x01).")

    param_id = container[5]
    if param_id not in PARAMS_BY_ID:
        raise ValueError(f"Parámetro desconocido en contenedor: 0x{param_id:02x}")
    params = PARAMS_BY_ID[param_id]
    if params.param_id != sk_params.param_id:
        raise ValueError(
            f"La clave secreta es para '{sk_params.name}', pero el archivo fue cifrado con '{params.name}'."
        )

    ct_len = int.from_bytes(container[6:8], "little")
    if ct_len != params.ct_bytes or len(container) < 8 + ct_len + 12 + 16:
        raise ValueError("Contenedor cifrado truncado o corrupto.")

    header_end = 8 + ct_len
    header = container[:header_end]
    C_bytes = container[8:header_end]
    nonce = container[header_end : header_end + 12]
    ct_and_tag = container[header_end + 12 :]

    # Decapsulación KEM (si C fue manipulado, devuelve clave de rechazo implícito K = H(0, s, C))
    K, _ = decap(sk_bytes, C_bytes, params)
    dem_key = _derive_dem_key(K)

    aesgcm = AESGCM(dem_key)
    try:
        return aesgcm.decrypt(nonce, ct_and_tag, header)
    except Exception as exc:
        raise ValueError(
            "Fallo de autenticación o descifrado: el criptograma o la clave privada son incorrectos."
        ) from exc
