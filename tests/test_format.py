import pytest
from mceliece.params import TOY_PARAMS, MCELIECE348864_PARAMS
from mceliece.kem import keygen
from mceliece.format import (
    serialize_key,
    deserialize_key,
    is_key_encrypted,
    PK_MAGIC,
    SK_MAGIC,
    SK_ENC_MAGIC,
)


def test_public_key_serialization():
    pk, _ = keygen(TOY_PARAMS, seed=b"\x5a" * 32)

    # Binario
    raw_bin = serialize_key(pk, TOY_PARAMS, is_secret=False, armor=False)
    assert raw_bin.startswith(PK_MAGIC)
    assert not is_key_encrypted(raw_bin)
    recovered_pk, params, armored = deserialize_key(raw_bin, expect_secret=False)
    assert recovered_pk == pk
    assert params == TOY_PARAMS
    assert armored is False

    # Armored PEM
    raw_pem = serialize_key(pk, TOY_PARAMS, is_secret=False, armor=True)
    assert raw_pem.startswith(b"-----BEGIN CLASSIC MCELIECE PUBLIC KEY-----")
    assert not is_key_encrypted(raw_pem)
    recovered_pk, params, armored = deserialize_key(raw_pem, expect_secret=False)
    assert recovered_pk == pk
    assert params == TOY_PARAMS
    assert armored is True


def test_unencrypted_secret_key_serialization():
    _, sk = keygen(TOY_PARAMS, seed=b"\x5a" * 32)

    # Binario
    raw_bin = serialize_key(sk, TOY_PARAMS, is_secret=True, armor=False)
    assert raw_bin.startswith(SK_MAGIC)
    assert not is_key_encrypted(raw_bin)
    recovered_sk, params, armored = deserialize_key(raw_bin, expect_secret=True)
    assert recovered_sk == sk
    assert params == TOY_PARAMS
    assert armored is False

    # Armored PEM
    raw_pem = serialize_key(sk, TOY_PARAMS, is_secret=True, armor=True)
    assert raw_pem.startswith(b"-----BEGIN CLASSIC MCELIECE SECRET KEY-----")
    assert not is_key_encrypted(raw_pem)
    recovered_sk, params, armored = deserialize_key(raw_pem, expect_secret=True)
    assert recovered_sk == sk
    assert params == TOY_PARAMS
    assert armored is True


def test_encrypted_secret_key_serialization():
    _, sk = keygen(TOY_PARAMS, seed=b"\x5a" * 32)
    passphrase = "UltraSecureKeyPassword!"

    # 1. Binario cifrado
    enc_bin = serialize_key(sk, TOY_PARAMS, is_secret=True, armor=False, passphrase=passphrase)
    assert enc_bin.startswith(SK_ENC_MAGIC)
    assert is_key_encrypted(enc_bin)

    # Error si no se provee contraseña
    with pytest.raises(ValueError, match="protegida con contraseña"):
        deserialize_key(enc_bin, expect_secret=True)

    # Error si contraseña es errónea
    with pytest.raises(ValueError, match="Contraseña incorrecta"):
        deserialize_key(enc_bin, expect_secret=True, passphrase="WrongPassword!")

    # Descifrado correcto
    recovered_sk, params, armored = deserialize_key(enc_bin, expect_secret=True, passphrase=passphrase)
    assert recovered_sk == sk
    assert params == TOY_PARAMS
    assert armored is False

    # 2. PEM Armored cifrado
    enc_pem = serialize_key(sk, TOY_PARAMS, is_secret=True, armor=True, passphrase=passphrase)
    assert enc_pem.startswith(b"-----BEGIN ENCRYPTED CLASSIC MCELIECE SECRET KEY-----")
    assert is_key_encrypted(enc_pem)

    recovered_sk_pem, params_pem, armored_pem = deserialize_key(enc_pem, expect_secret=True, passphrase=passphrase)
    assert recovered_sk_pem == sk
    assert params_pem == TOY_PARAMS
    assert armored_pem is True
