"""
Classic McEliece Cryptosystem & Hybrid Encryption CLI Library
Based on NIST PQC Round 4 / ISO/IEC 18033-2 Amd 2:2026.
"""

__version__ = "1.0.0"

from .params import TOY_PARAMS, MCELIECE348864_PARAMS, PARAMS_BY_NAME, PARAMS_BY_ID
from .kem import keygen, seeded_keygen, encap, decap, fixed_weight
from .hybrid import encrypt_data, decrypt_data
from .format import serialize_key, deserialize_key
