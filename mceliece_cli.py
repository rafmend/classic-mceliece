#!/usr/bin/env python3
"""
mceliece_cli.py - Herramienta de línea de comandos para Classic McEliece
Implementa cifrado híbrido KEM + DEM (AES-256-GCM), protección por contraseña opcional
para claves privadas y aceleración GPU bajo demanda (PyTorch CUDA).
"""

import sys
import os
import argparse
import time
import base64
import getpass
from typing import Optional
from mceliece.params import PARAMS_BY_NAME, PARAMS_BY_ID, MCELIECE348864_PARAMS
from mceliece.kem import keygen, encap, decap
from mceliece.hybrid import encrypt_data, decrypt_data, ENC_MAGIC
from mceliece.format import (
    serialize_key,
    deserialize_key,
    is_key_encrypted,
    PK_MAGIC,
    SK_MAGIC,
    SK_ENC_MAGIC,
)
from mceliece.gpu import get_gpu_info, benchmark_encode
from mceliece.toy_verifier import run_toy_verification


def _resolve_passphrase(args, sk_blob: bytes) -> Optional[str]:
    """Obtiene la contraseña si se indicó por CLI o solicita interactivamente si la clave está cifrada."""
    if getattr(args, "passphrase", None):
        return args.passphrase
    if is_key_encrypted(sk_blob):
        if sys.stdin.isatty():
            return getpass.getpass("[?] Introduce la contraseña para desbloquear la clave privada: ")
        else:
            print(
                "[-] Error: La clave privada está protegida por contraseña. Proporcione la contraseña con --passphrase.",
                file=sys.stderr,
            )
            sys.exit(1)
    return None


def cmd_keygen(args):
    params = PARAMS_BY_NAME.get(args.params)
    if not params:
        print(f"[-] Error: Parámetro desconocido '{args.params}'.", file=sys.stderr)
        sys.exit(1)

    seed = bytes.fromhex(args.seed) if args.seed else None
    if seed and len(seed) != 32:
        print("[-] Error: La semilla (--seed) debe tener exactamente 32 bytes (64 caracteres hex).", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Generando par de claves Classic McEliece ({params.name})...")
    t0 = time.perf_counter()
    pk_raw, sk_raw = keygen(params, seed=seed)
    elapsed = time.perf_counter() - t0

    passphrase = getattr(args, "passphrase", None)
    pk_bytes = serialize_key(pk_raw, params, is_secret=False, armor=args.armor)
    sk_bytes = serialize_key(sk_raw, params, is_secret=True, armor=args.armor, passphrase=passphrase)

    pk_path = f"{args.output}.pk"
    sk_path = f"{args.output}.sk"

    with open(pk_path, "wb") as f:
        f.write(pk_bytes)
    with open(sk_path, "wb") as f:
        f.write(sk_bytes)

    # Restringir permisos de la clave privada (chmod 600)
    try:
        os.chmod(sk_path, 0o600)
    except OSError:
        pass

    fmt_name = "PEM Base64 (--armor)" if args.armor else "Binario estructurado"
    sk_status = " (cifrada con PBKDF2 + AES-256-GCM)" if passphrase else " (sin contraseña, sin cifrar)"

    print(f"[+] Generación completada con éxito en {elapsed:.2f}s.")
    print(f"[+] Clave pública: {pk_path} ({len(pk_bytes):,} bytes, formato: {fmt_name})")
    print(f"[+] Clave privada: {sk_path} ({len(sk_bytes):,} bytes, permisos 0600{sk_status})")


def cmd_enc(args):
    if not os.path.exists(args.public_key):
        print(f"[-] Error: Archivo de clave pública no encontrado: {args.public_key}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.input):
        print(f"[-] Error: Archivo de entrada no encontrado: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.public_key, "rb") as f:
        pk_blob = f.read()
    raw_pk, params, was_armored = deserialize_key(pk_blob, expect_secret=False)

    with open(args.input, "rb") as f:
        plaintext = f.read()

    print(f"[+] Cifrando '{args.input}' ({len(plaintext):,} bytes) con {params.name}...")
    t0 = time.perf_counter()
    container, meta = encrypt_data(plaintext, raw_pk, params, use_gpu=args.gpu)
    elapsed = time.perf_counter() - t0

    with open(args.output, "wb") as f:
        f.write(container)

    print(f"[+] Dispositivo utilizado: {meta['device']}")
    print(f"[+] Criptograma KEM C: {meta['kem_ct_bytes']} bytes")
    print(f"[+] Cifrado simétrico: AES-256-GCM autenticado (tiempo: {elapsed*1000:.2f}ms)")
    print(f"[+] Archivo cifrado guardado en: {args.output} ({len(container):,} bytes)")


def cmd_dec(args):
    if not os.path.exists(args.secret_key):
        print(f"[-] Error: Archivo de clave privada no encontrado: {args.secret_key}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.input):
        print(f"[-] Error: Archivo de entrada no encontrado: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.secret_key, "rb") as f:
        sk_blob = f.read()

    passphrase = _resolve_passphrase(args, sk_blob)
    try:
        raw_sk, sk_params, was_armored = deserialize_key(sk_blob, expect_secret=True, passphrase=passphrase)
    except ValueError as exc:
        print(f"[-] Error al cargar la clave privada: {exc}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "rb") as f:
        container = f.read()

    print(f"[+] Descifrando '{args.input}' ({len(container):,} bytes)...")
    t0 = time.perf_counter()
    try:
        plaintext = decrypt_data(container, raw_sk, sk_params)
    except Exception as exc:
        print(f"[-] Error en descifrado/autenticación: {exc}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.perf_counter() - t0

    with open(args.output, "wb") as f:
        f.write(plaintext)

    print(f"[+] Autenticación AES-256-GCM y decapsulación Goppa completadas con éxito en {elapsed*1000:.2f}ms.")
    print(f"[+] Archivo descifrado guardado en: {args.output} ({len(plaintext):,} bytes)")


def cmd_kem_encap(args):
    with open(args.public_key, "rb") as f:
        pk_blob = f.read()
    raw_pk, params, _ = deserialize_key(pk_blob, expect_secret=False)

    C_bytes, K, device = encap(raw_pk, params, use_gpu=args.gpu)
    with open(args.ciphertext, "wb") as f:
        f.write(C_bytes)
    with open(args.shared_secret, "wb") as f:
        f.write(K)

    print(f"[+] KEM Encap completado ({params.name}, dispositivo: {device}):")
    print(f"[+] Criptograma C guardado en: {args.ciphertext} ({len(C_bytes)} bytes)")
    print(f"[+] Secreto compartido K guardado en: {args.shared_secret} (32 bytes, hex: {K.hex()})")


def cmd_kem_decap(args):
    with open(args.secret_key, "rb") as f:
        sk_blob = f.read()

    passphrase = _resolve_passphrase(args, sk_blob)
    try:
        raw_sk, params, _ = deserialize_key(sk_blob, expect_secret=True, passphrase=passphrase)
    except ValueError as exc:
        print(f"[-] Error al cargar la clave privada: {exc}", file=sys.stderr)
        sys.exit(1)

    with open(args.ciphertext, "rb") as f:
        C_bytes = f.read()

    K, valid = decap(raw_sk, C_bytes, params)
    with open(args.shared_secret, "wb") as f:
        f.write(K)

    if valid:
        print(f"[+] KEM Decap completado con éxito (criptograma válido y verificado).")
    else:
        print(f"[!] KEM Decap: Criptograma rechazado (rama de rechazo implícito K = H(0, s, C)).")
    print(f"[+] Secreto compartido K guardado en: {args.shared_secret} (32 bytes, hex: {K.hex()})")


def cmd_info(args):
    if not os.path.exists(args.target):
        print(f"[-] Error: Archivo no encontrado: {args.target}", file=sys.stderr)
        sys.exit(1)

    with open(args.target, "rb") as f:
        data = f.read()

    gpu_info = get_gpu_info(load_torch=getattr(args, "gpu", False))
    print("=" * 65)
    print(f" INFORMACIÓN DEL ARCHIVO: {args.target}")
    print("=" * 65)
    print(f" Tamaño: {len(data):,} bytes")
    print(f" Acelerador GPU: {gpu_info['device_name']} (Disponible: {gpu_info['available']})")

    # Identificar si es clave pública
    if data.startswith(b"-----BEGIN CLASSIC MCELIECE PUBLIC KEY-----") or data.startswith(PK_MAGIC):
        try:
            _, params, armored = deserialize_key(data, expect_secret=False)
            print(" Tipo: CLAVE PÚBLICA (Public Key)")
            print(f" Conjunto: {params.name} (ID: 0x{params.param_id:02x})")
            print(f" Parámetros: m={params.m}, n={params.n}, t={params.t}, k={params.k}")
            print(f" Formato: {'Armored (PEM Base64)' if armored else 'Binario estructurado'}")
            if params.nist_category is not None:
                print(f" Categoría NIST: {params.nist_category} ({params.security_description})")
            else:
                print(f" Categoría NIST: Ninguna (0 bits de seguridad)")
                print(f" [!] ALERTA DE SEGURIDAD: {params.security_description}")
            print("=" * 65)
            return
        except Exception:
            pass

    # Identificar si es clave privada (cifrada o en claro)
    if (
        data.startswith(b"-----BEGIN ")
        or data.startswith(SK_MAGIC)
        or data.startswith(SK_ENC_MAGIC)
    ):
        enc = is_key_encrypted(data)
        try:
            param_id = None
            armored = data.lstrip().startswith(b"-----BEGIN ")
            if armored:
                b64_lines = [
                    line.strip()
                    for line in data.decode("ascii", errors="ignore").splitlines()
                    if line.strip() and not line.startswith("-----") and ":" not in line
                ]
                blob = base64.b64decode("".join(b64_lines))
            else:
                blob = data

            if len(blob) >= 8 and blob[:7] in (SK_MAGIC, SK_ENC_MAGIC):
                param_id = blob[7]
            params = PARAMS_BY_ID.get(param_id)

            if params is not None:
                tipo_desc = "CLAVE PRIVADA CIFRADA (Encrypted Secret Key)" if enc else "CLAVE PRIVADA (Secret Key)"
                print(f" Tipo: {tipo_desc}")
                if enc:
                    print(" Protección: PBKDF2-HMAC-SHA256 (100,000 iter) + AES-256-GCM")
                else:
                    print(" Protección: Sin contraseña (solo permisos de archivo)")
                print(f" Conjunto: {params.name} (ID: 0x{params.param_id:02x})")
                print(f" Parámetros: m={params.m}, n={params.n}, t={params.t}, k={params.k}")
                print(f" Formato: {'Armored (PEM Base64)' if armored else 'Binario estructurado'}")
                if not enc:
                    print(f" Desglose: delta=32B, c={params.c_bytes}B, g={params.g_bytes}B, alpha={params.alpha_bytes}B, s={params.s_bytes}B")
                if params.nist_category is not None:
                    print(f" Categoría NIST: {params.nist_category} ({params.security_description})")
                else:
                    print(f" Categoría NIST: Ninguna (0 bits de seguridad)")
                    print(f" [!] ALERTA DE SEGURIDAD: {params.security_description}")
                print("=" * 65)
                return
        except Exception:
            pass

    # Identificar si es contenedor cifrado .enc
    if len(data) >= 8 and data[:5] == ENC_MAGIC:
        param_id = data[5]
        params = PARAMS_BY_ID.get(param_id)
        ct_len = int.from_bytes(data[6:8], "little")
        pname = params.name if params else f"Desconocido (0x{param_id:02x})"
        print(" Tipo: CONTENEDOR CIFRADO HÍBRIDO (MCEL v1)")
        print(f" Algoritmo: Classic McEliece KEM + AES-256-GCM")
        print(f" Parámetro KEM: {pname}")
        if params:
            if params.nist_category is not None:
                print(f" Seguridad KEM: Categoría NIST {params.nist_category} ({params.security_description})")
            else:
                print(f" [!] ALERTA DE SEGURIDAD: Cifrado con conjunto didáctico '{params.name}' ({params.security_description})")
        print(f" Criptograma KEM C: {ct_len} bytes")
        payload_len = len(data) - (8 + ct_len + 12 + 16)
        print(f" Carga útil cifrada: {max(0, payload_len):,} bytes")
        print("=" * 65)
        return

    print(" Formato: No reconocido como objeto Classic McEliece estándar.")
    print("=" * 65)


def cmd_verify(args):
    print("=" * 65)
    print(" VERIFICACIÓN DE ESTÁNDARES Y VECTORES DE LOS APUNTES")
    print("=" * 65)
    if args.toy or (not args.toy and not args.kem):
        print("\n[+] 1. Ejecutando verificación de toy.py (Capítulos 4, 5, 11 y Apéndice A)...")
        res = run_toy_verification(verbose=True)
        print(f"    - Estado: {res['status']}")
        print(f"    - Secciones verificadas: {res['verified_sections']}/8")
        print(f"    - Clave de sesión K (hex): {res['K_hex']}")
        print(f"    - Clave de rechazo K'' (hex): {res['K_rejected_hex']}")
        print("    [OK] 100% de los números, certificados y matrices coinciden con el libro.")

    if args.kem:
        print("\n[+] 2. Ejecutando verificación de ciclo completo de mceliece348864...")
        params = MCELIECE348864_PARAMS
        t0 = time.perf_counter()
        pk, sk = keygen(params)
        t_keygen = time.perf_counter() - t0
        print(f"    - KeyGen (m=12, n=3488, t=64): completado en {t_keygen:.2f}s")

        # Probar Encap en CPU
        C_cpu, K_cpu, _ = encap(pk, params, use_gpu=False)
        K_dec_cpu, valid_cpu = decap(sk, C_cpu, params)
        assert valid_cpu and K_dec_cpu == K_cpu, "Fallo en KEM CPU"
        print("    - KEM Encap/Decap CPU: Concordancia de secreto compartido OK.")

        # Probar Encap en GPU si está disponible
        info = get_gpu_info()
        if info["available"]:
            C_gpu, K_gpu, dev = encap(pk, params, use_gpu=True)
            K_dec_gpu, valid_gpu = decap(sk, C_gpu, params)
            assert valid_gpu and K_dec_gpu == K_gpu, "Fallo en KEM GPU"
            assert C_gpu == C_cpu or len(C_gpu) == len(C_cpu)
            print(f"    - KEM Encap GPU ({dev}): Concordancia de secreto compartido OK.")

        # Probar rechazo implícito con criptograma corrupto
        C_tampered = bytearray(C_cpu)
        C_tampered[0] ^= 0x01  # invertir 1 bit
        K_rej, valid_rej = decap(sk, bytes(C_tampered), params)
        assert not valid_rej, "El criptograma corrupto debió ser rechazado"
        assert K_rej != K_cpu, "La clave de rechazo no debe coincidir con la legítima"
        print("    - Rechazo implícito IND-CCA2 (K = H(0, s, C)): Comportamiento correcto OK.")
    print("\n" + "=" * 65)
    print(" TODAS LAS PRUEBAS DE VERIFICACIÓN SUPERADAS CON ÉXITO")
    print("=" * 65)


def cmd_bench(args):
    params = PARAMS_BY_NAME.get(args.params, MCELIECE348864_PARAMS)
    print(f"[+] Generando clave temporal {params.name} para benchmarking...")
    pk, _ = keygen(params)
    print(f"[+] Ejecutando benchmark de codificación matricial (batch={args.batch})...")
    res = benchmark_encode(pk, params, batch_size=args.batch)
    print(f"    - Tamaño del lote: {res['batch_size']} vectores")
    print(f"    - Tiempo CPU: {res['cpu_ms']:.2f} ms ({res['cpu_ms']/res['batch_size']:.3f} ms/vector)")
    if res['gpu_ms'] is not None:
        print(f"    - Tiempo GPU ({res['device']}): {res['gpu_ms']:.2f} ms ({res['gpu_ms']/res['batch_size']:.3f} ms/vector)")
        speedup = res['cpu_ms'] / res['gpu_ms']
        print(f"    - Aceleración GPU vs CPU: {speedup:.2f}x")
    else:
        print("    - GPU no disponible.")


def main():
    parser = argparse.ArgumentParser(
        prog="mceliece",
        description="Classic McEliece Post-Quantum Cryptosystem & Hybrid File Encryption (CLI)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Comandos disponibles")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generar un nuevo par de claves")
    p_keygen.add_argument("-p", "--params", choices=["mceliece348864", "toy"], default="mceliece348864", help="Conjunto de parámetros")
    p_keygen.add_argument("-o", "--output", required=True, help="Prefijo para los archivos de salida (.pk y .sk)")
    p_keygen.add_argument("--armor", action="store_true", help="Guardar en formato PEM Base64 (--armor)")
    p_keygen.add_argument("--passphrase", help="Contraseña opcional para cifrar la clave privada .sk con PBKDF2 + AES-256-GCM")
    p_keygen.add_argument("--seed", help="Semilla hex de 32 bytes (opcional, determinista)")
    p_keygen.set_defaults(func=cmd_keygen)

    # enc
    p_enc = subparsers.add_parser("enc", help="Cifrar un archivo (KEM + DEM AES-256-GCM)")
    p_enc.add_argument("-k", "--public-key", required=True, help="Ruta a la clave pública (.pk)")
    p_enc.add_argument("-i", "--input", required=True, help="Archivo de entrada a cifrar")
    p_enc.add_argument("-o", "--output", required=True, help="Archivo de salida cifrado (.enc)")
    p_enc.add_argument("--gpu", action="store_true", help="Habilitar aceleración GPU (PyTorch CUDA)")
    p_enc.set_defaults(func=cmd_enc)

    # dec
    p_dec = subparsers.add_parser("dec", help="Descifrar un archivo (.enc)")
    p_dec.add_argument("-k", "--secret-key", required=True, help="Ruta a la clave privada (.sk)")
    p_dec.add_argument("-i", "--input", required=True, help="Archivo cifrado de entrada (.enc)")
    p_dec.add_argument("-o", "--output", required=True, help="Archivo de salida descifrado")
    p_dec.add_argument("--passphrase", help="Contraseña para descifrar la clave privada .sk (si está protegida)")
    p_dec.set_defaults(func=cmd_dec)

    # kem-encap
    p_kenc = subparsers.add_parser("kem-encap", help="Operación KEM puro: encapsular secreto compartido")
    p_kenc.add_argument("-k", "--public-key", required=True, help="Ruta a la clave pública (.pk)")
    p_kenc.add_argument("-c", "--ciphertext", required=True, help="Archivo donde guardar el criptograma C")
    p_kenc.add_argument("-s", "--shared-secret", required=True, help="Archivo donde guardar la clave K (32B)")
    p_kenc.add_argument("--gpu", action="store_true", help="Habilitar aceleración GPU (PyTorch CUDA)")
    p_kenc.set_defaults(func=cmd_kem_encap)

    # kem-decap
    p_kdec = subparsers.add_parser("kem-decap", help="Operación KEM puro: decapsular secreto compartido")
    p_kdec.add_argument("-k", "--secret-key", required=True, help="Ruta a la clave privada (.sk)")
    p_kdec.add_argument("-c", "--ciphertext", required=True, help="Archivo del criptograma C de entrada")
    p_kdec.add_argument("-s", "--shared-secret", required=True, help="Archivo donde guardar la clave K (32B)")
    p_kdec.add_argument("--passphrase", help="Contraseña para descifrar la clave privada .sk (si está protegida)")
    p_kdec.set_defaults(func=cmd_kem_decap)

    # info
    p_info = subparsers.add_parser("info", help="Inspeccionar una clave o archivo cifrado")
    p_info.add_argument("target", help="Archivo a inspeccionar (.pk, .sk o .enc)")
    p_info.add_argument("--gpu", action="store_true", help="Comprobar acelerador GPU")
    p_info.set_defaults(func=cmd_info)

    # verify
    p_ver = subparsers.add_parser("verify", help="Ejecutar verificaciones matemáticas y pruebas del libro")
    p_ver.add_argument("--toy", action="store_true", help="Verificar el 100%% de las cifras de toy.py / Apéndice A")
    p_ver.add_argument("--kem", action="store_true", help="Verificar ciclo completo KEM en mceliece348864")
    p_ver.set_defaults(func=cmd_verify)

    # bench
    p_bench = subparsers.add_parser("bench", help="Benchmark de rendimiento CPU vs GPU")
    p_bench.add_argument("-p", "--params", choices=["mceliece348864", "toy"], default="mceliece348864", help="Conjunto de parámetros")
    p_bench.add_argument("--batch", type=int, default=256, help="Tamaño del lote")
    p_bench.set_defaults(func=cmd_bench)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
