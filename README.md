# Classic McEliece: Criptosistema Post-Cuántico & CLI con Aceleración GPU

[![Post-Quantum Cryptography](https://img.shields.io/badge/PQC-NIST%20Round%204%20%2F%20ISO%2F%20IEC%2018033--2-blue.svg)](https://classic.mceliece.org)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-brightgreen.svg)](https://www.python.org/)
[![PyTorch CUDA](https://img.shields.io/badge/GPU-CUDA%20Accelerated-76B900.svg?logo=nvidia)](https://pytorch.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 21 Passed](https://img.shields.io/badge/tests-21%2F21%20passed-success.svg)](tests/)

Implementación completa, moderna y de referencia didáctica del criptosistema post-cuántico **Classic McEliece**, diseñada siguiendo estrictamente las especificaciones de **NIST PQC Round 4** y **ISO/IEC 18033-2 Amd 2:2026** y la fundamentación teórica del libro didáctico incluido en la documentación ([`docs/ClassicMcEliece-Apuntes.pdf`](docs/ClassicMcEliece-Apuntes.pdf)).

El proyecto incluye una biblioteca modular en Python, una herramienta de consola (CLI) para cifrado híbrido de archivos (**KEM + DEM AES-256-GCM**), protección de claves privadas con contraseña opcional (**PBKDF2 + AES-GCM**), arranque ultrarrápido con carga diferida de GPU (**PyTorch CUDA** bajo demanda) y la documentación académica completa con los fuentes en LaTeX.

---

## Características Principales

- **Seguridad Post-Cuántica IND-CCA2**: Códigos de Goppa binarios libres de estructura adicional con más de 45 años de criptoanálisis invicto.
- **Cifrado Híbrido Autenticado (KEM + DEM)**:
  - **KEM**: Classic McEliece genera un secreto compartido $K$ de 256 bits y un criptograma $C$ de tan solo 96 bytes (`mceliece348864`).
  - **DEM**: Cifrado simétrico de alta velocidad **AES-256-GCM** para archivos de cualquier tamaño, vinculando el criptograma KEM como datos autenticados asociados (AAD) contra maleabilidad.
- **Aceleración por GPU (`--gpu`) & Arranque Ultrarrápido**:
  - Descarga el producto matriz-vector sobre $\mathbb{F}_2$ ($C = e_{\text{alto}} \oplus T \cdot e_{\text{bajo}}$) a la GPU usando tensores CUDA (PyTorch).
  - Aceleración de hasta **$14.27\times$** comprobada en GPU NVIDIA RTX 5060.
  - **Carga diferida (*lazy loading*)**: El CLI arranca en < 0.2s sin sobrecarga de importación cuando se usa la CPU.
- **Soporte de Parámetros y Alertas de Seguridad**:
  - **`mceliece348864`**: Parámetro estándar NIST Categoría 1 ($m=12, n=3488, t=64, k=2720$, clave pública de 255 KiB y seguridad clásica $\approx 141$ bits).
  - **`toy`**: Parámetro didáctico del libro ($m=4, n=16, t=2, k=8$) para pruebas pedagógicas instantáneas (claramente identificado como 0 bits de seguridad para evitar confusiones).
- **Almacenamiento Flexible y Protección de Claves**:
  - Formato binario estructurado y seguro con número mágico y metadatos.
  - Opción **`--armor`** para exportación e importación en texto plano PEM Base64 (`-----BEGIN CLASSIC MCELIECE PUBLIC KEY-----`).
  - **Protección por contraseña opcional (`--passphrase`)**: Cifrado de la clave privada `.sk` mediante derivación **PBKDF2-HMAC-SHA256** (100.000 iteraciones) + **AES-256-GCM**.
- **Verificación Matemática Paso a Paso**:
  - Subcomando `verify --toy` que reproduce al 100% todas las matrices, certificados y trazas del Apéndice A del libro.
- **Libro y Documentación Incluidos**:
  - Libro completo en PDF ([`docs/ClassicMcEliece-Apuntes.pdf`](docs/ClassicMcEliece-Apuntes.pdf)) de más de 300 páginas.
  - Código fuente completo en LaTeX ([`docs/src/`](docs/src/)).
  - Artículos fundacionales y guías de seguridad oficiales ([`docs/references/`](docs/references/)).

---

## Estructura del Repositorio

El repositorio separa limpiamente el código ejecutable de la biblioteca, los tests automatizados y la documentación académica:

```text
classic-mceliece/
├── README.md                      # Documentación principal del repositorio
├── pyproject.toml                 # Especificación de empaquetado pip / setuptools
├── LICENSE                        # Licencia MIT
├── .gitignore                     # Filtros para Python, LaTeX y claves de prueba
├── bin/
│   └── mceliece                   # Wrapper ejecutable directo para terminal
├── mceliece_cli.py                # Script CLI independiente
├── mceliece/                      # Paquete Python modular
│   ├── __init__.py                # Exportación de la API de alto nivel
│   ├── params.py                  # Parámetros estándar y didácticos
│   ├── gf.py                      # Cuerpos finitos GF(2^m) y empaquetado de bits LE
│   ├── poly.py                    # Anillo GF(2^m)[x], EEA y raíz cuadrada modular
│   ├── benes.py                   # Compresión/descompresión de permutaciones (5888 B)
│   ├── patterson.py               # Síndrome de Goppa y decodificación de Patterson
│   ├── gpu.py                     # Motor matricial CUDA (GPU) y CPU con benchmarking
│   ├── kem.py                     # Algoritmos KeyGen, FixedWeight, Encap y Decap
│   ├── format.py                  # Serialización de claves (binaria y PEM --armor)
│   ├── hybrid.py                  # Contenedor .enc y DEM AES-256-GCM autenticado
│   └── toy_verifier.py            # Verificador determinista del libro
├── tests/                         # Suite de tests automatizados (pytest)
│   ├── conftest.py                # Configuración de rutas para pytest
│   ├── test_toy.py                # Verificación del 100% de las cifras del libro
│   ├── test_kem.py                # KeyGen, Encap, Decap y rechazo implícito
│   ├── test_gpu.py                # Paridad bit a bit entre CPU y GPU (CUDA)
│   ├── test_gf_poly.py            # Cuerpos finitos, inversos, raíces y polinomios
│   ├── test_benes.py              # Red de Beneš (m=4 y m=12)
│   └── test_hybrid_cli.py         # Cifrado híbrido y subcomandos CLI
└── docs/                          # Documentación, Libro y Referencias
    ├── ClassicMcEliece-Apuntes.pdf # Libro didáctico completo en PDF
    ├── src/                       # Código fuente LaTeX del libro
    │   ├── ClassicMcEliece-Apuntes.tex
    │   └── apuntes-staging/       # Capítulos y apéndices modulares
    └── references/                # Artículos históricos y guías NIST/ISO
        ├── McEliece_Original_Paper.pdf
        ├── McEliece_cryptosystem_Wikipedia.pdf
        ├── mceliece-rationale.pdf
        ├── security-guide.pdf
        └── mceliece-20251120.txt
```

---

## Instalación y Requisitos

### Requisitos
- **Python**: `>= 3.9` (probado en Python 3.14).
- **Dependencias básicas**: `numpy`, `cryptography`.
- **Aceleración GPU (opcional)**: `torch` con soporte CUDA (NVIDIA GPU con drivers actualizados).

### Instalación Rápida
Puedes usar la herramienta inmediatamente mediante el wrapper `bin/mceliece`:
```bash
git clone https://github.com/tu-usuario/classic-mceliece.git
cd classic-mceliece
chmod +x bin/mceliece mceliece_cli.py
./bin/mceliece --help
```

O instalar el paquete editable en tu entorno virtual:
```bash
pip install -e .
# O con soporte GPU y tests:
pip install -e ".[gpu,test]"
```

---

## Guía de Uso de la Consola (CLI)

### 1. Generación de Claves (`keygen`)

Genera un par de claves Classic McEliece (`.pk` pública y `.sk` privada). Por defecto utiliza `mceliece348864`. Puedes proteger opcionalmente la clave privada con una contraseña:

```bash
# Formato binario estructurado:
./bin/mceliece keygen -o mi_clave

# Formato PEM blindado en texto (--armor):
./bin/mceliece keygen -o mi_clave --armor

# Protección opcional de la clave privada con contraseña (PBKDF2-HMAC-SHA256 + AES-256-GCM):
./bin/mceliece keygen -o mi_clave_segura --armor --passphrase "MiContraseñaSegura123!"

# Generación con el conjunto didáctico de bolsillo (toy):
./bin/mceliece keygen -p toy -o clave_toy --armor
```
*Salida:*
- `mi_clave.pk`: 261.120 bytes (binario) o ~353 KB (PEM Base64).
- `mi_clave.sk`: 6.492 bytes (con permisos automáticos `0600`, cifrada si se utilizó `--passphrase`).

---

### 2. Inspección de Claves y Criptogramas (`info`)

Muestra parámetros algebraicos, dimensiones, estado de protección y categoría de seguridad real de cualquier clave o archivo cifrado:

```bash
./bin/mceliece info mi_clave.pk
```
```text
=================================================================
 INFORMACIÓN DEL ARCHIVO: mi_clave.pk
=================================================================
 Tamaño: 353,730 bytes
 Acelerador GPU: CPU (carga GPU diferida, activar con --gpu) (Disponible: False)
 Tipo: CLAVE PÚBLICA (Public Key)
 Conjunto: mceliece348864 (ID: 0x01)
 Parámetros: m=12, n=3488, t=64, k=2720
 Formato: Armored (PEM Base64)
 Categoría NIST: 1 (NIST Categoría 1 (~141 bits clásicos, ~128 bits cuánticos))
=================================================================
```

Si se inspecciona una clave didáctica `toy`, el sistema emite una advertencia de seguridad explícita:
```text
 Categoría NIST: Ninguna (0 bits de seguridad)
 [!] ALERTA DE SEGURIDAD: Didáctico / Demostración (0 bits de seguridad, ¡NO USAR EN PRODUCCIÓN!)
```

---

### 3. Cifrado Híbrido de Archivos (`enc`)

Cifra cualquier tipo de archivo (documentos, imágenes, binarios) combinando Classic McEliece KEM con AES-256-GCM autenticado. Utiliza `--gpu` para aceleración por hardware:

```bash
./bin/mceliece enc -k mi_clave.pk -i documento.pdf -o documento.pdf.enc --gpu
```
```text
[+] Cifrando 'documento.pdf' (1,524,080 bytes) con mceliece348864...
[+] Dispositivo utilizado: NVIDIA GeForce RTX 5060 Laptop GPU
[+] Criptograma KEM C: 96 bytes
[+] Cifrado simétrico: AES-256-GCM autenticado (tiempo: 1.25ms)
[+] Archivo cifrado guardado en: documento.pdf.enc (1,524,212 bytes)
```

---

### 4. Descifrado Autenticado de Archivos (`dec`)

Descifra el contenedor `.enc`, decapsulando la clave de sesión con el decodificador de Patterson sobre el código de Goppa secreto. Si la clave está protegida por contraseña, la solicitará interactivamente o puede pasarse con `--passphrase`:

```bash
./bin/mceliece dec -k mi_clave.sk -i documento.pdf.enc -o documento_restaurado.pdf
```
```text
[+] Descifrando 'documento.pdf.enc' (1,524,212 bytes)...
[+] Autenticación AES-256-GCM y decapsulación Goppa completadas con éxito en 48.12ms.
[+] Archivo descifrado guardado en: documento_restaurado.pdf (1,524,080 bytes)
```
> Si el criptograma o los datos son modificados, el descifrado falla inmediatamente gracias a la verificación de rigidez y autenticación AAD.

---

### 5. Operaciones de KEM Puro (`kem-encap` / `kem-decap`)

Para protocolos de intercambio de claves o túneles post-cuánticos:

```bash
# Emisor: encapsula y genera la clave simétrica K y el criptograma C
./bin/mceliece kem-encap -k mi_clave.pk -c ciphertext.bin -s session_key.bin --gpu

# Receptor: decapsula C para recuperar K
./bin/mceliece kem-decap -k mi_clave.sk -c ciphertext.bin -s session_key.bin
```

---

### 6. Verificación de Estándares y Apuntes (`verify`)

Verifica punto por punto las aserciones algebraicas del libro:

```bash
./bin/mceliece verify --toy --kem
```
```text
=================================================================
 VERIFICACIÓN DE ESTÁNDARES Y VECTORES DE LOS APUNTES
=================================================================
[+] 1. Ejecutando verificación de toy.py (Capítulos 4, 5, 11 y Apéndice A)...
    - Estado: OK
    - Secciones verificadas: 8/8
    - Clave de sesión K (hex): 597f46fbba325c68f0b0b45c6ea984961461eb220d1f24024ed888912b336278
    - Clave de rechazo K'' (hex): ba1a72ac26b0fcf20c55c108bb681e27aa9c270c60802a821601130b7f1e1494
    [OK] 100% de los números, certificados y matrices coinciden con el libro.

[+] 2. Ejecutando verificación de ciclo completo de mceliece348864...
    - KeyGen (m=12, n=3488, t=64): completado en 1.26s
    - KEM Encap/Decap CPU: Concordancia de secreto compartido OK.
    - KEM Encap GPU (NVIDIA GeForce RTX 5060 Laptop GPU): Concordancia de secreto compartido OK.
    - Rechazo implícito IND-CCA2 (K = H(0, s, C)): Comportamiento correcto OK.
=================================================================
```

---

### 7. Benchmarking de Aceleración GPU (`bench`)

Compara la velocidad del producto matricial sobre $\mathbb{F}_2$ en CPU frente a GPU:

```bash
./bin/mceliece bench -p mceliece348864 --batch 256
```
```text
[+] Generando clave temporal mceliece348864 para benchmarking...
[+] Ejecutando benchmark de codificación matricial (batch=256)...
    - Tamaño del lote: 256 vectores
    - Tiempo CPU: 2538.86 ms (9.917 ms/vector)
    - Tiempo GPU (NVIDIA GeForce RTX 5060 Laptop GPU): 177.86 ms (0.695 ms/vector)
    - Aceleración GPU vs CPU: 14.27x
```

---

## Formato del Contenedor Cifrado (`.enc`)

El contenedor `.enc` es autocontenido y protege tanto la confidencialidad como la autenticidad e integridad de la cabecera:

```
+---------------+---------+-----------+-------------------+----------------+---------------+------------------+
| Magic (5B)    | Ver(1B) | Param(1B) | C_len (2B LE)     | KEM C (ct B)   | Nonce (12B)   | AES-GCM Payload  |
| "MCEL\x01"    | 0x01    | 0x01/0x00 | 96 B ó 1 B        | Criptograma    | IV aleatorio  | Datos + Tag 16B  |
+---------------+---------+-----------+-------------------+----------------+---------------+------------------+
|<----------------- Associated Authenticated Data (AAD) ------------------>|
```

---

## Ejecución de Pruebas

Para ejecutar la suite completa de pruebas unitarias:

```bash
pytest -v
```

Las 21 pruebas automatizadas cubren:
1. `test_benes`: Enrutamiento y evaluación de redes de Beneš en $m=4$ y $m=12$ (5.888 bytes).
2. `test_gf_poly`: Aritmética de cuerpos finitos $\mathbb{F}_{16}$ y $\mathbb{F}_{2^{12}}$, inversos, raíces cuadradas y algoritmo extendido de Euclides.
3. `test_gpu`: Paridad exacta bit a bit entre CPU y GPU en la codificación matricial y comprobación de disponibilidad.
4. `test_kem`: Generación de claves, encapsulación, decapsulación y rechazo implícito con criptogramas corruptos.
5. `test_toy`: Comprobación exhaustiva del 100% de las cifras y matrices del Apéndice A.
6. `test_format`: Serialización de claves públicas y privadas en binario y PEM, protección por contraseña con PBKDF2 + AES-GCM y detección de formato.
7. `test_hybrid_cli`: Cifrado/descifrado de archivos, protección de clave por contraseña en CLI, alertas dinámicas de seguridad en `info` y carga diferida (*lazy loading*) de GPU.

---

## Consideraciones de Seguridad, Auditoría y Rendimiento

> [!IMPORTANT]
> **Alcance de la Implementación & Estado de Auditoría**:
> - Esta implementación ha sido desarrollada con fines educativos, de investigación y como código de referencia didáctico de alta fidelidad para el libro didáctico adjunto.
> - **Código no auditado**: La biblioteca no ha sido sometida a una auditoría formal de seguridad por terceros independientes. Es segura para fines académicos, prácticas de laboratorio y protección de archivos personales, pero **no debe utilizarse como sustituto de bibliotecas certificadas para producción como `liboqs` u OpenSSL en infraestructuras críticas**.
> - **Canales laterales (*Side-Channels*)**: Los algoritmos algebraicos en Python puro (eliminación gaussiana, decodificación de Patterson, etapas de Beneš) contienen ramificaciones y tiempos dependientes de datos secretos (*variable-time*). No ofrecen garantías de tiempo constante (*constant-time*).
> - **Rendimiento de `keygen` (~0.7s)**: El tiempo de generación de claves en Python es sorprendentemente rápido porque utiliza el tipo `int` de Python (implementado en C con palabras de 64 bits para operaciones vectoriales XOR a nivel de palabra), pero no ejecuta las costosas mitigaciones de tiempo constante que ralentizan a la implementación C de referencia.

> [!NOTE]
> **Fuentes de Aleatoriedad Criptográfica**:
> - Todas las operaciones criptográficas del KEM y del DEM utilizan exclusivamente fuentes de entropía seguras proporcionadas por el sistema operativo (`os.urandom`) y expansión determinista estandarizada con SHAKE-256.
> - El generador `np.random` interviene **única y exclusivamente** dentro de `benchmark_encode` (`mceliece/gpu.py`) con el propósito de generar matrices sintéticas de prueba para medir el *throughput* matricial CPU vs GPU.

> [!TIP]
> **Rendimiento en Agentes y Tareas por Lotes (*Multi-file*)**:
> - Gracias a la **carga diferida (*lazy loading*)** de PyTorch, las llamadas de consola a la CLI (`mceliece --help`, `info`, `keygen`, `enc` en CPU) arrancan en **~0.15s** (16x más rápido que con carga eagerly de PyTorch).
> - Si se van a cifrar o procesar múltiples archivos (e.g., desde un agente o script automatizado), **se recomienda importar la biblioteca directamente en proceso en Python** (`from mceliece import encrypt_data, decrypt_data`), eliminando por completo el coste de inicialización de subprocesos en la shell.

---

## Documentación y Libro

En el directorio [`docs/`](docs/) se encuentran los recursos teóricos completos:

- [**`docs/ClassicMcEliece-Apuntes.pdf`**](docs/ClassicMcEliece-Apuntes.pdf): Libro didáctico exhaustivo en PDF que aborda la historia de la criptografía post-cuántica, la teoría de códigos lineales y cuerpos finitos, la construcción de Goppa, el decodificador de Patterson, la transformación IND-CCA2 y el análisis de seguridad frente a algoritmos ISD y cuánticos.
- [**`docs/src/`**](docs/src/): Fuentes originales en LaTeX para compilar el libro.
- [**`docs/references/`**](docs/references/): Documentos clave de referencia, incluyendo el artículo original de Robert McEliece (1978), la guía de seguridad oficial y el documento de diseño de Classic McEliece.

---

## Licencia

Este proyecto está bajo la Licencia [MIT](LICENSE).
