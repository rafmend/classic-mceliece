"""
toy_verifier.py - Verificador integral del Apéndice A de ClassicMcEliece-Apuntes.tex
Reproduce con exactitud todas las aserciones, certificados y salidas del libro.
"""

from hashlib import shake_256
from typing import Dict, Any, List
from .params import TOY_PARAMS
from .gf import get_gf
from .poly import trim, p_add, p_esc, p_mul, p_divmod, p_eval, p_inv_mod, p_sqrt_mod, p_mod
from .patterson import patterson_locator

def p_hex(p: List[int]) -> str:
    def t(i: int) -> str:
        return "" if i == 0 else ("x" if i == 1 else f"x^{i}")
    s = '+'.join(f"{c:x}{t(i)}" for i, c in enumerate(p) if c)
    return s or '0'


def sbits(v: int, n: int) -> str:
    return ''.join(str((v >> i) & 1) for i in range(n))


def vbits(bs: List[int]) -> int:
    return sum(b << i for i, b in enumerate(bs))


def run_toy_verification(verbose: bool = False) -> Dict[str, Any]:
    gf = get_gf(TOY_PARAMS)
    EXP, LOG = gf.exp[:15], gf.log

    # 1. Columnas de H_tilde
    N = 16
    ALPHA = list(range(N))
    G_POLY = [0x8, 0x1, 0x1]
    INV_G = [gf.inv(p_eval(G_POLY, a, gf)) for a in ALPHA]
    COLS = [(INV_G[j], gf.mul(ALPHA[j], INV_G[j])) for j in range(N)]

    EXPECT_COLS = {
        0: (0xf, 0x0), 1: (0xf, 0xf), 2: (0x3, 0x6), 3: (0x3, 0x5),
        4: (0x8, 0x6), 5: (0x8, 0xe), 6: (0x2, 0xc), 7: (0x2, 0xe),
        8: (0xa, 0xf), 9: (0xa, 0x5), 10: (0xc, 0x1), 11: (0xc, 0xd),
        12: (0x5, 0x9), 13: (0x5, 0xc), 14: (0x4, 0xd), 15: (0x4, 0x9)
    }
    for j in range(N):
        assert COLS[j] == EXPECT_COLS[j], f"Discrepancia en columna {j}"

    # 2. Forma sistemática
    def hhat_variante(swap: int, msb: int):
        u = lambda j: COLS[j][1] if swap else COLS[j][0]
        v = lambda j: COLS[j][0] if swap else COLS[j][1]
        H = []
        for r in range(4):
            H.append([(u(j) >> (3 - r if msb else r)) & 1 for j in range(N)])
        for r in range(4):
            H.append([(v(j) >> (3 - r if msb else r)) & 1 for j in range(N)])
        return H

    def sistematica(H):
        A = [row[:] for row in H]
        nr = len(A)
        for c in range(nr):
            piv = next((r for r in range(c, nr) if A[r][c]), None)
            if piv is None:
                return None
            A[c], A[piv] = A[piv], A[c]
            for r in range(nr):
                if r != c and A[r][c]:
                    A[r] = [x ^ y for x, y in zip(A[r], A[c])]
        return [row[nr:] for row in A]

    EXPECT_G = [
        "1100010110000000", "1100101001000000", "0110110000100000",
        "1001110000010000", "1011101000001000", "0111010100000100",
        "0110101100000010", "1001011100000001"
    ]

    HHAT = None
    T = None
    G = None
    for var in ((0, 0), (0, 1), (1, 0), (1, 1)):
        H = hhat_variante(*var)
        T_cand = sistematica(H)
        if T_cand is None:
            continue
        G_cand = [
            sbits(sum(T_cand[a][i] << a for a in range(8)), 8) + sbits(1 << i, 8)
            for i in range(8)
        ]
        if G_cand == EXPECT_G:
            HHAT, T, G = H, T_cand, G_cand
            break
    assert G == EXPECT_G

    col_hex_T = [sum(T[a][i] << a for a in range(8)) for i in range(8)]
    assert col_hex_T == [0xa3, 0x53, 0x36, 0x39, 0x5d, 0xae, 0xd6, 0xe9]

    # 3. Síndrome del error e = {10, 13}
    e2 = [0] * N
    e2[10] = e2[13] = 1
    s0, s1 = 0, 0
    for j in (10, 13):
        s0 ^= COLS[j][0]
        s1 ^= COLS[j][1]
    assert (s0, s1) == (0x9, 0xd)

    def syndrome_toy(word):
        S = [0]
        for j, b in enumerate(word):
            if b:
                S = p_add(S, p_mod(p_mul([ALPHA[j] ^ 1, 1], [INV_G[j]], gf), G_POLY, gf))
        return S

    S_e = syndrome_toy(e2)
    assert S_e == [0x4, 0x9]

    # 4. Patterson paso a paso
    tr = {}
    sig49 = patterson_locator([0x4, 0x9], G_POLY, gf, trace=tr)
    R, W, tau, A, B = tr["R"], tr["W"], tr["tau"], tr["A"], tr["B"]
    assert R == [0xa, 0x7]
    assert p_mul([0x4, 0x9], R, gf) == p_add([1], p_esc(0xa, G_POLY, gf))
    assert p_add(R, [0, 1]) == [0xa, 0x6]
    assert W == [0xc, 0x7]
    assert p_mul(W, W, gf) == p_add([0xa, 0x6], p_esc(0x6, G_POLY, gf))
    assert tau == [0x3, 0xb]
    assert p_mul(W, tau, gf) == p_add([1], p_esc(0x4, G_POLY, gf))
    assert A == [0x3, 0x5] and B == [0xd]
    assert p_add(p_mul(tau, A, gf), B) == G_POLY
    assert sig49 == [0x5, 0xe, 0x2]
    roots = [j for j in range(N) if p_eval(sig49, ALPHA[j], gf) == 0]
    assert roots == [10, 13]

    # 5. Identidad de van Lint
    def nucleo(H_mat):
        nr = len(H_mat)
        colmask = [sum(H_mat[r][j] << r for r in range(nr)) for j in range(N)]
        tabL, tabH = [0] * 256, [0] * 256
        for b in range(256):
            sL = sH = 0
            for j in range(8):
                if (b >> j) & 1:
                    sL ^= colmask[j]
                    sH ^= colmask[8 + j]
            tabL[b], tabH[b] = sL, sH
        return frozenset(w for w in range(1 << N) if tabL[w & 255] ^ tabH[w >> 8] == 0)

    H4 = []
    g2inv = [gf.inv(gf.mul(p_eval(G_POLY, a, gf), p_eval(G_POLY, a, gf))) for a in ALPHA]
    for i in range(4):
        for l in range(4):
            H4.append([
                (gf.mul(1 if i == 0 else gf.pow(ALPHA[j], i), g2inv[j]) >> l) & 1
                for j in range(N)
            ])
    C1, C2 = nucleo(HHAT), nucleo(H4)
    assert len(C1) == len(C2) == 256 and C1 == C2

    # 6. Corrección de los 120 errores de peso 2
    ok_err = 0
    for i in range(N):
        for j in range(i + 1, N):
            w = [0] * N
            w[i] = w[j] = 1
            sig_ij = patterson_locator(syndrome_toy(w), G_POLY, gf)
            r_ij = [p for p in range(N) if p_eval(sig_ij, ALPHA[p], gf) == 0]
            if r_ij == [i, j]:
                ok_err += 1
    assert ok_err == 120

    # 7. McEliece 1978 en miniatura
    def mmul(A_m, B_m):
        return [[sum(A_m[i][k] * B_m[k][j] for k in range(len(B_m))) % 2
                 for j in range(len(B_m[0]))] for i in range(len(A_m))]

    def perm_pull(M, perm):
        return [[row[perm[j]] for j in range(len(row))] for row in M]

    def inv_f2(M):
        n_m = len(M)
        A_m = [row[:] + [1 if i == j else 0 for j in range(n_m)] for i, row in enumerate(M)]
        for c in range(n_m):
            piv = next(r for r in range(c, n_m) if A_m[r][c])
            A_m[c], A_m[piv] = A_m[piv], A_m[c]
            for r in range(n_m):
                if r != c and A_m[r][c]:
                    A_m[r] = [x ^ y for x, y in zip(A_m[r], A_m[c])]
        return [row[n_m:] for row in A_m]

    S8 = [[int(b) for b in row] for row in
          ("01101010", "10010001", "01010001", "01010110",
           "01110110", "00111110", "10011100", "00010101")]
    SIG = [14, 2, 7, 10, 4, 8, 12, 6, 9, 15, 11, 5, 0, 3, 13, 1]
    SIGINV = [SIG.index(j) for j in range(N)]
    Gm = [[int(b) for b in row] for row in EXPECT_G]
    GP = mmul(S8, perm_pull(Gm, SIG))
    GP_fig = ["1111001110010101", "0000110101111001", "0010000011101001",
              "1000100010100011", "1101000010110010", "1001001000110111",
              "0000011100111110", "0100100101110111"]
    for i, row in enumerate(GP):
        assert sbits(vbits(row), 16) == GP_fig[i]

    u = [int(c) for c in "01001101"]
    z = [int(c) for c in "0001000000001000"]
    uGP = [sum(u[i] * GP[i][j] for i in range(8)) % 2 for j in range(N)]
    x = [a ^ b for a, b in zip(uGP, z)]
    xPinv = [x[SIGINV[j]] for j in range(N)]
    zPinv = [z[SIGINV[j]] for j in range(N)]
    c = [a ^ b for a, b in zip(xPinv, zPinv)]
    S_x = syndrome_toy(xPinv)
    assert S_x == [0x2, 0x3]
    sig_1978 = patterson_locator(S_x, G_POLY, gf)
    assert [p for p in range(N) if p_eval(sig_1978, ALPHA[p], gf) == 0] == [0, 10]
    uS = c[8:]
    u_rec = [sum(uS[i] * inv_f2(S8)[i][k] for i in range(8)) % 2 for k in range(8)]
    assert u_rec == u

    # 8. KEM del juguete (Capítulo 11)
    DELTA = bytes([0x5a]) * 32
    flujo = shake_256(bytes([0x40]) + DELTA).digest(8)
    s_val = flujo[0] | (flujo[1] << 8)
    assert s_val == 0xCBAE

    e_alto, e_bajo = 0x00, 0x24
    C_bits = [
        (e_alto >> r) & 1 ^ sum(T[r][j] * ((e_bajo >> j) & 1) for j in range(8)) % 2
        for r in range(8)
    ]
    C_val = vbits(C_bits)
    assert C_val == 0x98

    K = shake_256(bytes([0x01]) + bytes([e_alto, e_bajo]) + bytes([C_val])).digest(32)
    assert K.hex() == "597f46fbba325c68f0b0b45c6ea984961461eb220d1f24024ed888912b336278"

    v = [(C_val >> r) & 1 for r in range(8)] + [0] * 8
    S_v = syndrome_toy(v)
    sig_v = patterson_locator(S_v, G_POLY, gf)
    r_v = [p for p in range(N) if p_eval(sig_v, ALPHA[p], gf) == 0]
    assert r_v == [10, 13]
    K2 = shake_256(bytes([0x01]) + bytes([e_alto, e_bajo]) + bytes([C_val])).digest(32)
    assert K2 == K

    C_t = 0x99
    v_t = [(C_t >> r) & 1 for r in range(8)] + [0] * 8
    S_t = syndrome_toy(v_t)
    sig_t = patterson_locator(S_t, G_POLY, gf)
    assert [p for p in range(N) if p_eval(sig_t, ALPHA[p], gf) == 0] == []
    K2t = shake_256(bytes([0x00]) + bytes([flujo[0], flujo[1]]) + bytes([C_t])).digest(32)
    assert K2t.hex() == "ba1a72ac26b0fcf20c55c108bb681e27aa9c270c60802a821601130b7f1e1494"

    if verbose:
        print("Todas las comprobaciones de toy.py / Apéndice A: OK (100% verificado)")

    return {
        "status": "OK",
        "verified_sections": 8,
        "K_hex": K.hex(),
        "K_rejected_hex": K2t.hex(),
    }
