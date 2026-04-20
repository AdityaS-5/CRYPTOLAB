# ex/ex1/hill_cipher.py

from ex.ex1.extended_euclid import egcd
from ex.ex1.determinant import determinant


# -------------------------------------------------
# MATRIX MULTIPLICATION (P × K) WITH STEPS
# -------------------------------------------------
def matrix_multiply(vec, key, steps):
    n = len(vec)
    result = [0] * n

    steps.append("Matrix multiplication (P × K):")

    for i in range(n):
        total = 0
        expr = []

        for j in range(n):
            mul = vec[j] * key[j][i]
            expr.append(f"{vec[j]}×{key[j][i]}")
            total += mul

        result[i] = total % 26
        steps.append(
            f"C[{i}] = " +
            " + ".join(expr) +
            f" = {total} mod 26 = {result[i]}"
        )

    return result


# -------------------------------------------------
# MODULAR INVERSE
# -------------------------------------------------
def mod_inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Key matrix is not invertible modulo 26")
    return x % m


# -------------------------------------------------
# ADJOINT MATRIX (USES OLD DETERMINANT)
# -------------------------------------------------
def adjoint(matrix, steps):
    n = len(matrix)
    adj = [[0] * n for _ in range(n)]

    steps.append("Adjoint matrix calculation:")

    for i in range(n):
        for j in range(n):
            minor = [
                row[:j] + row[j+1:]
                for r, row in enumerate(matrix) if r != i
            ]

            sub_steps = []
            val = determinant(minor, sub_steps)

            steps.append(f"Minor matrix for element ({i},{j}):")
            steps.extend(sub_steps)

            adj[j][i] = ((-1) ** (i + j)) * val
            steps.append(f"Cofactor C[{i}][{j}] = {adj[j][i]}")

    return adj


# -------------------------------------------------
# INVERSE MATRIX MOD 26 (USES OLD DETERMINANT)
# -------------------------------------------------
def inverse_matrix(matrix, steps):
    det_steps = []
    det = determinant(matrix, det_steps)

    steps.append("Determinant calculation:")
    steps.extend(det_steps)
    steps.append(f"|K| = {det}")

    det_mod = det % 26
    steps.append(f"|K| mod 26 = {det_mod}")

    inv_det = mod_inverse(det_mod, 26)
    steps.append(f"Inverse of |K| mod 26 = {inv_det}")

    adj = adjoint(matrix, steps)

    inv = [
        [(inv_det * adj[i][j]) % 26 for j in range(len(matrix))]
        for i in range(len(matrix))
    ]

    steps.append("Inverse Key Matrix:")
    for row in inv:
        steps.append(" ".join(map(str, row)))

    return inv


# -------------------------------------------------
# TEXT PREPARATION
# -------------------------------------------------
def prepare_text(text, n):
    text = text.upper().replace("J", "I")
    text = "".join(c for c in text if c.isalpha())

    while len(text) % n != 0:
        text += "X"

    return text


# -------------------------------------------------
# ENCRYPTION
# -------------------------------------------------
def encrypt(plaintext, key):
    steps = []
    n = len(key)

    plaintext = prepare_text(plaintext, n)

    steps.append("Encryption:")
    steps.append("C = P × K (mod 26)")
    steps.append(f"Prepared plaintext: {plaintext}")

    nums = [ord(c) - 65 for c in plaintext]
    cipher = ""

    for i in range(0, len(nums), n):
        block = nums[i:i+n]
        steps.append(f"\nPlain block: {block}")

        result = matrix_multiply(block, key, steps)

        for v in result:
            cipher += chr(v + 65)

    steps.append(f"\nCipher text: {cipher}")
    return cipher, "\n".join(steps)


# -------------------------------------------------
# DECRYPTION
# -------------------------------------------------
def decrypt(ciphertext, key):
    steps = []
    steps.append("Decryption:")
    steps.append("P = C × K⁻¹ (mod 26)")

    inv_key = inverse_matrix(key, steps)

    plain, enc_steps = encrypt(ciphertext, inv_key)
    steps.append("\nDecryption using inverse key:")
    steps.append(enc_steps)

    return plain, "\n".join(steps)

