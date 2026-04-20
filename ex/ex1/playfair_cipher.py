def generate_matrix(key):
    key = key.upper().replace("J", "I")
    seen = set()
    matrix = []

    for c in key:
        if c.isalpha() and c not in seen:
            seen.add(c)
            matrix.append(c)

    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen:
            matrix.append(c)

    return [matrix[i:i+5] for i in range(0, 25, 5)]


def find_position(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
    return None


def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = "".join([c for c in text if c.isalpha()])

    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"

        if a == b:
            pairs.append((a, "X"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2

    if len(pairs[-1]) == 1:
        pairs[-1] = (pairs[-1][0], "X")

    return pairs


def encrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Same row
    if r1 == r2:
        c1n = (c1 + 1) % 5
        c2n = (c2 + 1) % 5
        return matrix[r1][c1n], matrix[r2][c2n], f"{a}{b} → Same row → {matrix[r1][c1n]}{matrix[r2][c2n]}"

    # Same column
    if c1 == c2:
        r1n = (r1 + 1) % 5
        r2n = (r2 + 1) % 5
        return matrix[r1n][c1], matrix[r2n][c2], f"{a}{b} → Same column → {matrix[r1n][c1]}{matrix[r2n][c2]}"

    # Rectangle
    return (
        matrix[r1][c2],
        matrix[r2][c1],
        f"{a}{b} → Rectangle → {matrix[r1][c2]}{matrix[r2][c1]}"
    )


def encrypt(text, key):
    matrix = generate_matrix(key)
    steps = []

    steps.append("Playfair Matrix:")
    for row in matrix:
        steps.append(" ".join(row))

    pairs = prepare_text(text)
    steps.append("\nPrepared pairs:")
    steps.append(" ".join([a+b for a, b in pairs]))

    cipher = ""

    steps.append("\nEncryption steps:")
    for a, b in pairs:
        c1, c2, step = encrypt_pair(a, b, matrix)
        cipher += c1 + c2
        steps.append(step)

    return cipher, matrix, "\n".join(steps)
def decrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Same row → move LEFT
    if r1 == r2:
        return (
            matrix[r1][(c1 - 1) % 5],
            matrix[r2][(c2 - 1) % 5],
            f"{a}{b} → Same row → shift left"
        )

    # Same column → move UP
    if c1 == c2:
        return (
            matrix[(r1 - 1) % 5][c1],
            matrix[(r2 - 1) % 5][c2],
            f"{a}{b} → Same column → shift up"
        )

    # Rectangle rule
    return (
        matrix[r1][c2],
        matrix[r2][c1],
        f"{a}{b} → Rectangle → swap columns"
    )

def decrypt(cipher_text, key):
    matrix = generate_matrix(key)
    steps = []

    steps.append("Playfair Matrix:")
    for row in matrix:
        steps.append(" ".join(row))

    cipher_text = cipher_text.upper().replace("J", "I")
    cipher_text = "".join(c for c in cipher_text if c.isalpha())

    pairs = [(cipher_text[i], cipher_text[i+1]) for i in range(0, len(cipher_text), 2)]
    steps.append("\nCipher pairs:")
    steps.append(" ".join(a + b for a, b in pairs))

    plain = ""
    steps.append("\nDecryption steps:")

    for a, b in pairs:
        p1, p2, step = decrypt_pair(a, b, matrix)
        plain += p1 + p2
        steps.append(step)

    return plain, matrix, "\n".join(steps)

