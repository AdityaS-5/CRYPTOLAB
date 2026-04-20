# ex/ex1/shift_cipher.py

def encrypt(text, key):
    steps = []
    result = ""

    for c in text:
        # Alphabetic characters
        if c.isalpha():
            base = ord('A')
            e = chr((ord(c.upper()) - base + key) % 26 + base)
            steps.append(f"{c} → {e} (letter shift)")
            result += e

        # Numeric characters
        elif c.isdigit():
            e = str((int(c) + key) % 10)
            steps.append(f"{c} → {e} (digit shift)")
            result += e

        # Other characters (space, symbols)
        else:
            steps.append(f"{c} → {c} (unchanged)")
            result += c

    return result, "\n".join(steps)


def decrypt(text, key):
    steps = []
    result = ""

    for c in text:
        # Alphabetic characters
        if c.isalpha():
            base = ord('A')
            d = chr((ord(c.upper()) - base - key) % 26 + base)
            steps.append(f"{c} → {d} (letter shift)")
            result += d

        # Numeric characters
        elif c.isdigit():
            d = str((int(c) - key) % 10)
            steps.append(f"{c} → {d} (digit shift)")
            result += d

        # Other characters
        else:
            steps.append(f"{c} → {c} (unchanged)")
            result += c

    return result, "\n".join(steps)

