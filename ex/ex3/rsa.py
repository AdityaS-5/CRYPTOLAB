"""
RSA Encryption Implementation
Provides RSA key generation, encryption, and decryption with detailed steps
"""


def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd_steps(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    d = old_s % b
    return d


def mod_pow_with_steps(base, exponent, modulus):
    result = 1
    base = base % modulus

    exp_binary = bin(exponent)[2:][::-1]

    powers = []
    current_power = base
    powers.append((1, current_power))

    for i in range(1, len(exp_binary)):
        current_power = (current_power * current_power) % modulus
        powers.append((1 << i, current_power))

    for i, bit in enumerate(exp_binary):
        if bit == '1':
            power_value = powers[i][1]
            result = (result * power_value) % modulus

    return result


def rsa_generate_keys(p, q):
    steps = []
    
    if not is_prime(p):
        steps.append("Error: p is not prime")
        return None, None, steps
    if not is_prime(q):
        steps.append("Error: q is not prime")
        return None, None, steps

    steps.append(f"Step 1: Verify primes")
    steps.append(f"  p = {p} is prime: {is_prime(p)}")
    steps.append(f"  q = {q} is prime: {is_prime(q)}")
    
    n = p * q
    steps.append(f"\nStep 2: Calculate modulus")
    steps.append(f"  n = p × q = {p} × {q} = {n}")
    
    phi = (p - 1) * (q - 1)
    steps.append(f"\nStep 3: Calculate Euler's totient function")
    steps.append(f"  φ(n) = (p-1) × (q-1) = {p-1} × {q-1} = {phi}")

    e = None
    for candidate in [65537, 17, 11, 7, 5, 3]:
        if candidate < phi and gcd(candidate, phi) == 1:
            e = candidate
            break

    if e is None:
        e = 3
        while e < phi:
            if gcd(e, phi) == 1:
                break
            e += 2
        if e >= phi:
            steps.append("Error: Could not find suitable e")
            return None, None, steps

    steps.append(f"\nStep 4: Choose public exponent e")
    steps.append(f"  e = {e} (gcd(e, φ(n)) = {gcd(e, phi)})")

    d = extended_gcd_steps(e, phi)
    steps.append(f"\nStep 5: Calculate private exponent d")
    steps.append(f"  d ≡ e^(-1) mod φ(n) = {d}")
    steps.append(f"  Verification: (e × d) mod φ(n) = ({e} × {d}) mod {phi} = {(e * d) % phi}")

    steps.append(f"\nStep 6: Key generation complete")
    steps.append(f"  Public Key (e, n): ({e}, {n})")
    steps.append(f"  Private Key (d, n): ({d}, {n})")

    return (e, n), (d, n), steps


def rsa_encrypt_number(message, e, n):
    steps = []
    
    try:
        m = int(message)
    except ValueError:
        steps.append("Error: Message must be a valid integer")
        return None, steps

    if m >= n:
        steps.append(f"Error: Message ({m}) must be less than modulus ({n})")
        return None, steps

    steps.append(f"Step 1: Input message")
    steps.append(f"  m = {m}")
    steps.append(f"  Public key (e, n) = ({e}, {n})")
    
    steps.append(f"\nStep 2: Encrypt using RSA")
    steps.append(f"  c ≡ m^e mod n")
    steps.append(f"  c ≡ {m}^{e} mod {n}")
    
    c = mod_pow_with_steps(m, e, n)
    
    steps.append(f"  c = {c}")
    steps.append(f"\nStep 3: Ciphertext")
    steps.append(f"  Encrypted message: {c}")

    return str(c), steps


def rsa_decrypt_number(ciphertext, d, n):
    steps = []
    
    try:
        c = int(ciphertext)
    except ValueError:
        steps.append("Error: Ciphertext must be a valid integer")
        return None, steps

    steps.append(f"Step 1: Input ciphertext")
    steps.append(f"  c = {c}")
    steps.append(f"  Private key (d, n) = ({d}, {n})")
    
    steps.append(f"\nStep 2: Decrypt using RSA")
    steps.append(f"  m ≡ c^d mod n")
    steps.append(f"  m ≡ {c}^{d} mod {n}")
    
    m = mod_pow_with_steps(c, d, n)
    
    steps.append(f"  m = {m}")
    steps.append(f"\nStep 3: Plaintext")
    steps.append(f"  Decrypted message: {m}")

    return str(m), steps


def rsa_encrypt_string(plaintext, e, n):
    steps = []
    encrypted_values = []

    if not plaintext:
        steps.append("Error: Plaintext cannot be empty")
        return None, steps

    steps.append(f"Step 1: Convert plaintext to ASCII values")
    
    ascii_values = []
    for i, char in enumerate(plaintext):
        ascii_val = ord(char)
        ascii_values.append(ascii_val)
        steps.append(f"  '{char}' → {ascii_val}")

    steps.append(f"\nStep 2: Encrypt each ASCII value")
    steps.append(f"  Public key (e, n) = ({e}, {n})")

    for i, ascii_val in enumerate(ascii_values):
        if ascii_val >= n:
            steps.append(f"Error: ASCII value {ascii_val} >= modulus {n}")
            return None, steps

        c = mod_pow_with_steps(ascii_val, e, n)
        encrypted_values.append(c)
        steps.append(f"  Character {i+1} (ASCII {ascii_val}): {ascii_val}^{e} mod {n} = {c}")

    steps.append(f"\nStep 3: Encrypted string")
    steps.append(f"  {' '.join(map(str, encrypted_values))}")

    return encrypted_values, steps


def rsa_decrypt_string(encrypted_values, d, n):
    steps = []
    decrypted_string = ""

    if isinstance(encrypted_values, str):
        encrypted_values = encrypted_values.replace(',', ' ').split()
        encrypted_values = [int(x.strip()) for x in encrypted_values if x.strip()]

    steps.append(f"Step 1: Input encrypted values")
    steps.append(f"  {' '.join(map(str, encrypted_values))}")
    steps.append(f"  Private key (d, n) = ({d}, {n})")

    steps.append(f"\nStep 2: Decrypt each value")

    for i, ciphertext in enumerate(encrypted_values):
        try:
            c = int(ciphertext)
            ascii_val = mod_pow_with_steps(c, d, n)

            try:
                char = chr(ascii_val)
                decrypted_string += char
                steps.append(f"  Value {i+1} ({c}): {c}^{d} mod {n} = {ascii_val} → '{char}'")
            except ValueError:
                steps.append(f"  Value {i+1} ({c}): {c}^{d} mod {n} = {ascii_val} → (invalid character)")
        except ValueError:
            steps.append(f"  Value {i+1}: Error converting to integer")

    steps.append(f"\nStep 3: Decrypted string")
    steps.append(f"  {decrypted_string}")

    return decrypted_string, steps
