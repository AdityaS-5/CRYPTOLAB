"""
Diffie-Hellman key exchange module
Implements validation and key exchange with detailed intermediate steps.
"""

import random

def dh_mod_exp(base, exp, mod, include_steps=False):
    """Modular exponentiation using repeated squaring."""
    result = 1
    current_base = base % mod
    current_exp = exp
    steps = []

    if include_steps:
        steps.append(f"    Start with result = 1, base = {base} mod {mod} = {current_base}, exponent = {exp}")

    iteration = 1
    while current_exp > 0:
        if include_steps:
            steps.append(
                f"    Iteration {iteration}: exponent = {current_exp}, result = {result}, base = {current_base}"
            )

        if current_exp % 2 == 1:
            new_result = (result * current_base) % mod
            if include_steps:
                steps.append(
                    f"      Exponent is odd, so result = ({result} x {current_base}) mod {mod} = {new_result}"
                )
            result = new_result
        elif include_steps:
            steps.append("      Exponent is even, so result stays unchanged")

        new_base = (current_base * current_base) % mod
        next_exp = current_exp // 2
        if include_steps:
            steps.append(
                f"      Square the base: ({current_base} x {current_base}) mod {mod} = {new_base}"
            )
            steps.append(f"      Halve the exponent: {current_exp} // 2 = {next_exp}")

        current_base = new_base
        current_exp = next_exp
        iteration += 1

    if include_steps:
        steps.append(f"    Final result = {result}")
        return result, steps

    return result


def dh_is_prime(n, k=5):
    """Probabilistic Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def dh_prime_factors(n):
    """Return distinct prime factors of n."""
    factors = set()
    i = 2
    while i * i <= n:
        while n % i == 0:
            factors.add(i)
            n //= i
        i += 1
    if n > 1:
        factors.add(n)
    return factors


def dh_is_primitive_root(g, p):
    """Check whether g is a primitive root modulo prime p."""
    if not dh_is_prime(p):
        return False

    phi = p - 1
    factors = dh_prime_factors(phi)

    for q in factors:
        if pow(g, phi // q, p) == 1:
            return False
    return True


def diffie_hellman_exchange(p, g, xa, xb):
    """Perform Diffie-Hellman key exchange with step-by-step output."""
    steps = []
    steps.append("Diffie-Hellman Key Exchange")
    steps.append(f"Input prime p = {p}")
    steps.append(f"Input primitive root g = {g}")
    steps.append(f"Private key XA = {xa}")
    steps.append(f"Private key XB = {xb}")
    steps.append("")

    if not dh_is_prime(p):
        return None, ["Error: p is not prime"]

    steps.append("Step 1: Prime validation")
    steps.append(f"  {p} is prime")
    steps.append("")

    phi = p - 1
    factors = sorted(dh_prime_factors(phi))
    steps.append("Step 2: Primitive root validation")
    steps.append(f"  phi(p) = p - 1 = {phi}")
    steps.append(f"  Prime factors of {phi}: {', '.join(map(str, factors))}")
    for factor in factors:
        value = pow(g, phi // factor, p)
        steps.append(f"  Check g^(phi/{factor}) mod p = {g}^{phi // factor} mod {p} = {value}")
        if value == 1:
            return None, steps + [f"Error: g = {g} is not a primitive root of p = {p}"]
    steps.append(f"  {g} is a primitive root of {p}")
    steps.append("")

    if xa >= p or xb >= p:
        return None, steps + ["Error: Private keys must be less than p"]

    steps.append("Step 3: Compute public keys")
    ya, ya_steps = dh_mod_exp(g, xa, p, include_steps=True)
    yb, yb_steps = dh_mod_exp(g, xb, p, include_steps=True)
    steps.append(f"  YA = g^XA mod p = {g}^{xa} mod {p} = {ya}")
    steps.append("  Detailed modulo exponentiation for YA:")
    steps.extend(ya_steps)
    steps.append(f"  YB = g^XB mod p = {g}^{xb} mod {p} = {yb}")
    steps.append("  Detailed modulo exponentiation for YB:")
    steps.extend(yb_steps)
    steps.append("")

    steps.append("Step 4: Compute shared secret keys")
    ka, ka_steps = dh_mod_exp(yb, xa, p, include_steps=True)
    kb, kb_steps = dh_mod_exp(ya, xb, p, include_steps=True)
    steps.append(f"  KA = YB^XA mod p = {yb}^{xa} mod {p} = {ka}")
    steps.append("  Detailed modulo exponentiation for KA:")
    steps.extend(ka_steps)
    steps.append(f"  KB = YA^XB mod p = {ya}^{xb} mod {p} = {kb}")
    steps.append("  Detailed modulo exponentiation for KB:")
    steps.extend(kb_steps)
    steps.append("")

    if ka == kb:
        steps.append("Step 5: Final verification")
        steps.append(f"  Shared key established successfully: {ka}")
    else:
        return None, steps + ["Error: Key exchange failed because KA != KB"]

    return {
        'p': p,
        'g': g,
        'xa': xa,
        'xb': xb,
        'ya': ya,
        'yb': yb,
        'ka': ka,
        'kb': kb,
        'factors': factors,
        'steps': steps
    }, steps
