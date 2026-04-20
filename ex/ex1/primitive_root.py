def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def factorize(n):
    factors = set()
    while n % 2 == 0:
        factors.add(2)
        n //= 2
    f = 3
    while f * f <= n:
        while n % f == 0:
            factors.add(f)
            n //= f
        f += 2
    if n > 1:
        factors.add(n)
    return factors


def primitive_roots(p):
    steps = []

    if not isinstance(p, int) or p < 2:
        return None, ["Invalid modulus. Provide an integer ≥ 2"]

    if not is_prime(p):
        return None, [f"{p} is not prime. Primitive roots require prime modulus."]

    phi = p - 1
    steps.append(f"p = {p}, φ(p) = {phi}")

    factors = sorted(factorize(phi))
    steps.append(f"Prime factors of φ(p): {factors}")

    roots = []
    for g in range(2, p):
        ok = True
        for q in factors:
            if pow(g, phi // q, p) == 1:
                ok = False
                steps.append(f"g = {g} failed: g^{phi//q} ≡ 1 (mod {p})")
                break
        if ok:
            roots.append(g)
            steps.append(f"g = {g} is a primitive root")

    return roots, steps
