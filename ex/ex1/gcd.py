def compute(a, b):
    steps = []
    while b != 0:
        steps.append(f"{a} = {b} × {a//b} + {a%b}")
        a, b = b, a % b
    steps.append(f"GCD = {a}")
    return a, "\n".join(steps)

