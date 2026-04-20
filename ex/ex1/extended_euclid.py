def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def compute(a, b):
    steps = []

    steps.append("Extended Euclidean Algorithm")
    steps.append("i\tr_i\tq_i\tx_i\ty_i")

    r_prev, r = a, b
    x_prev, x = 1, 0
    y_prev, y = 0, 1

    i = 0

    while r != 0:
        q = r_prev // r

        steps.append(
            f"{i}\t{r_prev}\t{q}\t{x_prev}\t{y_prev}"
        )

        r_prev, r = r, r_prev - q * r
        x_prev, x = x, x_prev - q * x
        y_prev, y = y, y_prev - q * y

        i += 1

    steps.append(
        f"{i}\t{r_prev}\t-\t{x_prev}\t{y_prev}"
    )

    steps.append("")
    steps.append(f"gcd({a}, {b}) = {r_prev}")
    steps.append(f"x = {x_prev}, y = {y_prev}")
    steps.append(f"{a}×({x_prev}) + {b}×({y_prev}) = {r_prev}")

    return r_prev, x_prev, y_prev, "\n".join(steps)

