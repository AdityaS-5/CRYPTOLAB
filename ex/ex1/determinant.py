def determinant(mat, steps, level=0):
    """
    Recursive determinant with VERY detailed steps.
    """
    indent = "  " * level

    # Base case
    if len(mat) == 1:
        steps.append(f"{indent}det([{mat[0][0]}]) = {mat[0][0]}")
        return mat[0][0]

    det = 0
    term_values = []

    steps.append(f"{indent}Expanding determinant for matrix:")
    for row in mat:
        steps.append(f"{indent}{row}")

    for c in range(len(mat)):
        minor = [row[:c] + row[c+1:] for row in mat[1:]]

        steps.append(f"{indent}→ Minor for column {c}:")
        sub_steps = []
        sub_det = determinant(minor, sub_steps, level + 1)

        steps.extend(sub_steps)

        sign = (-1) ** c
        term = sign * mat[0][c] * sub_det

        steps.append(
            f"{indent}Term{c+1} = ({'+' if sign > 0 else '−'}1) × {mat[0][c]} × {sub_det} = {term}"
        )

        term_values.append(term)
        det += term

    # Show summation clearly
    expr = " ".join(
        [f"{'+' if v >= 0 else '−'} {abs(v)}" for v in term_values]
    )

    steps.append(f"{indent}det = {expr} = {det}")
    return det

