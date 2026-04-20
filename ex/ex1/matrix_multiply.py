# matrix_multiply.py
def multiply(A, B):
    """Multiplies two matrices A and B (modulo 26)"""
    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])

    if cols_A != rows_B:
        return "Error: Columns of A must match rows of B", ""

    # Initialize result matrix with zeros
    result = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
    steps = []

    for i in range(rows_A):
        for j in range(cols_B):
            total = 0
            for k in range(cols_A):
                # This is where the error likely occurred:
                # Ensure you are multiplying numbers, not lists!
                total += A[i][k] * B[k][j]

            result[i][j] = total % 26
            steps.append(f"Result[{i}][{j}] = {total} mod 26 = {result[i][j]}")

    return result, "\n".join(steps)
