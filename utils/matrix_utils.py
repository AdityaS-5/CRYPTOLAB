def parse_matrix(text, n):
    nums = list(map(int, text.strip().split()))
    matrix = []
    idx = 0
    for i in range(n):
        row = []
        for j in range(n):
            row.append(nums[idx])
            idx += 1
        matrix.append(row)
    return matrix

