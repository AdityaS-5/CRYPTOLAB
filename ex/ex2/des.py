# des.py
# Complete DES implementation with ECB & CBC
# Full 16-round tracing
# Correct encryption & decryption
# Designed for Crypto Lab – Aditya

# =========================
# PERMUTATION TABLES
# =========================

IP = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]

FP = [40,8,48,16,56,24,64,32,
      39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,
      37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,
      35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,
      33,1,41,9,49,17,57,25]

E = [32,1,2,3,4,5,
     4,5,6,7,8,9,
     8,9,10,11,12,13,
     12,13,14,15,16,17,
     16,17,18,19,20,21,
     20,21,22,23,24,25,
     24,25,26,27,28,29,
     28,29,30,31,32,1]

P = [16,7,20,21,
     29,12,28,17,
     1,15,23,26,
     5,18,31,10,
     2,8,24,14,
     32,27,3,9,
     19,13,30,6,
     22,11,4,25]

PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,
       3,28,15,6,21,10,
       23,19,12,4,26,8,
       16,7,27,20,13,2,
       41,52,31,37,47,55,
       30,40,51,45,33,48,
       44,49,39,56,34,53,
       46,42,50,36,29,32]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# =========================
# ALL 8 S-BOXES (MANDATORY)
# =========================

SBOX = [
# S1
[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
 [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
 [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
 [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],

# S2
[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
 [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
 [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
 [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],

# S3
[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
 [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
 [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
 [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],

# S4
[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
 [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
 [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
 [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],

# S5
[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
 [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
 [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
 [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],

# S6
[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
 [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
 [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
 [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],

# S7
[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
 [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
 [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
 [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],

# S8
[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
 [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
 [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
 [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# =========================
# HELPERS
# =========================

def permute(bits, table):
    return [bits[i-1] for i in table]

def xor(a, b):
    return [i ^ j for i, j in zip(a, b)]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def hex_to_bits(h):
    bits = []
    for c in h:
        bits.extend(map(int, format(int(c,16),'04b')))
    return bits

def bits_to_hex(bits):
    return "".join(hex(int("".join(map(str,bits[i:i+4])),2))[2:]
                   for i in range(0,len(bits),4))

def text_to_bits(t):
    bits = []
    for c in t:
        bits.extend(map(int, format(ord(c),'08b')))
    return bits

def bits_to_text(bits):
    chars = []
    for i in range(0,len(bits),8):
        chars.append(chr(int("".join(map(str,bits[i:i+8])),2)))
    return "".join(chars).rstrip("\x00")

# =========================
# KEY SCHEDULE
# =========================

def generate_subkeys(key_bits):
    key56 = permute(key_bits, PC1)
    C, D = key56[:28], key56[28:]
    keys = []
    for s in SHIFTS:
        C, D = left_shift(C,s), left_shift(D,s)
        keys.append(permute(C+D, PC2))
    return keys

# =========================
# DES BLOCK
# =========================


def des_block(block, subkeys, steps, decrypt=False):
    steps.append("\n--- Initial Permutation ---")
    block = permute(block, IP)
    steps.append("IP: " + bits_to_hex(block))

    L, R = block[:32], block[32:]
    steps.append("L0: " + bits_to_hex(L))
    steps.append("R0: " + bits_to_hex(R))

    for r in range(16):
        steps.append(f"\n--- Round {r+1} ---")

        key = subkeys[15-r] if decrypt else subkeys[r]
        steps.append("Subkey: " + bits_to_hex(key))

        ER = permute(R, E)
        steps.append("Expanded R: " + bits_to_hex(ER))

        x = xor(ER, key)
        steps.append("XOR with key: " + bits_to_hex(x))

        s_out = []
        for i in range(8):
            row = (x[i*6] << 1) | x[i*6+5]
            col = int("".join(map(str, x[i*6+1:i*6+5])), 2)
            val = SBOX[i][row][col]
            s_out.extend(map(int, format(val, '04b')))

        steps.append("After S-Box: " + bits_to_hex(s_out))

        f = permute(s_out, P)
        steps.append("After P permutation: " + bits_to_hex(f))

        new_R = xor(L, f)
        L, R = R, new_R

        steps.append("L: " + bits_to_hex(L))
        steps.append("R: " + bits_to_hex(R))

    steps.append("\n--- Final Permutation ---")
    result = permute(R + L, FP)
    steps.append("FP: " + bits_to_hex(result))

    return result


# =========================
# MAIN API
# =========================
def compute_des_trace(plaintext, key, mode="ECB", operation="ENCRYPT"):
    steps = []

    # ---- Key handling ----
    key_bits = hex_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    # ---- IV for CBC ----
    IV = hex_to_bits("0123456789abcdef")
    prev = IV

    out_bits = []

    # ======================================================
    # BLOCK PREPARATION (THIS IS THE CRITICAL FIX)
    # ======================================================
    if operation == "ENCRYPT":
        # plaintext is normal text
        blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
        if len(blocks[-1]) < 8:
            blocks[-1] = blocks[-1].ljust(8, "\x00")
    else:
        # plaintext is HEX ciphertext
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    # ======================================================
    # PROCESS EACH BLOCK
    # ======================================================
    for bi, block in enumerate(blocks):
        steps.append(f"\n=== BLOCK {bi+1} ===")

        # ---- Convert block to bits correctly ----
        if operation == "ENCRYPT":
            bits = text_to_bits(block)
            steps.append(f"Plaintext: {block}")
        else:
            bits = hex_to_bits(block)
            steps.append(f"Ciphertext (hex): {block}")

        # ---- CBC XOR (ENCRYPT) ----
        if mode == "CBC" and operation == "ENCRYPT":
            bits = xor(bits, prev)
            steps.append("After XOR with IV/prev block")

        # ---- DES CORE ----
        out = des_block(bits, subkeys, steps, decrypt=(operation == "DECRYPT"))

        # ---- CBC XOR (DECRYPT) ----
        if mode == "CBC" and operation == "DECRYPT":
            out = xor(out, prev)
            prev = bits
            steps.append("After XOR with IV/prev block")
        else:
            prev = out

        out_bits.extend(out)

    # ======================================================
    # OUTPUT CONVERSION
    # ======================================================
    if operation == "ENCRYPT":
        result = bits_to_hex(out_bits)
    else:
        result = bits_to_text(out_bits)

    return {
        "ciphertext": result,
        "steps": steps
    }

"""
def compute_des_trace(plaintext, key, mode="ECB", operation="ENCRYPT"):
    steps = []
    key_bits = hex_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    IV = hex_to_bits("0123456789abcdef")
    prev = IV
    out_bits = []

    blocks = [plaintext[i:i+8] for i in range(0,len(plaintext),8)]
    if len(blocks[-1]) < 8:
        blocks[-1] = blocks[-1].ljust(8,"\x00")

    for block in blocks:
        bits = text_to_bits(block)

        if mode=="CBC" and operation=="ENCRYPT":
            bits = xor(bits, prev)

        out = des_block(bits, subkeys, steps, operation=="DECRYPT")

        if mode=="CBC" and operation=="DECRYPT":
            out = xor(out, prev)
            prev = bits
        else:
            prev = out

        out_bits.extend(out)

    if operation == "DECRYPT":
        try:
        	text = bits_to_text(out_bits)
        	# check if printable
        	if all(32 <= ord(c) <= 126 for c in text): result = text
        	else: result = bits_to_hex(out_bits)
        except:
            result = bits_to_hex(out_bits)
    else:
    	result = bits_to_hex(out_bits)
 

    return {
        "ciphertext": result,
   ###    "steps": steps
    """
