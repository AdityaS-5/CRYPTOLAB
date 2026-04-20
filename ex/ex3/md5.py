"""
MD5 hashing module
Provides a backend-only MD5 implementation with detailed intermediate steps.
"""

from math import sin

MD5_INIT_A = 0x67452301
MD5_INIT_B = 0xEFCDAB89
MD5_INIT_C = 0x98BADCFE
MD5_INIT_D = 0x10325476
MD5_SHIFT_AMOUNTS = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
]
MD5_K = [int(abs(sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]


def _md5_left_rotate(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def _md5_hex32(value):
    return f"{value & 0xFFFFFFFF:08x}"


def _md5_bytes_to_bit_string(data):
    return ''.join(f"{byte:08b}" for byte in data)


def _md5_format_block_bits(data):
    bit_string = _md5_bytes_to_bit_string(data)
    grouped = [bit_string[i:i + 32] for i in range(0, len(bit_string), 32)]
    return ' '.join(grouped)


def md5_hash_with_steps(message):
    """Compute an MD5 digest and return a detailed backend step trace."""
    if message is None:
        message = ""
    if not isinstance(message, str):
        message = str(message)

    original_bytes = message.encode('utf-8')
    original_bit_length = len(original_bytes) * 8
    remainder = original_bit_length % 512

    steps = []
    steps.append("MD5 Message Digest")
    steps.append(f"Input message: {message!r}")
    steps.append(f"UTF-8 bytes: {' '.join(f'{b:02x}' for b in original_bytes) or '(empty)'}")
    steps.append(f"Original length: {len(original_bytes)} bytes = {original_bit_length} bits")
    steps.append("")
    steps.append("Step 1: Divide input into 512-bit blocks")
    if original_bytes:
        original_block_count = (len(original_bytes) + 63) // 64
        for index in range(original_block_count):
            chunk = original_bytes[index * 64:(index + 1) * 64]
            steps.append(
                f"  Original chunk {index + 1}: {len(chunk)} bytes = {len(chunk) * 8} bits"
            )
    else:
        steps.append("  Original input occupies 0 full blocks before padding")

    steps.append("")
    steps.append("Step 2: Padding process")
    steps.append(f"  Original length mod 512 = {remainder}")
    if remainder == 448:
        padding_case = "Case 1: length mod 512 = 448, append only the 64-bit length field"
    elif remainder == 447:
        padding_case = "Case 2: length mod 512 = 447, append 1 bit and then the 64-bit length field"
    elif remainder < 447:
        padding_case = "Case 3: length mod 512 < 447, append 1 bit, enough 0 bits to reach 448, then append the 64-bit length field"
    else:
        padding_case = "Case 4: length mod 512 > 448, append 1 bit and zeros into a new block before appending the 64-bit length field"
    steps.append(f"  {padding_case}")

    padded = bytearray(original_bytes)
    padded.append(0x80)
    zero_bytes_added = 0
    while (len(padded) * 8) % 512 != 448:
        padded.append(0x00)
        zero_bytes_added += 1
    length_field = (original_bit_length & 0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder='little')
    padded.extend(length_field)

    steps.append("  Appended the '1' bit as byte 0x80")
    steps.append(f"  Added {zero_bytes_added} zero bytes ({zero_bytes_added * 8} zero bits)")
    steps.append(
        f"  Appended 64-bit original length (little-endian): {' '.join(f'{b:02x}' for b in length_field)}"
    )
    steps.append(f"  Total padded length: {len(padded)} bytes = {len(padded) * 8} bits")

    blocks = [bytes(padded[i:i + 64]) for i in range(0, len(padded), 64)]
    block_summaries = []
    steps.append("")
    steps.append("Step 3: Padded 512-bit blocks")
    for index, block in enumerate(blocks):
        block_summaries.append({
            'index': index + 1,
            'size_bits': len(block) * 8,
            'hex': block.hex(),
            'bits': _md5_format_block_bits(block)
        })
        steps.append(f"  Block {index + 1}: {len(block) * 8} bits")

    steps.append("")
    steps.append("Step 4: Initialize MD5 buffer values")
    steps.append(f"  A = {_md5_hex32(MD5_INIT_A)}")
    steps.append(f"  B = {_md5_hex32(MD5_INIT_B)}")
    steps.append(f"  C = {_md5_hex32(MD5_INIT_C)}")
    steps.append(f"  D = {_md5_hex32(MD5_INIT_D)}")

    a0 = MD5_INIT_A
    b0 = MD5_INIT_B
    c0 = MD5_INIT_C
    d0 = MD5_INIT_D
    block_details = []

    for block_index, block in enumerate(blocks):
        words = [
            int.from_bytes(block[offset:offset + 4], byteorder='little')
            for offset in range(0, 64, 4)
        ]
        aa, bb, cc, dd = a0, b0, c0, d0
        A, B, C, D = a0, b0, c0, d0
        rounds = []

        for t in range(64):
            old_a, old_b, old_c, old_d = A, B, C, D

            if 0 <= t <= 15:
                function_name = "F"
                f_value = (B & C) | ((~B) & D)
                word_index = t
            elif 16 <= t <= 31:
                function_name = "G"
                f_value = (B & D) | (C & (~D))
                word_index = (5 * t + 1) % 16
            elif 32 <= t <= 47:
                function_name = "H"
                f_value = B ^ C ^ D
                word_index = (3 * t + 5) % 16
            else:
                function_name = "I"
                f_value = C ^ (B | (~D))
                word_index = (7 * t) % 16

            f_value &= 0xFFFFFFFF
            word_value = words[word_index]
            constant = MD5_K[t]
            shift = MD5_SHIFT_AMOUNTS[t]
            accumulator = (A + f_value + constant + word_value) & 0xFFFFFFFF
            rotated = _md5_left_rotate(accumulator, shift)
            new_b = (B + rotated) & 0xFFFFFFFF

            A, D, C, B = D, C, B, new_b

            rounds.append({
                'round': t + 1,
                'function_name': function_name,
                'f_value': _md5_hex32(f_value),
                'word_index': word_index,
                'word_value': _md5_hex32(word_value),
                'k_value': _md5_hex32(constant),
                's_value': shift,
                'accumulator': _md5_hex32(accumulator),
                'rotated': _md5_hex32(rotated),
                'before': {
                    'A': _md5_hex32(old_a),
                    'B': _md5_hex32(old_b),
                    'C': _md5_hex32(old_c),
                    'D': _md5_hex32(old_d),
                },
                'after': {
                    'A': _md5_hex32(A),
                    'B': _md5_hex32(B),
                    'C': _md5_hex32(C),
                    'D': _md5_hex32(D),
                }
            })

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

        block_details.append({
            'index': block_index + 1,
            'bits': _md5_format_block_bits(block),
            'hex': block.hex(),
            'words': [_md5_hex32(word) for word in words],
            'buffer_in': {
                'A': _md5_hex32(aa),
                'B': _md5_hex32(bb),
                'C': _md5_hex32(cc),
                'D': _md5_hex32(dd),
            },
            'rounds': rounds,
            'buffer_out': {
                'A': _md5_hex32(a0),
                'B': _md5_hex32(b0),
                'C': _md5_hex32(c0),
                'D': _md5_hex32(d0),
            }
        })

        steps.append("")
        steps.append(f"Step 5: Process block {block_index + 1}")
        steps.append(f"  Block {block_index + 1} words M[0..15]: {' '.join(_md5_hex32(word) for word in words)}")
        for round_info in rounds:
            before = round_info['before']
            after = round_info['after']
            steps.append(
                f"  Round {round_info['round']:02d}: "
                f"{round_info['function_name']}={round_info['f_value']} "
                f"W[{round_info['word_index']}]={round_info['word_value']} "
                f"K={round_info['k_value']} S={round_info['s_value']} "
                f"A={before['A']} B={before['B']} C={before['C']} D={before['D']} "
                f"-> A={after['A']} B={after['B']} C={after['C']} D={after['D']}"
            )

        steps.append("  Block output after adding previous buffer:")
        steps.append(f"    A = {_md5_hex32(a0)}")
        steps.append(f"    B = {_md5_hex32(b0)}")
        steps.append(f"    C = {_md5_hex32(c0)}")
        steps.append(f"    D = {_md5_hex32(d0)}")

    final_hash = ''.join(_md5_hex32(word) for word in (a0, b0, c0, d0))

    steps.append("")
    steps.append("Step 6: Final hash output")
    steps.append(f"  Final MD5 Hash: {final_hash}")

    return {
        'message': message,
        'original_length_bits': original_bit_length,
        'padding': {
            'case': padding_case,
            'length_mod_512': remainder,
            'one_bit_appended': True,
            'zero_bytes_added': zero_bytes_added,
            'length_field_hex': length_field.hex(),
            'padded_length_bits': len(padded) * 8,
        },
        'initial_values': {
            'A': _md5_hex32(MD5_INIT_A),
            'B': _md5_hex32(MD5_INIT_B),
            'C': _md5_hex32(MD5_INIT_C),
            'D': _md5_hex32(MD5_INIT_D),
        },
        'block_division': block_summaries,
        'blocks': block_details,
        'final_values': {
            'A': _md5_hex32(a0),
            'B': _md5_hex32(b0),
            'C': _md5_hex32(c0),
            'D': _md5_hex32(d0),
        },
        'hash': final_hash,
        'steps': steps
    }
