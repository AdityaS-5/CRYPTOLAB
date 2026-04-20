# DES encryption function (simple implementation using pycryptodome)
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


def des_encrypt(message, key, mode='cbc'):
    """DES encryption function with steps tracking"""
    steps = []

    # Ensure message is bytes
    if isinstance(message, str):
        message = message.encode()

    # Ensure key is 8 bytes
    if isinstance(key, str):
        key = key.encode()
    
    key = key[:8].ljust(8, b'\0')

    # Initialization Vector (fixed for simplicity)
    iv = b'\0' * 8

    if mode.lower() == 'cbc':
        cipher = DES.new(key, DES.MODE_CBC, iv)

    # Pad message to 8-byte blocks
    padded_message = pad(message, DES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    steps.append(f"Original message: {message.decode('utf-8', errors='ignore')}")
    steps.append(f"Message (hex): {message.hex()}")
    steps.append(f"Padded message (hex): {padded_message.hex()}")
    steps.append(f"Key (hex): {key.hex()}")
    steps.append(f"IV (hex): {iv.hex()}")
    steps.append(f"Mode: DES-{mode.upper()}")
    steps.append(f"Ciphertext (hex): {ciphertext.hex()}")

    return ciphertext, steps


def des_decrypt(ciphertext_hex, key, mode='cbc'):
    """DES decryption function with steps tracking"""
    steps = []

    # Convert hex to bytes
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return None, ["Error: Invalid hexadecimal input"]

    # Ensure key is 8 bytes
    if isinstance(key, str):
        key = key.encode()
    
    key = key[:8].ljust(8, b'\0')

    # Initialization Vector (fixed for simplicity)
    iv = b'\0' * 8

    if mode.lower() == 'cbc':
        cipher = DES.new(key, DES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)

    steps.append(f"Ciphertext (hex): {ciphertext.hex()}")
    steps.append(f"Key (hex): {key.hex()}")
    steps.append(f"IV (hex): {iv.hex()}")
    steps.append(f"Mode: DES-{mode.upper()}")
    steps.append(f"Decrypted (hex): {plaintext.hex()}")
    steps.append(f"Decrypted (text): {plaintext.decode('utf-8', errors='ignore')}")

    return plaintext, steps


def cmac(message, key, n_bits):
    """CMAC (Cipher-based MAC) using DES"""
    steps = []

    # Convert message to bytes
    if isinstance(message, str):
        message = message.encode()

    steps.append(f"Original message: {message.decode('utf-8', errors='ignore')}")
    steps.append(f"Message length: {len(message)} bytes")

    # Padding to 8-byte block size
    padding_len = 8 - (len(message) % 8)
    if padding_len != 8:
        padded_message = message + b'\x00' * padding_len
    else:
        padded_message = message

    steps.append(f"Padding needed: {padding_len} bytes")
    steps.append(f"Padded message (hex): {padded_message.hex()}")

    # Encrypt using DES in CBC mode
    ciphertext_bytes, encryption_steps = des_encrypt(padded_message, key, mode='cbc')

    ciphertext_hex = ciphertext_bytes.hex()
    steps.append(f"Full ciphertext: {ciphertext_hex}")

    # Split into 8-byte (16 hex chars) blocks
    blocks = [ciphertext_hex[i:i+16] for i in range(0, len(ciphertext_hex), 16)]

    steps.append(f"Number of blocks: {len(blocks)}")
    steps.append("Encrypted blocks:")
    for i, block in enumerate(blocks):
        steps.append(f"  C{i+1} = {block}")

    # Take last block
    last_block = blocks[-1]
    steps.append(f"Last block (C{len(blocks)}) = {last_block}")

    # Convert to binary
    binary = bin(int(last_block, 16))[2:].zfill(64)
    steps.append(f"Binary (64-bit) = {binary}")

    # Truncate to n_bits
    if n_bits > 64:
        steps.append(f"Warning: n_bits ({n_bits}) exceeds maximum (64)")
        n_bits = 64
    
    truncated = binary[:n_bits]
    steps.append(f"First {n_bits} bits = {truncated}")

    # Convert to hex
    if len(truncated) > 0:
        # Pad truncated binary to make it divisible by 4 for hex conversion
        padded_truncated = truncated.ljust((len(truncated) + 3) // 4 * 4, '0')
        cmac_value = hex(int(padded_truncated, 2))[2:]
    else:
        cmac_value = "0"
    
    steps.append(f"CMAC ({n_bits} bits) = {cmac_value}")

    return cmac_value, steps


# Example usage
if __name__ == "__main__":
    message = "hello world"
    key = b"12345678"
    n_bits = 32

    mac, steps = cmac(message, key, n_bits)

    print("Final CMAC:", mac)
    print("\nSteps:")
    for step in steps:
        print(step)
