from flask import Flask, render_template, request

# import modules (SAFE STYLE)
import ex.ex1.shift_cipher as shift_cipher
import ex.ex1.gcd as gcd
import ex.ex1.extended_euclid as extended_euclid
import ex.ex1.determinant as determinant
import ex.ex1.matrix_multiply as matrix_multiply
import ex.ex1.playfair_cipher as playfair_cipher
import ex.ex1.hill_cipher as hill_cipher
import ex.ex1.primitive_root as primitive_root
from ex.ex2.aes import compute_aes_trace
from ex.ex2.des import compute_des_trace
import ex.ex3.md5 as md5
import ex.ex3.deffie_hellman as deffie_hellman
import ex.ex3.rsa as rsa
import ex.ex5.des as des

app = Flask(__name__)
@app.route("/ex2")
def ex2_menu():
    return render_template("ex2/menu.html")
@app.route("/ex2/aes", methods=["GET", "POST"])
def aes_view():
    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]
        mode = request.form["mode"]
        action = request.form["action"]

        result = compute_aes_trace(
            plaintext=text,
            key=key,
            mode=mode,
            operation=action
        )

        return render_template(
            "ex2/result.html",
            title="AES",
            result=result["ciphertext"],
            steps="\n".join(result["steps"])
        )

    return render_template("ex2/aes.html")
@app.route("/ex2/des", methods=["GET", "POST"])
def des_view():
    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]
        mode = request.form["mode"]
        action = request.form["action"]

        result = compute_des_trace(
            plaintext=text,
            key=key,
            mode=mode,
            operation=action
        )

        return render_template(
            "ex2/result.html",
            title="DES",
            result=result["ciphertext"],
            steps="\n".join(result["steps"])
        )

    return render_template("ex2/des.html")

# ---------------- MAIN MENU ----------------
@app.route("/")
def main_menu():
    return render_template("menu.html")


# ---------------- EXERCISE 1 MENU ----------------
@app.route("/ex1")
def ex1_menu():
    return render_template("ex1/menu.html")


# ---------------- SHIFT CIPHER ----------------
@app.route("/ex1/shift", methods=["GET", "POST"])
def shift():
    if request.method == "POST":
        text = request.form["text"]
        key = int(request.form["key"])
        action = request.form["action"]

        if action == "Encrypt":
            result, steps = shift_cipher.encrypt(text, key)
        else:
            result, steps = shift_cipher.decrypt(text, key)

        return render_template("ex1/result.html", result=result, steps=steps)

    return render_template("ex1/shift.html")


# ---------------- GCD ----------------
@app.route("/ex1/gcd", methods=["GET", "POST"])
def gcd_view():
    if request.method == "POST":
        a = int(request.form["a"])
        b = int(request.form["b"])
        result, steps = gcd.compute(a, b)
        return render_template("ex1/result.html", result=result, steps=steps)

    return render_template("ex1/gcd.html")


# ---------------- EXTENDED EUCLID ----------------
@app.route("/ex1/extended", methods=["GET", "POST"])
def extended():
    if request.method == "POST":
        a = int(request.form["a"])
        b = int(request.form["b"])
        g, x, y, steps = extended_euclid.compute(a, b)
        return render_template(
            "ex1/result.html",
            result=f"gcd={g}, x={x}, y={y}",
            steps=steps
        )

    return render_template("ex1/extended_euclid.html")


# ---------------- DETERMINANT ----------------
@app.route("/ex1/determinant", methods=["GET", "POST"])
def det():
    if request.method == "POST":
        n = int(request.form["n"])
        data = list(map(int, request.form["matrix"].split()))

        matrix = [data[i*n:(i+1)*n] for i in range(n)]
        steps = []
        result = determinant.determinant(matrix, steps)

        return render_template(
            "ex1/result.html",
            result=result,
            steps="\n".join(steps)
        )

    return render_template("ex1/determinant.html")


# ---------------- PLAYFAIR ----------------
@app.route("/ex1/playfair", methods=["GET", "POST"])
def playfair():
    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]

        result, matrix, steps = playfair_cipher.encrypt(text, key)

        return render_template(
            "ex1/result.html",
            result=result,
            steps=steps
        )

    return render_template("ex1/playfair.html")


# ---------------- HILL ----------------
@app.route("/ex1/hill", methods=["GET", "POST"])
def hill():
    if request.method == "POST":
        text = request.form["text"]
        n = int(request.form["n"])
        key_data = list(map(int, request.form["key"].split()))
        key = [key_data[i*n:(i+1)*n] for i in range(n)]

        action = request.form["action"]
        if action == "Encrypt":
            result, steps = hill_cipher.encrypt(text, key)
        else:
            result, steps = hill_cipher.decrypt(text, key)

        return render_template("ex1/result.html", result=result, steps=steps)

    return render_template("ex1/hill.html")


# ---------------- PRIMITIVE ROOT ----------------
@app.route("/ex1/primitive", methods=["GET", "POST"])
def primitive():
    if request.method == "POST":
        p = int(request.form["p"])
        roots, steps = primitive_root.primitive_roots(p)

        return render_template(
            "ex1/result.html",
            result=f"Primitive roots modulo {p}: {roots}",
            steps="\n".join(steps)
        )

    return render_template("ex1/primitive_root.html")


# ---------------- EXERCISE 3 MENU ----------------
@app.route("/ex3")
def ex3_menu():
    return render_template("ex3/menu.html")


# ---------------- MD5 HASH ----------------
@app.route("/ex3/md5", methods=["GET", "POST"])
def md5_view():
    if request.method == "POST":
        message = request.form["message"]
        result_dict = md5.md5_hash_with_steps(message)
        
        return render_template(
            "ex3/result.html",
            title="MD5 Hash",
            result=result_dict.get('hash', 'N/A'),
            steps="\n".join(result_dict.get('steps', []))
        )

    return render_template("ex3/md5.html")


# ---------------- DIFFIE-HELLMAN ----------------
@app.route("/ex3/deffie_hellman", methods=["GET", "POST"])
def deffie_hellman_view():
    if request.method == "POST":
        p = int(request.form["p"])
        g = int(request.form["g"])
        xa = int(request.form["xa"])
        xb = int(request.form["xb"])
        
        result_dict, steps = deffie_hellman.diffie_hellman_exchange(p, g, xa, xb)
        
        if result_dict is None:
            result = "Error in key exchange"
        else:
            result = f"Shared Key: {result_dict.get('ka', 'N/A')}"
        
        return render_template(
            "ex3/result.html",
            title="Diffie-Hellman Key Exchange",
            result=result,
            steps="\n".join(steps)
        )

    return render_template("ex3/deffie_hellman.html")


# ---------------- RSA ENCRYPTION ----------------
@app.route("/ex3/rsa")
def rsa_menu():
    return render_template("ex3/rsa_menu.html")


@app.route("/ex3/rsa/generate", methods=["GET", "POST"])
def rsa_generate():
    if request.method == "POST":
        p = int(request.form["p"])
        q = int(request.form["q"])
        
        public_key, private_key, steps = rsa.rsa_generate_keys(p, q)
        
        if public_key is None:
            result = "Error in key generation"
        else:
            result = f"Public Key (e, n): {public_key}\nPrivate Key (d, n): {private_key}"
        
        return render_template(
            "ex3/result.html",
            title="RSA Key Generation",
            result=result,
            steps="\n".join(steps)
        )
    
    return render_template("ex3/rsa/generate.html")


@app.route("/ex3/rsa/encrypt_number", methods=["GET", "POST"])
def rsa_encrypt_number():
    if request.method == "POST":
        message = request.form["message"]
        e = int(request.form["e"])
        n = int(request.form["n"])
        
        ciphertext, steps = rsa.rsa_encrypt_number(message, e, n)
        
        if ciphertext is None:
            result = "Error in encryption"
        else:
            result = f"Ciphertext: {ciphertext}"
        
        return render_template(
            "ex3/result.html",
            title="RSA Number Encryption",
            result=result,
            steps="\n".join(steps)
        )
    
    return render_template("ex3/rsa/encrypt_number.html")


@app.route("/ex3/rsa/decrypt_number", methods=["GET", "POST"])
def rsa_decrypt_number():
    if request.method == "POST":
        ciphertext = request.form["ciphertext"]
        d = int(request.form["d"])
        n = int(request.form["n"])
        
        plaintext, steps = rsa.rsa_decrypt_number(ciphertext, d, n)
        
        if plaintext is None:
            result = "Error in decryption"
        else:
            result = f"Plaintext: {plaintext}"
        
        return render_template(
            "ex3/result.html",
            title="RSA Number Decryption",
            result=result,
            steps="\n".join(steps)
        )
    
    return render_template("ex3/rsa/decrypt_number.html")


@app.route("/ex3/rsa/encrypt_string", methods=["GET", "POST"])
def rsa_encrypt_string():
    if request.method == "POST":
        plaintext = request.form["plaintext"]
        e = int(request.form["e"])
        n = int(request.form["n"])
        
        encrypted_values, steps = rsa.rsa_encrypt_string(plaintext, e, n)
        
        if encrypted_values is None:
            result = "Error in encryption"
        else:
            result = f"Encrypted values: {' '.join(map(str, encrypted_values))}"
        
        return render_template(
            "ex3/result.html",
            title="RSA String Encryption",
            result=result,
            steps="\n".join(steps)
        )
    
    return render_template("ex3/rsa/encrypt_string.html")


@app.route("/ex3/rsa/decrypt_string", methods=["GET", "POST"])
def rsa_decrypt_string():
    if request.method == "POST":
        encrypted_values = request.form["encrypted_values"]
        d = int(request.form["d"])
        n = int(request.form["n"])
        
        plaintext, steps = rsa.rsa_decrypt_string(encrypted_values, d, n)
        
        result = f"Decrypted string: {plaintext}"
        
        return render_template(
            "ex3/result.html",
            title="RSA String Decryption",
            result=result,
            steps="\n".join(steps)
        )
    
    return render_template("ex3/rsa/decrypt_string.html")


# ============ EXERCISE 5 ============
# DES Encryption & CMAC


# --------- EXERCISE 5 MENU ---------
@app.route("/ex5")
def ex5_menu():
    return render_template("ex5/menu.html")


# --------- DES ENCRYPTION ---------
@app.route("/ex5/des_encrypt", methods=["GET", "POST"])
def des_encrypt_view():
    if request.method == "POST":
        message = request.form["message"]
        key = request.form["key"]
        mode = request.form.get("mode", "cbc")
        
        ciphertext, steps = des.des_encrypt(message, key, mode)
        
        return render_template(
            "ex5/result.html",
            title="DES Encryption",
            result=ciphertext.hex(),
            steps="\n".join(steps)
        )
    
    return render_template("ex5/des_encrypt.html")


# --------- DES DECRYPTION ---------
@app.route("/ex5/des_decrypt", methods=["GET", "POST"])
def des_decrypt_view():
    if request.method == "POST":
        ciphertext_hex = request.form["ciphertext_hex"]
        key = request.form["key"]
        mode = request.form.get("mode", "cbc")
        
        plaintext, steps = des.des_decrypt(ciphertext_hex, key, mode)
        
        if plaintext is None:
            result = "Error: Cannot decrypt"
        else:
            result = plaintext.decode('utf-8', errors='ignore')
        
        return render_template(
            "ex5/result.html",
            title="DES Decryption",
            result=result,
            steps="\n".join(steps)
        )
    
    return render_template("ex5/des_decrypt.html")


# --------- CMAC GENERATION ---------
@app.route("/ex5/cmac", methods=["GET", "POST"])
def cmac_view():
    if request.method == "POST":
        message = request.form["message"]
        key = request.form["key"]
        n_bits = int(request.form["n_bits"])
        
        cmac_value, steps = des.cmac(message, key, n_bits)
        
        return render_template(
            "ex5/result.html",
            title="CMAC Generation",
            result=f"CMAC ({n_bits} bits): {cmac_value}",
            steps="\n".join(steps)
        )
    
    return render_template("ex5/cmac.html")


if __name__ == "__main__":
    app.run(debug=True)
