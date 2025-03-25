from flask import Flask, request, jsonify
from cipher.rsa import RSACipher
from cipher.ecc import ECCipher

app = Flask(__name__)

# RSA CIPHER ALGORITHM
rsa_cipher = RSACipher()

@app.route("/api/rsa/generate_keys", methods=["GET"])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({"message": "Keys generated successfully"})

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json
    message = data["message"]
    key_type = data["key_type"]

    private_key, public_key = rsa_cipher.load_keys()
    key = public_key if key_type == "public" else private_key
    encrypted_message = rsa_cipher.encrypt(message, key)

    return jsonify({"encrypted_message": encrypted_message.hex()})

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json
    ciphertext_hex = data["ciphertext"]
    key_type = data["key_type"]

    private_key, public_key = rsa_cipher.load_keys()
    key = private_key if key_type == "private" else public_key
    decrypted_message = rsa_cipher.decrypt(bytes.fromhex(ciphertext_hex), key)

    return jsonify({"decrypted_message": decrypted_message})

@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign_message():
    data = request.json
    message = data["message"]

    private_key, _ = rsa_cipher.load_keys()
    signature = rsa_cipher.sign(message, private_key)

    return jsonify({"signature": signature.hex()})

@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify_signature():
    data = request.json
    message = data["message"]
    signature_hex = data["signature"]

    _, public_key = rsa_cipher.load_keys()
    is_verified = rsa_cipher.verify(message, bytes.fromhex(signature_hex), public_key)

    return jsonify({"is_verified": is_verified})

# ECC CIPHER ALGORITHM
ecc_cipher = ECCipher()

@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign():
    data = request.json
    message = data['message']

    signature_hex = ecc_cipher.sign(message)  # Trả về dạng hex

    return jsonify({'signature': signature_hex})

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify():
    data = request.json
    message = data['message']
    signature_hex = data['signature']

    is_verified = ecc_cipher.verify(message, signature_hex)
    
    return jsonify({'is_verified': is_verified})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
