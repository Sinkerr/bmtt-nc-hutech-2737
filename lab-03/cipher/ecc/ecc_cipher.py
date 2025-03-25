import ecdsa
import os

# Tạo thư mục lưu khóa nếu chưa có
KEY_DIR = "cipher/ecc/keys"
if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)

class ECCipher:
    def __init__(self):
        self.private_key_path = os.path.join(KEY_DIR, "privateKey.pem")
        self.public_key_path = os.path.join(KEY_DIR, "publicKey.pem")

    def generate_keys(self):
        """Tạo khóa ECC và lưu vào file."""
        sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)  # Khóa riêng tư
        vk = sk.get_verifying_key()  # Khóa công khai

        with open(self.private_key_path, 'wb') as f:
            f.write(sk.to_pem())
        with open(self.public_key_path, 'wb') as f:
            f.write(vk.to_pem())

    def load_keys(self):
        """Tải khóa ECC từ file."""
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            raise FileNotFoundError("ECC keys not found. Please generate keys first.")

        with open(self.private_key_path, 'rb') as f:
            sk = ecdsa.SigningKey.from_pem(f.read())
        with open(self.public_key_path, 'rb') as f:
            vk = ecdsa.VerifyingKey.from_pem(f.read())

        return sk, vk

    def sign(self, message):
        """Ký dữ liệu bằng khóa riêng tư."""
        sk, _ = self.load_keys()
        return sk.sign(message.encode('utf-8')).hex()  # Chuyển bytes -> hex

    def verify(self, message, signature_hex):
        """Xác minh chữ ký bằng khóa công khai."""
        _, vk = self.load_keys()

        try:
            return vk.verify(bytes.fromhex(signature_hex), message.encode('utf-8'))
        except ecdsa.BadSignatureError:
            return False
