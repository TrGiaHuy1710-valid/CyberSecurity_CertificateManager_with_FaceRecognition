from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import re
import os


def generate_keys(school_id, student_id, save_dir="keys"):
    identifier = f"{school_id}_{student_id}"

    # Tạo private/public key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    # Serialize public key (để lưu DB)
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serialize private key và lưu vào file local (bảo mật)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    private_path = os.path.join(save_dir, f"{identifier}_private.pem")
    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # có thể dùng mật khẩu
            )
        )

    print(f"✅ Private key saved at: {private_path}")

    return identifier, pem_public_key


def get_clean_content(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    cleaned = re.findall(r"[\wÀ-ỹ]+", content)
    cleaned_text = "".join(cleaned)  # chỉ lấy chữ & số
    message = content.encode("utf-8")  # bản gốc để ký
    return cleaned_text, message


def sign_message(identifier, message, save_dir="keys"):
    private_path = os.path.join(save_dir, f"{identifier}_private.pem")
    with open(private_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key_pem, signature, message):
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False



if __name__ ==  '__main__':
    school_id = "PKA"
    student_id = "23010069"
    identifier, pem_public_key = generate_keys(school_id, student_id)
    print(pem_public_key)
    print(identifier)
    path = 'E:/Web_project/tkinter/trinhgiahuy.txt'

    with open(path, 'r', encoding='utf-8') as f:
        certificate = f.read()

    print(certificate)

    cleaned_text, message = get_clean_content(path)
    print(message)
    print("Cleaned text:", cleaned_text)

    # Ký số
    signature = sign_message(identifier, message)
    print("Signature (hex):", signature.hex()[:80], "...")

    # Verify đúng
    result = verify_signature(pem_public_key, signature, message)
    print("Verify đúng:", result)

    # Verify sai (cố tình đổi message)
    tampered_message = (cleaned_text + "123").encode("utf-8")
    result2 = verify_signature(pem_public_key, signature, tampered_message)
    print("Verify sai:", result2)
