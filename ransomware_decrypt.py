import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(file_path, password):
    # Đọc nội dung tệp đã mã hóa
    with open(file_path, 'rb') as enc_file:
        encrypted_base64 = enc_file.read()

    # Giải mã dữ liệu từ base64
    encrypted_data = base64.b64decode(encrypted_base64)

    # Tách salt, iv và dữ liệu đã mã hóa
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]

    # Tạo khóa từ mật khẩu
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Giải mã dữ liệu
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Lưu dữ liệu đã giải mã vào tệp mới
    with open(file_path[:-4], 'wb') as dec_file:
        dec_file.write(decrypted_data)
        
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
        if filename.endswith('.enc'):
            print(filename)
            decrypt_file(f'{filename}', password)

main()