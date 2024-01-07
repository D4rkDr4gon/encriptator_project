import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def key_derivation(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = key_derivation(password, salt)
    iv = os.urandom(16)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + iv + ciphertext)

def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = key_derivation(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Utilizar os.path.splitext para obtener el nombre del archivo original sin la extensión .enc
    original_file_path = os.path.splitext(encrypted_file_path)[0]

    with open(original_file_path, 'wb') as file:
        file.write(decrypted_data)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file with a master key.')
    parser.add_argument('file', help='File to process')
    parser.add_argument('-E', dest='encrypt', action='store_true', help='Encrypt the file')
    parser.add_argument('-D', dest='decrypt', action='store_true', help='Decrypt the file')
    parser.add_argument('key', help='Master key')

    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.file, args.key)
        print(f'{args.file} encrypted successfully.')
    elif args.decrypt:
        decrypt_file(args.file, args.key)
        print(f'{args.file} decrypted successfully.')
    else:
        print('Please specify whether to encrypt (-E) or decrypt (-D) the file.')

if __name__ == "__main__":
    main()
