#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 7402 - Cryptology
Assignment 4:
    - Implement an application that uses the brainpoolP256r1 cryptographic curve to generate a set of ECC public/private
    keys. The keys will be used to generate a common shared secret key to encrypt and decrypt a plaintext message.
    - Implement the ECDH algorithm from notes in class.
    - Can get a 32-byte plaintext message from the keyboard and display the encrypted ciphertext
Student:
    - Hung Yu (Angus) Lin, A01034410
----------------------------------------------------------------------------------------------------
encryption.py
    - Contains functions for generating ECDH public and private keys, calculating shared key, compressing and
    uncompressing a key, and AES encryption and decryption.
----------------------------------------------------------------------------------------------------
"""


import os, random, struct
# from Crypto.Cipher import AES
from tinyec import registry
import secrets
from nummaster.basic import sqrtmod
import tinyec.ec as ec
from hashlib import sha256, shake_256


curve = registry.get_curve('brainpoolP256r1')
# print('Curve:', curve)
p = 76884956397045344220809746629001649093037950200943055203735601445031516197751
a = curve.a
b = curve.b

def generate_ECDH_pub_priv_keys():
    private_key = secrets.randbelow(curve.field.n)
    public_key = curve.g * private_key
    public_key_compressed = compress_key(public_key)

    return private_key, public_key, public_key_compressed


def calculate_shared_key(private_key, compressed_key):
    public_key = uncompress_key(compressed_key, p, a, b)
    shared_key = ec.Point(curve, public_key[0], public_key[1]) * private_key
    shared_key_compressed = compress_key(shared_key)

    return shared_key, shared_key_compressed


# def AES_encrypt(shared_key, shared_key_iv, message):
#     aes_sha256_key = sha256(shared_key.encode("utf8")).hexdigest()
#     aes_shake256_iv = shake_256(shared_key_iv.encode("utf8")).digest(16)
#
#     print(f"\nAES Key (sha256 hashed shared secret): {aes_sha256_key}")
#     print(f"\nAES IV (sha256 hashed shared secret):  {aes_shake256_iv.hex()}")
#
#     key = bytes.fromhex(aes_sha256_key)
#     IV = aes_shake256_iv
#
#     # 32-byte Plaintext string
#     plaintext = message
#
#     encryptor = AES.new(key, AES.MODE_CBC, IV)
#
#     ciphertext = encryptor.encrypt(plaintext.encode("utf8"))
#     print("\nCipher text: ", ciphertext)
#
#     decryptor = AES.new(key, AES.MODE_CBC, IV)
#     decrypted = decryptor.decrypt(ciphertext)
#     print("\nDecrypt text: ", decrypted.decode("utf8"))
#
#     return ciphertext
#
#
# def AES_decrypt(shared_key, shared_key_iv, cipher_text):
#     aes_sha256_key = sha256(shared_key.encode("utf8")).hexdigest()
#     aes_shake256_iv = shake_256(shared_key_iv.encode("utf8")).digest(16)
#
#     print(f"\nAES Key (sha256 hashed 256-bit key): {aes_sha256_key}")
#     print(f"\nAES IV (shake256 hashed 128-bit IV):  {aes_shake256_iv.hex()}")
#
#     key = bytes.fromhex(aes_sha256_key)
#     IV = aes_shake256_iv
#
#     print("\nCipher text: ", cipher_text)
#
#     decryptor = AES.new(key, AES.MODE_CBC, IV)
#     decrypted = decryptor.decrypt(cipher_text)
#     print("\nDecrypt text: ", decrypted.decode("utf8"))
#
#     return decrypted


def compress_key(point):
    # return (point[0], point[1] % 2)
    return hex(point.x) + hex(point.y % 2)[2:]


def uncompress_key(compressed_point, p, a, b):
    is_odd = int(compressed_point[-1], 0)
    x = int(compressed_point[0:-1], 0)

    # x, is_odd = compressed_point
    y = sqrtmod(pow(x, 3, p) + a * x + b, p)
    if bool(is_odd) == bool(y & 1):
        return (x, y)
    return (x, p - y)




# def initiate_ECDH_key_exchange(address, port):
#     curve = registry.get_curve('brainpoolP256r1')
#     print('Curve:', curve)
#     p = 76884956397045344220809746629001649093037950200943055203735601445031516197751
#     a = curve.a
#     b = curve.b
#
#     sender_private_key = secrets.randbelow(curve.field.n)
#     sender_public_key = curve.g * sender_private_key
#     sender_public_key_compressed = compress_key(sender_public_key)
#
#     print(f"\nSender private key: {hex(sender_private_key)}")
#     print(f"Sender public key:  {sender_public_key_compressed}")
#     print(f"Sender public key (Curve point): {sender_public_key}")
#
#     # IPv4 Socket connection to receiver.
#     with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as my_sock:
#         my_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
#         my_sock.connect((address, port))
#         my_sock.sendall(sender_public_key_compressed.encode("utf-8"))
#         data = my_sock.recv(1024).decode("utf-8")
#         my_sock.close()
#
#     receiver_public_key = uncompress_key(data, p, a, b)
#     sender_shared_key = ec.Point(curve, receiver_public_key[0], receiver_public_key[1]) * sender_private_key
#
#     print(f"\nSender shared key:   {compress_key(sender_shared_key)}")
#     print(f"Sender shared key (Curve point): {sender_shared_key}")
#
#     return sender_shared_key

#
# def ECDH_encrypt():
#     curve = registry.get_curve('brainpoolP256r1')
#     print('Curve:', curve)
#     p = 76884956397045344220809746629001649093037950200943055203735601445031516197751
#     a = curve.a
#     b = curve.b
#     # a = 56698187605326110043627228396178346077120614539475214109386828188763884139993
#     # b = 17577232497321838841075697789794520262950426058923084567046852300633325438902
#
#     sender_private_key = secrets.randbelow(curve.field.n)
#     sender_public_key = curve.g * sender_private_key
#     # sender_public_key_compressed = '0' + str(2 + sender_public_key.y % 2) + str(hex(sender_public_key.x)[2:])
#     sender_private_key_compressed = hex(sender_private_key)
#     sender_public_key_compressed = compress_key(sender_public_key)
#
#     print(f"\nsender private key: {sender_private_key_compressed}")
#     print(f"sender public key:  {sender_public_key_compressed}")
#     print(f"sender public key point: {sender_public_key}")
#
#     receiver_private_key = secrets.randbelow(curve.field.n)
#     receiver_public_key = curve.g * receiver_private_key
#     receiver_private_key_compressed = hex(receiver_private_key)
#     receiver_public_key_compressed = compress_key(receiver_public_key)
#
#     print(f"\nreceiver private key: {receiver_private_key_compressed}")
#     print(f"receiver public key:  {receiver_public_key_compressed}")
#     print(f"receiver public key point: {receiver_public_key}")
#
#     uncompressed_key1 = uncompress_key(receiver_public_key_compressed, p, a, b)
#     sender_shared_key = ec.Point(curve, uncompressed_key1[0], uncompressed_key1[1]) * sender_private_key
#
#     print(f"\nsender shared key:   {compress_key(sender_shared_key)}")
#
#     uncompressed_key2 = uncompress_key(sender_public_key_compressed, p, a, b)
#     receiver_shared_key = ec.Point(curve, uncompressed_key2[0], uncompressed_key2[1]) * receiver_private_key
#
#     print(f"receiver shared key: {compress_key(receiver_shared_key)}")
#
#     print(f"shared key point: {receiver_shared_key}")
#     # assert(receiver_shared_key == sender_shared_key)
#
#
#     aes_sha256_key= sha256(compress_key(sender_shared_key).encode("utf8")).hexdigest()
#     # receiver versions
#     # aes_sha256_secret = sha256(compress_key(receiver_shared_key).encode("utf8")).hexdigest()
#
#     print(f"\nAES key (sha256 hashed shared secret): {aes_sha256_key}")
#
#     # 32-byte Plaintext string
#     plaintext = 'fortuneofthesedaysthatonemaythinkwhatonelikesandsaywhatonethinks'
#
#     key = bytes.fromhex(aes_sha256_key)
#     IV = os.urandom(16)
#     encryptor = AES.new(key, AES.MODE_CBC, IV)
#
#     ciphertext = encryptor.encrypt(plaintext.encode("utf8"))
#     print("\nCiphertext: ", ciphertext)
#
#     decryptor = AES.new(key, AES.MODE_CBC, IV)
#     decrypted = decryptor.decrypt(ciphertext)
#     print("\nPlaintext: ", decrypted.decode("utf8"))


# def compress_pub_key(point):
#     c_point = (point[0], point[1] % 2)
#     c_key = binascii.hexlify(bytes(c_point))
#     print(c_key)
#     print(hex(point.x) + hex(point.y % 2)[2:])
#     return c_key
#


#
# def EncryptDecrypt():
#     # 32-byte Plaintext string
#     plaintext = 'fortuneofthesedaysthatonemaythinkwhatonelikesandsaywhatonethinks'
#
#     # 32-byte key
#     # key = bytes.fromhex ("2e2921b4cde59cdf01e7a014a322abd530b3015085c31cb6e59502da761d29e9")
#     key = bytes.fromhex("a71d32c2ab4d799ea0d1adf75d2ad21254c69f1354642b569160827d7f89c5a1")
#     print(len(key))
#
#     # obj = AES.new('This is a key123'.encode("utf8"), AES.MODE_CBC, IV.encode("utf8"))
#
#     # Generate a random 16-byte IV
#     IV = os.urandom(16)
#
#     mode = AES.MODE_CBC
#
#     encryptor = AES.new(key, mode, IV)
#     ciphertext = encryptor.encrypt(plaintext.encode("utf8"))
#     print("\nCiphertext: ", ciphertext)
#
#     decryptor = AES.new(key, mode, IV)
#     decrypted = decryptor.decrypt(ciphertext)
#     print("\nPlaintext: ", decrypted.decode("utf8"))
#



