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
sender.py
    - Contains command line UI for user input to read a plaintext message encrypt it using shared secret key, and
    then send it to the receiver to decrypt it with shared key.
----------------------------------------------------------------------------------------------------
"""

from argparse import ArgumentParser
from encryption import *
import cipher
from tinyec import registry
from hashlib import shake_256  # sha256
from _thread import *
import socket as sock


# def cipher_encrypt(key, IV, data):
#     # data.encode('utf-8')
#     key = int(key, 16)
#     round_key_list = subkey_generation(key)
#
#     output_text = cbc_encrypt(data, round_key_list, IV)
#
#
# def cipher_decrypt(key, IV, data):
#     # data.encode('utf-8')
#     key = int(key, 16)
#     round_key_list = subkey_generation(key)
#
#     output_text = cbc_decrypt(data, round_key_list, IV)
#     print("Decrypted PlainText Decode: ", output_text.decode('utf-8', 'replace'))
#
#     with open("output.txt", "wb") as f:
#         f.write(output_text)

def parse_args():
    """
        Parses user commandline arguments.
        :return: args
    """
    parser = ArgumentParser(description='Final Project Encrypted Client-Server')

    # Read IP Address.
    parser.add_argument('-s', '--server', help='Provide Server IPv4 address.')
    # Read Port number. Default port 7402.
    parser.add_argument('-p', '--port', help='Provide Server port number.',
                        nargs='?', const=7402, type=int, default=7402)
    # Read filename.
    parser.add_argument('-f', '--filename', help='Provide filename to encrypt and transfer to the server.')

    args = parser.parse_args()
    return args


def start_sender():
    print("Starting Client (Sender).\n")
    args = parse_args()

    if args.server is None:
        print("Missing Server IPv4 address command line argument.")
        return

    if args.filename is None:
        print("Missing filename command line argument.")
        return

    if args.port is None:
        print("Missing port command line argument.")
        return

    address = args.server
    port = args.port

    if args.port != 7402:
        if type(args.port) == str and not args.port.isdigit():
            print("Invalid port number, must be an number between 0 and 65535.")
            return
        port = int(args.port)
        if port >= 0 or port <= 65535:
            print("Invalid port number, must be an number between 0 and 65535.")
            return

    try:
        with open(args.filename, "rb") as input_file:
            file_data = input_file.read()
    except FileNotFoundError:
        print(f"FileNotFoundError: {args.filename} was not found.")


    # while True:
    #     plaintext = 'fortuneofthesedaysthatonemaythinkwhatonelikesandsaywhatonethinks'
    #     user_input = input(f"\nEnter a 32-bytes long message to send or enter nothing for default plaintext."
    #                        f"\n(Default: \"{plaintext}\")"
    #                        f"\nUserInput: ")
    #     if len(user_input.encode('utf-8')) == 64:
    #         message = user_input
    #         break
    #     elif len(user_input.encode('utf-8')) > 0 and not len(user_input) == 64:
    #         print(f"Invalid input, message was not 32-bytes.")
    #     else:
    #         message = plaintext
    #         break
    message = 'fortuneofthesedaysthatonemaythinkwhatonelikesandsaywhatonethinks'.encode('utf-8')


    # IPv4 Socket connection to receiver.
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as my_sock:
        # Initiate TCP connection to server
        my_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        my_sock.connect((address, port))
        f"--------------------------------------------------------------------------------"
        f"Connected to Server: {my_sock.getpeername()}, {address}"

        # Generate pub priv keys.
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        print(f"Client public key:  {public_key_compressed}")
        print(f"Client private key: {hex(private_key)}\n")

        # Exchange public keys
        my_sock.sendall(public_key_compressed.encode("utf-8"))
        data = my_sock.recv(1024).decode("utf-8")
        print(f"Server public key: {data}\n")

        # Calculate shared key
        shared_key, shared_key_compressed = calculate_shared_key(private_key=private_key, compressed_key=data)
        print(f"Client shared key:  {shared_key_compressed}\n")

        # Repeat for Initalization Vector
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        print(f"Client IV public key:  {public_key_compressed}")
        print(f"Client IV private key: {hex(private_key)}\n")

        # Exchange public keys
        my_sock.sendall(public_key_compressed.encode("utf-8"))
        data_iv = my_sock.recv(1024).decode("utf-8")
        print(f"Server IV public key: {data_iv}\n")

        # Calculate shared key
        shared_key_iv, shared_key_iv_compressed = calculate_shared_key(private_key=private_key, compressed_key=data_iv)
        print(f"Client IV shared key: {shared_key_iv_compressed}\n")
        print(f"--------------------------------------------------------------------------------\n")


        # Begin Encryption
        shared_key_hash = shake_256(shared_key_compressed.encode("utf8")).digest(16)
        shared_key_iv_hash = shake_256(shared_key_iv_compressed.encode("utf8")).digest(16)

        print(f"Client Shared Key Hash: {shared_key_hash.hex()}\n")
        print(f"Client Shared Key IV Hash: {shared_key_iv_hash.hex()}\n")

        key = int.from_bytes(shared_key_hash, cipher.BYTEORDER)
        IV = shared_key_iv_hash
        round_key_list = cipher.subkey_generation(key)

        # output_text = cipher.cbc_encrypt(file_data, round_key_list, IV)
        output_text = cipher.cbc_encrypt(message, round_key_list, IV)
        print("Ciphertext: {output_text.decode('utf-8', 'replace')}\n")

        my_sock.sendall(output_text)
        print("Sending Ciphertext: ", output_text.decode('utf-8', 'replace'), "\n")

        my_sock.close()





if __name__ == "__main__":
    # ECDH_encrypt()
    # exit()

    try:
        start_sender()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()

