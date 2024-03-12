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
receiver.py
    - Contains command line UI for user input. Starts socket server to listen for incoming ECDH public key exchange,
    and then calculates the shared key to be used for AES decryption. Then decrypts and reads incoming messages sent
    to the command line.
----------------------------------------------------------------------------------------------------
"""

from argparse import ArgumentParser
from sender import *
import cipher
from hashlib import shake_256  # sha256
import socket as sock
from _thread import *
from encryption import *



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
    # parser.add_argument('-f', '--filename', help='Provide filename to encrypt and transfer to the server.')

    args = parser.parse_args()
    return args


def start_receiver():
    print("Starting Server (Receiver).\n")
    args = parse_args()

    if args.server is None:
        print("Missing Server IPv4 address command line argument.")
        return

    # if args.filename is None:
    #     print("Missing filename command line argument.")
    #     return

    if args.port is None:
        print("Missing port command line argument.")
        return

    if not args.port.isdigit() or int(args.port) >= 0 or int(args.port) <= 65535:
        print("Invalid port number, must be an number between 0 and 65535.")
        return

    address = args.server
    port = args.port

    if args.port != 7402:
        port = int(args.port)

    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as IPv4_sock:
        IPv4_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        IPv4_sock.bind((address, port))
        IPv4_sock.listen(10)
        print("Listening on: ", IPv4_sock.getsockname())

        while True:
            conn, addr = IPv4_sock.accept()
            start_new_thread(client_file_transfer_thread, (conn, addr))


def client_file_transfer_thread(conn, addr):

    data = conn.recv(1024).decode('utf8')
    if data:
        # Generate pub priv keys.
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        # "{conn.getpeername()}: \t{data}"

        # Calculate shared key and send server public key to client
        shared_key, shared_key_compressed = calculate_shared_key(private_key=private_key, compressed_key=data)
        conn.sendall(public_key_compressed.encode("utf8"))
        print(f"--------------------------------------------------------------------------------"
              f"Client Connected: {conn}, {addr}"
              f"Client public key:  {data}"
              f"Server public key:  {public_key_compressed}"
              f"Server private key: {hex(private_key)}\n"
              f"Server shared key ({conn.getpeername()}): {shared_key_compressed}\n"
              f"Sending Server public key: {public_key_compressed}\n"
              f"--------------------------------------------------------------------------------\n")

        # Repeat for Initialization Vector
        data_iv = conn.recv(1024).decode('utf8')

        private_key_iv, public_key_iv, public_key_iv_compressed = generate_ECDH_pub_priv_keys()
        shared_key_iv, shared_key_iv_compressed = calculate_shared_key(private_key=private_key_iv,
                                                                       compressed_key=data_iv)
        conn.sendall(public_key_iv_compressed.encode("utf8"))

        print(f"--------------------------------------------------------------------------------"
              f"Client: {conn.getpeername()}, {addr}"
              f"Client IV public key:  {data_iv}"
              f"Server IV public key:  {public_key_iv_compressed}"
              f"Server IV private key: {hex(private_key_iv)}\n"
              f"Server IV shared key ({conn.getpeername()}): {shared_key_iv_compressed}\n"
              f"Sending Server IV public key: {public_key_iv_compressed}\n"
              f"--------------------------------------------------------------------------------\n")


        # Decrypt cipher text
        cipher_text = conn.recv(1024)

        # Begin Decryption
        shared_key_hash = shake_256(shared_key_compressed.encode("utf8")).digest(16)
        shared_key_iv_hash = shake_256(shared_key_iv_compressed.encode("utf8")).digest(16)

        print(f"Server Shared Key Hash: {shared_key_hash.hex()}\n"
              f"Server Shared Key IV Hash: {shared_key_iv_hash.hex()}\n")

        key = int.from_bytes(shared_key_hash, cipher.BYTEORDER)
        IV = shared_key_iv_hash
        round_key_list = cipher.subkey_generation(key)

        # output_text = cipher.cbc_encrypt(file_data, round_key_list, IV)
        output_text = cipher.cbc_decrypt(cipher_text, round_key_list, IV)
        print(f"Ciphertext: {cipher_text.decode('utf-8', 'replace')}\n"
              f"Decrypted Result: {output_text.decode('utf-8', 'replace')}\n")

    else:
        conn.close()




# def server_ECDH_exchange(sender_public_key_compressed):
#     receiver_private_key = secrets.randbelow(curve.field.n)
#     receiver_public_key = curve.g * receiver_private_key
#     receiver_public_key_compressed = compress_key(receiver_public_key)
#
#     print(f"\nreceiver private key: {hex(receiver_private_key)}")
#     print(f"receiver public key:  {receiver_public_key_compressed}")
#     print(f"receiver public key point: {receiver_public_key}")
#
#     sender_public_key = uncompress_key(sender_public_key_compressed, p, a, b)
#     receiver_shared_key = ec.Point(curve, sender_public_key[0], sender_public_key[1]) * receiver_private_key
#
#     print(f"Receiver shared key: {compress_key(receiver_shared_key)}")
#
#     print(f"Receiver shared key (Curve point): {receiver_shared_key}")
#
#     return receiver_public_key_compressed, receiver_shared_key




if __name__ == "__main__":
    try:
        start_receiver()
    except KeyboardInterrupt as e:
        print("Server Shutdown")
        exit()


