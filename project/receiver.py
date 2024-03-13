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

    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as IPv4_sock:
        IPv4_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        IPv4_sock.bind((address, port))
        IPv4_sock.listen(10)
        print("Listening on: ", IPv4_sock.getsockname())

        while True:
            conn, addr = IPv4_sock.accept()
            start_new_thread(client_file_transfer_thread, (conn, addr))


def client_file_transfer_thread(conn, addr):
    msg_type, payload = receive_message_type(socket=conn)
    if msg_type != "EOT":
        data = payload.decode('utf-8')
        if msg_type != "KEY":
            print(f"Received Unexpected Msg_Type: {msg_type}, Expected KEY, Payload: {data}")
            return
        # Generate pub priv keys.
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        # "{conn.getpeername()}: \t{data}"

        # Calculate shared key and send server public key to client
        shared_key, shared_key_compressed = calculate_shared_key(private_key=private_key, compressed_key=data)
        shared_key_hash = shake_256(shared_key_compressed.encode("utf8")).digest(16)
        print(f"--------------------------------------------------------------------------------\n"
              f"Client IP: {addr[0]}\n"
              f"Received Msg_Type: {msg_type}, Payload: {data[2:]}\n"
              f"Client public key:  {data[2:]}\n"
              f"Server public key:  {public_key_compressed[2:]}\n"
              f"Server private key: {private_key:x}\n\n"
              f"Sending Server public key. Msg_Type: KEY, Payload: {public_key_compressed[2:]}\n\n"
              f"Server shared key ({addr[0]}): {shared_key_compressed[2:]}\n\n"
              f"Server Shared Key Hash: {shared_key_hash.hex()}\n")
        # conn.sendall(public_key_compressed.encode("utf8"))
        send_message_type(socket=conn, msg_type="KEY", payload=public_key_compressed.encode("utf-8"))

        # Repeat for Initialization Vector
        # data_iv = conn.recv(1024).decode('utf8')
        msg_type, payload = receive_message_type(socket=conn)
        data_iv = payload.decode('utf-8')
        if msg_type != "KEY":
            print(f"Received Unexpected Msg_Type: {msg_type}, Expected KEY, Payload: {data_iv}")
            return

        private_key_iv, public_key_iv, public_key_iv_compressed = generate_ECDH_pub_priv_keys()
        shared_key_iv, shared_key_iv_compressed = calculate_shared_key(private_key=private_key_iv,
                                                                       compressed_key=data_iv)
        shared_key_iv_hash = shake_256(shared_key_iv_compressed.encode("utf8")).digest(16)

        print(f"--------------------------------------------------------------------------------\n"
              f"Client IP: {addr[0]}\n"
              f"Received Msg_Type: {msg_type}, Payload: {data_iv[2:]}\n"
              f"Client IV (Nonce) public key:  {data_iv[2:]}\n"
              f"Server IV (Nonce) public key:  {public_key_iv_compressed[2:]}\n"
              f"Server IV (Nonce) private key: {private_key_iv:x}\n\n"
              f"Sending Server IV (Nonce) public key. Msg_Type: KEY, Payload: {public_key_iv_compressed[2:]}\n\n"
              f"Server IV (Nonce) shared key ({addr[0]}): {shared_key_iv_compressed[2:]}\n\n"
              f"Server Shared Key IV (Nonce) Hash: {shared_key_iv_hash.hex()}\n")
        # conn.sendall(public_key_iv_compressed.encode("utf8"))
        send_message_type(socket=conn, msg_type="KEY", payload=public_key_iv_compressed.encode("utf-8"))

        # Decrypt cipher text
        msg_type, cipher_text = receive_message_type(socket=conn)
        if msg_type != "DAT":
            print(f"Received Unexpected Msg_Type: {msg_type}, Expected DAT, Payload: {cipher_text}")
            return

        # Begin Decryption
        key = int.from_bytes(shared_key_hash, cipher.BYTEORDER)
        IV = shared_key_iv_hash
        round_key_list = cipher.subkey_generation(key)

        # output_text = cipher.cbc_encrypt(file_data, round_key_list, IV)
        output_text = cipher.cbc_decrypt(cipher_text, round_key_list, IV)
        print(f"--------------------------------------------------------------------------------\n"
              f"Client IP: {addr[0]}\n"
              f"Received Msg_Type: {msg_type}, Payload: ", end="")
        print(cipher_text.decode('utf-8', 'replace'), "\n")
        print(f"Decrypted Result: ", end="")
        print(output_text.decode('utf-8', 'replace'), "\n\n")
    else:
        return

    counter = 0
    current_iv = IV
    msg_type, cipher_block = receive_message_type(socket=conn)
    if msg_type != "DAT" and msg_type != "PAD":
        print(f"Received Unexpected Msg_Type: {msg_type}, Expected DAT or PAD, Payload: {cipher_block}")
        return

    decrypted_block = cipher.cbc_decrypt(cipher_block, round_key_list, current_iv)
    print(f"--------------------------------------------------------------------------------\n"
          f"Client IP: {addr[0]}\n"
          f"Received Encrypted Block: {counter}. Msg_Type: {msg_type}, Decrypted Payload: ", end="")
    print(decrypted_block.decode('utf-8', 'replace'), end="")

    output_filename = f"{addr[0]}_" + decrypted_block.decode('utf-8', 'replace')
    current_iv = cipher_block
    counter += 1

    print(f", Server Response: ACK")
    send_message_type(socket=conn, msg_type="ACK", payload="Server ACK".encode('utf-8'))

    msg_type, cipher_block = receive_message_type(socket=conn)

    while msg_type != "EOT":
        with open(output_filename, "ab") as output_file:
            if msg_type != "DAT" and msg_type != "PAD":
                print(f"Received Unexpected Msg_Type: {msg_type}, Expected DAT or PAD, Payload: {cipher_block}")
                return

            if msg_type == "PAD":
                decrypted_block = cipher.cbc_decrypt(cipher_block, round_key_list, current_iv)
            else:
                decrypted_block = cipher.cbc_decrypt(cipher_block, round_key_list, current_iv, unpad=False)
            print(f"--------------------------------------------------------------------------------\n"
                  f"Client IP: {addr[0]}\n"
                  f"Received Encrypted Block: {counter}. Msg_Type: {msg_type}, "
                  f"IV (hash): {IV} \nDecrypted Payload: ", end="")
            print(decrypted_block.decode('utf-8', 'replace'), end="")

            output_file.write(decrypted_block)
            current_iv = cipher_block
            counter += 1

            print(f", Server Response: ACK")
            send_message_type(socket=conn, msg_type="ACK", payload="Server ACK".encode('utf-8'))

            msg_type, cipher_block = receive_message_type(socket=conn)


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


