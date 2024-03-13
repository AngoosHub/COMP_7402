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
    # message = 'fortuneofthesedaysthatonemaythinkwhatonelikesandsaywhatonethinks'.encode('utf-8')
    test_message = 'Test Message for ECDH key exchange and Cipher encrypt/decrypt.'.encode('utf-8')


    # IPv4 Socket connection to receiver.
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as my_sock:
        # Initiate TCP connection to server
        my_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        my_sock.connect((address, port))
        print(f"--------------------------------------------------------------------------------\n"
              f"Connected to Server: {my_sock.getpeername()}")

        # Generate pub priv keys.
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        print(f"Client public key:  {public_key_compressed[2:]}")
        print(f"Client private key: {private_key:x}\n")

        # Exchange public keys
        # my_sock.sendall(public_key_compressed.encode("utf-8"))
        # data = my_sock.recv(1024).decode("utf-8")
        print(f"Sending public key to server. Msg_Type: KEY, Payload: {public_key_compressed[2:]}\n")
        send_message_type(socket=my_sock, msg_type="KEY", payload=public_key_compressed.encode("utf-8"))
        msg_type, payload = receive_message_type(socket=my_sock)
        data = payload.decode('utf-8')
        if msg_type != "KEY":
            print(f"Received Unexpected Msg_Type: {msg_type}, Expected KEY, Payload: {data}")
            return
        print(f"Received Msg_Type: {msg_type}, Payload: {data[2:]}")
        print(f"Server public key: {data[2:]}\n")

        # Calculate shared key
        shared_key, shared_key_compressed = calculate_shared_key(private_key=private_key, compressed_key=data)
        print(f"Client shared key:  {shared_key_compressed[2:]}\n")
        shared_key_hash = shake_256(shared_key_compressed.encode("utf8")).digest(16)
        print(f"Client Shared Key Hash: {shared_key_hash.hex()}\n")

        # Repeat for Initalization Vector
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        print(f"Client IV (Nonce) public key:  {public_key_compressed[2:]}")
        print(f"Client IV (Nonce) private key: {private_key:x}\n")

        # Exchange public keys
        # my_sock.sendall(public_key_compressed.encode("utf-8"))
        # data_iv = my_sock.recv(1024).decode("utf-8")
        # print(f"Server IV (Nonce) public key: {data_iv}\n")
        print(f"Sending IV (Nonce) public key to server. Msg_Type: KEY, Payload: {public_key_compressed[2:]}\n")
        send_message_type(socket=my_sock, msg_type="KEY", payload=public_key_compressed.encode("utf-8"))
        msg_type, payload = receive_message_type(socket=my_sock)
        data_iv = payload.decode('utf-8')
        if msg_type != "KEY":
            print(f"Received Unexpected Msg_Type: {msg_type}, Expected KEY, Payload: {data_iv[2:]}")
            return
        print(f"Received Msg_Type: {msg_type}, Payload: {data_iv[2:]}")
        print(f"Server IV (Nonce) public key: {data_iv[2:]}\n")

        # Calculate shared key
        shared_key_iv, shared_key_iv_compressed = calculate_shared_key(private_key=private_key, compressed_key=data_iv)
        print(f"Client IV (Nonce) shared key: {shared_key_iv_compressed[2:]}\n")
        shared_key_iv_hash = shake_256(shared_key_iv_compressed.encode("utf8")).digest(16)
        print(f"Client Shared Key IV (Nonce) Hash: {shared_key_iv_hash.hex()}\n")

        # Begin Encryption
        key = int.from_bytes(shared_key_hash, cipher.BYTEORDER)
        IV = shared_key_iv_hash
        round_key_list = cipher.subkey_generation(key)

        # output_text = cipher.cbc_encrypt(file_data, round_key_list, IV)
        output_text = cipher.cbc_encrypt(test_message, round_key_list, IV)
        print("Test plaintext: ", test_message.decode('utf-8', 'replace'))
        print("Test Ciphertext: ", output_text.decode('utf-8', 'replace'))
        print("Sending Ciphertext. Msg_Type: DAT, Payload: ", output_text.decode('utf-8', 'replace'), "\n")
        send_message_type(socket=my_sock, msg_type="DAT", payload=output_text)

        print(f"--------------------------------------------------------------------------------\n")

        my_sock.close()


def send_message_type(socket: sock.socket, msg_type: str, payload: bytes):
    if msg_type.upper() == "KEY":
        prefix = "KEY".encode('utf-8')
    elif msg_type.upper() == "ACK":
        prefix = "ACK".encode('utf-8')
    elif msg_type.upper() == "DAT":
        prefix = "DAT".encode('utf-8')
    elif msg_type.upper() == "EOT":
        prefix = "EOT".encode('utf-8')
    else:
        print(f"Unsupported message type: {msg_type}, defaulting to EOT.")
        prefix = "EOT".encode('utf-8')

    prefixed_payload = prefix + payload
    socket.send(prefixed_payload)


def receive_message_type(socket: sock.socket):
    message = socket.recv(1024)

    if not message:
        socket.close()
        print("Unexpected connection closed.")
        return "EOT", b''

    msg_type = message[0:3].decode("utf-8").upper()
    payload = message[3:]

    if msg_type == "EOT":
        print(f"Client IP: {socket.getpeername()[1]}, Received Msg_Type: {msg_type}, Closing connection.")
        socket.close()

    return msg_type, payload



if __name__ == "__main__":
    # ECDH_encrypt()
    # exit()

    try:
        start_sender()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()

