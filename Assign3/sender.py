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

from encryption import *
from tinyec import registry

from _thread import *
import socket as sock


CONFIGURATION_PATH = "configuration.txt"

def read_configuration():
    """
    Reads configuration file for IP address and port numbers.
    :return: list (config vars)
    """

    configuration = {
        'receiver_address': '',
        'sender_address': '',
        'receiver_port': 0,
    }

    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            config_data = line.split('=')
            if config_data[0] in configuration:
                if config_data[0] in ('receiver_address', 'sender_address'):
                    configuration[config_data[0]] = config_data[1]
                else:
                    data = config_data[1]
                    if data.isdigit():
                        configuration[config_data[0]] = int(config_data[1])
                    else:
                        print("Invalid configuration, ports must be integers.")
                        exit()
    return configuration


def command_line_menu():
    """
    Initializes command line menu to read user input.
    Can initiate an ECDH key exchange with a receiver server, then use the shared key to send a 32-byte message
    from keyboard input using AES encryption.
    :return: None
    """

    keep_going = True
    while keep_going:
        print(f"====================================\n"
              f"Menu:\n"
              f"    1. Start Sender \n"
              f"    0. Exit \n")
        user_input = input("Type number and press enter: ")

        if user_input == "1":
            start_sender()

        elif user_input == "0":
            print("Exiting Program.")
            break
        else:
            print("Invalid input, try again.")
            continue


def start_sender():
    print("Starting Sender Client.")
    configuration = read_configuration()
    address = configuration['receiver_address']
    port = configuration['receiver_port']

    while True:
        plaintext = 'fortuneofthesedaysthatonemaythinkwhatonelikesandsaywhatonethinks'
        user_input = input(f"\nEnter a 32-bytes long message to send or enter nothing for default plaintext."
                           f"\n(Default: \"{plaintext}\")"
                           f"\nUserInput: ")
        if len(user_input.encode('utf-8')) == 64:
            message = user_input
            break
        elif len(user_input.encode('utf-8')) > 0 and not len(user_input) == 64:
            print(f"Invalid input, message was not 32-bytes.")
        else:
            message = plaintext
            break

    # IPv4 Socket connection to receiver.
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as my_sock:
        my_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        my_sock.connect((address, port))

        # Generate pub priv keys.
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        print(f"\nSender private key: {hex(private_key)}")
        print(f"Sender public key:  {public_key_compressed}")
        # print(f"Sender public key (Curve point): {public_key}")

        # Exchange public keys
        my_sock.sendall(public_key_compressed.encode("utf-8"))
        data = my_sock.recv(1024).decode("utf-8")

        # Calculate shared key
        shared_key, shared_key_compressed = calculate_shared_key(private_key=private_key, compressed_key=data)
        print(f"\nSender shared key:   {shared_key_compressed}")
        # print(f"Sender shared key (Curve point): {shared_key}")


        # Repeat for Initalization Vector
        private_key, public_key, public_key_compressed = generate_ECDH_pub_priv_keys()
        print(f"\nSender private key: {hex(private_key)}")
        print(f"Sender public key:  {public_key_compressed}")
        # print(f"Sender public key (Curve point): {public_key}")

        # Exchange public keys
        my_sock.sendall(public_key_compressed.encode("utf-8"))
        data_iv = my_sock.recv(1024).decode("utf-8")

        # Calculate shared key
        shared_key_iv, shared_key_iv_compressed = calculate_shared_key(private_key=private_key, compressed_key=data_iv)
        print(f"\nSender shared key for IV:   {shared_key_iv_compressed}")
        # print(f"Sender shared key for IV (Curve point): {shared_key_iv}")

        cipher_text = AES_encrypt(shared_key_compressed, shared_key_iv_compressed, message)
        my_sock.sendall(cipher_text)

        my_sock.close()



if __name__ == "__main__":
    # ECDH_encrypt()
    # exit()

    try:
        command_line_menu()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()

