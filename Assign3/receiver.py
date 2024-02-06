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
from sender import *
import socket as sock
# from socket import *
from _thread import *


LOG_PATH = "log.txt"
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
    Can perform an ECDH key exchange sender client, and then use the shared key to decrypt an incoming 32-byte message
    using AES encryption.
    :return: None
    """

    keep_going = True
    while keep_going:
        print(f"====================================\n"
              f"Menu:\n"
              f"    1. Start Receiver \n"
              f"    0. Exit \n")
        user_input = input("Type number and press enter: ")

        if user_input == "1":
            start_new_thread(start_receiver, ())

        elif user_input == "0":
            print("Exiting Program.")
            break
        else:
            print("Invalid input, try again.")
            continue


def start_receiver():
    print("Starting Receiver.")
    configuration = read_configuration()
    address = configuration['receiver_address']
    port = configuration['receiver_port']
    sender_address = configuration['sender_address']
    host_address = configuration['receiver_address']

    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as IPv4_sock:
        IPv4_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        IPv4_sock.bind((address, port))
        IPv4_sock.listen(10)
        print("Listening on: ", IPv4_sock.getsockname())

        while True:
            conn, addr = IPv4_sock.accept()

            while True:
                data = conn.recv(1024).decode('utf8')
                if data:
                    print(f"{conn.getpeername()}: \t{data}")
                    receiver_public_key_compressed, receiver_shared_key = server_ECDH_exchange(data)
                    conn.sendall(receiver_public_key_compressed.encode("utf8"))
                else:
                    conn.close()
                    break


def server_ECDH_exchange(sender_public_key_compressed):
    curve = registry.get_curve('brainpoolP256r1')
    print('Curve:', curve)
    p = 76884956397045344220809746629001649093037950200943055203735601445031516197751
    a = curve.a
    b = curve.b

    receiver_private_key = secrets.randbelow(curve.field.n)
    receiver_public_key = curve.g * receiver_private_key
    receiver_public_key_compressed = compress_key(receiver_public_key)

    print(f"\nreceiver private key: {hex(receiver_private_key)}")
    print(f"receiver public key:  {receiver_public_key_compressed}")
    print(f"receiver public key point: {receiver_public_key}")

    sender_public_key = uncompress_key(sender_public_key_compressed, p, a, b)
    receiver_shared_key = ec.Point(curve, sender_public_key[0], sender_public_key[1]) * receiver_private_key

    print(f"Receiver shared key: {compress_key(receiver_shared_key)}")

    print(f"Receiver shared key (Curve point): {receiver_shared_key}")

    return receiver_public_key_compressed, receiver_shared_key




if __name__ == "__main__":
    try:
        command_line_menu()
    except KeyboardInterrupt as e:
        print("Receiver Shutdown")
        exit()


