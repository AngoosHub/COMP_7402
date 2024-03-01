#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 7402 - Cryptology
Assignment 4:
    - Implement an 8-round Feistel Cipher.
    - Implement ECB and CBC cryptographic modes.
    - Implement subkey generation.
    - Able to encrypt text file specified by user.
Student:
    - Hung Yu (Angus) Lin, A01034410
----------------------------------------------------------------------------------------------------
cipher.py
    - Contains command line UI for user input for text file to encrypt or plaintext from keyboard.
    - Implements an 8-round Feistel Cipher.
----------------------------------------------------------------------------------------------------
"""

from argparse import ArgumentParser
import sys
from lookup_tables import *
# from secrets import token_bytes


DEFAULT_SUBKEYS_PATH = "default_subkeys.txt"
# KEY_SIZE = 16
BLOCK_SIZE = 16
# BYTEORDER = sys.byteorder
TOTAL_ROUNDS = 16
BYTEORDER = "big"
IV = bytes.fromhex("ef05858fe66faa7f273b5eaad1080bf9")  # 16 byte iv

def parse_args():
    """
        Parses user commandline arguments.
        :return: args
    """
    parser = ArgumentParser(description='Assign 5 Feistel Cipher')

    # Select mode and encrypt or decrypt.
    parser.add_argument('-m', '--mode', help='Supported Modes: \"ECB\" or \"CBC\"')
    parser.add_argument('-e', '--encrypt', action='store_true',
                        help='Encryption flag (Overrides decryption flag, Default if unspecified).')
    parser.add_argument('-d', '--decrypt', action='store_true',
                        help='Decryption flag (Overrided by encryption flag).')

    # Will use subkey generation it no keys options specified.
    parser.add_argument('-s', '--subkeys_default', action='store_true', help='Use default (hardcoded) subkeys for each round.')
    parser.add_argument('-k', '--keysfile', help='Specify subkeys file to use for each round. (Overrides other key options)')

    # Read the Input and output filenames.
    parser.add_argument("-i", "--inputfile", help="Provide Input filename.")
    parser.add_argument("-o", "--outputfile", help="Provide Output filename.")

    args = parser.parse_args()

    return args


def start_cipher():
    """
    Reads the user arguments and starts the feistel cipher.
    :return: None
    """

    # args = parse_args()
    #
    # if not args.encrypt and args.decrypt:
    #     is_encrypt = False
    # else:
    #     is_encrypt = True
    #
    # if args.inputfile is None and is_encrypt:
    #     print(f"====================================\n")
    #     input_text = input("Enter plaintext to encrypt: ")
    # elif args.inputfile is None and not is_encrypt:
    #     print(f"====================================\n")
    #     input_text = input("Enter ciphertext to decrypt: ")
    # else:
    #     with open(args.inputfile, "rb") as input_file:
    #         input_text = input_file.read()
    #
    # if args.keysfile:
    #     try:
    #         with open(args.keysfile, "r") as key_file:
    #             subkeys_str = key_file.read()
    #             subkeys = [int(x.strip(), 16) for x in subkeys_str.split(',')]
    #
    #             for k in subkeys:
    #                 print(hex(k))
    #     except FileNotFoundError:
    #         print("Error: key file was not found.")
    #
    # elif args.subkeys_default:
    #     with open("default_subkeys.txt", "r") as key_file:
    #         subkeys_str = key_file.read()
    #         subkeys = [int(x.strip(), 16) for x in subkeys_str.split(',')]
    #
    #         for k in subkeys:
    #             print(hex(k))
    # else:
    #     print("implement this later")
    #     subkeys = generate_subkeys()
    #
    ###### handle the args.outputfile later or when outputing to terminal.

    subkeys = read_subkeys_file(DEFAULT_SUBKEYS_PATH)
    print(subkeys)

    # input_blocks = split_byte_data_to_blocks(input_text, BLOCK_SIZE)
    #
    # for data in input_blocks:
    #     print(data)

    # # XOR two bytes, and than XOR again to undo it.
    # temp = xor_bitwise(input_text, subkeys[0])
    # print(temp)
    # temp2 = xor_bitwise(temp, subkeys[0])
    # print(temp2)

    # print(token_bytes(16))

    key = 0x000102030405060708090a0b0c0d0e0f
    round_key_list = subkey_generation(key)

    # input_text = "good".encode("utf8")
    input_text = "goodgoodgoodgoodgoodgood".encode("utf-8")

    data = input_text

    ciphertext = ecb_encrypt(data, round_key_list)
    print(ciphertext)

    plaintext = ecb_decrypt(ciphertext, round_key_list)
    print(plaintext)

    ciphertext = cbc_encrypt(data, round_key_list, IV)
    print(ciphertext)

    ciphertext = cbc_decrypt(data, round_key_list, IV)
    print(plaintext)


    # unpadded_input = unpad_block(padded_input)



def split_byte_data_to_blocks(byte_data, block_size):
    # Split input data into block size.
    input_blocks = []
    for i in range(0, len(byte_data), block_size):
        data_block = byte_data[i:i + block_size]
        if len(data_block) < block_size:
            # print(f"i={i}, len{len(data_block)}, block_size{BLOCK_SIZE}, {data_block}")
            len_diff = block_size - len(data_block)
            data_block += b'\0' * len_diff
            # print(f"After fill: len{len(data_block)}, block_size{BLOCK_SIZE}, {data_block}")

        input_blocks.append(byte_data[i:i + block_size])

    return input_blocks

    # for data in input_blocks:
    #     print(data)




def xor_bitwise(block, key):
    # key, var = key[:len(var)], var[:len(key)]
    int_var = int.from_bytes(block, BYTEORDER)
    int_key = int.from_bytes(key, BYTEORDER)
    int_enc = int_var ^ int_key
    # print(int_enc.to_bytes(BLOCK_SIZE, BYTEORDER))
    return int_enc.to_bytes(max(len(block), len(key)), BYTEORDER)


def pad_block(block: bytes):
    size_of_last_block = len(block) % BLOCK_SIZE
    padding_amount = BLOCK_SIZE - size_of_last_block
    pad_bytes = bytes([padding_amount] * padding_amount)
    return block + pad_bytes

    # pad_len = self.block_size - len(byte_array) % self.block_size
    # return byte_array + (bytes([pad_len]) * pad_len)

def unpad_block(block: bytes):
    return block[:-ord(block[-1:])]


def read_subkeys_file(filename):
    with open(filename, "r") as key_file:
        subkeys_str = key_file.read()
        subkeys = [int(x.strip(), 16).to_bytes(BLOCK_SIZE, BYTEORDER) for x in subkeys_str.split(',')]
        # subkeys = [int(x.strip(), 16) for x in subkeys_str.split(',')]
        # subkeys = [str(int(x.strip(), 16)).encode('utf8') for x in subkeys_str.split(',')]

    return subkeys


def get_default_subkeys():
    print("Using default subkeys")
    default_subkeys = (0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd, 0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff)
    return default_subkeys



def bit_by_bit_compare(hex_string_1, hex_string_2):
    print("Start Bit by Bit Comparison:")
    if not len(hex_string_1) == len(hex_string_2):
        print(f"Length of compared hex strings do not match! 1: {len(hex_string_1)} != 2: {len(hex_string_2)}")
        return

    bit_length_1 = len(hex_string_1) * 4
    binary_string_1 = format(int(hex_string_1, 16), f'0>{bit_length_1}b')
    print(f'{hex_string_1}: {binary_string_1}')

    bit_length_2 = len(hex_string_2) * 4
    binary_string_2 = format(int(hex_string_2, 16), f'0>{bit_length_2}b')
    print(f'{hex_string_2}: {binary_string_2}')

    if not len(binary_string_1) == len(binary_string_2):
        print(f"Length of compared binary strings do not match! 1: {len(binary_string_1)} != 2: "
              f"{len(binary_string_2)}")
        return

    length = len(binary_string_1)
    count = 0

    for x in range(0, length):
        if binary_string_1[x] != binary_string_2[x]:
            count += 1

    print(f"Size: {length}")
    print(f"Difference: {count} \n")

    return count, length



def avalanche_effect():
    print("Starting Avalanche Effect.")


def image_test():
    print("Starting image test.")


def ecb_encrypt(data, round_key_list):
    # pad last block to block size.
    data_pad = pad_block(data)
    data_block_list = split_byte_data_to_blocks(data_pad, BLOCK_SIZE)

    cipher_block_list = []
    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        last_data_block = data_block

        for i in range(len(round_key_list)):
            data_block_temp = round_function(last_data_block, round_key_list[i])
            last_data_block = data_block_temp

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        cipher_block = right_block + left_block
        # print(cipher_block)
        cipher_block_list.append(cipher_block)

    return b''.join(cipher_block_list)


def ecb_decrypt(data, round_key_list):
    keys_reverse = list(reversed(round_key_list))
    # print(round_key_list)
    # print(keys_reverse)

    data_block_list = split_byte_data_to_blocks(data, BLOCK_SIZE)

    plaintext_block_list = []
    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        last_data_block = data_block

        for i in range(len(keys_reverse)):
            data_block_temp = round_function(last_data_block, keys_reverse[i])
            last_data_block = data_block_temp

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        plaintext_block = right_block + left_block
        # print(plaintext_block)
        plaintext_block_list.append(plaintext_block)

    # unpad last block
    plaintext_block_list[-1] = unpad_block(plaintext_block_list[-1])
    return b''.join(plaintext_block_list)


def cbc_encrypt(data, round_key_list, iv):
    # pad last block to block size.
    data_pad = pad_block(data)
    data_block_list = split_byte_data_to_blocks(data_pad, BLOCK_SIZE)

    cipher_block_list = []
    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        # XOR initialization vector with data block
        last_data_block = xor_bitwise(data_block, iv)

        for i in range(len(round_key_list)):
            data_block_temp = round_function(last_data_block, round_key_list[i])
            last_data_block = data_block_temp

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        cipher_block = right_block + left_block
        cipher_block_list.append(cipher_block)
        # set iv as current block for next block
        iv = cipher_block

    return b''.join(cipher_block_list)


def cbc_decrypt(data, round_key_list, iv):
    keys_reverse = list(reversed(round_key_list))

    data_block_list = split_byte_data_to_blocks(data, BLOCK_SIZE)

    plaintext_block_list = []
    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        last_data_block = data_block

        for i in range(len(keys_reverse)):
            data_block_temp = round_function(last_data_block, keys_reverse[i])
            last_data_block = data_block_temp

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        plaintext_block_iv = right_block + left_block

        # XOR initialization vector with data block
        plaintext_block = xor_bitwise(plaintext_block_iv, iv)

        plaintext_block_list.append(plaintext_block)
        # set iv as last cipher block for next block
        iv = data_block

    # unpad last block
    plaintext_block_list[-1] = unpad_block(plaintext_block_list[-1])
    return b''.join(plaintext_block_list)


def round_function(data_block, round_key):
    # split into left & right blocks
    left_block = data_block[:len(data_block) // 2]
    right_block = data_block[len(data_block) // 2:]

    # call f_function with right block and XOR output with left block
    # f_block = f_function(right_block, round_key) #### UNCOMMENT LATTER
    xor_block = xor_bitwise(left_block, right_block)

    # concatenate original right block with new left block in this order
    return right_block + xor_block


def f_function(data_block, round_key):
    left_key = round_key[:len(round_key) // 2]
    right_key = round_key[len(round_key) // 2:]

    return data_block



def subkey_generation(key):
    # key = 0xdddddddddddddddddddddddddddddddd
    # TOTAL_ROUNDS
    key_bytes = int.to_bytes(key, 16, BYTEORDER)
    # print(key_bytes)
    # print(len(key_bytes))
    BYTE_BLOCK_SIZE = 1
    key_blocks = split_byte_data_to_blocks(key_bytes, block_size=BYTE_BLOCK_SIZE)
    # print(key_blocks)

    # Split data block into 4-by-4 matrix, then into 4 columns of words
    word1, word2, word3, word4 = [], [], [], []

    for i in [0, 4, 8, 12]:
        # word1.append(key_blocks[i])
        word1.append(int.from_bytes(key_blocks[i], BYTEORDER))

    for i in [1, 5, 9, 13]:
        # word2.append(key_blocks[i])
        word2.append(int.from_bytes(key_blocks[i], BYTEORDER))

    for i in [2, 6, 10, 14]:
        # word3.append(key_blocks[i])
        word3.append(int.from_bytes(key_blocks[i], BYTEORDER))

    for i in [3, 7, 11, 15]:
        # word4.append(key_blocks[i])
        word4.append(int.from_bytes(key_blocks[i], BYTEORDER))

    # print(word1)
    # print(word2)
    # print(word3)
    # print(word4)

    # Begin Subkey Generation.
    round_key_list = []
    last_word_1 = word1
    last_word_2 = word2
    last_word_3 = word3
    last_word_4 = word4

    for i in range(TOTAL_ROUNDS):
        # pass word4 through rot, sub_mod and rcon_mod functions
        word_r = rot_word(last_word_4)
        word_rs = sub_word_mod(word_r)
        word_rsr = rcon_word_mod(word_rs, i)

        # XOR words from last round key with transformed word to get next round key
        word1_ = XOR_two_words(last_word_1, word_rsr)
        word2_ = XOR_two_words(last_word_2, word1_)
        word3_ = XOR_two_words(last_word_3, word2_)
        word4_ = XOR_two_words(last_word_4, word3_)

        # Join the words back into an block to get round key.
        new_subkey = []
        for j in range(len(word1)):
            new_subkey.append(word1_[j].to_bytes(BYTE_BLOCK_SIZE, byteorder=BYTEORDER))
            new_subkey.append(word2_[j].to_bytes(BYTE_BLOCK_SIZE, byteorder=BYTEORDER))
            new_subkey.append(word3_[j].to_bytes(BYTE_BLOCK_SIZE, byteorder=BYTEORDER))
            new_subkey.append(word4_[j].to_bytes(BYTE_BLOCK_SIZE, byteorder=BYTEORDER))

        new_subkey = b''.join(new_subkey)
        round_key_list.append(new_subkey)

        print(f"\n===Subkey Round {i}===")
        print("Word4: ", last_word_4)
        print("After Rot_word: ", word_r)
        print("After Sub_word_mod: ", word_rs)
        print("After Rcon_word_mod: ", word_rsr)
        print("After XOR with last_word1: ", word1_)
        print("Word1_: ", word1_)
        print("Word2_: ", word2_)
        print("Word3_: ", word3_)
        print("Word4_: ", word4_)
        print("Round_Key: ", new_subkey.hex())

        last_word_1 = word1_
        last_word_2 = word2_
        last_word_3 = word3_
        last_word_4 = word4_

    print("\n==== Subkey Generation ====")
    print(f"Inital Key: {key:x}")
    for n in range(len(round_key_list)):
        print(f"Round Key {n+1}: {round_key_list[n].hex()}")

    return round_key_list


def rot_word(word):
    word_r = word.copy()
    word_r.append(word_r.pop(0))
    return word_r


def sub_word_mod(word):
    word_rs = [sbox_1[word[0]], sbox_2[word[1]], sbox_3[word[2]], sbox_4[word[3]]]
    return word_rs


def rcon_word_mod(word, round_num):
    rcon = (round_num+1) ^ word[0] ^ word[1] ^ word[2] ^ word[3]
    sub_rcon = sbox_3[rcon]

    word_rsr = word.copy()
    word_rsr[0] = word_rsr[0] ^ sub_rcon

    # Test:
    # input: [229, 106, 160, 192], output: [29, 106, 160, 192]
    # 1 ^ 229 ^ 106 ^ 160 ^ 192 = 238. After sbox_3 = 248. Then 229 XOR 248 = 29
    return word_rsr


def XOR_two_words(word_a, word_b):
    word_c = []
    if not len(word_a) == len(word_b):
        print("Length of Words in Subkey Gen does not match.")
        raise ValueError

    for i in range(len(word_a)):
        word_c.append(word_a[i] ^ word_b[i])

    # Test A = [0, 4, 8, 12] B = [29, 106, 160, 192] C = [29, 110, 168, 204]
    # print(word_a)
    # print(word_b)
    # print(word_c)
    return word_c



if __name__ == "__main__":
    try:
        start_cipher()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()


# if __name__ == "__main__":
#
#     # key = "0xdddddddd"
#     # print(key)
#     # print(int(key, 16))
#     # print(hex(int(key, 16)))
#
#     # exit()
#     # val = 0xdddddddd
#     # sub_val = sbox_1[val]
#
#     # 3e9e98e31ba18d8d18283aceb3c6e170
#     # 16b729e1363afc5bea8bf7df295b03e9
#     import os
#     k = os.urandom(16)
#     # print(k)
#     # print(len(k))
#
#     val = 0xdddddddd
#     val2 = 0xeeeeeeee
#     g = int.to_bytes(val, 4, byteorder=BYTEORDER)
#     f = int.to_bytes(val2, 4, byteorder=BYTEORDER)
#     # print(g)
#     # print(len(g))
#
#     # z = "3e9e98e31ba18d8d18283aceb3c6e170"
#     # print(z.encode())
#     # print(len(z.encode()))
#
#     # import hashlib
#     # key = hashlib.sha256("test".encode()).digest()
#     # print(key)
#     # print(len(key))
#
#     val_hex = bytes(a ^ b for a, b in zip(g, f))
#     print(val_hex)
#
#     int_var = int.from_bytes(g, BYTEORDER)
#     int_key = int.from_bytes(f, BYTEORDER)
#     int_enc = int_var ^ int_key
#     output = int_enc.to_bytes(len(g), byteorder=BYTEORDER)
#     # print(output)
#     # print(output.hex())
#
#
#
#     # key = 0xdddddddddddddddddddddddddddddddd
#     key = 0x000102030405060708090a0b0c0d0e0f
#     subkey_generation(key)
#
#     start_cipher()
#
#
#     exit()
#
#
#     try:
#         start_cipher()
#     except KeyboardInterrupt as e:
#         print("Shutting Down.")
#         exit()
