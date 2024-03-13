#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 7402 - Cryptology
Assignment 5:
    - Implement an 16-round Feistel Cipher.
    - Implement CBC cryptographic mode.
    - Implement 128-bits subkey generation.
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
import csv
from PIL import Image
import math
import subprocess
import sys


DEFAULT_SUBKEYS_PATH = "default_subkeys.txt"
# KEY_SIZE = 16
BLOCK_SIZE = 16
# BYTEORDER = sys.byteorder
TOTAL_ROUNDS = 16
BYTEORDER = "big"
IV = bytes.fromhex("ef05858fe66faa7f273b5eaad1080bf9")  # 16 byte iv
RECORD_AVALANCHE = False
SHOW_CIPHER_COMMENTS = False


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

    parser.add_argument('-g', '--genkey',
                        help='Provide a 128-bit hexadecimal key to use for keygen. (Uses Default key if empty)')


    # Read the Input and output filenames.
    parser.add_argument("-i", "--inputfile", help="Provide Input filename.")
    parser.add_argument("-o", "--outputfile", help="Provide Output filename.")

    # # Read the Input and output filenames.
    # parser.add_argument('-a', '--avalanche', action='store_true',
    #                     help='Saves avalanche results to aa file.')

    args = parser.parse_args()

    return args


def start_cipher():
    """
    Reads the user arguments and starts the feistel cipher.
    :return: None
    """

    global RECORD_AVALANCHE

    args = parse_args()

    if not args.encrypt and args.decrypt:
        is_encrypt = False
    else:
        is_encrypt = True

    if not args.mode or (args.mode.lower() != "ecb" and args.mode.lower() != "cbc"):
        print("Invalid mode, only ECB and CBC supported.")
        return

    if args.inputfile is None and is_encrypt:
        print(f"====================================\n")
        input_text = input("Enter plaintext to encrypt: ")
        input_text = input_text.encode("utf-8")
    elif args.inputfile is None and not is_encrypt:
        print(f"====================================\n")
        input_text = input("Enter ciphertext (hexstring) to decrypt: ")
        input_text = bytes.fromhex(input_text)
    else:
        with open(args.inputfile, "rb") as input_file:
            input_text = input_file.read()

    if args.keysfile:
        try:
            round_key_list = read_subkeys_file(args.keysfile)
        except FileNotFoundError:
            print("Error: key file was not found.")
        print("==== Loaded Subkeys ====")
        for x in range(len(round_key_list)):
            print(f"Round Key {x}: {round_key_list[x].hex()}")
    elif args.subkeys_default:
        round_key_list = read_subkeys_file(DEFAULT_SUBKEYS_PATH)
        print("==== Default Subkeys ====")
        for x in range(len(round_key_list)):
            print(f"Round Key {x}: {round_key_list[x].hex()}")
    else:
        if args.genkey is not None and len(args.genkey) > 0:
            # key = bytes.fromhex(args.genkey)
            key = int(args.genkey, 16)
            round_key_list = subkey_generation(key)
        else:
            key = 0x000102030405060708090a0b0c0d0e0f
            round_key_list = subkey_generation(key)



    # print(token_bytes(16))

    # control
    # key = 0x000102030405060708090a0b0c0d0e0f
    # 1 bit diff
    # key = 0x100102030405060708090a0b0c0d0e0f
    # 2 bit diff
    # key = 0x110102030405060708090a0b0c0d0e0f
    # 3 bit diff
    # key = 0x111102030405060708090a0b0c0d0e0f
    # 4 bit diff
    # key = 0x101002130405060708090a0b0c0d0e0f
    # 6 bit diff
    # key = 0x10000213a405061708090a0b0c0d0e0f
    # 7 bit diff
    # key = 0x10100213a405061708090a0b0c0d0e0f
    # 10 bit diff
    # key = 0x10100213a405e61708090a0b0c0d0e0f

    # try:
    #     key_bytes = int.to_bytes(key, BLOCK_SIZE, BYTEORDER)
    # except OverflowError:
    #     print("Key too big. Key must be 128-bits")

    # control
    # input_text = "abcdefghijklmno".encode("utf-8")
    # 1 bit diff
    # input_text = "Abcdefghijklmno".encode("utf-8")
    # 2 bit diff
    # input_text = "bbcdefghijklmno".encode("utf-8")
    # 3 bit diff
    # input_text = "bBcdefghijklmno".encode("utf-8")
    # 4 bit diff
    # input_text = "bcccefghijklmno".encode("utf-8")
    # 6-bit diff
    # input_text = "abddegFhijklmnop".encode("utf-8")

    data = input_text
    # data_padded = pad_block(data)

    if args.mode.lower() == "ecb":
        if is_encrypt:
            output_text = ecb_encrypt(data, round_key_list)
            if args.outputfile and not args.outputfile.endswith(".bmp"):
                print("Encrypted CipherText Decode: ", output_text.decode('utf-8', 'replace'))
            if args.outputfile:
                with open(args.outputfile, "wb") as f:
                    f.write(output_text)
                if args.outputfile.endswith(".bmp"):
                    with open(f"dd_{args.outputfile}", "wb") as f:
                        f.write(output_text)
                    cmd = ["dd", f"if={args.inputfile}", f"of=dd_{args.outputfile}", "bs=2", "count=54", "conv=notrunc"]
                    process = subprocess.run(cmd)

        else:
            output_text = ecb_decrypt(data, round_key_list)
            print("Decrypted PlainText Decode: ", output_text.decode('utf-8', 'replace'))
            if args.outputfile:
                with open(args.outputfile, "wb") as f:
                    f.write(output_text)
                    # f.write(output_text.decode('utf-8', 'replace'))

    elif args.mode.lower() == "cbc":
        if is_encrypt:
            output_text = cbc_encrypt(data, round_key_list, IV)
            if args.outputfile and not args.outputfile.endswith(".bmp"):
                print("Encrypted CipherText Decode: ", output_text.decode('utf-8', 'replace'))
            if args.outputfile:
                with open(args.outputfile, "wb") as f:
                    f.write(output_text)
                if args.outputfile.endswith(".bmp"):
                    with open(f"dd_{args.outputfile}", "wb") as f:
                        f.write(output_text)
                    cmd = ["dd", f"if={args.inputfile}", f"of=dd_{args.outputfile}", "bs=2", "count=54", "conv=notrunc"]
                    process = subprocess.run(cmd)
        else:
            output_text = cbc_decrypt(data, round_key_list, IV)
            print("Decrypted PlainText Decode: ", output_text.decode('utf-8', 'replace'))
            if args.outputfile:
                with open(args.outputfile, "wb") as f:
                    f.write(output_text)
                    # f.write(output_text.decode('utf-8', 'replace'))



    # ciphertext = ecb_encrypt(data, round_key_list)
    # print("Encrypted CipherText Decode: ", ciphertext.decode('utf-8', 'replace'))

    # plaintext = ecb_decrypt(ciphertext, round_key_list)
    # print("Decrypted PlainText Decode: ", plaintext.decode('utf-8', 'replace'))

    # size, difference = avalanche_bit_compare(data_padded, ciphertext)

    # ciphertext = cbc_encrypt(data, round_key_list, IV)
    # print("Encrypted CipherText Decode: ", ciphertext.decode('utf-8', 'replace'))

    # plaintext = cbc_decrypt(ciphertext, round_key_list, IV)
    # print("Decrypted PlainText Decode: ", plaintext.decode('utf-8', 'replace'))

    # size, difference = avalanche_bit_compare(data_padded, ciphertext)



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
        try:
            subkeys = [int(x.strip(), 16).to_bytes(BLOCK_SIZE, BYTEORDER) for x in subkeys_str.split(',')]
        except OverflowError:
            print("Key size too big. Keys must be 128-bits.")
        # subkeys = [int(x.strip(), 16) for x in subkeys_str.split(',')]
        # subkeys = [str(int(x.strip(), 16)).encode('utf8') for x in subkeys_str.split(',')]

    return subkeys

# def get_default_subkeys():
#     print("Using default subkeys")
#     default_subkeys = (0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd, 0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff)
#     return default_subkeys


def avalanche_bit_compare(a, b):
    # print("len a:", len(a), " len b:", len(b))

    binary_string_1 = format(int.from_bytes(a, BYTEORDER), f'0{len(a)*8}b')
    binary_string_2 = format(int.from_bytes(b, BYTEORDER), f'0{len(b)*8}b')

    # print("bin1", len(binary_string_1))
    # print("bin2", len(binary_string_2))

    if not len(binary_string_1) == len(binary_string_2):
        print(f"Length of compared binary strings do not match! 1: {len(binary_string_1)} != 2: "
              f"{len(binary_string_2)}")
        return

    length = len(binary_string_1)
    count = 0

    for x in range(0, length):
        if binary_string_1[x] != binary_string_2[x]:
            count += 1

    difference = round((count / length) * 100, 2)
    # print(f"Size: {length}")
    print(f"Avalanche Bit Difference: {count}, {difference}%\n")
    return length, difference



def ecb_encrypt(data, round_key_list):
    # pad last block to block size.
    data_pad = pad_block(data)
    data_block_list = split_byte_data_to_blocks(data_pad, BLOCK_SIZE)

    cipher_block_list = []
    avalanche_data_list = []
    control_list = []
    if RECORD_AVALANCHE:
        with open('avalanche_control.csv', 'r') as file:
            file.readline()
            # Split columns while reading
            for a, b, c in csv.reader(file, delimiter=','):
                # Append each variable to a separate list
                control_list.append(c)

    # print(control_list)
    print("\n")

    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        last_data_block = data_block
        print(f"====Data Block {n + 1}====\n"
              f"Data Block = {data_block.hex()}")

        for i in range(len(round_key_list)):
            data_block_temp = round_function(last_data_block, round_key_list[i])
            last_data_block = data_block_temp
            print(f"Round {i+1} - Block = {last_data_block.hex()}")

            if RECORD_AVALANCHE and n == 0 and i == 0:
                size, difference = avalanche_bit_compare(int(control_list[i], 16).to_bytes(BLOCK_SIZE, BYTEORDER), data_block)
                avalanche_data = (0, difference, data_block.hex())
                avalanche_data_list.append(avalanche_data)

            if RECORD_AVALANCHE and n == 0:
                size, difference = avalanche_bit_compare(int(control_list[i+1], 16).to_bytes(BLOCK_SIZE, BYTEORDER), last_data_block)
                avalanche_data = (i+1, difference, last_data_block.hex())
                avalanche_data_list.append(avalanche_data)

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        cipher_block = right_block + left_block
        # print(cipher_block)
        cipher_block_list.append(cipher_block)
        print(f"CipherText = {cipher_block.hex()}")
        print("\n")

    if RECORD_AVALANCHE:
        with open('avalanche_record.csv', 'w') as out:
            csv_out = csv.writer(out)
            csv_out.writerow(['Round', 'Bit Difference', 'Hexadecimal'])
            for row in avalanche_data_list:
                csv_out.writerow(row)

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
        print(f"====Data Block {n + 1}====\n"
              f"Data Block = {data_block.hex()}")

        for i in range(len(keys_reverse)):
            data_block_temp = round_function(last_data_block, keys_reverse[i])
            last_data_block = data_block_temp
            print(f"Round {i + 1} - Block = {last_data_block.hex()}")

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        plaintext_block = right_block + left_block
        # print(plaintext_block)
        plaintext_block_list.append(plaintext_block)
        print(f"CipherText = {plaintext_block.hex()}")
        print("\n")


    # unpad last block
    plaintext_block_list[-1] = unpad_block(plaintext_block_list[-1])
    return b''.join(plaintext_block_list)


def cbc_encrypt(data: bytes, round_key_list, iv: bytes, pad=True):
    # pad last block to block size.
    if pad:
        data_pad = pad_block(data)
    else:
        data_pad = data
    data_block_list = split_byte_data_to_blocks(data_pad, BLOCK_SIZE)

    cipher_block_list = []
    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        # XOR initialization vector with data block
        last_data_block = xor_bitwise(data_block, iv)
        if SHOW_CIPHER_COMMENTS:
            print(f"====Data Block {n + 1}====\n"
                  f"Data Block = {data_block.hex()}")

        for i in range(len(round_key_list)):
            data_block_temp = round_function(last_data_block, round_key_list[i])
            last_data_block = data_block_temp
            if SHOW_CIPHER_COMMENTS:
                print(f"Round {i + 1} - Block = {last_data_block.hex()}")

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        cipher_block = right_block + left_block
        cipher_block_list.append(cipher_block)
        # set iv as current block for next block
        iv = cipher_block
        if SHOW_CIPHER_COMMENTS:
            print(f"CipherText = {cipher_block.hex()}")
            print("\n")

    return b''.join(cipher_block_list)


def cbc_decrypt(data, round_key_list, iv, unpad=True):
    keys_reverse = list(reversed(round_key_list))

    data_block_list = split_byte_data_to_blocks(data, BLOCK_SIZE)

    plaintext_block_list = []
    for n in range(len(data_block_list)):
        data_block = data_block_list[n]
        last_data_block = data_block
        if SHOW_CIPHER_COMMENTS:
            print(f"====Data Block {n + 1}====\n"
                  f"Data Block = {data_block.hex()}")

        for i in range(len(keys_reverse)):
            data_block_temp = round_function(last_data_block, keys_reverse[i])
            last_data_block = data_block_temp
            if SHOW_CIPHER_COMMENTS:
                print(f"Round {i + 1} - Block = {last_data_block.hex()}")

        # swap left and right halves after final round
        left_block = last_data_block[:len(last_data_block) // 2]
        right_block = last_data_block[len(last_data_block) // 2:]
        plaintext_block_iv = right_block + left_block

        # XOR initialization vector with data block
        plaintext_block = xor_bitwise(plaintext_block_iv, iv)

        plaintext_block_list.append(plaintext_block)
        if SHOW_CIPHER_COMMENTS:
            print(f"CipherText = {plaintext_block.hex()}")
            print("\n")
        # set iv as last cipher block for next block
        iv = data_block

    # unpad last block
    if unpad:
        plaintext_block_list[-1] = unpad_block(plaintext_block_list[-1])

    return b''.join(plaintext_block_list)


def round_function(data_block, round_key):
    # split into left & right blocks
    left_block = data_block[:len(data_block) // 2]
    right_block = data_block[len(data_block) // 2:]

    # call f_function with right block and XOR output with left block
    f_block = f_function(right_block, round_key)
    xor_block = xor_bitwise(left_block, f_block)

    # concatenate original right block with new left block in this order
    return right_block + xor_block


def f_function(data_block, round_key):
    left_key = round_key[:len(round_key) // 2]
    right_key = round_key[len(round_key) // 2:]
    # print("len check: ", len(left_key) == len(data_block))

    # XOR with left key
    xor_block_1 = xor_bitwise(data_block, left_key)

    # Split into 8 blocks of 1 byte each
    byte_blocks = split_byte_data_to_blocks(xor_block_1, block_size=1)
    for i in range(len(byte_blocks)):
        byte_blocks[i] = int.from_bytes(byte_blocks[i], BYTEORDER)

    # Substitute using 4 S-Boxes from Camellia
    byte_blocks[0] = sbox_1[byte_blocks[0]]
    byte_blocks[1] = sbox_2[byte_blocks[1]]
    byte_blocks[2] = sbox_3[byte_blocks[2]]
    byte_blocks[3] = sbox_4[byte_blocks[3]]
    byte_blocks[4] = sbox_2[byte_blocks[4]]
    byte_blocks[5] = sbox_3[byte_blocks[5]]
    byte_blocks[6] = sbox_4[byte_blocks[6]]
    byte_blocks[7] = sbox_1[byte_blocks[7]]

    # Permute with XOR using modified Camellia P-function
    byte_blocks[0] = byte_blocks[0] ^ byte_blocks[5]
    byte_blocks[1] = byte_blocks[1] ^ byte_blocks[6]
    byte_blocks[2] = byte_blocks[2] ^ byte_blocks[7]
    byte_blocks[3] = byte_blocks[3] ^ byte_blocks[4]
    byte_blocks[4] = byte_blocks[4] ^ byte_blocks[2]
    byte_blocks[5] = byte_blocks[5] ^ byte_blocks[3]
    byte_blocks[6] = byte_blocks[6] ^ byte_blocks[0]
    byte_blocks[7] = byte_blocks[7] ^ byte_blocks[1]

    byte_blocks[0] = byte_blocks[0] ^ byte_blocks[7]
    byte_blocks[1] = byte_blocks[1] ^ byte_blocks[4]
    byte_blocks[2] = byte_blocks[2] ^ byte_blocks[5]
    byte_blocks[3] = byte_blocks[3] ^ byte_blocks[6]
    byte_blocks[4] = byte_blocks[4] ^ byte_blocks[3]
    byte_blocks[5] = byte_blocks[5] ^ byte_blocks[0]
    byte_blocks[6] = byte_blocks[6] ^ byte_blocks[1]
    byte_blocks[7] = byte_blocks[6] ^ byte_blocks[2]

    # print(byte_blocks)
    # print(f"{sbox_1[116]}, {sbox_2[118]}, {sbox_3[117]}, {sbox_4[113]}, {sbox_2[3]}, {sbox_3[5]}, {sbox_4[2]}, {sbox_1[107]}")

    # Permute and Merge back to a block
    merge_order = [4, 5, 6, 7, 0, 1, 2, 3]
    merge_byte_list = [byte_blocks[i].to_bytes(1, byteorder=BYTEORDER) for i in merge_order]
    merge_block = b''.join(merge_byte_list)
    # print(merge_block)

    # XOR with right key
    xor_block_2 = xor_bitwise(merge_block, right_key)

    # permute with IP box from DES
    binary_str_list = list(format(int.from_bytes(xor_block_2, BYTEORDER), f'0{len(xor_block_2) * 8}b'))
    permute_str_list = [binary_str_list[i-1] for i in ip_box]
    permute_int = int(''.join(permute_str_list), 2)
    permute_block = permute_int.to_bytes(int(BLOCK_SIZE/2), byteorder=BYTEORDER)

    return permute_block



def subkey_generation(key):
    # key = 0xdddddddddddddddddddddddddddddddd
    # TOTAL_ROUNDS
    key_bytes = int.to_bytes(key, BLOCK_SIZE, BYTEORDER)
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

        if SHOW_CIPHER_COMMENTS:
            print(f"\n===Subkey Round {i}===")
            print("LastWord: ", last_word_4)
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

    if SHOW_CIPHER_COMMENTS:
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

    # bmp = open("black_white.bmp", 'rb')


    # key = 0x000102030405060708090a0b0c0d0e0f
    # key_str = f'{key:032x}'
    #
    # # 1 bit diff
    # key2 = 0x100102030405060708090a0b0c0d0e0f
    # key2_str = f'{key2:032x}'
    # # 2 bit diff
    # key3 = 0x110102030405060708090a0b0c0d0e0f
    # key3_str = f'{key3:032x}'
    # # 3 bit diff
    # key4 = 0x111102030405060708090a0b0c0d0e0f
    # key4_str = f'{key4:032x}'
    # # 4 bit diff
    # key5 = 0x101002130405060708090a0b0c0d0e0f
    # key5_str = f'{key5:032x}'
    # # 7 bit diff
    # key7 = 0x10100213a405061708090a0b0c0d0e0f
    # key7_str = f'{key7:032x}'
    #
    # # 10 bit diff
    # key6 = 0x10100213a405e61708090a0b0c0d0e0f
    # key6_str = f'{key6:032x}'
    #
    # # 6 bit diff
    # key8 = 0x10000213a405061708090a0b0c0d0e0f
    # key8_str = f'{key8:032x}'
    #
    # key9 = 0x00010213a405061708090a0b0c0d0e0f
    # key9_str = f'{key9:032x}'
    #
    # avalanche_bit_compare(key.to_bytes(BLOCK_SIZE, BYTEORDER), key9.to_bytes(BLOCK_SIZE, BYTEORDER))
    # exit()

    # input_text = "abcdefghijklmno".encode("utf-8")
    # input_text2 = "Abcdefghijklmno".encode("utf-8")
    # input_text3 = "bbcdefghijklmno".encode("utf-8")
    # input_text4 = "bBcdefghijklmno".encode("utf-8")
    # input_text5 = "abDdefghijklmno".encode("utf-8")
    # # 6 bit
    # input_text6 = "abddegFhijklmno".encode("utf-8")
    #
    # avalanche_bit_compare(input_text, input_text6)
    # exit()

    try:
        start_cipher()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()

