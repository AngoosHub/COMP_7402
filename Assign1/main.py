#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 7402 - Cryptology
Assignment 1:
    - To learn how to analyze the strength of a cipher by analyzing its Confusion and Diffusion
    characteristics using the Avalanche effect for SPAC and SKAC conditions in DES and AES ciphers.
Student:
    - Hung Yu (Angus) Lin, A01034410
----------------------------------------------------------------------------------------------------
main.py
    - Contains command line UI for user input to display DES and AES ciphers text round by round, and
    analyze Avalanche effect for SPAC and SKAc and save output into csv file.
----------------------------------------------------------------------------------------------------
"""

import DES
import aes
import data_record


def command_line_menu():
    """
    Initializes command line menu to read user input.
    :return: None
    """

    keep_going = True
    while keep_going:
        print(f"====================================\n"
              f"Menu:\n"
              f"    1. Start DES \n"
              f"    2. Start AES \n"
              f"    3. Avalanche Effect\n"
              f"    4. Start DES & AES (SPAC & SKAC) Experiment 1 to 10 bit change to CSV \n"
              f"    5. Exit \n")
        user_input = input("Type number and press enter: ")

        if user_input == "1":
            print("Starting DES.")
            plain_text_hex = input("Enter plain text (in hexadecimal): ")
            key_hex = input("Enter key (in hexadecimal): ")
            DES.start_des(plain_text_hex.lower(), key_hex.lower())
        elif user_input == "2":
            print("Starting AES.")
            plaintext_str = input("Enter plain text (in hexadecimal): ")
            plaintext = int(plaintext_str, 16)
            master_key = int(input("Enter key (in hexadecimal): "), 16)
            my_aes = aes.AES(master_key)

            data_aes = []
            aes_original = data_record.read_AES_original_to_csv()
            encrypted, data = my_aes.encrypt_modified_original(plaintext, plaintext_str, data_aes)
            # print(data)
            data_record.write_AES_original_to_csv(data)

        elif user_input == "3":
            print("Starting Avalanche Effect.")
            hex_string_1 = input("Enter hex string 1: ")
            hex_string_2 = input("Enter hex string 2: ")
            bit_by_bit_compare(hex_string_1, hex_string_2)
        elif user_input == "4":
            print("Starting Experiment.")
            DES.start_des_1_to_10_csv()
            save_aes_1_to_10_bits_change_csv()

        elif user_input == "5":
            print("Exiting Program.")
            break
        else:
            print("Invalid input, try again.")
            continue


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


def DES_SPAC_and_SKAC_bit_compare_check():
    print("SPAC 1 to 10 bit changes")
    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "12468aceeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13468aceeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13568aceeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13578aceeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13579aceeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13579bceeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13579bdeeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13579bdfeca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13579bdffca86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "02468aceeca86420"
    hex_string_2 = "13579bdffda86420"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    print("SKAC 1 to 10 bit changes")
    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1f1571c947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e1571c947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0571c947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0471c947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0461c947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0460c947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0460d947d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0460d847d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0460d857d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e859"
    hex_string_2 = "1e0460d856d9e859"
    bit_by_bit_compare(hex_string_1, hex_string_2)


def AES_SPAC_and_SKAC_bit_compare_check():
    print("SPAC 1 to 10 bit changes")
    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0023456789abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0033456789abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032456789abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032556789abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032546789abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032547789abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032547689abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032547699abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032547698abcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0123456789abcdeffedcba9876543210"
    hex_string_2 = "0032547698bbcdeffedcba9876543210"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    print("SKAC 1 to 10 bit changes")
    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e1571c947d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0571c947d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0471c947d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0461c947d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0460c947d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0460d947d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0460d957d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0460d956d9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0460d956c9e8590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)

    hex_string_1 = "0f1571c947d9e8590cb7add6af7f6798"
    hex_string_2 = "0e0460d956c9e9590cb7add6af7f6798"
    bit_by_bit_compare(hex_string_1, hex_string_2)


def save_aes_original_csv():
    master_key = int("0f1571c947d9e8590cb7add6af7f6798", 16)
    my_aes = aes.AES(master_key)

    plaintext_str = "0123456789abcdeffedcba9876543210"
    plaintext = int(plaintext_str, 16)

    data_aes = []
    original_aes = []
    encrypted, data = my_aes.encrypt_modified_original(plaintext, plaintext_str, data_aes)
    print(data)
    data_record.write_AES_original_to_csv(data)


def save_aes_1_to_10_bits_change_csv():
    # master_key = int("0f1571c947d9e8590cb7add6af7f6798", 16)
    # my_aes = AES.aes.AES(master_key)
    # plaintext_str = "0123456789abcdeffedcba9876543210"
    # plaintext = int(plaintext_str, 16)

    print("SPAC 1 to 10 bit changes")
    spac_1_to_10 = ["0023456789abcdeffedcba9876543210",
                    "0033456789abcdeffedcba9876543210",
                    "0032456789abcdeffedcba9876543210",
                    "0032556789abcdeffedcba9876543210",
                    "0032546789abcdeffedcba9876543210",
                    "0032547789abcdeffedcba9876543210",
                    "0032547689abcdeffedcba9876543210",
                    "0032547699abcdeffedcba9876543210",
                    "0032547698abcdeffedcba9876543210",
                    "0032547698bbcdeffedcba9876543210"]

    print("SKAC 1 to 10 bit changes")
    skac_1_to_10 = ["0e1571c947d9e8590cb7add6af7f6798",
                    "0e0571c947d9e8590cb7add6af7f6798",
                    "0e0471c947d9e8590cb7add6af7f6798",
                    "0e0461c947d9e8590cb7add6af7f6798",
                    "0e0460c947d9e8590cb7add6af7f6798",
                    "0e0460d947d9e8590cb7add6af7f6798",
                    "0e0460d957d9e8590cb7add6af7f6798",
                    "0e0460d956d9e8590cb7add6af7f6798",
                    "0e0460d956c9e8590cb7add6af7f6798",
                    "0e0460d956c9e9590cb7add6af7f6798"]


    for x in range(0, 10):
        master_key = int("0f1571c947d9e8590cb7add6af7f6798", 16)
        my_aes = aes.AES(master_key)
        plaintext_str = spac_1_to_10[x]
        plaintext = int(plaintext_str, 16)

        data_aes = []
        aes_original = data_record.read_AES_original_to_csv()
        encrypted, data = my_aes.encrypt_modified(plaintext, plaintext_str, data_aes, aes_original)
        print(data)
        data_record.write_to_csv_aes(data, f"AES_SPAC_{x+1}_bit_changed")

    for x in range(0, 10):
        master_key = int(skac_1_to_10[x], 16)
        my_aes = aes.AES(master_key)
        plaintext_str = "0123456789abcdeffedcba9876543210"
        plaintext = int(plaintext_str, 16)

        data_aes = []
        aes_original = data_record.read_AES_original_to_csv()
        encrypted, data = my_aes.encrypt_modified(plaintext, plaintext_str, data_aes, aes_original)
        print(data)
        data_record.write_to_csv_aes(data, f"AES_SKAC_{x+1}_bit_changed")


if __name__ == "__main__":

    # hex_string_1 = "da02ce3a89ecac3b"
    # hex_string_2 = "ee92b50606b62b0b"
    # bit_by_bit_compare(hex_string_1, hex_string_2)

    # DES_SPAC_and_SKAC_bit_compare_check()

    # master_key = int("0f1571c947d9e8590cb7add6af7f6798", 16)
    # my_aes = AES.aes.AES(master_key)
    #
    # plaintext_str = "0123456789abcdeffedcba9876543210"
    # plaintext = int(plaintext_str, 16)
    #
    # data_aes = []
    # original_aes = []
    # encrypted, data = my_aes.encrypt_modified(plaintext, plaintext_str, data_aes, original_aes)
    # print(data)
    # data_record.write_AES_original_to_csv(data)

    # save_aes_original_csv()
    # save_aes_1_to_10_bits_change_csv()
    # AES_SPAC_and_SKAC_bit_compare_check()
    # DES.start_des_1_to_10_csv()
    # exit()

    try:
        command_line_menu()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()


