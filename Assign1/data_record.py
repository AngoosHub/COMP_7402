"""
----------------------------------------------------------------------------------------------------
COMP 7402 - Cryptology
Assignment 1:
    - To learn how to analyze the strength of a cipher by analyzing its Confusion and Diffusion
    characteristics using the Avalanche effect for SPAC and SKAC conditions in DES and AES ciphers.
Student:
    - Hung Yu (Angus) Lin, A01034410
----------------------------------------------------------------------------------------------------
data_record.py
    - Contains utility functions for reading and writing to csv files.
----------------------------------------------------------------------------------------------------
"""


import csv


def read_DES_original_to_csv():
    with open(f'DES_original_pt_and_key.csv', 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        # rows = list(csv_reader)
        data_list = []

        # Iterate through each row in the CSV file
        for row in csv_reader:
            # Append each row (as a dictionary) to the list
            data_list.append(row)
        return data_list


def read_AES_original_to_csv():
    with open(f'AES_original_pt_and_key.csv', 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        # rows = list(csv_reader)
        data_list = []

        # Iterate through each row in the CSV file
        for row in csv_reader:
            # Append each row (as a dictionary) to the list
            data_list.append(row)
        return data_list


def write_DES_original_to_csv(data):
    with open(f'DES_original_pt_and_key.csv', 'w') as csv_file:
        fieldnames = ['Round', 'Hexadecimal Comparison', 'Round Key', 'Bits Difference (Size 64)']
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=',')
        csv_writer.writeheader()
        csv_writer.writerows(data)


def write_AES_original_to_csv(data):
    with open(f'AES_original_pt_and_key.csv', 'w') as csv_file:
        fieldnames = ['Round', 'Hexadecimal Comparison', 'Round Key', 'Bits Difference (Size 128)']
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=',')
        csv_writer.writeheader()
        csv_writer.writerows(data)


def write_to_csv(data, name):
    with open(f'{name}.csv', 'w') as csv_file:
        fieldnames = ['Round', 'Hexadecimal Comparison', 'Round Key',
                      'Bits Difference (Size 64)']
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=',')
        csv_writer.writeheader()
        csv_writer.writerows(data)


def write_to_csv_aes(data, name):
    with open(f'{name}.csv', 'w') as csv_file:
        fieldnames = ['Round', 'Hexadecimal Comparison', 'Round Key',
                      'Bits Difference (Size 128)']
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=',')
        csv_writer.writeheader()
        csv_writer.writerows(data)
