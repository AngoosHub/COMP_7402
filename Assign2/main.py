#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 7402 - Cryptology
Assignment 2:
    - To design and implement an application that will generate a frequency count of all letters in a text file.
    The output is used to generate a graph of the relative distributions of the letters.
Student:
    - Hung Yu (Angus) Lin, A01034410
----------------------------------------------------------------------------------------------------
main.py
    - Contains command line UI for user input. Computes frequency count of letters for selected text file.
----------------------------------------------------------------------------------------------------
"""

from pathlib import Path
import csv


def command_line_menu():
    """
    Initializes command line menu to read user input.
    :return: None
    """

    print(f"====================================")
    user_input = input("Enter filename of text file for letter frequency count: ")
    text_file = read_text_file(user_input)
    # text_file = read_text_file("alice_in_wonderland.txt")
    # text_file2 = read_text_file("moby_dick.txt")


def read_text_file(filename):
    text_file = Path(filename)
    if not text_file.is_file():
        print(f'File was not found. Filename: {filename}')
        return

    if not filename.endswith('.txt'):
        print(f'File is not a ".txt" file. Filename: {filename}')
        return

    letter_freq = {}

    try:
        print(f"Filename: {filename}\n")
        with open(filename, 'r', encoding='utf-8') as my_file:
            while True:
                c = my_file.read(1)
                if not c:
                    break

                if c.isascii() and c.isalpha():
                    letter = c.lower()
                    letter_freq[letter] = letter_freq.get(letter, 0) + 1

    except FileNotFoundError as fnfe:
        print(f"File was not found. Error: {fnfe}")

    print(f"Frequency Count of Letters:")
    sorted_dict = dict(sorted(letter_freq.items(), key=lambda item: item[1], reverse=True))
    for key, value in sorted_dict.items():
        print(f"{key}: {value}")

    relative_distribution_dict = compute_frequency_count(sorted_dict)

    write_to_csv(sorted_dict, f"{filename}_freq")
    write_to_csv(sorted_dict, f"{filename}_dist")
    write_to_csv(relative_distribution_dict, f"{filename}_freq")
    write_to_csv(relative_distribution_dict, f"{filename}_dist")


def compute_frequency_count(dict):
    total_count = 0
    for key, value in dict.items():
        total_count += value

    relative_distribution_dict = {}
    probability_sum = 0

    for key, value in dict.items():
        relative_dist = value/total_count
        relative_distribution_dict[key] = relative_dist
        probability_sum += relative_dist

    probability_sum = round(probability_sum, 10)
    print("\nRelative Distribution of Letters:")
    for key, value in relative_distribution_dict.items():
        print(f"{key}: {round(value * 100, 4)} %")
    print(f"\nSum of Probabilities: {probability_sum}")

    return relative_distribution_dict


def write_to_csv(mydict, filename):
    with open(f'{filename}.csv', 'w', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        for key, value in mydict.items():
            writer.writerow([key, value])



if __name__ == "__main__":

    # alice_in_wonderland.txt
    # moby_dick.txt

    try:
        command_line_menu()
    except KeyboardInterrupt as e:
        print("Shutting Down.")
        exit()


