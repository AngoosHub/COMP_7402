#!/usr/bin/python3.5

"""
Credits:
Author - Aman Abdulla
"""



# Caesar Cipher brute force cryptanalysis

import sys, getopt

# Symbol alphabet
ALPHABET = 'abcdefghijklmnopqrstuvwxyz'

def main (argv):
    
    try:
        opts, args = getopt.getopt (argv, "hc:",["cipher="])
    
    except getopt.getoptError:
        sys.exit (1)
    
    if len (sys.argv[1:]) < 2:
        print ('Usage: ./brkcaesar.py -c <cipher text>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('Usage: ./brkcaesar.py -c <cipher text>')
            sys.exit ()
        elif opt in ("-c", "--cipher"):
            message = arg
                
    # convert chars to lower case and call the cryptanalysis function
    message = message.lower()
    BreakCipher (message)



def BreakCipher (message):

    # Iterate through every possible key
    for key in range(len(ALPHABET)):

        # Initialize the ciphertext variable
        translated = ''

        # run the decryption code on each symbol in the message
        for symbol in message:
            if symbol in ALPHABET:
                num = ALPHABET.find(symbol) # get the index value of the symbol
                num -= key

                # Wrap-around if num is larger than the length of the symbol alphabet or less than 0
                if num < 0:
                    num += len(ALPHABET)

                # add encrypted/decrypted symbol to the end of translated string
                translated += ALPHABET[num]

            else:
                 # character is not part of the symbol alphabet
                translated += symbol

        # print current key value and the decrypted string
        print('Key #%s: %s' % (key, translated))


if __name__ == "__main__":
    main (sys.argv[1:])
