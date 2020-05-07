#!/usr/bin/python
# -*- coding: utf8 -*-

import random
import string
import base64


class Client:
    """ Simple implementation of a C2 client acting as a DNS requester that receives
    information via a DKIM records.

        :param c2s_ip: C2 server IP address
        :param target_domain: Domain to ask for
    """

    ASCII_VALUE_CHAR = {x:chr(x) for x in range(0,128)}

    def __init__(self, c2s_ip: str, target_domain: str):
        self.c2s_ip = c2s_ip
        self.target_domain = target_domain

    @property
    def port(self, p):
        return self._port

    @port.setter
    def port(self, v):
        self._port = v

        # Assert port value
        assert 1 <= v <= 65535

    @staticmethod
    def decode(pk: str) -> (None, str):
        """ Applies the algorithm described in the repository to decipher and decode a given Public Key
        from the DNS DKIM TXT record.

        :param pk: Public decodable key
        :return: Public key
        """

        # Decode from base64
        pk = base64.b64decode(pk).decode('utf8')

        # Function number is the reversed de-hexed value from the first two characters
        function_number = int(pk[0:2][::-1], 16)
        # The separator character is the ascii value of the third and forth ascii values combined
        separator = Client.ASCII_VALUE_CHAR[ord(pk[2]) + ord(pk[3])]
        # Evaluable_length are the fifth and sixth ascii values combined
        evaluable_length = ord(pk[4]) + ord(pk[5])
        # Calculate the number of characters to decrypt
        to_decrypt = pk[7:7+evaluable_length]
        # The key is the rest of the characters
        key = pk[7+evaluable_length:]

        print('[+] Function number:{}'.format(function_number))
        print("[+] Separator: {}".format(separator))
        print('[+] Evaluable information length: {}'.format(evaluable_length))
        print('[+] Key:{}'.format(repr(key)))

        # If length of the key is greater that the text to decrypt
        if len(key) > len(to_decrypt):
            # Get only the needd length
            aux = key[0:len(to_decrypt)]
        # If key is shorter, take the key as many times as needed plus the characters to fill the decryption text
        elif len(to_decrypt) > len(key):
            number_of_repetitions = len(to_decrypt) // len(key)
            number_of_partial_repetitions = len(to_decrypt) % len(key)
            aux = key * number_of_repetitions + key[0:number_of_partial_repetitions]
        else:
            # If equal, leave the key as such
            aux = key

        # XOR decrypt
        decrypted_text = ''.join([chr(ord(a) ^ ord(b)) for (a,b) in zip(to_decrypt, aux)])

        # Split by the separator (There should only be used as a separator, other characters included on the
        # parameters themselves are excluded.
        params = decrypted_text.split(separator)

        print('{} params:\n-{}'.format(len(params),'\n-'.join(params)))

 
if __name__ == '__main__':
    c = Client('127.0.0.1', 'example.com')
    c.decode('MTADJRIVKHYNZRkcd2kvWl4vXxA7SisGbgVTGE4rGS5KVTZ+U1VdCglWOCw2BD5oCXVzVz5AKDJLfjhyakprTnUhcSBfcEAtdUIJPHUufns/VktFJUgJIXNJQiVebn4ufHRVUW1NSUNLXzYLOSYxWl5mIXJnZHJ+Ny8yY2RGRQ0=')
