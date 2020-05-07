#!/user/bin/python
# -*- coding: utf8 -*-

import sys
from server import Server
from client import Client


def main():
    print('===============')
    print('SERVER')
    print('===============')
    s = Server('example.com')
    msg = s.encode(1, 'Hello World!', 'I am printing two strings!')
    if msg is None:
        sys.exit(-1)
    print('===============')
    print('CLIENT')
    print('===============')
    c = Client('127.0.0.1', 'example.com')
    c.decode(msg)


if __name__ == '__main__':
    main()