import argparse
import sys

import chaffer


class Decoder():

    def __init__(self, key, mac_algorithm):
        self._serial = 0
        self._chaffer = chaffer.Chaffer(key, mac_algorithm)

    def authentic(self, serial, bit, mac):
        actual_mac = self._chaffer.authenticate(serial, bit)
        return mac == actual_mac.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decode text with MooCaW.')
    parser.add_argument('key', metavar='S', help='Secret key')
    parser.add_argument('--algorithm', metavar='A', default='sha512', help='Python hashlib algorithm')
    args = parser.parse_args()

    decoder = Decoder(args.key, args.algorithm)

    byte = ''
    for line in sys.stdin:
        serial, bit, mac = map(str.strip, line.split(','))
        if decoder.authentic(serial, bit, mac):
            byte += bit
            if len(byte) == 8:
                print(chr(int(byte, 2)), end='')
                byte = ''
