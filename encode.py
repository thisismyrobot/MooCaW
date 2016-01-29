import argparse
import secrets
import sys

import chaffer


class Encoder():

    def __init__(self, key, multiplier, mac_algorithm):
        self._serial = 0
        self._chaffer = chaffer.Chaffer(key, mac_algorithm)
        self._multiplier = multiplier

    def encode(self, message):
        for bit in bits(message):
            mac = self._chaffer.authenticate(self._serial, bit)

            signed_message = (self._serial, bit, mac.hexdigest())
            chaff = self._chaffer.chaff(self._serial, self._multiplier, len(mac.digest()))
            chaff.append(signed_message)
            secrets.SystemRandom().shuffle(chaff)
            for c in chaff:
                yield c

            self._serial += 1


def bits(message):
    for char in message:
        for bit in map(int, '{:08b}'.format(ord(char))):
            yield bit


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Encode text with MooCaW.')
    parser.add_argument('key', metavar='S', help='Secret key')
    parser.add_argument('--multiplier', metavar='M', default=10, help='Chaff multiplier')
    parser.add_argument('--algorithm', metavar='A', default='sha512', help='Python hashlib algorithm')
    args = parser.parse_args()

    encoder = Encoder(args.key, int(args.multiplier), args.algorithm)

    for line in sys.stdin:
        for result in encoder.encode(line):
            print(','.join(map(str, result)))
