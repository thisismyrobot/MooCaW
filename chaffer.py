import hashlib
import secrets


class Chaffer():

    def __init__(self, authentication_key, mac_algorithm = 'sha512'):
        self._authentication_key = authentication_key
        self._mac_algorithm = mac_algorithm

    def authenticate(self, serial, message):
        h = hashlib.new(self._mac_algorithm)
        h.update(f'{serial}{message}{self._authentication_key}'.encode())
        return h

    def chaff(self, serial, count, mac_bytes):
        chaff = []
        for i in range(count):
            chaff.append((serial, secrets.randbits(1), secrets.token_hex(mac_bytes)))
        return chaff
