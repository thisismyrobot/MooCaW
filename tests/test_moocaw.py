import decode
import encode

import secrets


def test_simple_round_trip(monkeypatch):
    monkeypatch.setattr(secrets, 'randbits', lambda b: 1)
    monkeypatch.setattr(secrets, 'token_hex', lambda c: 'ffffffffffffff000000000000000000')
    monkeypatch.setattr(secrets.SystemRandom, 'shuffle', lambda a, b: b)

    key = '1234'
    multiplier = 2
    algorithm = 'md5'
    message = 'hi'
    encoder = encode.Encoder(key, multiplier, algorithm)

    chaffed_message = list(encoder.encode(message))

    assert len(chaffed_message) == len(message) * 8 * (multiplier + 1)
    assert chaffed_message == [
        (0, 1, 'ffffffffffffff000000000000000000'),
        (0, 1, 'ffffffffffffff000000000000000000'),
        (0, 0, '91d5181d621bd9838b00655d29f0577d'),
        (1, 1, 'ffffffffffffff000000000000000000'),
        (1, 1, 'ffffffffffffff000000000000000000'),
        (1, 1, 'd763c394f6a9c868ce44dcf4ddd253f0'),
        (2, 1, 'ffffffffffffff000000000000000000'),
        (2, 1, 'ffffffffffffff000000000000000000'),
        (2, 1, '0502e9fbb792b9914718d5dab3045300'),
        (3, 1, 'ffffffffffffff000000000000000000'),
        (3, 1, 'ffffffffffffff000000000000000000'),
        (3, 0, '3364fcbbccca0b3888fd7721993e19f0'),
        (4, 1, 'ffffffffffffff000000000000000000'),
        (4, 1, 'ffffffffffffff000000000000000000'),
        (4, 1, '9702a69fbbba281f432f188ff5a23cb2'),
        (5, 1, 'ffffffffffffff000000000000000000'),
        (5, 1, 'ffffffffffffff000000000000000000'),
        (5, 0, '5940841806a304e15a8e3277950aefe4'),
        (6, 1, 'ffffffffffffff000000000000000000'),
        (6, 1, 'ffffffffffffff000000000000000000'),
        (6, 0, '38936ed9e6d2b4aa2a79c3726e9bc411'),
        (7, 1, 'ffffffffffffff000000000000000000'),
        (7, 1, 'ffffffffffffff000000000000000000'),
        (7, 0, '7fb48aa12e0b29169dcbe3b6e74e60f3'),
        (8, 1, 'ffffffffffffff000000000000000000'),
        (8, 1, 'ffffffffffffff000000000000000000'),
        (8, 0, 'e242cb97d9de6b4358ca61182e9c9af4'),
        (9, 1, 'ffffffffffffff000000000000000000'),
        (9, 1, 'ffffffffffffff000000000000000000'),
        (9, 1, 'b35a76fc7552acb2f6ed1a60ad88c0cc'),
        (10, 1, 'ffffffffffffff000000000000000000'),
        (10, 1, 'ffffffffffffff000000000000000000'),
        (10, 1, 'c927adbb36ca029c7ea7b688a2c58e0e'),
        (11, 1, 'ffffffffffffff000000000000000000'),
        (11, 1, 'ffffffffffffff000000000000000000'),
        (11, 0, '7c79ad2eb1a7d6cde23bf6e65e1dae2e'),
        (12, 1, 'ffffffffffffff000000000000000000'),
        (12, 1, 'ffffffffffffff000000000000000000'),
        (12, 1, '3017f76d2b9530d8f1c1e54c5952c054'),
        (13, 1, 'ffffffffffffff000000000000000000'),
        (13, 1, 'ffffffffffffff000000000000000000'),
        (13, 0, '732fcb3687df2c3d1c9961889b7d49c9'),
        (14, 1, 'ffffffffffffff000000000000000000'),
        (14, 1, 'ffffffffffffff000000000000000000'),
        (14, 0, 'fd1ef060f50266e66c301891d0ee7a19'),
        (15, 1, 'ffffffffffffff000000000000000000'),
        (15, 1, 'ffffffffffffff000000000000000000'),
        (15, 1, 'abbd4fc3f2d54cda3cc286e1ef96e440'),
    ]

    decoder = decode.Decoder(key, algorithm)

    decoded_message = ''
    byte = ''
    for serial, bit, mac in chaffed_message:
        serial = str(serial)
        bit = str(bit)
        if decoder.authentic(serial, bit, mac):
            byte += bit
            if len(byte) == 8:
                decoded_message += chr(int(byte, 2))
                byte = ''

    assert decoded_message == message
