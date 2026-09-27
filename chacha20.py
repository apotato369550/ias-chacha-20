"""Small, pure-Python implementation of the original ChaCha20 design.

This version uses a 32-byte key, an 8-byte nonce, and a 64-bit block counter.
It follows the layout used by references/chacha20.py.
"""

import struct


KEY_SIZE = 32
NONCE_SIZE = 8
BLOCK_SIZE = 64
MASK = 0xFFFFFFFF


def _rotate_left(value, bits):
    return ((value << bits) & MASK) | (value >> (32 - bits))


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & MASK
    state[d] = _rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK
    state[d] = _rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotate_left(state[b] ^ state[c], 7)


def _block(key, nonce, counter):
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants))
    state += list(struct.unpack("<8I", key))
    state += [counter & MASK, (counter >> 32) & MASK]
    state += list(struct.unpack("<2I", nonce))

    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    return struct.pack(
        "<16I", *( (working[i] + state[i]) & MASK for i in range(16) )
    )


def _check_inputs(key, nonce):
    if len(key) != KEY_SIZE:
        raise ValueError("key must be exactly 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be exactly 8 bytes")


def crypt(message, key, nonce, counter=0):
    """Encrypt or decrypt bytes with ChaCha20.

    ChaCha20 is a stream cipher, so the same operation does both jobs:
    applying it twice with the same key and nonce returns the original data.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    _check_inputs(key, nonce)
    if not 0 <= counter <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("counter must fit in 64 bits")

    result = bytearray()
    for block_start in range(0, len(message), BLOCK_SIZE):
        block = message[block_start:block_start + BLOCK_SIZE]
        keystream = _block(key, nonce, counter)
        result.extend(a ^ b for a, b in zip(block, keystream))
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF
    return bytes(result)


def encrypt(message, key, nonce):
    return crypt(message, key, nonce)


def decrypt(message, key, nonce):
    return crypt(message, key, nonce)
