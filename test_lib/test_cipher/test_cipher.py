from aes import AES
import struct
import sys

def long_to_bytes(n, blocksize=0):

    if n < 0 or blocksize < 0:
        raise ValueError("Values must be non-negative")

    result = []
    pack = struct.pack

    # Fill the first block independently from the value of n
    bsr = blocksize
    while bsr >= 8:
        result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
        n = n >> 64
        bsr -= 8

    while bsr >= 4:
        result.insert(0, pack('>I', n & 0xFFFFFFFF))
        n = n >> 32
        bsr -= 4

    while bsr > 0:
        result.insert(0, pack('>B', n & 0xFF))
        n = n >> 8
        bsr -= 1

    if n == 0:
        if len(result) == 0:
            bresult = b'\x00'
        else:
            bresult = b''.join(result)
    else:
        # The encoded number exceeds the block size
        while n > 0:
            result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
            n = n >> 64
        result[0] = result[0].lstrip(b'\x00')
        bresult = b''.join(result)
        # bresult has minimum length here
        if blocksize > 0:
            target_len = ((len(bresult) - 1) // blocksize + 1) * blocksize
            bresult = b'\x00' * (target_len - len(bresult)) + bresult

    return bresult


def bytes_to_long(s):
    """Convert a byte string to a long integer (big endian).

    In Python 3.2+, use the native method instead::

        >>> int.from_bytes(s, 'big')

    For instance::

        >>> int.from_bytes(b'\x00P', 'big')
        80

    This is (essentially) the inverse of :func:`long_to_bytes`.
    """
    acc = 0

    unpack = struct.unpack

    # Up to Python 2.7.4, struct.unpack can't work with bytearrays nor
    # memoryviews
    if sys.version_info[0:3] < (2, 7, 4):
        if isinstance(s, bytearray):
            s = bytes(s)
        elif isinstance(s, memoryview):
            s = s.tobytes()

    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\x00' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc


def _copy_bytes(start, end, seq):
    """Return an immutable copy of a sequence (byte string, byte array, memoryview)
    in a certain interval [start:seq]"""

    if isinstance(seq, memoryview):
        return seq[start:end].tobytes()
    elif isinstance(seq, bytearray):
        return bytes(seq[start:end])
    else:
        return seq[start:end]

def divide_bytestring(data):
    block_size = 16
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    last_block = blocks[-1]
    if len(last_block) < block_size:
        last_block += b'\x00' * (block_size - len(last_block))
        blocks[-1] = last_block
    return blocks



class CbcMode(object):
    def __init__(self, key, iv):
        self.block_size = len(iv)
        """The block size of the underlying cipher, in bytes."""

        self.key = key

        self.iv = _copy_bytes(None, None, iv)
        """The Initialization Vector originally used to create the object.
        The value does not change."""

    def _xor(self, a, b):
        return bytes([x ^ y for x, y in zip(a, b)])

    def _pad(self, data):
        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _aes_encrypt(self, block, key):
        
        key = AES(bytes_to_long(key))
        cp = key.encrypt(bytes_to_long(block))
        return long_to_bytes(cp)

    def encrypt(self, data):
        data = self._pad(data)
        previous_block = self.iv
        ciphertext = b''
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            block = self._xor(block, previous_block)
            block = self._aes_encrypt(block, self.key)
            ciphertext += block
            previous_block = block
        return ciphertext


plaintext = b'This is a secret message.'
key = b'Sixteen byte key'
iv = b'Sixteen byte iv.'

cbc = CbcMode(key, iv)
ciphertext = cbc.encrypt(plaintext)
print(ciphertext)
