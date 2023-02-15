from multiprocessing.managers import SharedMemoryManager
from aes import AES, long_to_bytes, bytes_to_long, _copy_bytes
from binascii import hexlify, unhexlify
import binascii
import time
import os


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
        self.padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes(chr(48) * self.padding_length, encoding = 'UTF - 8')
        return data + padding

    def _unpad(self, data):
        padding_length = self.padding_length
        return data[:-padding_length]

    def _aes_encrypt(self, block):
        key = AES(self.key)
        cp = key.encrypt(block)
        return cp

    def _aes_decrypt(self, block):
        key = AES(self.key)
        pt = key.decrypt(block)
        return pt

    def encrypt(self, data):
        data = self._pad(data)
        previous_block = self.iv
        ciphertext = b''
        for i in range(0, len(data), self.block_size):
            #print(len(ciphertext), ciphertext)
            block = data[i:i + self.block_size]
            block = self._xor(block, previous_block)
            block = self._aes_encrypt(block)
            ciphertext += block
            previous_block = block
        return ciphertext

    def decrypt(self, data):
        previous_block = self.iv
        plaintext = b''
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            block = self._aes_decrypt(block)
            block = self._xor(block, previous_block)
            plaintext += block
            previous_block = data[i:i + self.block_size]
        return self._unpad(plaintext)
        #return plaintext


plaintext = b'nguyen minh quan \n dai hoc bach khoa ha noi'
key = b'Sixteen byte key'
iv = b'Sixteen byte iv.'
cbc = CbcMode(key, iv)
ciphertext = cbc.encrypt(plaintext)
print('input:', plaintext, len(plaintext), '\n\n')
print(ciphertext, len(ciphertext), '\n\n')

pt = cbc.decrypt(ciphertext)
print('output:', pt, len(pt))


'''                                           
timestamp = str(int(time.time()))
salt = os.urandom(16) # generate a random 16-byte salt value
salted_input = salt + timestamp.encode()


shared_key_A = b'12345'
shared_key_B = b'12345'
assert shared_key_A == shared_key_B
master_key = shared_key_A

session_key = salted_input + master_key
print(session_key)
'''
