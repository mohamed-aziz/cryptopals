from set3 import MT19937
from Crypto.Util.strxor import strxor
from Crypto.Random import random
from Crypto.Util.number import long_to_bytes


class MT19937Cipher(MT19937):

    def __init__(self, seed):
        super(MT19937Cipher, self).__init__(seed & 0xffff)

    def gen_8_bit_val(self):
        return self.extract_number() & 0xff


def mt19937_cipher_oracle(ciphertext, key):
    obj = MT19937Cipher(key)
    randlen = random.choice(range(10))
    ciphertext += long_to_bytes(random.getrandbits(randlen * 8))
    s = ""
    for i in range(len(ciphertext)):
        s += long_to_bytes(obj.gen_8_bit_val())
    return strxor(s, ciphertext)


def break_mt19937_cipher(ciphertext, plaintext):
    for i in range(0xffff):
        obj = MT19937Cipher(i)
        s =""
        for _ in range(len(ciphertext)):
            s += long_to_bytes(obj.gen_8_bit_val())
        if plaintext in strxor(s, ciphertext):
            return i