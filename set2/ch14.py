from set2 import aes_ecb_encrypt
from set1 import paddpkcs7
import base64


def encryption_oracle(plaintext, key, randomdata):
    buff = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK"
    return aes_ecb_encrypt(
        paddpkcs7(randomdata + plaintext + base64.b64decode(buff), 16), key)


def get_random_data_length(oracle, blocksize=16):
    randlen = 0
    bl = 0
    for i in range(2, 100):
        block = oracle("\xff" * i)
        # check 10 consecutive blocks
        for j in range(1, 11):
            if 16*(j+2) > len(block):
                break
            if block[16*j:16*(j+1)] == block[16*(j+1):16*(j+2)]:
                randlen = i
                bl = j
                break
        if randlen:
            break
    return (blocksize * bl - randlen - blocksize * bl * 2)\
        % (blocksize * bl) or blocksize * bl
