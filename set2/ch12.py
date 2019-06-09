from set2 import aes_ecb_encrypt
from set1 import paddpkcs7
from string import printable
import base64


def encryption_oracle(plaintext, key):    
    buff = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK"
    return aes_ecb_encrypt(paddpkcs7(plaintext + base64.b64decode(buff), 16), key)


def guess_block_size(oracle):
    """
    Only works for ecb mode
    """
    prevblock = None

    for i in range(2, 40):
        block = oracle("\xff" * i)[:i]
        if prevblock:
            if block[:i-1] == prevblock:
                return len(block) - 1
        prevblock = block

    raise Exception


def break_ecb_oracle(oracle, blocksize, prefix="", startindex=0):
    found = ""
    bl = startindex // blocksize
    while 1:
        lookup = {}
        bts = prefix + "A" * ((blocksize - (len(found) % blocksize)) - 1)
        for c in printable:
            lookup[oracle(bts + found + c)[startindex:blocksize * (len(found) // blocksize+1+bl)]] = c
        try:
            found += lookup[oracle(bts)[startindex:blocksize * (len(found) // blocksize+1+bl)]]
        except KeyError:
            break
    return found
