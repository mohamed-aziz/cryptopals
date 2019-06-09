from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Random import random
from Crypto import Random
from set2.ch10 import aes_cbc_encrypt, aes_ecb_encrypt
from set1.ch07 import paddpkcs7
from functools import partial

AES_CBC_MODE = 0
AES_ECB_MODE = 1


def generate_random_key(keysize=16):
    return Random.new().read(keysize)


def encryption_oracle(cleartext, key):
    choice = random.choice([AES_ECB_MODE, AES_CBC_MODE])
    if choice == AES_ECB_MODE:
        func = lambda x: aes_ecb_encrypt(x, key)
    else:
        IV = Random.new().read(16)
        func = lambda x: aes_cbc_encrypt(x, key, IV)
    return func(paddpkcs7(Random.new().read(random.choice(range(5, 11))) +
                          cleartext + Random.new().read(random.choice(range(5, 11))), 16)), choice


def encryption_get_oracle_func(key, oracle_func):
    """
    Return partially applied oracle
    """
    # return lambda x: oracle_func(x, key)
    return partial(oracle_func, key=key)


def check_block_mode(oracle=encryption_oracle):
    out, result = oracle("\xff" * 48)
    if out[16:32] == out[32:48]:
        return AES_ECB_MODE, result
    else:
        return AES_CBC_MODE, result


def check_block_mode_decoupled(oracle=encryption_oracle):
    """
    Lame but I need the ret value of the other one
    """
    out = oracle("\xff" * 48)
    if out[16:32] == out[32:48]:
        return AES_ECB_MODE
    else:
        return AES_CBC_MODE
