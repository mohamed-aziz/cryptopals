from set2 import aes_ecb_encrypt
import struct
from Crypto.Util.strxor import strxor
from set2 import split_blocks


def form_nonce(nonce):
    return struct.pack("<Q", nonce)


def aes_ctr_produce_blocks(nonce):
    # xrange doesn't support 64 bit numbers 
    for counter in xrange(2**32-1):
        yield nonce + struct.pack("<Q", counter)


def aes_ctr_encrypt_block(block, key):
    return aes_ecb_encrypt(block, key)


def aes_ctr_encrypt_decrypt(text, key, nonce):
    blocksize = len(key)
    ctr_block_gen = aes_ctr_produce_blocks(nonce)
    output = ""
    for block in split_blocks(text, blocksize):
        blk = next(ctr_block_gen)
        blk = aes_ctr_encrypt_block(blk, key)
        blk = blk[:len(block)]
        output += strxor(blk, block)

    return output
