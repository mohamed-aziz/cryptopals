from set2 import aes_cbc_decrypt, aes_cbc_encrypt, paddpkcs7, validatepkcs7, split_blocks
from set1 import unpadpkcs7
from Crypto import Random
from Crypto.Util.strxor import strxor
import binascii

def get_block(text, block, blocksize):
    return split_blocks(text, blocksize)[block]


def produce_ciphertext(plaintext, key):
    blocksize = len(key)
    iv = Random.new().read(blocksize)
    return iv + aes_cbc_encrypt(paddpkcs7(plaintext, blocksize), key, iv)


def cbc_padding_oracle(ciphertext, key):
    blocksize = len(key)
    iv = ciphertext[:blocksize]
    return validatepkcs7(aes_cbc_decrypt(ciphertext[blocksize:], key, iv))


def break_cbc_padding_oracle(oracle, ciphertext, blocksize=16):
    plaintext_block = ""
    plaintext = ""
    prefix = ""
    for block_counter in range(1, len(split_blocks(ciphertext, blocksize))):
        current_block = get_block(ciphertext, block_counter, blocksize)
        last_block    = get_block(ciphertext, block_counter-1, blocksize)
        for j in range(blocksize-1, -1, -1):
            for i in range(255)[::-1]:
                guessed_block = strxor(last_block,
                                       ("\x00" * j) + chr(i) + strxor(plaintext_block, (chr((blocksize - j)))*len(plaintext_block)))
                if oracle(prefix + guessed_block + current_block):
                    plaintext_block = chr(i ^ (blocksize - j)) + plaintext_block
                    break
        plaintext += plaintext_block
        plaintext_block = ""
        prefix += last_block
    return plaintext
