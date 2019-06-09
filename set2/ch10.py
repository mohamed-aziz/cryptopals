from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from set1.ch07 import aes_ecb_decrypt


def split_blocks(cipher, keysize):
    return [cipher[i:i+keysize] for i in
            range(0, len(cipher), keysize)]


def aes_ecb_encrypt(cipher, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(cipher)


def aes_cbc_encrypt(cipher, key, iv="\x00" * 16):
    last_block = iv
    output = ""
    for block in split_blocks(cipher, len(key)):
        last_block = aes_ecb_encrypt(strxor(last_block, block), key)
        output += last_block
    return output


def aes_cbc_decrypt(cipher, key, iv="\x00" * 16):
    last_block = iv
    output = ""

    for block in split_blocks(cipher, len(key)):
        output += strxor(aes_ecb_decrypt(block, key), last_block)
        last_block = block
    return output
