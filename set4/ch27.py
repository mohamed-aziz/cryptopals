from set2 import paddpkcs7, aes_cbc_encrypt, aes_cbc_decrypt
from set1 import unpadpkcs7
from set3 import get_block
from Crypto.Util.strxor import strxor


class Not7BitAscii(Exception):
    def __init__(self, *args, **kwargs):
        super(Not7BitAscii, self).__init__(*args, **kwargs)


def clean(t):
    return t.replace(';', '?').replace('=', '?')


def encryption_oracle(plaintext, key, blocksize=16):
    app = ";comment2=%20like%20a%20pound%20of%20bacon"
    prefix = "comment1=cooking%20MCs;userdata="
    plaintext = clean(plaintext)
    # check 7bit ascii
    iv = key
    return aes_cbc_encrypt(paddpkcs7(prefix + plaintext + app, blocksize),
                           key, iv)


def decryption_oracle(ciphertext, key, blocksize=16):
    iv = key
    blocks = aes_cbc_decrypt(ciphertext, key, iv)
    if not all(map(lambda x: x in range(0, 128), blocks)):
        raise Not7BitAscii(blocks)
    return unpadpkcs7(blocks)


def break_cbc_oracle(enc_oracle, dec_oracle, blocksize=16):
    # P1' = D(C1) ^ KEY
    # P2' = C1  ^ D(16*\00)
    # P3' = 16*\00 ^ D(C1)
    # P3' ^ P1' = KEY
    plaintext = "\x41"
    blocks = enc_oracle(plaintext=plaintext * blocksize * 3)
    ret = None
    try:
        first_block = get_block(blocks, 0, blocksize)
        dec_oracle(first_block + "\x00" * 16 + first_block)
    except Not7BitAscii as e:
        ret = e.message
    if ret:
        first_block = get_block(ret, 0, blocksize)
        third_block = get_block(ret, 2, blocksize)
        key = strxor(first_block, third_block)
        return key
