from Crypto import Random

from set3 import form_nonce, aes_ctr_encrypt_decrypt


def clean(t):
    return t.replace(';', '?').replace('=', '?')


def aes_ctr_encryption_oracle(plaintext, key, blocksize=16):
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    prefix = "comment1=cooking%20MCs;userdata="
    plaintext = clean(plaintext)
    iv = Random.new().read(blocksize)
    nonce = form_nonce(0)
    return aes_ctr_encrypt_decrypt(prefix + plaintext + suffix, key, nonce)


def aes_ctr_break_bitflipping(enc_oracle, dec_oracle):
    c = enc_oracle(";admin=true")
    d1 = chr(ord(c[32]) ^ ord('?') ^ ord(';'))
    d2 = chr(ord(c[38]) ^ ord('?') ^ ord('='))
    return dec_oracle(c[:32] + d1 + c[33:38] + d2 + c[39:])