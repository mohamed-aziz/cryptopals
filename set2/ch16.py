from set2 import paddpkcs7, aes_cbc_encrypt, aes_cbc_decrypt
from set1 import unpadpkcs7
from Crypto import Random 


def clean(t):
    return t.replace(';', '?').replace('=', '?')


def encryption_oracle(plaintext, key, blocksize=16):
    app = ";comment2=%20like%20a%20pound%20of%20bacon"
    prefix = "comment1=cooking%20MCs;userdata="
    plaintext = clean(plaintext)
    iv = Random.new().read(blocksize)
    return iv + aes_cbc_encrypt(paddpkcs7(prefix + plaintext + app, blocksize),
                                key, iv)


def decryption_oracle(ciphertext, key, blocksize=16):
    iv = ciphertext[:blocksize]
    return unpadpkcs7(aes_cbc_decrypt(ciphertext[blocksize:], key, iv))


def break_cbc_oracle(enc_oracle, dec_oracle, blocksize=16):
    g = enc_oracle(";admin=true;")
    iv, c = g[:blocksize], g[blocksize:]

    d1 = ord('?') ^ ord(";") ^ ord(c[blocksize])
    d2 = ord('?') ^ ord("=") ^ ord(c[blocksize+6])
    d3 = ord('?') ^ ord(";") ^ ord(c[blocksize+11])

    nc = c[:blocksize] + chr(d1) + c[blocksize+1:blocksize+6] \
        + chr(d2) + c[blocksize+7:blocksize+11] + chr(d3) + c[blocksize+12:]

    return dec_oracle(iv + nc)
