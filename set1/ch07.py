from Crypto.Cipher import AES


def paddpkcs7(s, n):
    s = str(s)
    return s + ((n - len(s)) % n) * chr(n - len(s) % n)

def unpadpkcs7(s):
    i = ord(s[-1])
    return s[0:-i]

def aes_ecb_decrypt(cipher, key):
    aes = AES.new(key, AES.MODE_ECB, "\x00" * 16)
    return aes.decrypt(cipher)
