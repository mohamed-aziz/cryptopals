import urlparse
from collections import OrderedDict
from set2 import aes_ecb_encrypt, paddpkcs7, aes_ecb_decrypt
from set1 import unpadpkcs7


def key_value_parse(s):
    d = {}
    for k, v in urlparse.parse_qs(s).items():
        d[k] = v[0]
    return d


def profile_for(email):
    email = email.replace('=', '').replace('&', '')
    d = OrderedDict()
    d['email'] = email
    d['uid'] = '10'
    d['role'] = 'user'
    return '&'.join(map(lambda x: x[0] + '=' + x[1], d.items()))


def encryption_oracle(cleartext, key):
    return aes_ecb_encrypt(paddpkcs7(profile_for(cleartext), 16), key)


def decryption_oracle(cipher, key):
    return key_value_parse(unpadpkcs7(aes_ecb_decrypt(cipher, key)))


def cut_and_paste_attack(email, enc_oracle, dec_oracle):
    # encrypted("email=someemail.com&uid=10&role=") + encrypted("admin" + padding)
    first_part = enc_oracle(email)[:48]
    second_part = enc_oracle("AAAABBBBCC" + "admin" + '\x0b' * 0x0b)[16:32]

    ciphertext = first_part + second_part
    return dec_oracle(ciphertext)
