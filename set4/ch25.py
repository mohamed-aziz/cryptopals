from set3 import form_nonce, aes_ctr_encrypt_decrypt
from Crypto.Util.strxor import strxor


def edit_ciphertext(ciphertext, key, offset, newtext):
    nonce = form_nonce(0)
    f = aes_ctr_encrypt_decrypt(ciphertext[:offset] + newtext
                            + ciphertext[offset + len(newtext):], key, nonce)[offset:offset+len(newtext)]
    return ciphertext[:offset] + f + ciphertext[offset + len(newtext):]


def break_edit_ciphertext(ciphertext, edit_func):
    result = edit_func(ciphertext, offset=0, newtext="\00" * len(ciphertext))
    return strxor(result, ciphertext)