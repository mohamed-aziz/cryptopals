import unittest
from test import support

from set1 import aes_ecb_decrypt, unpadpkcs7
from set2 import generate_random_key
from set3 import form_nonce, aes_ctr_encrypt_decrypt
from set4 import edit_ciphertext, break_edit_ciphertext, aes_ctr_break_bitflipping, aes_ctr_encryption_oracle, encryption_oracle, Not7BitAscii, decryption_oracle, break_cbc_oracle
from base64 import b64decode
from functools import partial


class Set4(unittest.TestCase):
    def test_ch25(self):
        key = generate_random_key(16)
        with open('static/25.txt', 'r') as myfile:
            cipher = b64decode(myfile.read())
        plaintext = unpadpkcs7(aes_ecb_decrypt(cipher, "YELLOW SUBMARINE"))
        nonce = form_nonce(0)

        ciphertext = aes_ctr_encrypt_decrypt(plaintext, key, nonce)

        edit_func = partial(edit_ciphertext, key=key)
        # test edit_ciphertext function
        result = edit_ciphertext(ciphertext, key, 32, "YELLOW")
        self.assertEquals(result, aes_ctr_encrypt_decrypt(plaintext[:32] + "YELLOW" + plaintext[38:], key, nonce))

        # break it
        self.assertEquals(break_edit_ciphertext(ciphertext, edit_func), plaintext)

    def test_ch26(self):

        key = generate_random_key()

        dec_oracle = partial(aes_ctr_encrypt_decrypt, key=key, nonce=form_nonce(0))
        enc_oracle = partial(aes_ctr_encryption_oracle, key=key, blocksize=16)

        self.assertIn("admin=true", aes_ctr_break_bitflipping(enc_oracle, dec_oracle))

    def test_ch27(self):
        key = generate_random_key(16)
        enc_oracle = partial(encryption_oracle, key=key, blocksize=16)
        dec_oracle = partial(decryption_oracle, key=key, blocksize=16)

        recovered_key = break_cbc_oracle(enc_oracle, dec_oracle)
        self.assertEquals(recovered_key, key)


if __name__ == "__main__":
    support.run_unittest(Set4)
