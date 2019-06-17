#!/usr/bin/env python

import unittest
from base64 import b64decode
from test import support
from set3 import produce_ciphertext, break_cbc_padding_oracle, cbc_padding_oracle, form_nonce, aes_ctr_encrypt_decrypt,\
    break_ctr_reused_nonce_substitutions, MT19937, break_mt19937_seeded_time, clone_mt19937,\
    mt19937_cipher_oracle, break_mt19937_cipher

from set2 import encryption_get_oracle_func, generate_random_key
from set1 import unpadpkcs7
from Crypto.Random import random


class Set3(unittest.TestCase):
    def test_ch17(self):
        key = generate_random_key()
        oracle = encryption_get_oracle_func(key, cbc_padding_oracle)

        lst = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", 
               "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
               "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
               "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
               "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
               "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
               "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
               "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
               "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
               "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

        for plaintext in lst:
            #test funcs
            ciphertext = produce_ciphertext(plaintext, key)
            self.assertTrue(oracle(ciphertext))

            self.assertEqual(unpadpkcs7(break_cbc_padding_oracle(oracle, ciphertext)), plaintext)

    def test_ch18(self):
        cipher = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        key = "YELLOW SUBMARINE"
        nonce = form_nonce(0)

        self.assertEqual(aes_ctr_encrypt_decrypt(cipher, key, nonce),
                         "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")

    def test_ch19(self):
        # this is a many time pad problem
        plaintexts = []
        ciphertexts = []

        key = generate_random_key(16)

        with open('static/19.txt', 'r') as myfile:
            for line in myfile.read().splitlines():
                plaintexts.append(b64decode(line))

        for plaintext in plaintexts:
            nonce = form_nonce(0)
            ciphertexts.append(aes_ctr_encrypt_decrypt(plaintext, key, nonce))

        break_ctr_reused_nonce_substitutions(ciphertexts)
        raise NotImplementedError

    def test_ch20(self):
        plaintexts = []
        ciphertexts = []

        key = generate_random_key(16)

        with open('static/19.txt', 'r') as myfile:
            for line in myfile.read().splitlines():
                plaintexts.append(b64decode(line))

        for plaintext in plaintexts:
            nonce = form_nonce(0)
            ciphertexts.append(aes_ctr_encrypt_decrypt(plaintext, key, nonce))

        raise NotImplementedError

    def test_ch21(self):
        obj = MT19937(1337)
        self.assertEqual(obj.extract_number(), 1125387415)

    def test_ch22(self):
        import time
        time.sleep(random.choice(range(1, 10)))

        time_now = int(time.time())
        orig_seed = time_now
        obj = MT19937(time_now)
        num = obj.extract_number()

        time.sleep(random.choice(range(1, 10)))

        i = break_mt19937_seeded_time(int(time.time()), num)
        self.assertEqual(i, orig_seed)

    def test_ch23(self):

        for randseed in [random.choice(range(100000)) for _ in range(10)]:
            obj = MT19937(randseed)
            numbers = []
            for i in range(624):
                f = obj.extract_number()
                numbers.append(f)
            obj2 = clone_mt19937(numbers)
            self.assertEqual(obj.extract_number(), obj2.extract_number())

    def test_ch24(self):
        randseed = random.choice(range(0xffff))
        plaintext = "A" * 14
        cipher = mt19937_cipher_oracle(plaintext, randseed)
        self.assertEqual(randseed, break_mt19937_cipher(cipher, plaintext))



if __name__ == "__main__":
    support.run_unittest(Set3)
