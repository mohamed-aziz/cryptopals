#!/usr/bin/env python

import unittest
from base64 import b64decode
from test import support
from set3 import produce_ciphertext, break_cbc_padding_oracle, cbc_padding_oracle
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

if __name__ == "__main__":
    support.run_unittest(Set3)
