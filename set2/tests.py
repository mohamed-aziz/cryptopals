#!/usr/bin/env python

from ch09 import paddpkcs7
from ch10 import aes_cbc_decrypt
from test import support
from base64 import b64decode
from set1.tests import Set1
from set1 import unpadpkcs7
from set2 import encryption_oracle1, generate_random_key, AES_ECB_MODE,\
    AES_CBC_MODE, check_block_mode, guess_block_size, encryption_get_oracle_func,\
    check_block_mode_decoupled, encryption_oracle1, encryption_oracle2, break_ecb_oracle,\
    encryption_oracle13, decryption_oracle13, cut_and_paste_attack, encryption_oracle14,\
    get_random_data_length, validatepkcs7, decryption_oracle16, encryption_oracle16,\
    break_cbc_oracle
from functools import partial
import unittest
from Crypto import Random
from Crypto.Random import random


class Set2(unittest.TestCase):
    poem = Set1.poem

    def test_ch9(self):
        result = paddpkcs7("YELLOW SUBMARINE", 20)
        self.assertEqual(result, "YELLOW SUBMARINE\x04\x04\x04\x04")
        result = paddpkcs7("YELLOW SUBMARINE", 16)
        self.assertEqual(result, "YELLOW SUBMARINE" + "\x10" * 16)

    def test_ch10(self):
        with open("static/10.txt", "r") as myfile:
            cipher = b64decode(myfile.read())
        key = "YELLOW SUBMARINE"
        self.assertEqual(unpadpkcs7(aes_cbc_decrypt(cipher, key)), self.poem)

    def test_ch11(self):
        key = generate_random_key()
        oracle = encryption_get_oracle_func(key, encryption_oracle1)
        for _ in range(20):
            result, correct_result = check_block_mode(oracle)
            self.assertEqual(result, correct_result)

    def test_ch12(self):
        cleartext = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK")
        key = generate_random_key()
        oracle = encryption_get_oracle_func(key, encryption_oracle2)

        mode = check_block_mode_decoupled(oracle)
        self.assertEqual(mode, AES_ECB_MODE)

        block_size = guess_block_size(oracle)
        self.assertEqual(16, block_size)

        self.assertEqual(break_ecb_oracle(oracle, block_size), cleartext)

    def test_ch13(self):
        key = generate_random_key()
        dec_oracle = encryption_get_oracle_func(key, decryption_oracle13)
        enc_oracle = encryption_get_oracle_func(key, encryption_oracle13)

        obj = cut_and_paste_attack("abcdabcdefsomeone10@gmail.com", enc_oracle, dec_oracle)
        self.assertEqual("admin", obj["role"])

    def test_ch14(self):
        cleartext = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK")
        key = generate_random_key()
        block_size = len(key)
        randomdata = Random.new().read(random.choice(range(1, 31)))
        oracle = partial(encryption_get_oracle_func(key, encryption_oracle14), randomdata=randomdata)
        self.assertEqual(len(randomdata), get_random_data_length(oracle))

        filling_text = (block_size - (len(randomdata) % block_size)) * "A"

        out = break_ecb_oracle(oracle, block_size, filling_text,
                               startindex=len(filling_text)+len(randomdata))

        self.assertEqual(out, cleartext)

    def test_ch15(self):
        self.assertTrue(validatepkcs7("ICE ICE BABY\x04\x04\x04\x04"))
        self.assertFalse(validatepkcs7("ICE ICE BABY\x05\x05\x05\x05"))
        self.assertFalse(validatepkcs7("ICE ICE BABY\x01\x02\x03\x04"))

    def test_ch16(self):
        key = generate_random_key()

        dec_oracle = encryption_get_oracle_func(key, decryption_oracle16)
        enc_oracle = encryption_get_oracle_func(key, encryption_oracle16)

        self.assertIn("admin=true", break_cbc_oracle(enc_oracle, dec_oracle))
        
if __name__ == "__main__":
    support.run_unittest(Set2)
