from itertools import cycle
from binascii import hexlify


def repeating_xor(text, key):
    l = ""
    k = 0
    for i in cycle(key):
        try:
            l += chr(ord(i) ^ ord(text[k]))
        except IndexError:
            return l
        k += 1
