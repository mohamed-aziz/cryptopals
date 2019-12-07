import sys
from random import randint


def popcount(x):
    setBits = 0
    while (x > 0):
        setBits += x & 1
        x /= 2
    return setBits


def hamming_distance(s1, s2):
    assert len(s1) ==  len(s2)
    f = 0
    for i in range(len(s1)):
        f += popcount(ord(s1[i]) ^ ord(s2[i]))
    return f


def find_keysize(cipher, keysize):
    blocknum = randint(1, 5)
    blocknum2 = randint(1, 5)
    if blocknum2 == blocknum:
        blocknum2 = randint(1, 5)
    block1, block2 = cipher[keysize*(blocknum-1):keysize*blocknum], cipher[keysize*(blocknum2-1):keysize*(blocknum2)]
    return float(hamming_distance(block1, block2)) / keysize


def transpose(cipher, keysize):
    cipher = cipher + (keysize - (len(cipher) % keysize)) * "\x00"
    blocks = [cipher[i:i+keysize] for i in range(0, len(cipher), keysize)]
    return "".join(["".join(c) for c in zip(*blocks)])


def simulation(cipher):
    smallestScore = sys.maxint
    keysize = 0
    for KEYSIZE in range(10, 41):
        distance = find_keysize(cipher, KEYSIZE)
        if distance < smallestScore:
            smallestScore = distance
            keysize = KEYSIZE
    return keysize

