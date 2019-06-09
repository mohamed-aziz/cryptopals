
def xor_two_strings(s1, s2):
    import binascii
    s1, s2 = s1.decode("hex"), s2.decode("hex")
    res = ""
    for i in range(len(s1)):
        res += chr(ord(s1[i]) ^ ord(s2[i]))
    return binascii.hexlify(res)
