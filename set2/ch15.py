
def validatepkcs7(s, blocksize=16):
    lastchar = ord(s[-1])
    if lastchar > blocksize:
        raise ValueError("Padding char is bigger than blocksize")
    if s[-(((lastchar - blocksize) % blocksize) or blocksize):] == lastchar * chr(lastchar):
        return True
    return False
