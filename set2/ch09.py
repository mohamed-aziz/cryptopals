
def paddpkcs7(s, n=16):
    s = str(s)
    char = ((n - len(s)) % n) or n
    return s + char * chr(char)
