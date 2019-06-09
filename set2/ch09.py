
def paddpkcs7(s, n=16):
    s = str(s)
    return s + ((n - len(s)) % n) * chr(n - len(s) % n)
