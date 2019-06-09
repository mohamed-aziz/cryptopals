

def convert_hex_to_base64(hex):
    import base64
    return base64.b64encode(hex.decode("hex"))

