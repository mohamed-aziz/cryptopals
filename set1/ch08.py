
def probably_ecb(cipher):
    blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
    for i, block1 in enumerate(blocks):
        for j, block2 in enumerate(blocks):
            if block1 == block2 and i != j:
                return True
    return False
