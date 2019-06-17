

def break_ctr_reused_nonce_substitutions(ciphertexts):
    with open("static/words") as myfile:
        words = myfile.read().splitlines()