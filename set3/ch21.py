
class MT19937(object):

    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1 << R) - 1
    UPPER_MASK = (~LOWER_MASK) & 0xffffffff

    def __init__(self, seed):
        self.mt = []

        self.mt.append(seed)
        for i in range(1, self.N):
            self.mt.append(self.F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.W - 2))) + i& 0xffffffff)
        self.index = self.N

    def extract_number(self):
        if self.index == self.N:
            self.twist()

        y = self.mt[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)

        self.index += 1
        return y & 0xffffffff

    def twist(self):
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            xA = x >> 1
            if x & 1 != 0:
                xA ^= self.A

            self.mt[i] = self.mt[(i + self.M) % self.N] ^ xA

        self.index = 0
