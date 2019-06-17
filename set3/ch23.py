from set3 import MT19937


def clone_mt19937(numbers):
    T, C = 15, 0xEFC60000
    L = 18
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    mt = []
    for number in numbers:
        y = number
        y ^= (y >> L)
        y ^= (y << T) & C
        for _ in range(S):
            y ^= (y << S) & B
        for _ in range(U):
            y ^= (y >> U) & D
        mt.append(y & 0xffffffff)
    obj = MT19937(0)
    obj.mt = mt
    obj.index = obj.N
    return obj
