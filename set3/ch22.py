from set3 import MT19937


def break_mt19937_seeded_time(timestamp, num, lim=1000):
    for i in range(timestamp-lim, timestamp):
        obj = MT19937(i)
        num2 = obj.extract_number()
        if num2 == num:
            return i
    return None
