def encrypt(d, l, key):
    buff = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    rbx = key
    for i in range(l):
        al = d[i]
        al ^= bl
        buff[i] = al
    return buff


def main():
    d = 'decrypted text'
    l = len(d)
    key = 0x32
    e = encrypt(d, l, key)
    asm(' int 3')
    return e
