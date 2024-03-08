

def do_something(p1):
    return p1

def main():
    s = 'this is a string'
    l = len(s)
    for i in range(l):
        do_something(i)

    num = 3
    while num > 0:
        x = do_something(num)
        num -= 1

    ptr = 0x123123
    rax = ptr
    rax(num)

    return 0
