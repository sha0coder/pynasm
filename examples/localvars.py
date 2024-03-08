

# limit: max 5 vars per function
# var size: qword


def main():
    ptr = 0
    test = ret = 0

    # internally uses rdi
    mystr = 'this is a string'

    # mem to mem internally uses rsi
    test = ptr

    # PEB uses rsi to access gs and rsi to do the mem to mem
    mypeb = PEB

    ret = cont()

    ret += 1
    rbx += ret

    return ret




def cont():
    ptr2 = ptr = 0x7ffff123
    if ptr == ptr2:
        return 0
    return 123 

