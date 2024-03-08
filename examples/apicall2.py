import runtime


def virtual_alloc(size):
    runtime()
    str_valloc = 'VirtualAlloc'
    rax = get_api(str_valloc, 12)
    addr = rax(0, size, 0x00001000, 0x40)
    return addr



def main():
    alloc1 = virtual_alloc(1024)
    alloc2 = virtual_alloc(100)
    return 0

