import runtime


def virtual_alloc(rsi):
    push(rsi)
    runtime()
    rbx = 'VirtualAlloc'
    rax = get_api(rbx, 12)
    pop(rsi)
    rax = rax(0, rsi, 0x00001000, 0x40)
    return rax



def main():
    rax = virtual_alloc(1024)
    push(rax)
    rbx = virtual_alloc(100)
    pop(rax)
    return 0

