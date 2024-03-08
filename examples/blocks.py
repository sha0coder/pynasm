

def do_something(ecx):
    return 1

def main():
    rax = rbx = 0   # xors
    ebx += 1        # 32bits inc
    asm('  cpuid')  # custom instructions


    rbx = 3
    while rbx > 0:
        rbx -= 1


    while True:     
        if rax == 0:
            for rcx in range(rbx):
                rax = do_something(rcx)
        else:
            for rcx in range(3,10,1):
                rax = do_something(rcx)

    ebx = 3
    while ebx > 0:
        ebx -= 1


