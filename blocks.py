

def do_something(ecx):
    return 1

def main():
    rax = rbx = 0
    ebx += 1
    asm('  cpuid')
    while True:
        if rax == 0:
            for rcx in range(rbx):
                rax = do_something(rcx)
        else:
            for rcx in range(3,10,1):
                rax = do_something(rcx)


