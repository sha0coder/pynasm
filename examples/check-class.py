
def checksum(rcx, rdx):
    # rcx = buf, rdx = len
    rax = 0
    rbx = 0

    while rbx < rdx:
        rsi = mem[rcx+rbx]
        rax += rsi
        rbx += 1

    return rax

def classify(rcx):
    tag = 0        # local var, gets a stack slot

    if rcx < 0x10:
        tag = 1
    elif rcx > 0xf0:
        tag = 3
    else:
        tag = 2

    return rcx

def main():
    # byte array on the stack, rax -> first byte
    rax = [0x1a, 0x3b, 0xff, 0x00]
    rcx = rax       # buf
    rdx = 4         # len

    r9 = checksum(rcx, rdx)

    # rcx still points at the array, callee saved the regs for us
    r8 = mem[rcx+1]

    # elif chain
    r10 = classify(r8)

    rax = r9
    rax += r10
    return rax
