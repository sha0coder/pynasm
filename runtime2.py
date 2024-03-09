

def get_kernel32():
    rdi = rax = rdx = 0
    rbx = PEB
    rbx = mem[rbx+0x18] # LDR
    rbx = mem[rbx+0x20] # ntdll
    rbx = mem[rbx] # kernelbase
    rbx = mem[rbx] # kernel32
    rbx = mem[rbx+0x20] # kernel32 base
    r8 = rbx
    return rbx


def get_export_address(rbx):
    ebx = mem[rbx+0x3c]
    rbx += r8
    rcx = 0x88
    edx = mem[rbx+rcx]
    rdx += r8
    return rdx


def names_and_pointers():
    r10 = 0
    r10d = mem[rdx+0x1c]
    r10 += r8
    r11 = 0
    r11d = mem[rdx+0x20]
    r11 += r8
    r12 = 0
    r12d = mem[rdx+0x24]
    r12 += r8
    return 0


def get_kernel32_api(rdx, rcx): # rdx: api_name rcx: api_size
    rax = 0
    while True:
        rdi = 0
        edi = mem[r11+rax*4] 
        rdi += r8
        rsi = rdx
        push(rcx)
        if str(rsi) == str(rdi):  # repe cmpsb
            ax = mem[r12+rax*2]
            eax = mem[r10+rax*4]
            rax += r8
            push(rbx)
            return rax
        pop(rcx)
        eax += 1


def get_api(lib, name):
    runtime()
    str_load = 'LoadLibraryA'
    len_load = len(str_load)
    str_proc = 'GetProcAddress'
    len_proc = len(str_proc)
    ptr_load = get_kernel32_api(str_load, len_load)
    ptr_proc = get_kernel32_api(str_proc, len_proc)
    rax = ptr_load
    hndl = rax(lib)
    rax = ptr_proc # ebp-40h
    ptr = rax(hdnl, name)
    return ptr



def resolve_addr():
    ax = mem[r12+rax*2]
    eax = mem[r10+rax*4]
    rax += r8
    return rax


def runtime():
    rbx = get_kernel32()
    rbx = get_export_address(rbx)
    names_and_pointers()
    return 0




