import runtime

def main():
    runtime()
    rax = 'WinExec'
    rax = get_api(rax, 7)
    rcx = 'calc.exe'
    rax(rcx, 1)  # pretty huh?
    return 0

