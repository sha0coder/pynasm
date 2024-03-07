import runtime


def main():
    runtime()

    rax = 'WinExec'
    rbx = get_api(rax, 7)
    rcx = 'calc.exe'
    rbx(rcx, 1)

    return 0
