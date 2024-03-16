import winapi


def main():
    winexec = get_api('kernel32.dll','WinExec')
    rax = winexec
    rax('calc.exe', 1)  # pretty huh?
    return 0

