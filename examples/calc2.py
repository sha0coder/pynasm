import winapi

def main():
    shellexec = get_api('shell32.dll','RealShellExecuteA')
    if shellexec == 0:
        shellexec = get_api('shell32.dll', 'ShellExecuteA')
    rax = shellexec
    rax(0, 0, 'C:\\windows\\system32\\calc.exe', 0, 0, 0)
    return 0
