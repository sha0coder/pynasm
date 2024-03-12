import winapi

def main():
    shellexec = get_api('shell32.dll','ShellExecuteA')
    rax = shellexec
    rax(0, 0, 'calc.exe', 0, 0, 0)
