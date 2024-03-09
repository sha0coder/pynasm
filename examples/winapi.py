import runtime2

def main():
    msgbox = get_api('user32.dll','MessageBoxA')
    rax = msgbox
    rax(0, 'message', 'title', 0)
