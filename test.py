import runtime2

def main():
    msgbox = get_api('user32.dll','MessageBoxA')
    rax = msgbox
    title = 'helo'
    msg = 'hola'
    rax(0,title,msg,0)
