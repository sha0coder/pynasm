

def main():
    msg = 'Hello, World!\n'
    l = len(msg)
    libc_write(1, msg, l)
    libc_exit(0)
