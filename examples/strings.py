'''
    relocatable strings are compiled to call + ret 

    'rcx' and 'if str(rax) == str(rbx):' is a way 
    to compare strings with the instruction 
'''

def process(rax, rcx):
    rbx = 'not hello'
    if str(rax) == str(rbx):
        return 1
    return 0


def main():
    msg = 'hello'
    rax = process(msg, 5)
    if rax == 1:
        pass

    return 0
