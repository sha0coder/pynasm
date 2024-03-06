'''
    relocatable strings are compiled to call + ret 

    'ecx' and 'if str(eax) == str(ebx):' is a way 
    to compare strings with the instruction 
'''

def process(eax, ecx):
    ebx = 'not hello'
    if str(eax) == str(ebx):
        return 1
    return 0


def main():
    eax = 'hello'
    eax = process(eax, 5)
    if eax == 1:
        pass

