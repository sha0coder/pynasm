# PyNasm documentation

## Things not currently supported


cannot use len() as parameter or from a different function 

```python
def main():
    s = 'string'
    somefunc(s, len(s))
```

For now the way is:
```python
def main():
    s = 'string'
    l = len(s)
    somefunc(s, l)
```

You only can do the len() from same function that was defined the string or array


cannot do operations in this way:
```python
def main():
    a = 1 + 1
```

cannot do operations in this way:
```python
def main():
    a = 1
    b = 2
    c = a + b
```

for now the way is:
```python
def main():
    a = 1
    b = 2
    c = 0
    c += a
    c += b
    return 0
```

remember to always return something, every function needs a return 


the assembly operations are translated from += -= and if you know what you are doing *= and /=


you cannot use and/or operatos for now:
```python
def main():
    if 1 == 1 and 2 == 2:
        return 0
    return 1
```

for now the way is:
```python
def main():
    if 1 == 1:
        if 2 == 2:
            return 0
    return 1
```

and for the or use the else + if (elif doesn't exist for now)

## Things supported

### Definitions

```python
def main():
    mystring = 'test'
    mynum = 123
    myarray = [1,2,3,4,5]
    a = b = b = 0
    rax = rbx = 0
```

### Operations

Use augmented assign a += b instead of a = a + b
parentesis and complex expressions are not supported for now

```python
def main():
    a = 1
    b = 2
    b += 1
    a -= b
    return a
```

### Ifs

whithout and/or for now:

```python
def main():
    a = 2
    if a == 2:
        if 1 == 1:
            return 0
        else:
            return 1
    else:
        if 2 == 3:
            return 3
    return 4
```

### While

dont combine len() or range(), basically use while for infinite loops, 
but some condition is supported.

```python
def main():
    a = 0
    b = 5
    while True:
        while a == b:
            a += 1
    return 0
```


### For

range can be used in any of his variants:
range(max)
range(min,max)
range(min,max,step)

you can use register or variable, 
for example "for i in ..." or "for ecx in..."

```python
def main():
    arr = [0x41,0x42,0x43,0x44]
    l = len(arr)
    for i in range(l):
        do_something(arr[i])
    return 0
```

### Functions

Despite being in 64bits the internal calling convention for 
python functions im using stack based.

```python
def sum(a, b):
    a += b
    return a

def main():
    r = sum(100, 200)
    return r
```

### String parse

```python
def get(s, pos):
    return s[pos]

def main():
    c = get('my string', 4)
    s = '1234'
    rax = 0x41
    s[3] = al
    return 0
```

### Raw assembly

```python

def trap():
    asm('  int 3')

def main():
    rax = 3
    asm('  cpuid')
    trap()
    return 0
```


### Indirect function call

for calling pointers ie winapi calls

```python
def main():
    ptr = 0x12123123
    rax = ptr
    r = rax(1)
    return 0
```


### Importing other files

pynasm look for imported files in current folder

```python
import helper

def main():
    function_on_helper()
```

This compile both .py files in one .nasm file

### Xor operation

Xors to remove a register:

```python
def main():
    rax = rbx = rcx = 0
```

Xor logic operation to encode/encrypt or whatever

```python
def main():
    a = 0x3fa498
    b = 0x234234
    a ^= b
```

```python
def encrypt(d, l, key):
    buff = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    rbx = key
    for i in range(l):
        al = d[i]
        al ^= bl
        buff[i] = al
    return buff


def main():
    d = 'decrypted text'
    l = len(d)
    key = 0x32
    e = encrypt(d, l, key)
    return e
```

scemu emulator:
```assembly
202 0x3c00cf: mov   rax,[rbp-20h]
=>
203 0x3c00d3: leave
=>r rax
	rax: 0x3c002f 3932207 'VWQ@KBFWV' (code)
```

len() has to be done from same function where the string was defined, but you can implement your own length() function that checks the 0x00 at the end of the string.


### Allocator

don't expect an allocator on a PIC code, use winapi VirtualAlloc importing winapi

```python
import winapi

def main():
    valloc = get_api('kernel32.dll','VirtuallAlloc')
    # ...
    rax = valloc
    size = 1024
    rax(0, size, 0x00001000, 0x40)
    return 0
```


