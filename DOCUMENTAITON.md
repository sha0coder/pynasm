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
