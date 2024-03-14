# pynasm

python to nasm assembly conversion, with cpu control.
- x86 64bits only for now.

This allows to create:
- shellcodes
- PIC relocatable low-level code 
- infections (for red-teaming)
- obfuscation



## Disclaimer

Don't use this for creating malicious payloads!

## Usage

generating a relocatable 64bits code blob

```bash
python3 pynasm.py shellcode.py
nasm -f bin shellcode.nasm
ls shellcode
```

or generating an 64bits exe 

```hash
python3 pynasm.py program.py exe
nasm -f win64 program.nasm
x86_64-w64-mingw32-ld program.obj
ls a.exe
```


## Emulate with SCEMU for testing

```bash
./scemu -f shellcode -vv -6
```

## Demo

https://www.youtube.com/watch?v=o072bXNtxmg

## Examples

check the examples folder.


### WinapiAcces importing winapi lib

![winapi](pics/runtime2.png)

![msgbox](pics/msgbox.png)


### Control blocks

![blocks](pics/blocks.png)

### Comparing strings

![python code](pics/strings_compare1.png)

![emulated binary](pics/strings_compare.png)


### API Call

![api call](pics/api_call1.png)

![emulation](pics/api_call2.png)


![virtual allocs](pics/api_call3.png)

![emulation](pics/api_call4.png)


### Arrays and memory blobs 


![arrays](pics/arrays.png)


## TODO:

- complex ifs and/or
- elif
- break
- continue
- structures



