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

python3 pynasm.py shellcode.py
nasm -f bin shellcode.nasm

## Emulate with SCEMU

./scemu -f shellcode -vv -6

## Examples

check the examples folder.

### Comparing strings

![python code](pics/strings_compare1.png)

![emulated binary](pics/strings_compare.png)


### Control blocks


![blocks](pics/strings_compare.png)



