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

```bash
python3 pynasm.py shellcode.py
nasm -f bin shellcode.nasm
```

## Emulate with SCEMU for testing

```bash
./scemu -f shellcode -vv -6
```

## Examples

check the examples folder.


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


## TODO:

- use pushad/popad on prologe/epiloge to isolate registers on functions
- support local vars?


