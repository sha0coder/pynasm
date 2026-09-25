'''
    pynasm test suite
    Compiles python snippets and verifies the generated NASM assembly.

    Each test is a (name, python_code, expected_patterns, forbidden_patterns) tuple.
    - expected_patterns: list of strings that MUST appear in the .nasm output
    - forbidden_patterns: list of strings that MUST NOT appear (optional)

    Run:  python3 tests.py
'''

import os
import sys
import tempfile
import subprocess
import re


PYNASM = os.path.join(os.path.dirname(__file__), 'pynasm.py')


def compile_snippet(code, mode='64'):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        pyfile = f.name

    nasmfile = pyfile.replace('.py', '.nasm')
    try:
        result = subprocess.run(
            [sys.executable, PYNASM, pyfile, mode],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None, result.stderr.strip()

        if not os.path.exists(nasmfile):
            return None, 'no .nasm file generated'

        with open(nasmfile) as nf:
            asm = nf.read()
        return asm, None
    finally:
        for path in (pyfile, nasmfile, nasmfile.replace('.nasm','.bin')):
            if os.path.exists(path):
                os.unlink(path)


def nasm_check(asm, mode='64'):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.nasm', delete=False) as f:
        f.write(asm)
        f.flush()
        nasmfile = f.name
    outfile = nasmfile + '.o'
    fmt = 'elf64' if mode == 'elf' else 'bin'
    try:
        result = subprocess.run(
            ['nasm', '-f', fmt, nasmfile, '-o', outfile],
            capture_output=True, text=True, timeout=10
        )
        errors = [l for l in result.stderr.splitlines()
                  if 'error' in l.lower() and 'warning' not in l.lower()]
        return errors
    finally:
        for p in (nasmfile, outfile):
            if os.path.exists(p):
                os.unlink(p)


# ============================================================
#  test cases: (name, code, expected_asm_patterns, forbidden)
# ============================================================

TESTS = [

    # --- basic assignments ---

    ('assign_reg_zero', '''
def main():
    rax = rbx = 0
''', ['xor rax, rax', 'xor rbx, rbx'], []),

    ('assign_reg_const', '''
def main():
    rax = 0x41
''', ['mov rax, 65'], []),

    ('assign_reg_string', '''
def main():
    rsi = 'hello'
''', ['db "hello", 0', 'pop rsi'], []),

    ('assign_var_const', '''
def main():
    x = 42
''', ['mov qword [rbp-', '42'], []),

    ('assign_var_string', '''
def main():
    s = 'test'
''', ['db "test", 0', 'mov [rbp-'], []),

    ('assign_var_to_var', '''
def main():
    x = 10
    y = x
''', ['mov rdi, qword [rbp-', 'mov qword [rbp-'], []),

    ('assign_reg_to_var', '''
def main():
    x = rax
''', ['mov qword [rbp-', 'rax'], []),

    ('assign_var_to_reg', '''
def main():
    x = 10
    rax = x
''', ['mov rax, qword [rbp-'], []),

    ('assign_reg_to_reg', '''
def main():
    rbx = rax
''', ['mov rbx, rax'], []),

    # --- assignment with arrays ---

    ('assign_array_literal', '''
def main():
    buf = [0x41, 0x42, 0x43]
''', ['db 0x41, 0x42, 0x43,'], []),

    ('assign_array_subscript_const_idx', '''
def main():
    buf = [0x41, 0x42, 0x43]
    buf[1] = 0x44
''', ['mov byte [rdi+1], 68'], []),

    ('assign_from_subscript', '''
def main():
    buf = [0x41, 0x42, 0x43]
    al = buf[0]
''', ['mov al, byte [rsi+0]'], []),

    # --- assignment with mem[] ---

    ('assign_mem_reg', '''
def main():
    rax = mem[rbx]
''', ['mov rax, [rbx]'], []),

    ('assign_mem_reg_plus_const', '''
def main():
    rax = mem[rbx+8]
''', ['mov rax, [rbx+8]'], []),

    ('assign_mem_reg_plus_reg', '''
def main():
    rax = mem[rbx+rcx]
''', ['mov rax, [rbx+rcx]'], []),

    # --- BinOp assignments ---

    ('binop_add', '''
def main():
    x = 10
    y = 3
    z = x + y
''', ['add rax, rdi', 'mov [rbp-'], []),

    ('binop_sub', '''
def main():
    x = 10
    y = 3
    z = x - y
''', ['sub rax, rdi'], []),

    ('binop_mul', '''
def main():
    x = 10
    y = 3
    z = x * y
''', ['mul rdi'], []),

    ('binop_div', '''
def main():
    x = 10
    y = 3
    z = x / y
''', ['xor rdx, rdx', 'div rdi'], []),

    ('binop_mod', '''
def main():
    x = 10
    y = 3
    z = x % y
''', ['div rdi', 'mov rax, rdx'], []),

    ('binop_xor', '''
def main():
    x = 0xff
    y = 0x0f
    z = x ^ y
''', ['xor rax,'], []),

    ('binop_and', '''
def main():
    x = 0xff
    y = 0x0f
    z = x & y
''', ['and rax,'], []),

    ('binop_or', '''
def main():
    x = 0xf0
    y = 0x0f
    z = x | y
''', ['or rax,'], []),

    ('binop_lshift', '''
def main():
    x = 1
    y = 4
    z = x << y
''', ['shl rax, cl'], []),

    ('binop_rshift', '''
def main():
    x = 256
    y = 4
    z = x >> y
''', ['shr rax, cl'], []),

    ('binop_reg_plus_const', '''
def main():
    rax = 10
    rbx = rax + 5
''', ['add rax, 5'], []),

    # --- UnaryOp assignments ---

    ('unary_neg', '''
def main():
    x = 10
    y = -x
''', ['neg rax'], []),

    ('unary_invert', '''
def main():
    x = 0xff
    y = ~x
''', ['not rax'], []),

    ('unary_not', '''
def main():
    x = 1
    y = not x
''', ['test rax, rax', 'setz al', 'movzx rax, al'], []),

    # --- AugAssign ---

    ('augassign_add', '''
def main():
    rax = 10
    rax += 5
''', ['add rax, 5'], []),

    ('augassign_sub', '''
def main():
    rax = 10
    rax -= 3
''', ['sub rax, 3'], []),

    ('augassign_mul', '''
def main():
    rax = 10
    rax *= 3
''', ['mul rdi'], []),

    ('augassign_div', '''
def main():
    rax = 10
    rax /= 2
''', ['div rdi'], []),

    ('augassign_mod', '''
def main():
    rax = 10
    rax %= 3
''', ['div rdi', 'mov rax, rdx'], []),

    ('augassign_xor', '''
def main():
    rax = 0xff
    rax ^= 0xff
''', ['xor rax, 255'], []),

    ('augassign_bitand', '''
def main():
    rax = 0xff
    rax &= 0x0f
''', ['and rax, 15'], []),

    ('augassign_bitor', '''
def main():
    rax = 0x0f
    rax |= 0xf0
''', ['or rax, 240'], []),

    ('augassign_lshift', '''
def main():
    rax = 1
    rax <<= 4
''', ['shl rax, cl'], []),

    ('augassign_rshift', '''
def main():
    rax = 256
    rax >>= 4
''', ['shr rax, cl'], []),

    ('augassign_32bit_mul', '''
def main():
    ecx = 4
    ecx *= 10
''', ['mov rax, rcx', 'mul rdi', 'mov rcx, rax'], []),

    ('augassign_var_add_var', '''
def main():
    x = 10
    y = 3
    x += y
''', ['mov rsi,', 'mov rdi,', 'add rdi, rsi', 'mov [rbp-'], []),

    ('augassign_var_mul_var', '''
def main():
    x = 10
    y = 3
    x *= y
''', ['mul rdi', 'mov [rbp-', 'rax'], []),

    # --- function definition & calls ---

    ('func_def', '''
def main():
    pass
''', ['main:', 'push rbp', 'mov rbp, rsp', 'sub rsp,'], []),

    ('func_call', '''
def foo():
    return 1

def main():
    foo()
''', ['call foo'], []),

    ('func_call_with_args', '''
def foo(a, b):
    return 1

def main():
    foo(10, 20)
''', ['push 20', 'push 10', 'call foo', 'add rsp, 16'], []),

    ('func_call_string_arg', '''
def foo(s):
    return 1

def main():
    foo('hello')
''', ['db "hello", 0', 'call foo'], []),

    ('func_call_assign_result', '''
def foo():
    return 42

def main():
    rbx = foo()
''', ['call foo', 'mov rbx, rax'], []),

    ('func_call_assign_result_var', '''
def foo():
    return 42

def main():
    x = foo()
''', ['call foo', 'mov [rbp-', 'rax'], []),

    ('func_params', '''
def myfunc(a, b):
    return a

def main():
    myfunc(1, 2)
''', ['myfunc:', 'mov rdi, qword [rbp+16]', 'mov qword [rbp-', 'rdi'], []),

    ('func_params_reg', '''
def myfunc(rax, rbx):
    return rax

def main():
    myfunc(1, 2)
''', ['mov rax, qword [rbp+16]', 'mov rbx, qword [rbp+24]'], []),

    # --- return ---

    ('return_zero', '''
def main():
    return 0
''', ['xor rax, rax', 'leave', 'ret'], []),

    ('return_const', '''
def main():
    return 42
''', ['mov rax, 42', 'leave', 'ret'], []),

    ('return_reg', '''
def main():
    rbx = 1
    return rbx
''', ['mov rax, rbx', 'leave', 'ret'], []),

    ('return_var', '''
def main():
    x = 10
    return x
''', ['mov rax, [rbp-', 'leave', 'ret'], []),

    ('return_binop', '''
def main():
    rax = 10
    return rax + 5
''', ['add rax, 5', 'leave', 'ret'], []),

    ('return_call', '''
def foo():
    return 1

def main():
    return foo()
''', ['call foo', 'leave', 'ret'], []),

    ('return_none', '''
def main():
    rax = 1
    return
''', ['leave', 'ret'], []),

    ('return_neg', '''
def main():
    x = 10
    return -x
''', ['neg rax', 'leave', 'ret'], []),

    # --- if/else ---

    ('if_reg_eq_const', '''
def main():
    rax = 1
    if rax == 1:
        rbx = 1
''', ['cmp rax, 1', 'je if'], []),

    ('if_reg_neq_const', '''
def main():
    rax = 1
    if rax != 0:
        rbx = 1
''', ['cmp rax, 0', 'jne if'], []),

    ('if_reg_gt', '''
def main():
    rax = 5
    if rax > 3:
        rbx = 1
''', ['jg if'], []),

    ('if_reg_lt', '''
def main():
    rax = 1
    if rax < 10:
        rbx = 1
''', ['jl if'], []),

    ('if_reg_gte', '''
def main():
    rax = 5
    if rax >= 5:
        rbx = 1
''', ['jge if'], []),

    ('if_reg_lte', '''
def main():
    rax = 5
    if rax <= 5:
        rbx = 1
''', ['jle if'], []),

    ('if_else', '''
def main():
    rax = 1
    if rax == 1:
        rbx = 10
    else:
        rbx = 20
''', ['je if', 'jmp else', 'jmp endif', 'else', 'endif'], []),

    ('if_subscript', '''
def main():
    buf = [0x41, 0x42, 0x43]
    if buf[0] == 0x41:
        rax = 1
''', ['mov al, byte [rsi+0]', 'cmp'], []),

    ('if_var_eq_var', '''
def main():
    x = 10
    y = 10
    if x == y:
        rax = 1
''', ['mov rsi,', 'mov rdi,', 'cmp rsi, rdi', 'je if'], []),

    # --- elif ---

    ('elif_basic', '''
def main():
    rax = 5
    if rax == 1:
        rbx = 10
    elif rax == 5:
        rbx = 50
    else:
        rbx = 0
''', ['je if', 'jmp elif', 'elif', 'jmp else', 'else', 'endif'], []),

    ('elif_chain', '''
def main():
    rax = 3
    if rax == 1:
        rbx = 1
    elif rax == 2:
        rbx = 2
    elif rax == 3:
        rbx = 3
    elif rax == 4:
        rbx = 4
    else:
        rbx = 0
''', ['elif'], []),

    ('elif_no_else', '''
def main():
    rax = 3
    if rax == 1:
        rbx = 1
    elif rax == 2:
        rbx = 2
    elif rax == 3:
        rbx = 3
''', ['elif', 'endif'], []),

    # --- complex ifs (and/or) ---

    ('if_and', '''
def main():
    rax = 5
    rbx = 10
    if rax > 0 and rbx > 0:
        rcx = 1
''', ['andfail', 'jle andfail', 'jmp if'], []),

    ('if_or', '''
def main():
    rax = 5
    rbx = 10
    if rax > 100 or rbx > 5:
        rcx = 1
''', ['jg if', 'jmp endif'], []),

    ('if_and_three', '''
def main():
    rax = 1
    rbx = 2
    rcx = 3
    if rax > 0 and rbx > 0 and rcx > 0:
        rdx = 1
''', ['andfail'], []),

    ('if_or_three', '''
def main():
    rax = 0
    rbx = 0
    rcx = 1
    if rax > 0 or rbx > 0 or rcx > 0:
        rdx = 1
''', ['jg if'], []),

    # --- if truthy / not ---

    ('if_truthy_reg', '''
def main():
    rax = 1
    if rax:
        rbx = 1
''', ['test rax, rax', 'jnz if'], []),

    ('if_not_reg', '''
def main():
    rax = 0
    if not rax:
        rbx = 1
''', ['test rax, rax', 'jz if'], []),

    ('if_truthy_var', '''
def main():
    x = 1
    if x:
        rax = 1
''', ['mov rdi, [rbp-', 'test rdi, rdi', 'jnz if'], []),

    ('if_not_var', '''
def main():
    x = 0
    if not x:
        rax = 1
''', ['mov rdi, [rbp-', 'test rdi, rdi', 'jz if'], []),

    # --- while ---

    ('while_true', '''
def main():
    while True:
        rax += 1
''', ['while', 'jmp while'], []),

    ('while_compare', '''
def main():
    rcx = 10
    while rcx > 0:
        rcx -= 1
''', ['while', 'jg while'], []),

    ('while_boolop', '''
def main():
    rax = 0
    rbx = 10
    while rax < 10 and rbx > 0:
        rax += 1
        rbx -= 1
''', ['while', 'andfail', 'endwhile'], []),

    # --- for ---

    ('for_range_1arg', '''
def main():
    for rcx in range(10):
        rax += 1
''', ['mov rcx, 0', 'for', 'add rcx, 1', 'cmp rcx, 10', 'jl for'], []),

    ('for_range_2arg', '''
def main():
    for rcx in range(5, 15):
        rax += 1
''', ['mov rcx, 5', 'cmp rcx, 15', 'jl for'], []),

    ('for_range_3arg', '''
def main():
    for rcx in range(0, 100, 2):
        rax += 1
''', ['mov rcx, 0', 'add rcx, 2', 'cmp rcx, 100', 'jl for'], []),

    ('for_localvar', '''
def main():
    for i in range(10):
        rax += 1
''', ['mov rcx, 0', 'mov qword [rbp-', 'rcx', 'cmp rcx, 10'], []),

    ('for_range_var_stop', '''
def main():
    n = 10
    for rcx in range(n):
        rax += 1
''', ['cmp rcx, qword [rbp-'], []),

    # --- break / continue ---

    ('break_in_for', '''
def main():
    for rcx in range(10):
        if rcx == 5:
            break
''', ['jmp endfor', 'endfor'], []),

    ('continue_in_for', '''
def main():
    rbx = 0
    for rcx in range(10):
        if rcx == 3:
            continue
        rbx += 1
''', ['jmp forcont', 'forcont'], []),

    ('break_in_while', '''
def main():
    rcx = 0
    while True:
        rcx += 1
        if rcx == 10:
            break
''', ['jmp endwhile', 'endwhile'], []),

    ('continue_in_while', '''
def main():
    rcx = 0
    rbx = 0
    while rcx < 10:
        if rcx == 5:
            continue
        rbx += 1
''', ['jmp while', 'endwhile'], []),

    ('nested_loops_break', '''
def main():
    for rax in range(5):
        for rbx in range(5):
            if rbx == 2:
                break
''', ['endfor'], []),

    # --- pass ---

    ('pass_nop', '''
def main():
    pass
''', ['nop'], []),

    # --- asm() ---

    ('raw_asm', '''
def main():
    asm('  cpuid')
    asm('  nop')
''', ['cpuid', 'nop'], []),

    # --- push/pop ---

    ('push_pop', '''
def main():
    push(rax)
    pop(rbx)
''', ['push rax', 'pop rbx'], []),

    # --- alloc ---

    ('alloc_basic', '''
def main():
    rax = alloc(16)
''', ['padding times 16 db 0x00', 'pop rax'], []),

    # --- len ---

    ('len_string', '''
def main():
    s = 'hello'
    rax = len(s)
''', ['mov rax, 5'], []),

    # --- PEB access ---

    ('peb_assign', '''
def main():
    rax = PEB
''', ['mov rax, gs:[rdi+0x60]'], []),

    # --- libc calls ---

    ('libc_call', '''
def main():
    rsi = 'hello'
    libc_puts(rsi)
''', ['call puts', 'pop rdi'], [], 'elf'),

    # --- string escape ---

    ('string_escape', '''
def main():
    s = 'hello\\nworld'
''', ['db "hello", 0x0a, "world", 0'], []),

    # --- indirect reg call ---

    ('indirect_call_reg', '''
def main():
    rax = 0x41414141
    rax(1, 2, 3, 4)
''', ['mov rcx, 1', 'mov rdx, 2', 'mov r8, 3', 'mov r9, 4', 'call rax'], []),

    # --- multiple targets ---

    ('multi_assign_zero', '''
def main():
    rax = rbx = rcx = 0
''', ['xor rax, rax', 'xor rbx, rbx', 'xor rcx, rcx'], []),

    # --- nested if in elif ---

    ('nested_if_in_elif', '''
def main():
    rax = 3
    rbx = 1
    if rax == 1:
        rcx = 1
    elif rax == 3:
        if rbx > 0:
            rcx = 2
        else:
            rcx = 3
''', ['elif', 'if', 'else', 'endif'], []),

    # --- 32bit register operations ---

    ('reg32_augassign', '''
def main():
    ecx = 0
    ecx += 4
    ebx = ecx
    ecx *= 10
    ecx /= 2
''', ['xor ecx, ecx', 'add ecx, 4', 'mov ebx, ecx', 'mul rdi', 'div rdi'],
    ['mov rax, ecx', 'mov ecx, rax']),

    # --- existing examples (regression) ---

    ('example_xors', '''
def main():
    rbx = rcx = rdx = 0
    eax = 0xff
    eax ^= 0xff
''', ['xor rbx, rbx', 'xor rcx, rcx', 'xor rdx, rdx', 'xor eax, 255'], []),

    ('example_strings', '''
def main():
    mistr = 'test'
    l = len(mistr)
    al = mistr[0]
''', ['db "test", 0', 'mov rax, 4', 'mov al, byte [rsi+0]'], []),

]


# ============================================================

def run_tests():
    passed = 0
    failed = 0
    errors = []

    for entry in TESTS:
        name, code, expected, *rest = entry
        forbidden = rest[0] if rest else []
        mode = rest[1] if len(rest) > 1 else '64'

        asm, err = compile_snippet(code, mode)

        if err:
            if 'UNIMPLEMENTED' in err:
                errors.append((name, f'UNIMPLEMENTED: {err}'))
                failed += 1
                continue
            errors.append((name, f'pynasm error: {err}'))
            failed += 1
            continue

        if asm is None:
            errors.append((name, 'no asm generated'))
            failed += 1
            continue

        nasm_errors = nasm_check(asm, mode)
        if nasm_errors:
            errors.append((name, f'NASM errors:\n' + '\n'.join(f'    {e}' for e in nasm_errors)))
            failed += 1
            continue

        missing = []
        for pat in expected:
            if pat not in asm:
                missing.append(pat)

        present_forbidden = []
        for pat in forbidden:
            if pat in asm:
                present_forbidden.append(pat)

        if missing or present_forbidden:
            msg = ''
            if missing:
                msg += f'  missing patterns: {missing}\n'
            if present_forbidden:
                msg += f'  forbidden patterns found: {present_forbidden}\n'
            errors.append((name, msg.rstrip()))
            failed += 1
        else:
            passed += 1
            print(f'  \033[32mPASS\033[0m  {name}')

    if errors:
        print()
        for name, msg in errors:
            print(f'  \033[31mFAIL\033[0m  {name}')
            for line in msg.split('\n'):
                print(f'        {line}')

    print(f'\n  {passed}/{passed+failed} passed', end='')
    if failed:
        print(f', {failed} failed')
    else:
        print()

    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run_tests())
