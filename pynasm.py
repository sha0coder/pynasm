'''
    Python3 to nasm 64bits
    @sha0coder

    Disclaimer!! dont use this to create malicious payloads.
'''


import sys
import ast
import os

STACK_SPACE = 10*8 # space for 10 local vars
nasm = []
lbl = 1


regs64 = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip']
regs32 = ['eax','ebx','ecx','edx','esi','edi','rbp','esp','eip','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d']
regs16 = ['ax','bx','cx','dx','si','di','bp','sp','ip','r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w']
regs8 = ['al','ah','bl','bh','cl','ch','dl','dh','r8l','r9l','r10l','r11l','r12l','r13l','r14l','r15l']
xmm = ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7','xmm8','xmm9','xmm10','xmm11','xmm12','xmm13','xmm14','xmm15']
ymm = ['ymm0','ymm1','ymm2','ymm3','ymm4','ymm5','ymm6','ymm7','ymm8','ymm9','ymm10','ymm11','ymm12','ymm13','ymm14','ymm15']

is_reg = lambda r : r in regs64 or r in regs32 or r in regs16 or r in regs8 or r in xmm or r in ymm
extern = set()


def unimplemented(msg): # rust style
    print(f'UNIMPLEMENTED: {msg}')
    sys.exit(1)


class Var:

    def __init__(self, func, name, pos, s=None):
        self.func = func
        self.name = name
        self.pos = pos
        self.str = s

class LocalVars:

    def __init__(self):
        self.vars = []

    def add(self, var):
        self.vars.append(var)

    def dump(self):
        for var in self.vars:
            print(f'{var.func} {var.name}')

    def get_str(self, func, name):
        for var in self.vars:
            #print(f' if {var.func} == {func} and {var.name} == {name}:')
            if var.func == func and var.name == name:
                #print(f' str: {var.str}')
                return var.str
        return None
    
    def get_pos(self, func, name, s=None, dbg=False):
        for var in self.vars:
            if dbg:
                print(f'if "{var.func}" == "{func}" and "{var.name}" == "{name}"')
            if var.func == func and var.name == name:
                if s:
                    var.str = s
                return var.pos * 8 + 8
        if dbg:
            print(f'new {func} {name}')
        pos = self.get_next_pos(func)
        self.add( Var(func, name, pos, s) )
        return pos * 8 + 8

    def get_next_pos(self, func):
        nxt = 0
        for var in self.vars:
            if var.func == func:
                nxt += 1
        return nxt
           


def align_stack(pos):
    global nasm, lbl
    nasm.append(f'  mov [rbp-{pos}], rsp')
    nasm.append(f'  and rsp, 0xfffffffffffffff0')
    '''
    need_adjust = f'need_adjust{lbl}'
    lbl += 1
    dont_need = f'dont_need_adjust{lbl}'
    lbl += 1

    nasm.append(f'  push rsp')
    nasm.append(f'  test rsp, 0xf')
    nasm.append(f'  jnz {need_adjust}')
    nasm.append(f'  jmp {dont_need}')
    nasm.append(f'{need_adjust}:')
    nasm.append(f'  sub rsp, 8')
    nasm.append(f'{dont_need}:')
    '''
   


class visit_functions(ast.NodeVisitor):
    def __init__(self):
        self.current_func = ''
        self.vars = LocalVars()


    def visit_Import(self, node):
        global nasm, lbl
        for alias in node.names:
            try:
                code = open(alias.name+'.py','r').read()
            except:
                unimplemented('only import .py in base folder, compile from py''s folder')
            tree = ast.parse(code)
            visitor = visit_functions()
            visitor.visit(tree)

        self.generic_visit(node)


    def visit_FunctionDef(self, node):
        global nasm
        self.current_func = node.name
        nasm.append(f'\n{node.name}:')
        nasm.append(f'  push rbp')
        nasm.append(f'  mov rbp, rsp')
        nasm.append(f'  sub rsp, {STACK_SPACE}')
        i = 16 
        for arg in node.args.args:
            if is_reg(arg.arg):
                nasm.append(f'  mov {arg.arg}, qword [rbp+{i}]')
            else:
                pos = self.vars.get_pos(self.current_func, arg.arg)
                nasm.append(f'  mov rdi, qword [rbp+{i}]')
                nasm.append(f'  mov qword [rbp-{pos}], rdi ; {arg.arg}')

            i += 8
        self.generic_visit(node)

    
    def visit_Pass(self, node):
        global nasm
        nasm.append('  nop')
        self.generic_visit(node)


    def visit_Call(self, node):
        global nasm, lbl
    
        if isinstance(node.func, ast.Name): # built-ins
            if node.func.id == 'range':
                return
            elif node.func.id == 'push':
                nasm.append(f'  push {node.args[0].id}')
                return
            elif node.func.id == 'pop':
                nasm.append(f'  pop {node.args[0].id}')
                return
            elif node.func.id == 'asm':
                nasm.append(f'{node.args[0].value}')
                return
            elif node.func.id == 'str':
                return
            elif node.func.id == 'len':
                if is_reg(node.args[0].id):
                    unimplemented("len(reg) use len(var)")
                else:
                    s = self.vars.get_str(self.current_func, node.args[0].id)
                    if s:
                        nasm.append(f'  mov rax, {len(s)}')
                        self.generic_visit(node)
                    else:
                        unimplemented('len() weird case')
                    return
            elif node.func.id == 'alloc':
                sz = node.args[0].id
                label = f'alloc{lbl}'
                lbl += 1
                nasm.append(f'  call {label}')
                nasm.append(f'  padding times {sz} db 0x00')
                nasm.append(f'{label}:')
                nasm.append(f'  pop rax')


            elif node.func.id in regs64:
                # rax('test',123)
                # indirect function call reg64 -> use 64bits calling convention
               
                # save previous stack and align rsp to 16
                pos = self.vars.get_pos(self.current_func, 'rsp')
                align_stack(pos)

                l = len(node.args)
                if l >= 1:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant):  # constants 
                        try:
                            # rax(123)
                            n = int(arg.value)
                            arg = arg.value
                        except:
                            # rax('test')
                            label = f'str_arg{lbl}'
                            lbl += 1
                            nasm.append(f'  call {label}')
                            nasm.append(f'  db "{arg.value}", 0')
                            nasm.append(f'{label}:')
                            arg = 'rdi'
                            nasm.append(f'  pop {arg}')

                    elif isinstance(arg, ast.Name):  # vars
                        # rax(var)
                        arg = arg.id
                        if not is_reg(arg):
                            pos = self.vars.get_pos(self.current_func, arg)
                            arg = f'qword [rbp-{pos}] ; {arg}'
                    if arg != 'rcx':
                        nasm.append(f'  mov rcx, {arg}')
                if l >= 2:
                    arg = node.args[1]
                    if isinstance(arg, ast.Constant):  # constants 
                        try:
                            # rax(1,123)
                            n = int(arg.value)
                            arg = arg.value
                        except:
                            # rax(1,'test')
                            label = f'str_arg{lbl}'
                            lbl += 1
                            nasm.append(f'  call {label}')
                            nasm.append(f'  db "{arg.value}", 0')
                            nasm.append(f'{label}:')
                            arg = 'rdi'
                            nasm.append(f'  pop {arg}')
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                        if not is_reg(arg):
                            # rax(1,var)
                            pos = self.vars.get_pos(self.current_func, arg)
                            arg = f'qword [rbp-{pos}] ; {arg}'
                    if arg != 'rdx':
                        nasm.append(f'  mov rdx, {arg}')
                if l >= 3:
                    arg = node.args[2]
                    if isinstance(arg, ast.Constant):  # constants 
                        try:
                            # rax(1,1,123)
                            n = int(arg.value)
                            arg = arg.value
                        except:
                            # rax(1,1,'test')
                            label = f'str_arg{lbl}'
                            lbl += 1
                            nasm.append(f'  call {label}')
                            nasm.append(f'  db "{arg.value}", 0')
                            nasm.append(f'{label}:')
                            arg = 'rdi'
                            nasm.append(f'  pop {arg}')
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                        if not is_reg(arg):
                            pos = self.vars.get_pos(self.current_func, arg)
                            arg = f'qword [rbp-{pos}] ; {arg}'
                    if arg != 'r8':
                        nasm.append(f'  mov r8, {arg}')
                if l >= 4:
                    arg = node.args[3]
                    if isinstance(arg, ast.Constant):  # constants 
                        try:
                            # rax(1,1,1,123)
                            n = int(arg.value)
                            arg = arg.value
                        except:
                            # rax(1,1,1,'test')
                            label = f'str_arg{lbl}'
                            lbl += 1
                            nasm.append(f'  call {label}')
                            nasm.append(f'  db "{arg.value}", 0')
                            nasm.append(f'{label}:')
                            arg = 'rdi'
                            nasm.append(f'  pop {arg}')
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                        if not is_reg(arg):
                            pos = self.vars.get_pos(self.current_func, arg)
                            arg = f'qword [rbp-{pos}] ; {arg}'
                    if arg != 'r9':
                        nasm.append(f'  mov r9, {arg}')
                if l > 4:
                    for arg in reversed(node.args[4:]):
                        if isinstance(arg, ast.Constant):  # constants 
                            try:
                                # rax(123)
                                n = int(arg.value)
                                arg = arg.value
                                nasm.append(f'  push {arg}')
                            except:
                                # rax('test')
                                label = f'str_arg{lbl}'
                                lbl += 1
                                nasm.append(f'  call {label}')
                                nasm.append(f'  db "{arg.value}", 0')
                                nasm.append(f'{label}:')
                        elif isinstance(arg, ast.Name):  # vars
                            arg = arg.id
                            if is_reg(arg):
                                nasm.append(f'  push {arg}')
                            else:
                                pos = self.vars.get_pos(self.current_func, arg)
                                arg2 = f'qword [rbp-{pos}]'
                                nasm.append(f'  mov edi, {arg2} ; {arg}')
                                nasm.append(f'  push edi')

                        else:
                            unimplemented("call with more than 4 args in weird param")

                nasm.append(f'  call {node.func.id}')

                # restore previous stack
                pos = self.vars.get_pos(self.current_func, 'rsp')
                nasm.append(f'  mov rsp, [rbp-{pos}]')
                '''
                if len(node.args) > 0:
                    nasm.append(f'  add rsp, {len(node.args) * 8}')
                '''
                return



        for arg in reversed(node.args):
            if isinstance(arg, ast.Constant):  # constants 
                try:
                    # func(123)
                    n = int(arg.value)
                    nasm.append(f'  push {arg.value}')
                except:
                    # func('mystr')
                    str_param = f'str_param{lbl}'
                    lbl += 1
                    nasm.append(f'  call {str_param}')
                    nasm.append(f'  db "{arg.value}",0')
                    nasm.append(f'{str_param}:')


            elif isinstance(arg, ast.Name):  # vars
                if is_reg(arg.id):
                    nasm.append(f'  push {arg.id}')
                else:
                    # func(var)
                    pos = self.vars.get_pos(self.current_func, arg.id)
                    nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {arg.id}')
                    nasm.append(f'  push rdi')


        if isinstance(node.func, ast.Name):
            fname = node.func.id
            if fname.startswith('libc_'):
                l = len(node.args)
                sym = fname[5:]
                extern.add(sym)
                if l >= 1:
                    nasm.append(f'  pop rdi')
                if l >= 2:
                    nasm.append(f'  pop rsi')
                if l >= 3:
                    nasm.append(f'  pop rdx')
                if l >= 4:
                    nasm.append(f'  pop rcx')
                if l >= 5:
                    nasm.append(f'  pop r8')
                if l >= 6:
                    nasm.append(f'  pop r9')
                nasm.append(f'  call {sym}')
                if l >= 1:
                    nasm.append(f'  push rdi')
                if l >= 2:
                    nasm.append(f'  push rsi')
                if l >= 3:
                    nasm.append(f'  push rdx')
                if l >= 4:
                    nasm.append(f'  push rcx')
                if l >= 5:
                    nasm.append(f'  push r8')
                if l >= 6:
                    nasm.append(f'  push r9')
            else:
                nasm.append(f'  call {fname}')

        elif isinstance(node.func, ast.Attribute):
            fname = node.func.attr
            unimplemented('call method')

        if len(node.args) > 0:
            if not fname.startswith('api_'):
                nasm.append(f'  add rsp, {len(node.args) * 8}')

        self.generic_visit(node)


    '''
    def visit_arguments(self, node):
        global nasm
        #for i in range(len(node.args)):
        #    nasm.append(f'push {node.args[i]}')

        self.generic_visit(node)
    '''

    def visit_Return(self, node):
        global nasm
        if isinstance(node.value, ast.Constant):
            if node.value.value == 0:
                # return 0
                nasm.append(f'  xor rax, rax')
            else:
                # return 123
                nasm.append(f'  mov rax, {node.value.value}')
        elif isinstance(node.value, ast.Name):
            if is_reg(node.value.id):
                if node.value.id != 'rax':
                    # return rbx
                    nasm.append(f'  mov rax, {node.value.id}')
            else:
                # return var
                pos = self.vars.get_pos(self.current_func, node.value.id)
                nasm.append(f'  mov rax, [rbp-{pos}] ; {node.value.id}')
        else:
            unimplemented('return '+node.value)
        nasm.append('  leave')
        nasm.append('  ret')


    def visit_While(self, node):
        global nasm, lbl

        lbl_while = f'while{lbl}'
        lbl += 1
        nasm.append(f'\n{lbl_while}:')

        self.generic_visit(node)

        if isinstance(node.test, ast.Constant):
            if str(node.test.value) == 'True':
                nasm.append(f'  jmp {lbl_while}')
            else:
                unimplemented('value '+str(node.test.value))

        elif isinstance(node.test, ast.Compare):

            if isinstance(node.test.left, ast.Constant):
                left = node.test.left.value
            else:
                left = node.test.left.id
                if not is_reg(left):
                    pos = self.vars.get_pos(self.current_func, left)
                    left = f'qword [rbp-{pos}]'

            if isinstance(node.test.comparators[0], ast.Constant):
                right = node.test.comparators[0].value
            else:
                right = node.test.comparators[0].id
                if not is_reg(right):
                    pos = self.vars.get_pos(self.current_func, right)
                    right = f'qword [rbp-{pos}]'

            if is_reg(right) and is_reg(left):
                nasm.append(f'  cmp {left}, {right}')
            else:
                nasm.append(f'  mov rsi, {left}')
                nasm.append(f'  mov rdi, {right}')
                nasm.append(f'  cmp rsi, rdi')

            ops = node.test.ops[0]
            if isinstance(ops, ast.Gt):
                nasm.append(f'  jg {lbl_while}')
            elif isinstance(ops, ast.Lt):
                nasm.append(f'  jl {lbl_while}')
            elif isinstance(ops, ast.LtE):
                nasm.append(f'  jle {lbl_while}')
            elif isinstance(ops, ast.GtE):
                nasm.append(f'  jge {lbl_while}')
            elif isinstance(ops, ast.Eq):
                nasm.append(f'  je {lbl_while}')
            elif isinstance(ops, ast.NotEq):
                nasm.append(f'  jne {lbl_while}')
            else:
                unimplemented("while operator "+str(node.test.ops))
              
        else:
            unimplemented('while variant '+str(node.test))



    def visit_For(self, node):
        global nasm, lbl
        if isinstance(node.target, ast.Name):
            reg = node.target.id
            if isinstance(node.iter, ast.Call) and \
                    isinstance(node.iter.func, ast.Name) and \
                    node.iter.func.id == 'range':
                        args = node.iter.args
                        if len(args) == 1:
                            # range(stop)
                            range_min = 0 
                            if isinstance(args[0], ast.Constant):
                                range_max = args[0].value
                            else:
                                range_max = args[0].id
                                if not is_reg(range_max):
                                    pos = self.vars.get_pos(self.current_func, range_max)
                                    range_max = f'qword [rbp-{pos}]'

                            range_step = 1  
                        elif len(args) == 2:
                            # range(start, stop)
                            if isinstance(args[0], ast.Constant):
                                range_min = args[0].value
                            else:
                                range_min = args[0].id
                                if not is_reg(range_min):
                                    pos = self.vars.get_pos(self.current_func, range_min)
                                    range_min = f'qword [rbp-{pos}]'
                            if isinstance(args[1], ast.Constant):
                                range_max = args[1].value
                            else:
                                range_max = args[1].id
                                if not is_reg(range_max):
                                    pos = self.vars.get_pos(self.current_func, range_max)
                                    range_max = f'qword [rbp-{pos}]'
                            range_step = 1 
                        elif len(args) == 3:
                            # range(start, stop, step)
                            if isinstance(args[0], ast.Constant):
                                range_min = args[0].value
                            else:
                                range_min = args[0].id
                                if not is_reg(range_min):
                                    pos = self.vars.get_pos(self.current_func, range_min)
                                    range_min = f'qword [rbp-{pos}]'
                            if isinstance(args[1], ast.Constant):
                                range_max = args[1].value
                            else:
                                range_max = args[1].id
                                if not is_reg(range_max):
                                    pos = self.vars.get_pos(self.current_func, range_max)
                                    range_max = f'qowrd [rbp-{pos}]'
                            if isinstance(args[2], ast.Constant):
                                range_step= args[2].value
                            else:
                                range_step = args[2].id

                        pos = 0
                        if not is_reg(reg):
                            pos = self.vars.get_pos(self.current_func, reg)
                            #nasm.append(f'  mov rcx, qword [rbp-{pos}]')
                            reg = 'rcx'

                        nasm.append(f'  mov {reg}, {range_min}')
                        for_lbl = f'for{lbl}'
                        lbl += 1
                        nasm.append(f'{for_lbl}:')
                        self.generic_visit(node)
                        nasm.append(f'  add {reg}, {range_step}')
                        if pos > 0:
                            nasm.append(f'  mov qword [rbp-{pos}], {reg}')
                        nasm.append(f'  cmp {reg}, {range_max}')
                        nasm.append(f'  jl {for_lbl}')


            else:
                unimplemented('only for range is suported')
        else:
            unimplemented('complex for')


    def visit_If(self, node):
        global nasm, lbl

        #nasm.append( ast.unparse(node.test) )

        if isinstance(node.test, ast.Compare) and \
                len(node.test.ops) == 1 and \
                len(node.test.comparators) == 1:
                    left = node.test.left
                    op = node.test.ops[0]
                    right = node.test.comparators[0]

                    cmpsb = False
                    if isinstance(left, ast.Call) and isinstance(right, ast.Call):
                        if left.func.id == 'str' and right.func.id == 'str':
                            left = left.args[0].id
                            right = right.args[0].id
                            cmpsb = True
                        else:
                            unimplemented('weird if + call')

                    if cmpsb:
                        nasm.append(f'  rep cmpsb')
                    else:
                        if isinstance(left, ast.Subscript):
                            var = left.value.id 
                            pos = self.vars.get_pos(self.current_func, var)
                            if isinstance(left.slice, ast.Constant):
                                # if a[0] == 3
                                idx = left.slice.value
                                nasm.append(f'  mov rsi, qword [rbp-{pos}] ; {var}')
                                nasm.append(f'  mov al, byte [rsi+{idx}]')
                            else:
                                # if a[i] == 3
                                idx = left.slice.id
                                pos2 = self.vars.get_pos(self.current_func, idx)
                                nasm.append(f'  mov rsi, qword [rbp-{pos}] ; {var}')
                                nasm.append(f'  mov rdi, qword [rbp-{pos2}] ; {idx}')
                                nasm.append(f'  mov al, byte [rsi+rdi]')
                            left = ' al'

                        if isinstance(right, ast.Subscript):
                            # if 3 == a[0]:
                            var = right.value.id 
                            pos = self.vars.get_pos(self.current_func, var)
                            if isinstance(left.slice, ast.Constant):
                                # if a[0] == ...
                                idx = right.slice.value
                                nasm.append(f'  mov rsi, qword [rbp-{pos}] ; {var}')
                                nasm.append(f'  mov bl, byte [rsi]')
                            else:
                                # if a[i] == ...
                                idx = right.slice.id
                                pos2 = self.vars.get_pos(self.current_func, idx)
                                nasm.append(f'  mov rsi, qword [rbp-{pos}] ; {var}')
                                nasm.append(f'  mov rdi, qword [rbp-{pos2}] ; {idx}')
                                nasm.append(f'  mov bl, byte [rsi+rdi]')
                            right = ' bl'

                       
                        
                        if not isinstance(left, str):
                            if isinstance(left, ast.Constant):
                                # if 3 == ...
                                left = left.value
                            else:
                                # if a == ...
                                left = left.id

                        if not isinstance(right, str):
                            if isinstance(right, ast.Constant):
                                # if ... == 3
                                right = right.value
                            else:
                                # if ... == a
                                right = right.id

                        if is_reg(left) and not is_reg(right):
                            # if eax == 3:
                            pos = self.vars.get_pos(self.current_func, right)
                            right = f'qword [rbp-{pos}]'
                        elif not is_reg(left) and is_reg(right):
                            # if 3 == eax:
                            pos = self.vars.get_pos(self.current_func, left)
                            left = f'qword [rbp-{pos}]'
                        else:
                            # let's alloc if var1 == var2 using rsi and rdi
                            if left != ' al' and right != ' bl':
                                # if a == b: 64bits compare
                                pos1 = self.vars.get_pos(self.current_func, left)
                                nasm.append(f'  mov rsi, [rbp-{pos1}] ; {left}')
                                left = 'rsi'

                                pos2 = self.vars.get_pos(self.current_func, right)
                                nasm.append(f'  mov rdi, [rbp-{pos2}] ; {right}')
                                right = 'rdi'
                            elif left == ' al' and right == ' bl':
                                pass
                            elif left == ' al' and right != ' bl':
                                try:
                                    n = int(right)
                                    nasm.append(f'  mov bl, byte {right}')
                                except:
                                    nasm.append(f'  mov bl, byte \'{right}\'')
                                right = ' bl'
                            elif left != ' al' and right == ' bl':
                                try:
                                    n = int(left)
                                    nasm.append(f'  mov al, byte {left}')
                                except:
                                    nasm.append(f'  mov al, byte \'{left}\'')
                                left = ' al'
                            else:
                                unimiplemented("imposible case")


                        nasm.append(f'  cmp {left}, {right}')

                    label_if = f'if{lbl}'
                    lbl += 1
                    if isinstance(op, ast.Gt):
                        nasm.append(f'  jg {label_if}')
                    elif isinstance(op, ast.Lt):
                        nasm.append(f'  jl {label_if}')
                    elif isinstance(op, ast.LtE):
                        nasm.append(f'  jle {label_if}')
                    elif isinstance(op, ast.GtE):
                        nasm.append(f'  jge {label_if}')
                    elif isinstance(op, ast.Eq):
                        nasm.append(f'  je {label_if}')
                    elif isinstance(op, ast.NotEq):
                        nasm.append(f'  jne {label_if}')
                    else:
                        unimplemented("if operator "+str(node.test.op))


                    if node.orelse:
                        label_else = f'else{lbl}'
                        lbl += 1
                        label_endif = f'endif{lbl}'
                        lbl += 1
                        nasm.append(f'  jmp {label_else}')
                        nasm.append(f'\n{label_if}:')
                        for b in node.body:
                            self.visit(b)
                        nasm.append(f'  jmp {label_endif}')
                        nasm.append(f'\n{label_else}:')
                        for e in node.orelse:
                            self.visit(e)
                        nasm.append(f'\n{label_endif}:')
                        return

                    label_noif = f'endif{lbl}'
                    lbl += 1

                    nasm.append(f'  jmp {label_noif}')
                    nasm.append(f'\n{label_if}:')
                    self.generic_visit(node)
                    nasm.append(f'\n{label_noif}:')
                    
                    
        else:
            unimplemented('complex if')


    def visit_Assign(self, node):
        global nasm, lbl
        for target in node.targets:
            if isinstance(node.value, ast.Constant):
                if node.value.value == 0:
                    if isinstance(target, ast.Subscript):
                        pos = self.vars.get_pos(self.current_func, target.value.id)
                        if isinstance(target.slice, ast.Name):
                            # arr[i] = 0
                            idx = target.slice.id
                            pos2 = self.vars.get_pos(self.current_func, idx)
                            nasm.append(f'  mov rsi, qword [rbp-{pos2}] ; {idx}')
                            nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {target.value.id}')
                            nasm.append(f'  mov byte [rdi+rsi], 0')
                        else:
                            # arr[3] = 0
                            idx = target.slice.value
                            nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {target.value.id}')
                            nasm.append(f'  mov byte [rdi+{idx}], 0') 
                    else:
                        if is_reg(target.id):
                            # rax = rbx = 0
                            nasm.append(f'  xor {target.id}, {target.id}')
                        else:
                            # var = 0
                            pos = self.vars.get_pos(self.current_func, target.id)
                            nasm.append(f'  mov qword [rbp-{pos}], 0 ; {target.id}')
                else:
                    # value nonzero

                    if isinstance(target, ast.Subscript):
                        var = target.value.id
                        if isinstance(target.slice, ast.Constant):
                            # var[idx] = val
                            # arr[3] = 0x33
                            idx = target.slice.value
                            pos = self.vars.get_pos(self.current_func, var)
                            val = node.value.value

                            nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {var}')
                            nasm.append(f'  mov byte [rdi+{idx}], {val} ')


                        elif isinstance(target.slice, ast.Name):
                            # var[idx] = val
                            # arr[i] = 0x33
                            idx = target.slice.id
                            pos = self.vars.get_pos(self.current_func, var)
                            pos1 = self.vars.get_pos(self.current_func, idx)
                            val = node.value.value

                            nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {var}')
                            nasm.append(f'  mov rsi, qword [rbp-{pos2}] ; {idx}')
                            nasm.append(f'  mov byte [rdi+rsi], {val}')

                    else:
                        try:
                            n = int(node.value.value)
                            if is_reg(target.id):
                                # rcx = 3
                                nasm.append(f'  mov {target.id}, {node.value.value}')
                            else:
                                # var = 3
                                pos = self.vars.get_pos(self.current_func, target.id)
                                nasm.append(f'  mov qword [rbp-{pos}], {node.value.value} ; {target.id}')
                        except Exception as e:
                            # strings  s = 'hello'
                            nasm.append(f'  call lbl{lbl}')
                            s = node.value.value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t')
                            nasm.append(f'  db "{s}",0')
                            nasm.append(f'lbl{lbl}:')
                            lbl += 1
                            if is_reg(target.id):
                                nasm.append(f'  pop {target.id}')
                            else:
                                pos = self.vars.get_pos(self.current_func, target.id, node.value.value)
                                nasm.append(f'  pop rdi')
                                nasm.append(f'  mov [rbp-{pos}], rdi ; {target.id}')

            elif isinstance(node.value, ast.Name):
                if node.value.id == 'PEB':
                    nasm.append(f'  xor rdi, rdi')
                    if is_reg(target.id):
                        # eax = PEB
                        nasm.append(f'  mov {target.id}, gs:[rdi+0x60]')
                    else:
                        # the_peb = PEB
                        pos = self.vars.get_pos(self.current_func, target.id)
                        nasm.append(f'  mov rsi, gs:[rdi+0x60]')
                        nasm.append(f'  mov qword [rbp-{pos}], rsi ; {target.id}')

                else:
                    if isinstance(target, ast.Subscript):
                        # target.value.id[target.slice.id] = node.value.id
                        pos = self.vars.get_pos(self.current_func, target.value.id)
                        val = node.value.id

                        if isinstance(target.slice, ast.Constant):
                            # var[3] = al
                            idx = target.slice.value
                            nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {target.value.id}')
                            nasm.append(f'  mov [rdi+{idx}], {val}')
                        elif isinstance(target.slice, ast.Name):
                            # var[i] = al
                            idx = target.slice.id
                            pos2 = self.vars.get_pos(self.current_func, idx)
                            nasm.append(f'  mov rsi, [rbp-{pos2}] ; {idx}')
                            nasm.append(f'  mov rdi, [rbp-{pos}] ; {target.value.id}')
                            nasm.append(f'  mov [rdi+rsi], {val}') 
                        else:
                            unimplemented('weird array[] = reg')

                        
                    elif isinstance(target, ast.Name):
                        if target.id != node.value.id:
                            if is_reg(target.id) and is_reg(node.value.id):
                                nasm.append(f'  mov {target.id}, {node.value.id}')
                            elif not is_reg(target.id) and is_reg(node.value.id):
                                pos = self.vars.get_pos(self.current_func, target.id)
                                nasm.append(f'  mov qword [rbp-{pos}], {node.value.id} ; {target.id}')
                            elif is_reg(target.id) and not is_reg(node.value.id):
                                pos = self.vars.get_pos(self.current_func, node.value.id)
                                nasm.append(f'  mov {target.id}, qword [rbp-{pos}] ; {node.value.id}')
                        else:
                            unimplemented("var = var not alowed, so does eax = eax")


            elif isinstance(node.value, ast.Subscript):
                if node.value.value.id == 'mem':
                    # mem as second argument ... = mem[ ... ]

                    if isinstance(node.value.slice, ast.BinOp):
                        # mem[rax+something]
                        left = node.value.slice.left.id

                        if isinstance(node.value.slice.op, ast.Add):
                            op1 = '+'
                        elif isinstance(node.value.slice.op, ast.Sub):
                            op1 = '-' 
                        elif isinstance(node.value.slice.op, ast.Mult):
                            op1 = '*'
                        elif isinstance(node.value.slice.op, ast.Div):
                            op1 = '/'
                        else:
                            unimplemented('weird memory access operation')


                        if isinstance(node.value.slice.right, ast.Constant):
                            # mem[rax+3]
                            right = node.value.slice.right.value
                            nasm.append(f'  mov {target.id}, [{left}{op1}{right}] ; mem[rax+3]')

                        elif isinstance(node.value.slice.right, ast.Name):
                            # mem[rax+rbx]
                            right = node.value.slice.right.id
                            nasm.append(f'  mov {target.id}, [{left}{op1}{right}] ; mem[rax+rbx]')
                        else:
                            if isinstance(node.value.slice.right, ast.BinOp):
                                # mem[eax+ebx*8]

                                if isinstance(node.value.slice.right.left, ast.Name):
                                    right_left = node.value.slice.right.left.id
                                else:
                                    unimplemented('bad assign, has to be like [reg+reg*num]')
                                
                                if isinstance(node.value.slice.right.right, ast.Constant):
                                    right_right = node.value.slice.right.right.value
                                else:
                                    unimplemented('bad assign, has to be like [reg+reg*num]')


                                if isinstance(node.value.slice.right.op, ast.Add):
                                    op2 = '+'
                                elif isinstance(node.value.slice.right.op, ast.Sub):
                                    op2 = '-' 
                                elif isinstance(node.value.slice.right.op, ast.Mult):
                                    op2 = '*'
                                elif isinstance(node.value.slice.right.op, ast.Div):
                                    op2 = '/'
                                else:
                                    unimplemented('weird memory access operation2')

                                nasm.append(f'  mov {target.id}, [{left}{op1}{right_left}{op2}{right_right}] ; mem[rax+rbx*8]')
                            else:
                                unimplemented('weird assign')


                    elif isinstance(node.value.slice, ast.Name):
                        # rax = mem[rbx]
                        reg = node.value.slice.id
                        nasm.append(f'  mov {target.id}, [{reg}] ; x = mem[rbx]')
                    elif isinstance(node.value.slice, ast.Constant):
                        # rax = mem[0x11223344]
                        nasm.append(f'  mov {target.id}, qword [0x{node.value.slice.value:x}] ; x = mem[0x11223344]')
                    else:
                        unimplemented(node.value.slice)
                else:
                    '''
                        mistr = 'test'
                        l = len(mistr)
                        bl = al = mistr[0]
                        if mistr[0] == al:
                    '''
                    var = node.value.value.id
                    pos = self.vars.get_pos(self.current_func, var)
                    if isinstance(node.value.slice, ast.Constant):
                        idx = node.value.slice.value
                        nasm.append(f'  mov rsi, [rbp-{pos}] ; {var}')
                        nasm.append(f'  mov {target.id}, byte [rsi+{idx}]')
                    elif isinstance(node.value.slice, ast.Name):
                        idx = node.value.slice.id
                        nasm.append(f'  mov rsi, [rbp-{pos}] ; {var}')
                        if is_reg(idx):
                            nasm.append(f'  mov rdi, {idx}')
                        else:
                            pos2 = self.vars.get_pos(self.current_func, idx)
                            nasm.append(f'  mov rdi, [rbp-{pos2}] ; {idx}')
                        nasm.append(f'  mov {target.id}, byte [rsi+rdi]')

                    else:
                        unimplemented("weird array case")


            elif isinstance(node.value, ast.Call): # asign call: ebx = somthing()
                self.generic_visit(node)
                if isinstance(target, ast.Subscript):
                    pos = self.vars.get_pos(self.current_func, target.slice.id)
                    nasm.append(f'  mov rdi, qword [rbp-{pos}] ; {target.slice.id}')
                    nasm.append(f'  mov qword [rdi], rax')

                else:
                    if is_reg(target.id):
                        nasm.append(f'  mov {target.id}, rax')
                    else:
                        pos = self.vars.get_pos(self.current_func, target.id)
                        nasm.append(f'  mov [rbp-{pos}], rax ; {target.id}')
                return


            elif isinstance(node.value, ast.List):

                if len(node.value.elts) == 0:
                    unimplemented("cannot define an empty array")
                
                else:
                    line = '  db '
                    for byte in node.value.elts:
                        line += hex(byte.value)
                        line += ', '
                    line = line[:-1]
                    nasm.append(f'  call arr{lbl}')
                    nasm.append(line)
                    nasm.append(f'arr{lbl}:')
                    lbl += 1
                    if is_reg(target.id):
                        nasm.append(f'  pop {target.id}')
                    else:
                        pos = self.vars.get_pos(self.current_func, target.id, 'A'*len(node.value.elts))
                        nasm.append(f'  pop rdi')
                        nasm.append(f'  mov qword [rbp-{pos}], rdi ; {target.id}')


            else:
                unimplemented('assign else')


        self.generic_visit(node)



    def visit_AugAssign(self, node):
        global nasm
        var2var = ()
        prevreg = reg = node.target.id # dst

        if not is_reg(reg):
            pos = self.vars.get_pos(self.current_func, reg)
            prevreg = reg
            reg = f'qword [rbp-{pos}]'

        if isinstance(node.value, ast.Name):
            val = node.value.id # src
            if not is_reg(val):
                if not is_reg(reg):
                    # var1 += var2
                    pos2 = self.vars.get_pos(self.current_func, val)
                    nasm.append(f'  mov rsi, [rbp-{pos2}] ; {val}');
                    nasm.append(f'  mov rdi, [rbp-{pos}] ; {prevreg}');
                    val = 'rsi'
                    reg = 'rdi'
                    var2var = (pos, pos2) 
                else:
                    # var1 += rax
                    pos = self.vars.get_pos(self.current_func, val)
                    val = f'qword [rbp-{pos}] ; {val}'


        elif isinstance(node.value, ast.Constant):
            val = node.value.value
        else:
            unimplemented(node.value)


        if isinstance(node.op, ast.Add):
            nasm.append(f'  add {reg}, {val}')
        elif isinstance(node.op, ast.Sub):
            nasm.append(f'  sub {reg}, {val}')
        elif isinstance(node.op, ast.Mult):
            nasm.append(f'  mov rax, {val}')
            nasm.append(f'  mul {reg}')
        elif isinstance(node.op, ast.Div):
            nasm.append(f'  xor rdx, rdx')
            nasm.append(f'  mov rax, {reg}')
            nasm.append(f'  mov {reg}, {val}')
            nasm.append(f'  div {reg}')
        elif isinstance(node.op, ast.BitXor):
            nasm.append(f'  xor {reg}, {val}')
        else:
            unimplemented(node.op)

        if var2var:
            nasm.append(f'  mov rsi, [rbp-{var2var[1]}] ; {prevreg}')




def main(pyfile):
    global nasm

    tree = ast.parse(open(pyfile).read())

    win64_mode = False
    lin64_mode = False
    raw64_mode = False
    if 'exe' in sys.argv:
        win64_mode = True
    elif 'elf' in sys.argv:
        lin64_mode = True
    elif '64' in sys.argv:
        raw64_mode = True

    
    visitor = visit_functions()
    visitor.visit(tree)

    nasmfile = pyfile.replace('.py','.nasm')
    if win64_mode:
        code ='''
; python compiled with pynasm
bits 64
default rel
global _start
section .text
_start:
    call main
    jmp end
        '''+'\n'.join(nasm)+'\n\nend:\n  int 3' 
    elif lin64_mode:
        code ='''
; python compiled with pynasm
bits 64
default rel
'''
        for e in extern:
            code+=f'extern {e}\n'
        code+='''
global main
section .text

        '''+'\n'.join(nasm)+'\n\nend:\n  int 3' 
    elif raw64_mode:
        code ='''
; python compiled with pynasm
bits 64
default rel
call main
jmp end
        '''+'\n'.join(nasm)+'\n\nend:\n  int 3' 
    else:
        code ='''
; python compiled with pynasm
bits 32
default rel
call main
jmp end
        '''+'\n'.join(nasm)+'\n\nend:\n  int 3' 



    open(nasmfile,'w').write(code)
    if win64_mode:
        os.system(f'nasm -f win64 {nasmfile} -o {nasmfile.replace(".nasm",".obj")}')
        os.system(f'x86_64-w64-mingw32-ld {nasmfile.replace(".nasm",".obj")} -o {pyfile.replace(".py", ".exe")} -e main')
    elif lin64_mode:
        os.system(f'nasm -f elf64 {nasmfile} -o {nasmfile.replace(".nasm",".o")}')
        os.system(f'gcc {nasmfile.replace(".nasm",".o")} -o {pyfile.replace(".py", "")} -no-pie')
    elif raw64_mode:
        os.system(f'nasm -f bin {nasmfile} -o {nasmfile.replace(".nasm",".bin")}')
        

main(sys.argv[1])


