'''
    Python3 to nasm 64bits
    @sha0coder

    Disclaimer!! dont use this to create malicious payloads.
'''


import sys
import ast

nasm = []
lbl = 1

regs64 = ['rax','rbx','rcx','rdx','rsi','rdi', 'rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15']


def unimplemented(msg): # rust style
    print(f'UNIMPLEMENTED: {msg}')
    sys.exit(1)


class visit_functions(ast.NodeVisitor):
    def __init__(self):
        pass


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
        nasm.append(f'\n{node.name}:')
        nasm.append(f'  push rbp')
        nasm.append(f'  mov rbp, rsp')
        nasm.append(f'  sub rsp, 32')
        i = 16 
        for arg in node.args.args:
            nasm.append(f'  mov {arg.arg}, [rbp+{i}]')
            i += 8
        self.generic_visit(node)

    
    def visit_Pass(self, node):
        global nasm
        nasm.append('  nop')
        self.generic_visit(node)


    def visit_Call(self, node):
        global nasm
    
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
            elif node.func.id in regs64:
                # call reg64 -> use 64bits calling convention

                l = len(node.args)
                if l >= 1:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant):  # constants 
                        arg = arg.value
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                    if arg != 'rcx':
                        nasm.append(f'  mov rcx, {arg}')
                if l >= 2:
                    arg = node.args[1]
                    if isinstance(arg, ast.Constant):  # constants 
                        arg = arg.value
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                    if arg != 'rdx':
                        nasm.append(f'  mov rdx, {arg}')
                if l >= 3:
                    arg = node.args[2]
                    if isinstance(arg, ast.Constant):  # constants 
                        arg = arg.value
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                    if arg != 'r8':
                        nasm.append(f'  mov r8, {arg}')
                if l >= 4:
                    arg = node.args[3]
                    if isinstance(arg, ast.Constant):  # constants 
                        arg = arg.value
                    elif isinstance(arg, ast.Name):  # vars
                        arg = arg.id
                    if arg != 'r9':
                        nasm.append(f'  mov r9, {arg}')
                if l > 4:
                    for arg in reversed(node.args[4:]):
                        if isinstance(arg, ast.Constant):  # constants 
                            arg = arg.value
                        elif isinstance(arg, ast.Name):  # vars
                            arg = arg.id
                        nasm.append(f'  push {arg}')
                nasm.append(f'  call {node.func.id}')
                return



        for arg in reversed(node.args):
            if isinstance(arg, ast.Constant):  # constants 
                nasm.append(f'  push {arg.value}')
            elif isinstance(arg, ast.Name):  # vars
                nasm.append(f'  push {arg.id}')

        if isinstance(node.func, ast.Name):
            fname = node.func.id
            if fname.startswith('api_'):
                nasm.append(f'  apicall {fname}')
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
            nasm.append(f'  mov rax, {node.value.value}')
        elif isinstance(node.value, ast.Name):
            if node.value.id != 'rax':
                nasm.append(f'  mov rax, {node.value.id}')
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
                unimplemented('value'+str(node.test.value))

        elif isinstance(node.test, ast.Compare):

            if isinstance(node.test.left, ast.Constant):
                left = node.test.left.value
            else:
                left = node.test.left.id

            if isinstance(node.test.comparators[0], ast.Constant):
                right = node.test.comparators[0].value
            else:
                right = node.test.comparators[0].id

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
                            range_step = 1  
                        elif len(args) == 2:
                            # range(start, stop)
                            if isinstance(args[0], ast.Constant):
                                range_min = args[0].value
                            else:
                                range_min = args[0].id
                            if isinstance(args[1], ast.Constant):
                                range_max = args[1].value
                            else:
                                range_max = args[1].id
                            range_step = 1 
                        elif len(args) == 3:
                            # range(start, stop, step)
                            if isinstance(args[0], ast.Constant):
                                range_min = args[0].value
                            else:
                                range_min = args[0].id
                            if isinstance(args[1], ast.Constant):
                                range_max = args[1].value
                            else:
                                range_max = args[1].id
                            if isinstance(args[2], ast.Constant):
                                range_step= args[2].value
                            else:
                                range_step = args[2].id
                        nasm.append(f'  mov {reg}, {range_min}')
                        for_lbl = f'for{lbl}'
                        lbl += 1
                        nasm.append(f'{for_lbl}:')
                        self.generic_visit(node)
                        nasm.append(f'  add {reg}, {range_step}')
                        nasm.append(f'  cmp {reg}, {range_max}')
                        nasm.append(f'  jle {for_lbl}')


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
                        nasm.append(f'  repe cmpsb')
                    else:
                        if isinstance(left, ast.Constant):
                            left = left.value
                        else:
                            left = left.id
                        if isinstance(right, ast.Constant):
                            right = right.value
                        else:
                            right = right.id
                        nasm.append(f'  mov rsi, {str(left)}')
                        nasm.append(f'  mov rdi, {str(right)}')
                        nasm.append('  cmp rsi, rdi')

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
                    nasm.append(f'  xor {target.id}, {target.id}')
                else:
                    try:
                        n = int(node.value.value)
                        nasm.append(f'  mov {target.id}, {node.value.value}')
                    except:
                        nasm.append(f'  call lbl{lbl}')
                        nasm.append(f'  db "{node.value.value}",0')
                        nasm.append(f'lbl{lbl}:')
                        nasm.append(f'  pop {target.id}')
                        lbl += 1
            elif isinstance(node.value, ast.Name):
                if node.value.id == 'PEB':
                    nasm.append(f'  xor rdi, rdi')
                    nasm.append(f'  mov {target.id}, gs:[rdi+0x60]')
                else:
                    if target.id != node.value.id:
                        nasm.append(f'  mov {target.id}, {node.value.id}')

            elif isinstance(node.value, ast.Subscript):
                if node.value.value.id == 'mem':
                    if isinstance(node.value.slice, ast.BinOp):
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
                            right = node.value.slice.right.value
                            nasm.append(f'  mov {target.id}, [{left}{op1}{right}]')
                        elif isinstance(node.value.slice.right, ast.Name):
                            right = node.value.slice.right.id
                            nasm.append(f'  mov {target.id}, [{left}{op1}{right}]')
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


                                nasm.append(f'  mov {target.id}, [{left}{op1}{right_left}{op2}{right_right}]')
                            else:
                                unimplemented('weird assign')


                    elif isinstance(node.value.slice, ast.Name):
                        reg = node.value.slice.id
                        nasm.append(f'  mov {target.id}, [{reg}]')
                    else:
                        unimplemented(node.value.slice)
                else:
                    unimplemented('array')

            elif isinstance(node.value, ast.Call): # asign call: ebx = somthing()
                self.generic_visit(node)
                nasm.append(f'  mov {target.id}, rax')
                return


            else:
                unimplemented('assign '+node.value)


        self.generic_visit(node)



    def visit_AugAssign(self, node):
        global nasm
        reg = node.target.id
        if isinstance(node.value, ast.Name):
            val = node.value.id
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
            nasm.append(f'  mov eax, {reg}')
            nasm.append(f'  mov {reg}, {val}')
            nasm.append(f'  div {reg}')
        elif isinstance(node.op, ast.BitXor):
            nasm.append(f'  xor {reg}, {val}')
        else:
            unimplemented(node.op)

        




def main(pyfile):
    global nasm

    tree = ast.parse(open(pyfile).read())

    
    visitor = visit_functions()
    visitor.visit(tree)

    nasmfile = pyfile.replace('.py','.nasm')
    open(nasmfile,'w').write('; python compiled with pynasm\n\nBITS 64\n\ncall main\njmp end\n'+'\n'.join(nasm)+'\n\nend:')



main(sys.argv[1])


