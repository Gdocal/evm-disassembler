#!/usr/bin/env python3.6

import sys
import json
import math
from copy import deepcopy
from z3 import *
from typing import List, Dict, Tuple, Any
from byte2op import Opcode, decode

from collections import defaultdict

from timeit import default_timer as timer
from eliot import to_file, log_call, start_action
to_file(open("out.log", "w"))

set_option(timeout=500)
set_option(max_width=240)

Word = Any # z3 expression (including constants)
Byte = Any # z3 expression (including constants)

def wload(mem: List[Byte], loc: int, size: int) -> Word:
    return simplify(Concat(mem[loc:loc+size])) # BitVecSort(size * 8)

def wstore(mem: List[Byte], loc: int, size: int, val: Word) -> None:
    assert eq(val.sort(), BitVecSort(size*8))
    for i in range(size):
        mem[loc + i] = simplify(Extract((size-1 - i)*8+7, (size-1 - i)*8, val))

class State:
    stack: List[Word]
    memory: List[Byte]

    def __init__(self) -> None:
        self.stack: List[Word] = []
        self.memory: List[Byte] = []

    def __deepcopy__(self, memo):
        st = State()
        st.stack = deepcopy(self.stack)
        st.memory = deepcopy(self.memory)
        return st

    def __str__(self) -> str:
        return ''.join([
            "stack:  ", str(self.stack),
#           self.str_memory(),
            ])
#       return "stack:  " + str(self.stack) + \
#              self.str_memory()
#              # "memory: " + str(self.memory)

    def str_memory(self) -> str:
        idx: int = 0
        ret: str = ""
        size: int = len(self.memory)
        while idx < size:
            ret = ret + "\n" + "memory[" + str(idx) + "]: " + str(self.memory[idx:min(idx+32,size)])
            idx = idx + 32
        return ret

    def push(self, v: Word) -> None:
        assert eq(v.sort(), BitVecSort(256)) or eq(v.sort(), BoolSort())
        self.stack.insert(0, simplify(v))
        #self.stack.insert(0, v)

    def pop(self) -> Word:
        v = self.stack[0]
        del self.stack[0]
        return v

    def dup(self, n: int) -> None:
        self.push(self.stack[n-1])

    def swap(self, n: int) -> None:
        tmp = self.stack[0]
        self.stack[0] = self.stack[n]
        self.stack[n] = tmp

    def mloc(self) -> int:
        loc: int = int(str(self.pop())) # loc must be concrete
        while len(self.memory) < loc + 32:
            self.memory.extend([BitVecVal(0, 8) for _ in range(32)])
        return loc

    def mstore(self) -> None:
        loc: int = self.mloc()
        val: Word = self.pop()
        if eq(val.sort(), BoolSort()):
            val = If(val, con(1), con(0))
        wstore(self.memory, loc, 32, val)
#       for i in range(32):
#           self.memory[loc + i] = simplify(Extract((31-i)*8+7, (31-i)*8, val))

    def mload(self) -> None:
        loc: int = self.mloc()
        self.push(wload(self.memory, loc, 32))
#       self.push(Concat(self.memory[loc:loc+32]))

    def sha3(self) -> None:
        loc: int = self.mloc()
        size: int = int(str(self.pop())) # size (in bytes) must be concrete
        sha3: Any = Function('sha3_'+str(size*8), BitVecSort(size*8), BitVecSort(256))
        self.push(sha3(wload(self.memory, loc, size)))
#       self.push(sha3(Concat(self.memory[loc:loc+size])))

    def ret(self) -> Word:
        loc: int = self.mloc()
        size: int = int(str(self.pop())) # size (in bytes) must be concrete
        if size > 0:
            return wload(self.memory, loc, size)
#           return simplify(Concat(self.memory[loc:loc+size]))
        else:
            return None

def con(n: int) -> Word:
    return BitVecVal(n, 256)

f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256)) # index
f_calldatasize = Function('calldatasize', BitVecSort(256))
f_callvalue = Function('callvalue', BitVecSort(256))
f_caller = Function('caller', BitVecSort(256))
f_address = Function('address', BitVecSort(256))
f_extcodesize = Function('extcodesize', BitVecSort(256), BitVecSort(256)) # target address
f_gas = Function('gas', IntSort(), BitVecSort(256)) # cnt
f_timestamp = Function('timestamp', BitVecSort(256))
f_balance = Function('balance', BitVecSort(256), IntSort(), BitVecSort(256)) # target address, cnt
#f_selfbalance = Function('selfbalance', IntSort(), IntSort(), BitVecSort(256)) # pc, cnt

# convert opcode list to opcode map
def ops_to_pgm(ops: List[Opcode]) -> List[Opcode]:
    pgm: List[Opcode] = [None for _ in range(ops[-1].pc + 1)]
    for o in ops:
        pgm[o.pc] = o
    return pgm

def simplify_cnts(cnts: Dict[str,int]) -> Dict[str,int]:
    new_cnts = defaultdict(int)

    for (op, cnt) in cnts.items():
        if (   op == 'STOP'
            or op == 'RETURN'
            or op == 'REVERT'
        ):
            new_cnts['_0_zero'] += cnt
        elif (
               op == 'JUMPDEST'
        ):
            new_cnts['_1_jumpdest'] += cnt
        elif (
               op == 'ADDRESS'
            or op == 'ORIGIN'
            or op == 'CALLER'
            or op == 'CALLVALUE'
            or op == 'CALLDATASIZE'
            or op == 'RETURNDATASIZE'
            or op == 'CODESIZE'
            or op == 'GASPRICE'
            or op == 'COINBASE'
            or op == 'TIMESTAMP'
            or op == 'NUMBER'
            or op == 'DIFFICULTY'
            or op == 'GASLIMIT'
            or op == 'POP'
            or op == 'PC'
            or op == 'MSIZE'
            or op == 'GAS'
            or op == 'CHAINID'
        ):
            new_cnts['_2_base'] += cnt
        elif (
               op == 'ADD'
            or op == 'SUB'
            or op == 'NOT'
            or op == 'LT'
            or op == 'GT'
            or op == 'SLT'
            or op == 'SGT'
            or op == 'EQ'
            or op == 'ISZERO'
            or op == 'AND'
            or op == 'OR'
            or op == 'XOR'
            or op == 'BYTE'
            or op == 'SHL'
            or op == 'SHR'
            or op == 'SAR'
            or op == 'CALLDATALOAD'
            or op == 'MLOAD'
            or op == 'MSTORE'
            or op == 'MSTORE8'
            or op == 'PUSH1' or op == 'PUSH2' or op == 'PUSH3' or op == 'PUSH4' or op == 'PUSH5' or op == 'PUSH6' or op == 'PUSH7' or op == 'PUSH8' or op == 'PUSH9' or op == 'PUSH10' or op == 'PUSH11' or op == 'PUSH12' or op == 'PUSH13' or op == 'PUSH14' or op == 'PUSH15' or op == 'PUSH16' or op == 'PUSH17' or op == 'PUSH18' or op == 'PUSH19' or op == 'PUSH20' or op == 'PUSH21' or op == 'PUSH22' or op == 'PUSH23' or op == 'PUSH24' or op == 'PUSH25' or op == 'PUSH26' or op == 'PUSH27' or op == 'PUSH28' or op == 'PUSH29' or op == 'PUSH30' or op == 'PUSH31' or op == 'PUSH32'
            or op == 'DUP1' or op == 'DUP2' or op == 'DUP3' or op == 'DUP4' or op == 'DUP5' or op == 'DUP6' or op == 'DUP7' or op == 'DUP8' or op == 'DUP9' or op == 'DUP10' or op == 'DUP11' or op == 'DUP12' or op == 'DUP13' or op == 'DUP14' or op == 'DUP15' or op == 'DUP16'
            or op == 'SWAP1' or op == 'SWAP2' or op == 'SWAP3' or op == 'SWAP4' or op == 'SWAP5' or op == 'SWAP6' or op == 'SWAP7' or op == 'SWAP8' or op == 'SWAP9' or op == 'SWAP10' or op == 'SWAP11' or op == 'SWAP12' or op == 'SWAP13' or op == 'SWAP14' or op == 'SWAP15' or op == 'SWAP16'
        ):
            new_cnts['_3_verylow'] += cnt
        elif (
               op == 'MUL'
            or op == 'DIV'
            or op == 'SDIV'
            or op == 'MOD'
            or op == 'SMOD'
            or op == 'SIGNEXTEND'
            or op == 'SELFBALANCE'
        ):
            new_cnts['_5_low'] += cnt
        else:
            new_cnts[op] = cnt

    return new_cnts

class Exec:
    pgm: List[Opcode]
    code: List[str]
    st: State
    pc: int
    sol: Solver
    storage: Any # Array('storage', BitVecSort(256), BitVecSort(256))
    output: Any
    log: List[Tuple[List[Word], Any]]
    balance: Any
    cnts: Dict[str,int]

    def __init__(self, pgm: List[Opcode], code: List[str], st: State, pc: int, sol: Solver, storage: Any, output: Any, log: List[Tuple[List[Word], Any]], balance: Any, cnts: Dict[str,int]) -> None:
        self.pgm = pgm
        self.code = code
        self.st = st
        self.pc = pc
        self.sol = sol
        self.storage = storage
        self.output = output
        self.log = log
        self.balance = balance
        self.cnts = cnts

    def str_cnts(self) -> str:
#       cnts = self.cnts
        cnts = simplify_cnts(self.cnts)
        return ''.join([f'{x[0]}: {x[1]}\n' for x in sorted(cnts.items(), key=lambda x: x[0])])

    def summary(self) -> str:
        return ''.join([
            str(self.pc), ' ', str(self.pgm[self.pc].op[0]), "\n",
            "stack3:  ", str(self.st.stack[0:3]), "\n",
            "storage: ", str(self.storage), "\n",
            "balance: ", str(self.balance), "\n",
            "output: " , str(self.output) , "\n",
            "log: "    , str(self.log)    , "\n",
            ])

    def __str__(self) -> str:
        return ''.join([
            str(self.pc), ' ', str(self.pgm[self.pc].op[0]), "\n",
            str(self.st), "\n",
            "storage: ", str(self.storage), "\n",
            "balance: ", str(self.balance), "\n",
            "path: "   , str(self.sol)    , "\n",
            "output: " , str(self.output) , "\n",
            "log: "    , str(self.log)    , "\n",
            "opcodes:\n", self.str_cnts(),
            "memsize: ", str(len(self.st.memory)), "\n",
            ])
#       return str(self.pc) + " " + str(self.pgm[self.pc].op[0]) + "\n" + \
#              str(self.st) + "\n" + \
#              "storage: " + str(self.storage) + "\n" + \
#              "path: " + str(self.sol) + "\n" + \
#              "output: " + str(self.output) + "\n" + \
#              "log: " + str(self.log) + "\n"

    def next_pc(self) -> int:
        self.pc += 1
        while self.pgm[self.pc] is None:
            self.pc += 1

    def sstore(self, loc: Any, val: Any):
        new_storage = Array(f'storage{self.cnt_sstore()}', BitVecSort(256), BitVecSort(256))
        self.sol.add(new_storage == Store(self.storage, loc, val))
        self.storage = new_storage

    def cnt_call(self) -> int:
        return self.cnts['CALL'] + self.cnts['STATICCALL']
    def cnt_sstore(self) -> int:
        return self.cnts['SSTORE']
    def cnt_gas(self) -> int:
        return self.cnts['GAS']
    def cnt_balance(self) -> int:
        return self.cnts['BALANCE']

def read_code(code: List[str], idx: int) -> str:
    if idx < len(code):
        return code[idx]
    else:
        return '00'

# TODO: cleanup
def simp(expr: Word) -> Word:
#   print("start " + str(expr))
    # expr: 0 == If(cond, 1, 0)  ==>  Not(cond)
    # expr: 0 != If(cond, 1, 0)  ==>      cond
    # expr: 0 == If(cond, 0, 1)  ==>      cond
    # expr: 0 != If(cond, 0, 1)  ==>  Not(cond)
    if (expr.decl().name() == '=' or expr.decl().name() == 'distinct') and eq(expr.arg(0), con(0)):
#       print("then-1")
        rhs = expr.arg(1)
        # If(cond, 1, 0)
        if rhs.decl().name() == 'if' and eq(rhs.arg(1), con(1)) and eq(rhs.arg(2), con(0)):
#           print("then-2")
            cond = simp(rhs.arg(0))
            if expr.decl().name() == '=':
                return Not(cond)
            else: # expr.decl().name() == 'distinct':
                return cond
        # If(cond, 0, 1)
        elif rhs.decl().name() == 'if' and eq(rhs.arg(1), con(0)) and eq(rhs.arg(2), con(1)):
            cond = simp(rhs.arg(0))
            if expr.decl().name() == '=':
                return cond
            else: # expr.decl().name() == 'distinct':
                return Not(cond)
        else:
            return expr
#           print("else-2")
    else:
        return expr
#       print("else-1")

#             x  == b   if sort(x) = bool
# int_to_bool(x) == b   if sort(x) = int
def test(x: Word, b: bool) -> Word:
    if eq(x.sort(), BoolSort()):
        if b:
            return x
        else:
            return Not(x)
    elif x.sort().name() == 'bv':
        if b:
            return (x != con(0))
        else:
            return (x == con(0))
    else:
        print(x)
        raise Exception('invalid argument of test: ' + x)

def is_non_zero(x: Word) -> Word:
    return test(x, True)

def is_zero(x: Word) -> Word:
    return test(x, False)

def and_or(x: Word, y: Word, is_and: bool) -> Word:
    if eq(x.sort(), BoolSort()) and eq(y.sort(), BoolSort()):
        if is_and:
            return And(x, y)
        else:
            return Or(x, y)
    #elif x.sort().name() == 'bv' and y.sort().name() == 'bv':
    elif eq(x.sort(), BitVecSort(256)) and eq(y.sort(), BitVecSort(256)):
        if is_and:
            return (x & y)
        else:
            return (x | y)
    elif eq(x.sort(), BoolSort()) and eq(y.sort(), BitVecSort(256)):
        return and_or(If(x, con(1), con(0)), y, is_and)
    elif eq(x.sort(), BitVecSort(256)) and eq(y.sort(), BoolSort()):
        return and_or(x, If(y, con(1), con(0)), is_and)
    else:
        print(is_and, x, y)
        raise Exception('invalid argument of and/or: ' + x + y)

def and_of(x: Word, y: Word) -> Word:
    return and_or(x, y, True)

def or_of(x: Word, y: Word) -> Word:
    return and_or(x, y, False)

f_sdiv = Function('evm_sdiv', BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_smod = Function('evm_smod', BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_div  = Function('evm_div',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_mod  = Function('evm_mod',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_exp  = Function('evm_exp',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_add  = Function('evm_add',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_sub  = Function('evm_sub',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_mul  = Function('evm_mul',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_xor  = Function('evm_xor',  BitVecSort(256), BitVecSort(256), BitVecSort(256))

def is_power_of_two(x: int) -> bool:
    if x > 0:
        return not (x & (x - 1))
    else:
        return False

def arith(op: str, w1: Word, w2: Word) -> Word:
    if op == 'ADD':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 + w2
        else:
            return f_add(w1, w2)
    elif op == 'MUL':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 * w2
        elif w1.decl().name() == 'bv':
            i1: int = int(str(w1)) # must be concrete
            if i1 == 0:
                return con(0)
            elif is_power_of_two(i1):
                return w2 << int(math.log(i1,2))
            else:
                return f_mul(w1, w2)
        elif w2.decl().name() == 'bv':
            i2: int = int(str(w2)) # must be concrete
            if i2 == 0:
                return con(0)
            elif is_power_of_two(i2):
                return w1 << int(math.log(i2,2))
            else:
                return f_mul(w1, w2)
        else:
            return f_mul(w1, w2)
    elif op == 'SUB':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 - w2
        else:
            return f_sub(w1, w2)
    elif op == 'SDIV':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 / w2
        else:
            return f_sdiv(w1, w2)
    elif op == 'SMOD':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 % w2
        else:
            return f_smod(w1, w2)
    elif op == 'DIV':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return UDiv(w1, w2)
        elif w2.decl().name() == 'bv':
            i2: int = int(str(w2)) # must be concrete
            if i2 == 0:
                return con(0)
            elif is_power_of_two(i2):
                return UDiv(w1, w2)
            else:
                return f_div(w1, w2)
        else:
            return f_div(w1, w2)
    elif op == 'MOD':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return URem(w1, w2)
        else:
            return f_mod(w1, w2)
    elif op == 'EXP':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            i1: int = int(str(w1)) # must be concrete
            i2: int = int(str(w2)) # must be concrete
            return con(i1 ** i2)
        else:
            return f_exp(w1, w2)
    else:
        assert False

def call(ex: Exec, static: bool) -> None:
    gas = ex.st.pop()
    to = ex.st.pop()
    if static:
        fund = con(0)
    else:
        fund = ex.st.pop()
    arg_loc: int = ex.st.mloc()
    arg_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
    ret_loc: int = ex.st.mloc()
    ret_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete

    ex.balance = f_sub(ex.balance, fund)

    # push exit code
    if arg_size > 0:
        f_call = Function('call_'+str(arg_size*8), IntSort(), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(arg_size*8), BitVecSort(256))
        exit_code = f_call(ex.cnt_call(), gas, to, fund, simplify(wload(ex.st.memory, arg_loc, arg_size)))
    else:
        assert arg_size == 0
        f_call = Function('call_'+str(arg_size*8), IntSort(), BitVecSort(256), BitVecSort(256), BitVecSort(256),                         BitVecSort(256))
        exit_code = f_call(ex.cnt_call(), gas, to, fund)
#   ex.st.push(exit_code)
    exit_code_var = BitVec(f'call{ex.cnt_call()}', 256)
    ex.sol.add(exit_code_var == exit_code)
    ex.st.push(exit_code_var)

    # store return value
    if ret_size > 0:
        f_ret = Function('ret_'+str(ret_size*8), BitVecSort(256), BitVecSort(ret_size*8))
#       ret = f_ret(exit_code)
        ret = f_ret(exit_code_var)
        wstore(ex.st.memory, ret_loc, ret_size, ret)
#       for i in range(ret_size):
#           ex.st.memory[ret_loc + i] = simplify(Extract((ret_size - i)*8+7, (ret_size - i)*8, ret))
        ex.output = ret
    else:
        assert ret_size == 0
        ex.output = None

@log_call(include_args=[], include_result=False)
def jumpi(ex: Exec, stack: List[Exec], step_id: int) -> None:
    target: int = int(str(ex.st.pop())) # target must be concrete
    cond: Word = ex.st.pop()

    with start_action(action_type="z3 then branch"):
        ex.sol.push()
        #ex.sol.add(simplify(simp(cond != con(0))))
        #ex.sol.add(cond != con(0))
        ex.sol.add(simplify(is_non_zero(cond)))
        if ex.sol.check() != unsat: # jump
            with start_action(action_type="z3 clone"):
                new_sol = Solver()
                new_sol.add(ex.sol.assertions())
                new_ex = Exec(ex.pgm, ex.code, deepcopy(ex.st), target, new_sol, deepcopy(ex.storage), deepcopy(ex.output), deepcopy(ex.log), deepcopy(ex.balance), deepcopy(ex.cnts))
            stack.append((new_ex, step_id))
#           if __debug__:
#               print('jump')
#       else:
#           print("unsat: " + str(ex.sol))
        ex.sol.pop()

    with start_action(action_type="z3 else branch"):
        #ex.sol.add(simplify(simp(cond == con(0))))
        #ex.sol.add(cond == con(0))
        ex.sol.add(simplify(is_zero(cond)))
        if ex.sol.check() != unsat:
            ex.next_pc()
            stack.append((ex, step_id))
#       else:
#           print("unsat: " + str(ex.sol))

def returndatasize(ex: Exec) -> int:
    if ex.output is None:
        return 0
    else:
        size: int = ex.output.sort().size()
        assert size % 8 == 0
        return int(size / 8)

Steps = Dict[int,Dict[str,Any]]

def run(ex0: Exec) -> Tuple[List[Exec], Steps]:
    out: List[Exec] = []
    steps: Steps = {}
    step_id: int = 0

    stack: List[Tuple[Exec,int]] = [(ex0, 0)]
    while stack:
        (ex, prev_step_id) = stack.pop()
        step_id += 1

        o = ex.pgm[ex.pc]
        ex.cnts[o.op[0]] += 1

        if __debug__:
            if o.op[0] == 'JUMPI':
                steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
#           elif o.op[0] == 'CALL':
#               steps[step_id] = {'parent': prev_step_id, 'exec': str(ex) + ex.st.str_memory() + '\n'}
            else:
                steps[step_id] = {'parent': prev_step_id, 'exec': ex.summary()}
#           print(ex)

        #with start_action(action_type="run", op=o.op[0], pc=ex.pc):
        if o.op[0] == 'STOP':
            out.append(ex)
            continue

        elif o.op[0] == 'REVERT':
            ex.output = ex.st.ret()
            out.append(ex)
            continue

        elif o.op[0] == 'RETURN':
            ex.output = ex.st.ret()
            out.append(ex)
            continue

        elif o.op[0] == 'JUMPI':
            jumpi(ex, stack, step_id)
            continue

        elif o.op[0] == 'JUMP':
            target: int = int(str(ex.st.pop())) # target must be concrete
            ex.pc = target
            stack.append((ex, step_id))
            continue

        elif o.op[0] == 'JUMPDEST':
            pass

        elif int('01', 16) <= int(o.hx, 16) <= int('07', 16): # ADD MUL SUB DIV SDIV MOD SMOD
            ex.st.push(arith(o.op[0], ex.st.pop(), ex.st.pop()))

        elif o.op[0] == 'EXP':
            ex.st.push(arith(o.op[0], ex.st.pop(), ex.st.pop()))

#       elif o.op[0] == 'ADD':
#           ex.st.push(ex.st.pop() + ex.st.pop())
#       elif o.op[0] == 'MUL':
#           ex.st.push(ex.st.pop() * ex.st.pop())
#       elif o.op[0] == 'SUB':
#           ex.st.push(ex.st.pop() - ex.st.pop())
#       elif o.op[0] == 'SDIV':
#           ex.st.push(ex.st.pop() / ex.st.pop())
#       elif o.op[0] == 'SMOD':
#           ex.st.push(ex.st.pop() % ex.st.pop())
#       elif o.op[0] == 'DIV':
#           ex.st.push(UDiv(ex.st.pop(), ex.st.pop()))
#       elif o.op[0] == 'MOD':
#           ex.st.push(URem(ex.st.pop(), ex.st.pop()))

#       elif o.op[0] == 'EXP':
#           w1: int = int(str(ex.st.pop())) # must be concrete
#           w2: int = int(str(ex.st.pop())) # must be concrete
#           ex.st.push(con(w1 ** w2))

#       elif o.op[0] == 'LT':
#           ex.st.push(If(ULT(ex.st.pop(), ex.st.pop()), con(1), con(0)))
#       elif o.op[0] == 'GT':
#           ex.st.push(If(UGT(ex.st.pop(), ex.st.pop()), con(1), con(0)))
#       elif o.op[0] == 'SLT':
#           ex.st.push(If(ex.st.pop() < ex.st.pop(), con(1), con(0)))
#       elif o.op[0] == 'SGT':
#           ex.st.push(If(ex.st.pop() > ex.st.pop(), con(1), con(0)))
#       elif o.op[0] == 'EQ':
#           ex.st.push(If(ex.st.pop() == ex.st.pop(), con(1), con(0)))
#       elif o.op[0] == 'ISZERO':
#           ex.st.push(If(ex.st.pop() == con(0), con(1), con(0)))

        elif o.op[0] == 'LT':
            ex.st.push(ULT(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'GT':
            ex.st.push(UGT(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'SLT':
            ex.st.push(ex.st.pop() < ex.st.pop())
        elif o.op[0] == 'SGT':
            ex.st.push(ex.st.pop() > ex.st.pop())
        elif o.op[0] == 'EQ':
            w1 = ex.st.pop()
            w2 = ex.st.pop()
            if eq(w1.sort(), w2.sort()):
                ex.st.push(w1 == w2)
            else:
                if eq(w1.sort(), BoolSort()):
                    assert eq(w2.sort(), BitVecSort(256))
                    ex.st.push(If(w1, con(1), con(0)) == w2)
                else:
                    assert eq(w1.sort(), BitVecSort(256))
                    assert eq(w2.sort(), BoolSort())
                    ex.st.push(w1 == If(w2, con(1), con(0)))
        elif o.op[0] == 'ISZERO':
            ex.st.push(is_zero(ex.st.pop()))

        elif o.op[0] == 'AND':
            #ex.st.push(ex.st.pop() & ex.st.pop())
            ex.st.push(and_of(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'OR':
            #ex.st.push(ex.st.pop() | ex.st.pop())
            ex.st.push(or_of(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'NOT':
            ex.st.push(~ ex.st.pop())
        elif o.op[0] == 'SHL':
            w = ex.st.pop()
            ex.st.push(ex.st.pop() << w)
        elif o.op[0] == 'SAR':
            w = ex.st.pop()
            ex.st.push(ex.st.pop() >> w)
        elif o.op[0] == 'SHR':
            w = ex.st.pop()
            ex.st.push(LShR(ex.st.pop(), w))

        elif o.op[0] == 'XOR':
            ex.st.push(f_xor(ex.st.pop(), ex.st.pop()))

        elif o.op[0] == 'CALLDATALOAD':
            ex.st.push(f_calldataload(ex.st.pop()))
        elif o.op[0] == 'CALLDATASIZE':
            ex.st.push(f_calldatasize())
        elif o.op[0] == 'CALLVALUE':
            ex.st.push(f_callvalue())
        elif o.op[0] == 'CALLER':
            ex.st.push(f_caller())
        elif o.op[0] == 'ADDRESS':
            ex.st.push(f_address())
        elif o.op[0] == 'EXTCODESIZE':
            ex.st.push(f_extcodesize(ex.st.pop()))
        elif o.op[0] == 'CODESIZE':
            ex.st.push(con(len(ex.code)))
        elif o.op[0] == 'GAS':
            ex.st.push(f_gas(ex.cnt_gas()))
        elif o.op[0] == 'TIMESTAMP':
            ex.st.push(f_timestamp())

        elif o.op[0] == 'BALANCE':
            ex.st.push(f_balance(ex.st.pop(), ex.cnt_balance()))
        elif o.op[0] == 'SELFBALANCE':
#           ex.st.push(f_selfbalance(ex.pc, ex.cnt))
            ex.st.push(ex.balance)

        elif o.op[0] == 'CALL':
            call(ex, False)
        elif o.op[0] == 'STATICCALL':
            call(ex, True)

        elif o.op[0] == 'SHA3':
            ex.st.sha3()

        elif o.op[0] == 'POP':
            ex.st.pop()
        elif o.op[0] == 'MLOAD':
            ex.st.mload()
        elif o.op[0] == 'MSTORE':
            ex.st.mstore()

        elif o.op[0] == 'SLOAD':
            ex.st.push(Select(ex.storage, ex.st.pop()))
        elif o.op[0] == 'SSTORE':
#           ex.storage = Store(ex.storage, ex.st.pop(), ex.st.pop())
            ex.sstore(ex.st.pop(), ex.st.pop())

        elif o.op[0] == 'RETURNDATASIZE':
            ex.st.push(con(returndatasize(ex)))
        elif o.op[0] == 'RETURNDATACOPY':
            loc: int = ex.st.mloc()
            offset: int = int(str(ex.st.pop())) # offset must be concrete
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            if size > 0:
                datasize: int = returndatasize(ex)
                assert datasize >= offset + size
                data = Extract((datasize-1 - offset)*8+7, (datasize - offset - size)*8, ex.output)
                wstore(ex.st.memory, loc, size, data)

        elif o.op[0] == 'CODECOPY':
            loc: int = ex.st.mloc()
            pc: int = int(str(ex.st.pop())) # pc must be concrete
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            while len(ex.st.memory) < loc + size:
                ex.st.memory.extend([BitVecVal(0, 8) for _ in range(32)])
            for i in range(size):
                ex.st.memory[loc + i] = BitVecVal(int(read_code(ex.code, pc + i), 16), 8)

        elif o.op[0] == 'BYTE':
            idx: int = int(str(ex.st.pop())) # index must be concrete
            assert idx >= 0 and idx < 32
            w = ex.st.pop()
            ex.st.push(ZeroExt(248, Extract((31-idx)*8+7, (31-idx)*8, w)))

        elif int('a0', 16) <= int(o.hx, 16) <= int('a4', 16): # LOG0 -- LOG4
            num_keys: int = int(o.hx, 16) - int('a0', 16)
            loc: int = ex.st.mloc()
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            keys = []
            for _ in range(num_keys):
                keys.append(ex.st.pop())
            ex.log.append((keys, wload(ex.st.memory, loc, size) if size > 0 else None))
#           ex.log.append((keys, simplify(Concat(ex.st.memory[loc:loc+size])) if size > 0 else None))

        elif int('60', 16) <= int(o.hx, 16) <= int('7f', 16): # PUSH1 -- PUSH32
            ex.st.push(con(int(o.op[1], 16)))
        elif int('80', 16) <= int(o.hx, 16) <= int('8f', 16): # DUP1  -- DUP16
            ex.st.dup(int(o.hx, 16) - int('80', 16) + 1)
        elif int('90', 16) <= int(o.hx, 16) <= int('9f', 16): # SWAP1 -- SWAP16
            ex.st.swap(int(o.hx, 16) - int('90', 16) + 1)

        else:
        #   print(ex)
        #   raise Exception('unsupported opcode: ' + o.op[0])
            out.append(ex)
            continue

        ex.next_pc()
        stack.append((ex, step_id))

    return (out, steps)

@log_call(include_args=[], include_result=False)
def dasm(ops: List[Opcode], code: List[str], sol: Solver = Solver(), storage: Any = Array('storage', BitVecSort(256), BitVecSort(256)), output: Any = None, log = [], balance: Any = BitVec('balance', 256), cnts: Dict[str,int] = defaultdict(int)) -> Tuple[List[Exec], Steps]:
    st = State()
    ex = Exec(ops_to_pgm(ops), code, st, 0, sol, storage, output, log, balance, cnts)
    return run(ex)

if __name__ == '__main__':
    hexcode: str = input()
    dasm(decode(hexcode))
