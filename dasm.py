#!/usr/bin/env python3.6

import sys
from copy import deepcopy
from z3 import *
from typing import List, Dict, Tuple, Any
from byte2op import Opcode, decode

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
        return "stack:  " + str(self.stack) + "\n" + \
               "memory: " + str(self.memory)

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

f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256))
f_calldatasize = Function('calldatasize', BitVecSort(256))
f_callvalue = Function('callvalue', BitVecSort(256))
f_caller = Function('caller', BitVecSort(256))
f_address = Function('address', BitVecSort(256))
f_extcodesize = Function('extcodesize', BitVecSort(256), BitVecSort(256))
f_gas = Function('extcodesize', IntSort(), IntSort(), BitVecSort(256))

# convert opcode list to opcode map
def ops_to_pgm(ops: List[Opcode]) -> List[Opcode]:
    pgm: List[Opcode] = [None for _ in range(ops[-1].pc + 1)]
    for o in ops:
        pgm[o.pc] = o
    return pgm

class Exec:
    pgm: List[Opcode]
    code: List[str]
    st: State
    pc: int
    sol: Solver
    storage: Any # Array('storage', BitVecSort(256), BitVecSort(256))
    ret: Any
    log: List[Tuple[List[Word], Any]]
    cnt: int

    def __init__(self, pgm: List[Opcode], code: List[str], st: State, pc: int, sol: Solver, storage: Any) -> None:
        self.pgm = pgm
        self.code = code
        self.st = st
        self.pc = pc
        self.sol = sol
        self.storage = storage
        self.ret = None
        self.log = []
        self.cnt = 0

    def __str__(self) -> str:
        return str(self.pc) + " " + str(self.pgm[self.pc].op[0]) + "\n" + \
               str(self.st) + "\n" + \
               "storage: " + str(self.storage) + "\n" + \
               "path: " + str(self.sol) + "\n" + \
               "output: " + str(self.ret) + "\n" + \
               "log: " + str(self.log) + "\n"

    def next_pc(self) -> int:
        self.cnt += 1
        self.pc += 1
        while self.pgm[self.pc] is None:
            self.pc += 1

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
    else:
        print(x, y)
        raise Exception('invalid argument of and/or: ' + x + y)

def and_of(x: Word, y: Word) -> Word:
    return and_or(x, y, True)

def or_of(x: Word, y: Word) -> Word:
    return and_or(x, y, False)

def call(ex: Exec) -> None:
    gas = ex.st.pop()
    to = ex.st.pop()
    fund = ex.st.pop()
    arg_loc: int = ex.st.mloc()
    arg_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
    ret_loc: int = ex.st.mloc()
    ret_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete

    # push exit code
    f_call = Function('call_'+str(arg_size*8), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(arg_size*8), BitVecSort(256))
    exit_code = f_call(gas, to, fund, simplify(wload(ex.st.memory, arg_loc, arg_size)))
    ex.st.push(exit_code)

    # store return value
    f_ret = Function('ret_'+str(ret_size*8), BitVecSort(256), BitVecSort(ret_size*8))
    ret = f_ret(exit_code)
    wstore(ex.st.memory, ret_loc, ret_size, ret)
#   for i in range(ret_size):
#       ex.st.memory[ret_loc + i] = simplify(Extract((ret_size - i)*8+7, (ret_size - i)*8, ret))

def run(ex0: Exec) -> List[Exec]:
    out: List[Exec] = []

    stack: List[Exec] = [ex0]
    while stack:
        ex = stack.pop()
        if __debug__:
            print(ex)

        o = ex.pgm[ex.pc]

        if o.op[0] == 'STOP':
            out.append(ex)
            continue

        elif o.op[0] == 'REVERT':
            ex.ret = ex.st.ret()
            out.append(ex)
            continue

        elif o.op[0] == 'RETURN':
            ex.ret = ex.st.ret()
            out.append(ex)
            continue

        elif o.op[0] == 'JUMPI':
            target: int = int(str(ex.st.pop())) # target must be concrete
            cond: Word = ex.st.pop()

            ex.sol.push()
            #ex.sol.add(simplify(simp(cond != con(0))))
            #ex.sol.add(cond != con(0))
            ex.sol.add(simplify(is_non_zero(cond)))
            if ex.sol.check() != unsat: # jump
                new_sol = Solver()
                new_sol.add(ex.sol.assertions())
                new_ex = Exec(ex.pgm, ex.code, deepcopy(ex.st), target, new_sol, deepcopy(ex.storage))
                stack.append(new_ex)
                if __debug__:
                    print('jump')
#           else:
#               print("unsat: " + str(ex.sol))
            ex.sol.pop()

            #ex.sol.add(simplify(simp(cond == con(0))))
            #ex.sol.add(cond == con(0))
            ex.sol.add(simplify(is_zero(cond)))
            if ex.sol.check() != unsat:
                ex.next_pc()
                stack.append(ex)
#           else:
#               print("unsat: " + str(ex.sol))

            continue

        elif o.op[0] == 'JUMP':
            target: int = int(str(ex.st.pop())) # target must be concrete
            ex.pc = target
            stack.append(ex)
            continue

        elif o.op[0] == 'JUMPDEST':
            pass

        elif o.op[0] == 'ADD':
            ex.st.push(ex.st.pop() + ex.st.pop())
        elif o.op[0] == 'MUL':
            ex.st.push(ex.st.pop() * ex.st.pop())
        elif o.op[0] == 'SUB':
            ex.st.push(ex.st.pop() - ex.st.pop())
        elif o.op[0] == 'SDIV':
            ex.st.push(ex.st.pop() / ex.st.pop())
        elif o.op[0] == 'SMOD':
            ex.st.push(ex.st.pop() % ex.st.pop())
        elif o.op[0] == 'DIV':
            ex.st.push(UDiv(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'MOD':
            ex.st.push(URem(ex.st.pop(), ex.st.pop()))

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
            ex.st.push(ex.st.pop() == ex.st.pop())
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
        elif o.op[0] == 'GAS':
            ex.st.push(f_gas(ex.pc, ex.cnt))

        elif o.op[0] == 'CALL':
            call(ex)

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
            ex.storage = Store(ex.storage, ex.st.pop(), ex.st.pop())

        elif o.op[0] == 'CODECOPY':
            loc: int = ex.st.mloc()
            pc: int = int(str(ex.st.pop())) # pc must be concrete
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            for i in range(size):
                ex.st.memory[loc + i] = BitVecVal(int(ex.code[pc + i], 16), 8)

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
        stack.append(ex)

    return out

def dasm(ops: List[Opcode], code: List[str], sol: Solver = Solver(), storage: Any = Array('storage', BitVecSort(256), BitVecSort(256))) -> List[Exec]:
    st = State()
    ex = Exec(ops_to_pgm(ops), code, st, 0, sol, storage)
    return run(ex)

if __name__ == '__main__':
    hexcode: str = input()
    dasm(decode(hexcode))
