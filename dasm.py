#!/usr/bin/env python3.6

import sys
from copy import deepcopy
from z3 import *
from typing import List, Dict, Any
from byte2op import Opcode, decode

Word = Any # z3 expression (including constants)
Byte = Any # z3 expression (including constants)

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
        self.stack.insert(0, simplify(v))

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
        for i in range(32):
            self.memory[loc + i] = simplify(Extract((31-i)*8+7, (31-i)*8, val))

    def mload(self) -> None:
        loc: int = self.mloc()
        self.push(Concat(self.memory[loc:loc+32]))

def con(n: int) -> Word:
    return BitVecVal(n, 256)

f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256))
f_calldatasize = Function('calldatasize', BitVecSort(256))
f_callvalue = Function('callvalue', BitVecSort(256))

# convert opcode list to opcode map
def ops_to_pgm(ops: List[Opcode]) -> List[Opcode]:
    pgm: List[Opcode] = [None for _ in range(ops[-1].pc + 1)]
    for o in ops:
        pgm[o.pc] = o
    return pgm

class Exec:
    pgm: List[Opcode]
    st: State
    pc: int
    sol: Solver

    def __init__(self, pgm: List[Opcode], st: State, pc: int, sol: Solver) -> None:
        self.pgm = pgm
        self.st = st
        self.pc = pc
        self.sol = sol

    def __str__(self) -> str:
        return str(self.pc) + " " + str(self.pgm[self.pc].op[0]) + "\n" + \
               str(self.st) + "\n" + \
               str(self.sol)

    def next_pc(self) -> int:
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

def run(ex0: Exec) -> List[Exec]:
    out: List[Exec] = []

    stack: List[Exec] = [ex0]
    while stack:
        ex = stack.pop()
#       print(ex)

        o = ex.pgm[ex.pc]

        if o.op[0] == 'STOP':
            out.append(ex)
            continue

        elif o.op[0] == 'REVERT':
            out.append(ex)
            continue

        elif o.op[0] == 'RETURN':
            out.append(ex)
            continue

        elif o.op[0] == 'JUMPI':
            target: int = int(str(ex.st.pop())) # target must be concrete
            cond: Word = ex.st.pop()

            ex.sol.push()
            ex.sol.add(simplify(simp(cond != con(0))))
            if ex.sol.check() != unsat: # jump
                new_sol = Solver()
                new_sol.add(ex.sol.assertions())
                new_ex = Exec(ex.pgm, deepcopy(ex.st), target, new_sol)
                stack.append(new_ex)
#               print('jump')
#           else:
#               print("unsat: " + str(ex.sol))
            ex.sol.pop()

            ex.sol.add(simplify(simp(cond == con(0))))
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

        elif o.op[0] == 'LT':
            ex.st.push(If(ULT(ex.st.pop(), ex.st.pop()), con(1), con(0)))
        elif o.op[0] == 'GT':
            ex.st.push(If(UGT(ex.st.pop(), ex.st.pop()), con(1), con(0)))
        elif o.op[0] == 'SLT':
            ex.st.push(If(ex.st.pop() < ex.st.pop(), con(1), con(0)))
        elif o.op[0] == 'SGT':
            ex.st.push(If(ex.st.pop() > ex.st.pop(), con(1), con(0)))
        elif o.op[0] == 'EQ':
            ex.st.push(If(ex.st.pop() == ex.st.pop(), con(1), con(0)))
        elif o.op[0] == 'ISZERO':
            ex.st.push(If(ex.st.pop() == con(0), con(1), con(0)))

        elif o.op[0] == 'AND':
            ex.st.push(ex.st.pop() & ex.st.pop())
        elif o.op[0] == 'OR':
            ex.st.push(ex.st.pop() | ex.st.pop())
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

        elif o.op[0] == 'POP':
            ex.st.pop()
        elif o.op[0] == 'MLOAD':
            ex.st.mload()
        elif o.op[0] == 'MSTORE':
            ex.st.mstore()

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

def dasm(ops: List[Opcode], sol: Solver = Solver()) -> List[Exec]:
    st = State()
    ex = Exec(ops_to_pgm(ops), st, 0, sol)
    return run(ex)

if __name__ == '__main__':
    hexcode: str = input()
    dasm(decode(hexcode))
