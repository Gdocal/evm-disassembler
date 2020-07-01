#!/usr/bin/env python3.6

import sys
from z3 import *
from typing import List, Dict, Any
from byte2op import Opcode, decode

Word = Any
Byte = Any

class State:
    stack: List[Word]
    memory: List[Byte]

    def __init__(self) -> None:
        self.stack: List[Word] = []
        self.memory: List[Byte] = []

    def push(self, v: Word) -> None:
        self.stack.insert(0, v)

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
        self.push(simplify(Concat(self.memory[loc:loc+32])))

    def calldataload(self) -> None:
        self.push(f_calldataload(self.pop()))

    def __str__(self) -> str:
        return "stack:  " + str(self.stack) + "\n" + \
               "memory: " + str(self.memory)

f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256))

class Exec:
    pgm: List[Opcode]
    st: State
    pc: int

    def __init__(self, ops: List[Opcode], st: State, pc: int) -> None:
        self.pgm = [None for _ in range(ops[-1].pc + 1)]
        for o in ops:
            self.pgm[o.pc] = o
        self.st = st
        self.pc = pc

    def next_pc(self) -> int:
        self.pc += 1
        while self.pgm[self.pc] is None:
            self.pc += 1

    def run(self) -> None:
        o = self.pgm[self.pc]
        # PUSH1 -- PUSH32
        if int('60', 16) <= int(o.hx, 16) <= int('7f', 16):
            self.st.push(BitVecVal(int(o.op[1], 16), 256))
        # DUP1 -- DUP16
        elif int('80', 16) <= int(o.hx, 16) <= int('8f', 16):
            self.st.dup(int(o.hx, 16) - int('80', 16) + 1)
        # SWAP1 -- SWAP16
        elif int('90', 16) <= int(o.hx, 16) <= int('9f', 16):
            self.st.swap(int(o.hx, 16) - int('90', 16) + 1)
        elif o.op[0] == 'POP':
            self.st.pop()
        elif o.op[0] == 'MLOAD':
            self.st.mload()
        elif o.op[0] == 'MSTORE':
            self.st.mstore()
        elif o.op[0] == 'CALLDATALOAD':
            self.st.calldataload()
        elif o.op[0] == 'STOP':
            return

        self.next_pc()
        self.run()

def dasm(ops: List[Opcode]) -> Exec:
    st = State()
    ex = Exec(ops, st, 0)
    ex.run()
    return ex

if __name__ == '__main__':
    hexcode: str = input()
    dasm(decode(hexcode))
