#!/usr/bin/env python3.6

import sys
from typing import List, Dict, Any
from byte2op import Opcode, decode
from z3 import *

Word = Any
Byte = Any

class State:
    def __init__(self) -> None:
        self.stack: List[Word] = []
        self.memory: List[Byte] = []

    def push(self, value: Word) -> None:
        self.stack.insert(0, value)

    def pop(self) -> Word:
        tmp = self.stack[0]
        del self.stack[0]
        return tmp

    def dup(self, n: int) -> None:
        self.push(self.stack[n])

    def swap(self, n: int) -> None:
        tmp = self.stack[0]
        self.stack[0] = self.stack[n]
        self.stack[n] = tmp

    def mstore(self) -> None:
        loc: int = int(str(self.pop()))
        val: Word = self.pop()
        while len(self.memory) < loc + 32:
            self.memory.extend([BitVec(0, 8) for _ in range(32)])
        for i in range(32):
            self.memory[loc + i] = simplify(Extract((31-i)*8+7, (31-i)*8, val))

    def mload(self) -> None:
        loc: int = int(str(self.pop()))
        while len(self.memory) < loc + 32:
            self.memory.extend([BitVec(0, 8) for _ in range(32)])
        self.push(simplify(Concat(self.memory[loc:loc+32])))

    def __str__(self) -> str:
        return "stack:  " + str(self.stack) + "\n" + \
               "memory: " + str(self.memory)


def dasm(ops: List[Opcode]) -> None:
    for o in ops:
        print(o.pc, o.op)

if __name__ == '__main__':
    hexcode: str = input()
    dasm(decode(hexcode))
