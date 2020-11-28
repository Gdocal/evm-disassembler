from z3 import *
from byte2op import Opcode
from dasm import *

ops = []
ops.append(Opcode(0, '60', ['PUSH1', '00']))
ops.append(Opcode(2, '35', ['CALLDATALOAD']))
ops.append(Opcode(3, '60', ['PUSH1', '1c']))
ops.append(Opcode(5, '52', ['MSTORE']))
ops.append(Opcode(6, '60', ['PUSH1', '00']))
ops.append(Opcode(8, '51', ['MLOAD']))
ops.append(Opcode(9, '00', ['STOP']))

exs = dasm(ops, [])
for ex in exs:
    print(ex)
#   print(ex.pc)
#   print(ex.st)
#   #print(ex.pgm)

    s = Solver()
    s.add(Not(
        ex.st.stack[0] == Concat(BitVecVal(0, 224), Extract(255, 224, f_calldataload(0)))
    ))
    print(s.check())
