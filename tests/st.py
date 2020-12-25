#from z3 import *
#from byte2op import Opcode, decode
from dasm import *

import os
with open('toys/struct.sol.out/Struct.bin-runtime', 'r') as file:
    hexcode = file.read().strip()

(ops, code) = decode(hexcode)

sol = Solver()

storage = Array('storage', BitVecSort(256), BitVecSort(256))

funsig = 0x01ba793b # updateRewardCheckpoint(address)

# calldata
sol.add(Extract(255, 224, f_calldataload(con(0))) == funsig) 

exs = dasm(ops, code, sol, storage)
for ex in exs:
    print(ex)
