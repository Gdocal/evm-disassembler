from z3 import *
from byte2op import Opcode, decode
from dasm import *

hexcode = '608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634b64e492146044575b600080fd5b348015604f57600080fd5b506082600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505060c4565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b60008190509190505600a165627a7a72305820fef7ba925e24a935e59bb401907893518a66095fa9e2c2506b29051dfdaa6ff80029'

ops = decode(hexcode)

exs = dasm(ops)
for ex in exs:
    print(ex)
#   print(ex.pc)
#   print(ex.st)
#   print(ex.sol)
#   #print(ex.pgm)

#   s = Solver()
#   s.add(Not(
#       ex.st.stack[2] == Concat(BitVecVal(0, 224), Extract(255, 224, f_calldataload(0)))
#   ))
#   print(s.check())
