#from z3 import *
#from byte2op import Opcode, decode
from dasm import *

import json
from os.path import expanduser
with open(expanduser('~/contracts/stakewise/artifacts/build-info/ba3f7730-12cd-4d66-81ee-8e82b674b02f.json')) as f:
    evm = json.load(f)['output']['contracts']['contracts/collectors/Solos.sol']['Solos']['evm']

hexcode = evm['deployedBytecode']['object']

(ops, code) = decode(hexcode)

sol = Solver()

storage = Array('storage', BitVecSort(256), BitVecSort(256))

funsig = int(evm['methodIdentifiers']['addDeposit(bytes32)'], 16)
#size = 2

sha3_256 = Function('sha3_256', BitVecSort(256), BitVecSort(256))

# calldata
sol.add(Extract(255, 224, f_calldataload(con(0))) == funsig) 

# sha3 is not too small nor too big
#sol.add(UGT(sha3_256(con(0)), con(100)))
#sol.add(ULT(sha3_256(con(0)), con(1000)))

# original data size
#sol.add(Select(storage, con(0)) == con(4))

#start = timer()
exs = dasm(ops, code, sol, storage)
#end = timer()
for ex in exs:
    print(ex)
#print(f"Total time (seconds): {end - start:0.2f}")
