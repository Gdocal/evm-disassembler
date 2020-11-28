from z3 import *
from byte2op import Opcode, decode
from dasm import *

import json
from os.path import expanduser
with open(expanduser('~/contracts/stakewise/artifacts/build-info/ba3f7730-12cd-4d66-81ee-8e82b674b02f.json')) as f:
    evm = json.load(f)['output']['contracts']['contracts/access/Admins.sol']['Admins']['evm']

hexcode = evm['deployedBytecode']['object']

(ops, code) = decode(hexcode)

sol = Solver()

storage = Array('storage', BitVecSort(256), BitVecSort(256))

funsig = int(evm['methodIdentifiers']['addAdmin(address)'], 16)
#size = 2

sha3_256 = Function('sha3_256', BitVecSort(256), BitVecSort(256))

# calldata
sol.add(Extract(255, 224, f_calldataload(con(0))) == funsig) 

# sha3 is not too small nor too big
#sol.add(UGT(sha3_256(con(0)), con(100)))
#sol.add(ULT(sha3_256(con(0)), con(1000)))

# original data size
#sol.add(Select(storage, con(0)) == con(4))

exs = dasm(ops, code, sol, storage)
for ex in exs:
    print(ex)
