#from z3 import *
#from byte2op import Opcode, decode
from dasm import *

import os
import json
dir_path = os.path.dirname(os.path.realpath(__file__))
with open(f'{dir_path}/19da824.json') as f:
    evm = json.load(f)['output']['contracts']['contracts/collectors/Solos.sol']['Solos']['evm']

hexcode = evm['deployedBytecode']['object']

(ops, code) = decode(hexcode)

sol = Solver()

storage = Array('storage', BitVecSort(256), BitVecSort(256))

#funsig = int(evm['methodIdentifiers']['addDeposit(bytes32)'], 16)
#funsig = int(evm['methodIdentifiers']['cancelDeposit(bytes32,uint256)'], 16)
#funsig = int(evm['methodIdentifiers']['setValidatorPrice(uint256)'], 16)
#funsig = int(evm['methodIdentifiers']['setCancelLockDuration(uint256)'], 16)
funsig = int(evm['methodIdentifiers']['registerValidator((bytes,bytes,bytes32,bytes32))'], 16)

# calldata
sol.add(Extract(255, 224, f_calldataload(con(0))) == funsig) 
sol.add(f_calldataload(con(4)) == con(32))
sol.add(f_calldataload(con(4+32)) == con(32*4))
sol.add(f_calldataload(con(4+32*2)) == con(32*4+32*3))
sol.add(f_calldataload(con(4+32*5)) == con(48))
sol.add(f_calldataload(con(4+32*8)) == con(96))
sol.add(f_calldatasize() == con(4+32*12))

start = timer()
(exs, steps) = dasm(ops, code, sol, storage)
end = timer()
for ex in exs:
    print(ex)
with open('out.json', 'w') as json_file:
    json.dump(steps, json_file)
print(f"Total time (seconds): {end - start:0.2f}")
