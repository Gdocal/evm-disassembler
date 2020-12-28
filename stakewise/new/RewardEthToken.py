#from z3 import *
#from byte2op import Opcode, decode
from dasm import *

import os
import json
dir_path = os.path.dirname(os.path.realpath(__file__))
with open(f'{dir_path}/579ab81d-40a8-4997-8455-586df53426d4.json') as f:
#with open(os.path.expanduser('~/ethereum/stakewise/artifacts/build-info/579ab81d-40a8-4997-8455-586df53426d4.json')) as f:
    evm = json.load(f)['output']['contracts']['contracts/tokens/RewardEthToken.sol']['RewardEthToken']['evm']

hexcode = evm['deployedBytecode']['object']

(ops, code) = decode(hexcode)

sol = Solver()

storage = Array('storage', BitVecSort(256), BitVecSort(256))

#funsig = int(evm['methodIdentifiers']['updateRewardCheckpoint(address)'], 16)
#funsig = int(evm['methodIdentifiers']['updateRewardCheckpoints(address,address)'], 16)
#funsig = int(evm['methodIdentifiers']['updateTotalRewards(uint256)'], 16)
funsig = int(evm['methodIdentifiers']['claimRewards(address,uint256)'], 16)

# calldata
sol.add(Extract(255, 224, f_calldataload(con(0))) == funsig) 

start = timer()
(exs, steps) = dasm(ops, code, sol, storage)
end = timer()
for ex in exs:
    print(ex)
with open('out.json', 'w') as json_file:
    json.dump(steps, json_file)
print(f"Total time (seconds): {end - start:0.2f}")
