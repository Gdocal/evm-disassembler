from z3 import *
from byte2op import Opcode, decode
from dasm import *

# memcpy.sol
hexcode = '608060405234801561001057600080fd5b506004361061002b5760003560e01c80638b44cef114610030575b600080fd5b6100a06004803603602081101561004657600080fd5b81019060208101813564010000000081111561006157600080fd5b82018360208201111561007357600080fd5b8035906020019184602083028401116401000000008311171561009557600080fd5b5090925090506100a2565b005b6100ae600083836100b3565b505050565b8280548282559060005260206000209081019282156100ee579160200282015b828111156100ee5782358255916020019190600101906100d3565b506100fa9291506100fe565b5090565b61011891905b808211156100fa5760008155600101610104565b9056fea264697066735822122068d5d045c283d9172f8dee5d9232705e3ff164830e187f0809a7d65cc8b96d3264736f6c634300060b0033'

(ops, code) = decode(hexcode)

sol = Solver()

storage = Array('storage', BitVecSort(256), BitVecSort(256))

funsig = 0x8b44cef1 # foo(uint256[])
size = 2

sha3_256 = Function('sha3_256', BitVecSort(256), BitVecSort(256))

# calldata
sol.add(Extract(255, 224, f_calldataload(con(0))) == funsig) 
sol.add(f_calldataload(con(4)) == con(32)) # offset to d.length
sol.add(f_calldataload(con(4+32)) == con(size)) # d.length == size
sol.add(f_calldatasize() == con(4+32+32+32*size)) # msg.data.length == 132 = 4 + 32 + 32 + 32 * d.length

# callvalue
sol.add(f_callvalue() == con(0)) # msg.value == 0

# sha3 is not too small nor too big
sol.add(UGT(sha3_256(con(0)), con(100)))
sol.add(ULT(sha3_256(con(0)), con(1000)))

# original data size
sol.add(Select(storage, con(0)) == con(4))

(exs, _) = dasm(ops, code, sol, storage)
for ex in exs:
    print(ex)
