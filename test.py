from z3 import *
from dasm import State

st = State()

#st.push(BitVecVal(1, 256))
st.push(BitVec('x', 256))
st.push(BitVecVal(0, 256))
st.mstore()
st.push(BitVecVal(0, 256))
st.mload()

print(str(st))

# help_simplify()
