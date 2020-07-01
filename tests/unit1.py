from z3 import *
from dasm import *

st = State()

def con(c: int):
    return BitVecVal(c, 256)
def var(x: str):
    return BitVec(x, 256)

st.push(con(1)) # var('x')
st.push(con(0))
st.mstore()
st.push(con(0))
st.mload()

print(str(st))

# help_simplify()
